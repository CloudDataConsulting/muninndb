package mbp

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/scrypster/muninndb/internal/auth"
)

// vaultAuthStore is the narrow auth surface required by MBP. Server construction
// still accepts *auth.Store; the interface keeps authorization logic testable
// without weakening the production type boundary.
type vaultAuthStore interface {
	ValidateAPIKey(token string) (auth.APIKey, error)
	GetVaultConfig(vault string) (auth.VaultConfig, error)
}

// connectionSession is established exactly once by HELLO. Its credential,
// vault, and mode fields are immutable for the life of the connection. The
// subscription set is the only mutable session state.
type connectionSession struct {
	authMethod string
	token      string
	key        *auth.APIKey
	vault      string
	mode       string
	terminate  context.CancelFunc
	termOnce   sync.Once

	subscriptionsMu sync.Mutex
	subscriptions   map[string]struct{}
}

const (
	defaultSessionAuthRecheckInterval = 30 * time.Second
	defaultSubscriptionCleanupTimeout = 5 * time.Second
	maxSubscriptionCleanupWorkers     = 8
)

type connectionSessionContextKey struct{}

func withConnectionSession(ctx context.Context, session *connectionSession) context.Context {
	ctx = context.WithValue(ctx, connectionSessionContextKey{}, session)
	ctx = context.WithValue(ctx, auth.ContextVault, session.vault)
	ctx = context.WithValue(ctx, auth.ContextMode, session.mode)
	if session.key != nil {
		key := *session.key
		ctx = context.WithValue(ctx, auth.ContextAPIKey, &key)
		ctx = context.WithValue(ctx, auth.ContextPrincipal, auth.PrincipalAPIKey)
	} else {
		ctx = context.WithValue(ctx, auth.ContextPrincipal, auth.PrincipalPublic)
	}
	return ctx
}

func connectionSessionFromContext(ctx context.Context) (*connectionSession, error) {
	session, _ := ctx.Value(connectionSessionContextKey{}).(*connectionSession)
	if session == nil {
		return nil, newAuthorizationError(ErrAuthFailed, "connection is not authorized")
	}
	return session, nil
}

type authorizationError struct {
	code    ErrorCode
	message string
}

func (e *authorizationError) Error() string { return e.message }

func newAuthorizationError(code ErrorCode, format string, args ...any) error {
	return &authorizationError{code: code, message: fmt.Sprintf(format, args...)}
}

func authorizationErrorCode(err error) ErrorCode {
	if authErr, ok := err.(*authorizationError); ok {
		return authErr.code
	}
	return ErrAuthFailed
}

func validAPIKeyMode(mode string) bool {
	switch mode {
	case auth.ModeFull, auth.ModeObserve, auth.ModeWrite:
		return true
	default:
		return false
	}
}

func sameExpiry(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}

func sameSecurityClaims(current auth.APIKey, expected *auth.APIKey) bool {
	return expected != nil &&
		current.ID == expected.ID &&
		current.Vault == expected.Vault &&
		current.Mode == expected.Mode &&
		sameExpiry(current.ExpiresAt, expected.ExpiresAt)
}

// authenticateHello validates HELLO and returns the immutable authorization
// claims for the connection. Anonymous access is accepted only for an
// explicitly public vault. Public MBP sessions retain the documented open
// read/write behavior; observe semantics require an observe-mode key.
func (s *Server) authenticateHello(req *HelloRequest) (*connectionSession, error) {
	if s.authStore == nil {
		return nil, newAuthorizationError(ErrAuthFailed, "server authentication is unavailable")
	}

	requestedVault := req.Vault
	if requestedVault != "" && !auth.ValidVaultName(requestedVault) {
		return nil, newAuthorizationError(ErrAuthFailed, "invalid vault name")
	}
	switch req.AuthMethod {
	case "token":
		key, err := s.authStore.ValidateAPIKey(req.Token)
		if err != nil {
			return nil, newAuthorizationError(ErrAuthFailed, "invalid token")
		}
		if key.ID == "" || !auth.ValidVaultName(key.Vault) {
			return nil, newAuthorizationError(ErrAuthFailed, "invalid api key scope")
		}
		if !validAPIKeyMode(key.Mode) {
			return nil, newAuthorizationError(ErrAuthFailed, "invalid api key mode")
		}
		if requestedVault != "" && requestedVault != key.Vault {
			return nil, newAuthorizationError(ErrVaultForbidden, "api key is not authorized for vault %q", requestedVault)
		}
		keyCopy := key
		return &connectionSession{
			authMethod:    "token",
			token:         req.Token,
			key:           &keyCopy,
			vault:         key.Vault,
			mode:          key.Mode,
			subscriptions: make(map[string]struct{}),
		}, nil

	case "none":
		vault := requestedVault
		if vault == "" {
			vault = "default"
		}
		cfg, err := s.authStore.GetVaultConfig(vault)
		if err != nil || !cfg.Public {
			return nil, newAuthorizationError(ErrAuthFailed, "vault %q requires an api key", vault)
		}
		return &connectionSession{
			authMethod:    "none",
			vault:         vault,
			mode:          auth.ModeFull,
			subscriptions: make(map[string]struct{}),
		}, nil

	default:
		return nil, newAuthorizationError(ErrAuthFailed, "invalid auth method")
	}
}

// revalidateSession makes revocation, expiry, scope/mode edits, and public-vault
// policy changes effective on the next frame and during periodic idle checks.
func (s *Server) revalidateSession(session *connectionSession) error {
	if session == nil || s.authStore == nil {
		return newAuthorizationError(ErrAuthFailed, "connection is not authorized")
	}

	switch session.authMethod {
	case "token":
		current, err := s.authStore.ValidateAPIKey(session.token)
		if err != nil || !sameSecurityClaims(current, session.key) {
			return newAuthorizationError(ErrAuthFailed, "api key expired, revoked, or changed")
		}
	case "none":
		cfg, err := s.authStore.GetVaultConfig(session.vault)
		if err != nil || !cfg.Public {
			return newAuthorizationError(ErrAuthFailed, "vault %q is no longer public", session.vault)
		}
	default:
		return newAuthorizationError(ErrAuthFailed, "connection is not authorized")
	}
	return nil
}

func (s *connectionSession) terminateConnection() {
	if s == nil || s.terminate == nil {
		return
	}
	s.termOnce.Do(s.terminate)
}

// monitorSessionAuthorization bounds the lifetime of authorization on an idle
// connection. Frame-level checks remain authoritative; this monitor ensures an
// idle revoked/expired key or newly locked public vault cannot retain trigger
// subscriptions indefinitely.
func (s *Server) monitorSessionAuthorization(ctx context.Context, session *connectionSession) {
	interval := s.authRecheckInterval
	if interval <= 0 {
		interval = defaultSessionAuthRecheckInterval
	}

	for {
		wait := interval
		if session != nil && session.key != nil && session.key.ExpiresAt != nil {
			untilExpiry := time.Until(*session.key.ExpiresAt)
			if untilExpiry <= 0 {
				session.terminateConnection()
				return
			}
			if untilExpiry < wait {
				wait = untilExpiry
			}
		}

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-timer.C:
		}

		if err := s.revalidateSession(session); err != nil {
			session.terminateConnection()
			return
		}
	}
}

func (s *Server) authorizeFrame(ctx context.Context, frameType uint8) (*connectionSession, error) {
	session, err := connectionSessionFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if err := s.revalidateSession(session); err != nil {
		return nil, err
	}

	switch session.mode {
	case auth.ModeFull:
		return session, nil
	case auth.ModeObserve:
		switch frameType {
		case TypeWrite, TypeLink, TypeForget:
			return nil, newAuthorizationError(ErrVaultForbidden, "observe-mode api key cannot write")
		}
	case auth.ModeWrite:
		switch frameType {
		case TypeRead, TypeActivate, TypeSubscribe, TypeStat:
			return nil, newAuthorizationError(ErrVaultForbidden, "write-only api key cannot read")
		}
	default:
		return nil, newAuthorizationError(ErrAuthFailed, "invalid api key mode")
	}
	return session, nil
}

// pinRequestVault makes the HELLO-authorized vault authoritative. Empty vaults
// are canonicalized; an explicit different vault is rejected before the engine
// is invoked.
func pinRequestVault(session *connectionSession, requestVault *string) error {
	if session == nil || requestVault == nil {
		return newAuthorizationError(ErrAuthFailed, "connection is not authorized")
	}
	vault := *requestVault
	if vault != "" && !auth.ValidVaultName(vault) {
		return newAuthorizationError(ErrVaultForbidden, "invalid vault name")
	}
	if vault != "" && vault != session.vault {
		return newAuthorizationError(ErrVaultForbidden, "connection is not authorized for vault %q", vault)
	}
	*requestVault = session.vault
	return nil
}

func (s *Server) pinContextVault(ctx context.Context, requestVault *string) error {
	session, err := connectionSessionFromContext(ctx)
	if err != nil {
		return err
	}
	return pinRequestVault(session, requestVault)
}

func (s *connectionSession) addSubscription(subID string) bool {
	if strings.TrimSpace(subID) == "" {
		return false
	}
	s.subscriptionsMu.Lock()
	defer s.subscriptionsMu.Unlock()
	s.subscriptions[subID] = struct{}{}
	return true
}

func (s *connectionSession) takeSubscription(subID string) bool {
	s.subscriptionsMu.Lock()
	defer s.subscriptionsMu.Unlock()
	if _, ok := s.subscriptions[subID]; !ok {
		return false
	}
	delete(s.subscriptions, subID)
	return true
}

func (s *connectionSession) restoreSubscription(subID string) {
	s.subscriptionsMu.Lock()
	s.subscriptions[subID] = struct{}{}
	s.subscriptionsMu.Unlock()
}

func (s *connectionSession) drainSubscriptions() []string {
	s.subscriptionsMu.Lock()
	defer s.subscriptionsMu.Unlock()
	ids := make([]string, 0, len(s.subscriptions))
	for id := range s.subscriptions {
		ids = append(ids, id)
		delete(s.subscriptions, id)
	}
	return ids
}

func (s *Server) rollbackSubscriptions(ids ...string) {
	session := &connectionSession{subscriptions: make(map[string]struct{})}
	for _, id := range ids {
		session.addSubscription(id)
	}
	s.cleanupSubscriptions(session)
}

// cleanupSubscriptions prevents connection-scoped subscriptions from leaking
// after disconnect. One deadline bounds the whole connection cleanup, and a
// small worker pool prevents a slow adapter from multiplying teardown latency
// by the number of subscriptions it owns.
func (s *Server) cleanupSubscriptions(session *connectionSession) {
	if session == nil {
		return
	}
	ids := session.drainSubscriptions()
	if len(ids) == 0 {
		return
	}
	timeout := s.subscriptionCleanupTimeout
	if timeout <= 0 {
		timeout = defaultSubscriptionCleanupTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	workers := len(ids)
	if workers > maxSubscriptionCleanupWorkers {
		workers = maxSubscriptionCleanupWorkers
	}
	jobs := make(chan string, len(ids))
	for _, id := range ids {
		jobs <- id
	}
	close(jobs)

	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			for subID := range jobs {
				if ctx.Err() != nil {
					return
				}
				if err := s.engine.Unsubscribe(ctx, subID); err != nil && ctx.Err() == nil {
					slog.Warn("mbp: failed to clean up connection subscription", "subscription_id", subID, "error", err)
				}
			}
		}()
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		slog.Warn("mbp: connection subscription cleanup timed out", "subscriptions", len(ids), "timeout", timeout)
	}
}

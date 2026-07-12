// Package authz defines the policy-neutral authorization contract for MCP.
//
// It deliberately does not authenticate legacy mdb_ tokens, select an entity
// isolation model, or provide an administrative multi-vault principal. Those
// product policies must be chosen before this package is wired into MCPServer.
package authz

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/scrypster/muninndb/internal/auth"
)

var (
	ErrInvalidPrincipal = errors.New("mcp authz: invalid principal")
	ErrPrincipalExpired = errors.New("mcp authz: principal expired")
	ErrClaimsChanged    = errors.New("mcp authz: principal claims changed")
)

// PrincipalClaims is the construction input for an immutable Principal.
// CredentialRef must be a non-secret stable fingerprint or record reference;
// raw bearer tokens must never be retained in a Principal or session.
type PrincipalClaims struct {
	Kind          auth.PrincipalKind
	Vault         string
	Mode          string
	CredentialRef string
	KeyID         string
	ExpiresAt     *time.Time
}

// Principal is the immutable identity pinned to one MCP session. Its fields
// are intentionally private so a caller cannot change vault or mode in place.
type Principal struct {
	valid         bool
	kind          auth.PrincipalKind
	vault         string
	mode          string
	credentialRef string
	keyID         string
	expiresAt     time.Time
	hasExpiry     bool
}

// NewPrincipal validates and copies claims into an immutable Principal.
func NewPrincipal(claims PrincipalClaims) (Principal, error) {
	if !validKind(claims.Kind) {
		return Principal{}, fmt.Errorf("%w: unsupported principal kind", ErrInvalidPrincipal)
	}
	if !auth.ValidVaultName(claims.Vault) {
		return Principal{}, fmt.Errorf("%w: invalid vault", ErrInvalidPrincipal)
	}
	if !validMode(claims.Mode) {
		return Principal{}, fmt.Errorf("%w: invalid mode", ErrInvalidPrincipal)
	}
	if claims.CredentialRef == "" {
		return Principal{}, fmt.Errorf("%w: credential reference is required", ErrInvalidPrincipal)
	}
	if claims.Kind == auth.PrincipalAPIKey && claims.KeyID == "" {
		return Principal{}, fmt.Errorf("%w: api key ID is required", ErrInvalidPrincipal)
	}
	if claims.Kind != auth.PrincipalAPIKey && claims.KeyID != "" {
		return Principal{}, fmt.Errorf("%w: key ID is only valid for api key principals", ErrInvalidPrincipal)
	}
	if claims.Kind == auth.PrincipalPublic && claims.Mode != auth.ModeFull {
		return Principal{}, fmt.Errorf("%w: public principals must use full mode", ErrInvalidPrincipal)
	}
	if claims.ExpiresAt != nil && !time.Now().Before(*claims.ExpiresAt) {
		return Principal{}, ErrPrincipalExpired
	}

	principal := Principal{
		valid:         true,
		kind:          claims.Kind,
		vault:         claims.Vault,
		mode:          claims.Mode,
		credentialRef: claims.CredentialRef,
		keyID:         claims.KeyID,
	}
	if claims.ExpiresAt != nil {
		principal.hasExpiry = true
		principal.expiresAt = claims.ExpiresAt.UTC().Round(0)
	}
	return principal, nil
}

func validKind(kind auth.PrincipalKind) bool {
	switch kind {
	case auth.PrincipalAPIKey, auth.PrincipalPublic:
		return true
	default:
		return false
	}
}

func validMode(mode string) bool {
	return mode == auth.ModeFull || mode == auth.ModeObserve || mode == auth.ModeWrite
}

func (p Principal) Kind() auth.PrincipalKind { return p.kind }
func (p Principal) Vault() string            { return p.vault }
func (p Principal) Mode() string             { return p.mode }
func (p Principal) CredentialRef() string    { return p.credentialRef }
func (p Principal) KeyID() string            { return p.keyID }

// ExpiresAt returns a value copy so callers cannot mutate the pinned claim.
func (p Principal) ExpiresAt() (time.Time, bool) {
	return p.expiresAt, p.hasExpiry
}

// ExpiredAt reports whether the principal is expired at now. Expiry is
// inclusive: a principal is invalid at its exact expiration instant.
func (p Principal) ExpiredAt(now time.Time) bool {
	return p.hasExpiry && !now.Before(p.expiresAt)
}

func (p Principal) claimsEqual(other Principal) bool {
	if !p.valid || !other.valid {
		return false
	}
	if p.kind != other.kind || p.vault != other.vault || p.mode != other.mode ||
		p.credentialRef != other.credentialRef || p.keyID != other.keyID ||
		p.hasExpiry != other.hasExpiry {
		return false
	}
	return !p.hasExpiry || p.expiresAt.Equal(other.expiresAt)
}

// PrincipalStore is the narrow boundary an MCP transport needs from its auth
// store. Implementations re-read current claims using the non-secret reference.
// Revoked, locked, missing, or otherwise unauthorized principals return an
// error. This package intentionally does not prescribe the persistence model.
type PrincipalStore interface {
	Revalidate(ctx context.Context, credentialRef string) (Principal, error)
}

// RevalidatedPrincipal is a short-lived authorization capability returned only
// after current store claims exactly match a pinned Principal. Tool decisions
// and authenticated contexts require this type, so callers cannot accidentally
// authorize a merely constructed or stale Principal.
type RevalidatedPrincipal struct {
	principal Principal
}

func (p RevalidatedPrincipal) Kind() auth.PrincipalKind { return p.principal.kind }
func (p RevalidatedPrincipal) Vault() string            { return p.principal.vault }
func (p RevalidatedPrincipal) Mode() string             { return p.principal.mode }
func (p RevalidatedPrincipal) KeyID() string            { return p.principal.keyID }

func (p RevalidatedPrincipal) ExpiresAt() (time.Time, bool) {
	return p.principal.ExpiresAt()
}

// RevalidatePinned revalidates a session's principal and rejects any claim
// drift. A key that changes vault, mode, ID, expiry, kind, or reference requires
// a new session rather than silently gaining different authority.
func RevalidatePinned(
	ctx context.Context,
	store PrincipalStore,
	pinned Principal,
) (RevalidatedPrincipal, error) {
	return revalidatePinnedAt(ctx, store, pinned, time.Now())
}

func revalidatePinnedAt(
	ctx context.Context,
	store PrincipalStore,
	pinned Principal,
	now time.Time,
) (RevalidatedPrincipal, error) {
	if ctx == nil {
		return RevalidatedPrincipal{}, ErrInvalidPrincipal
	}
	if !pinned.valid {
		return RevalidatedPrincipal{}, ErrInvalidPrincipal
	}
	if pinned.ExpiredAt(now) {
		return RevalidatedPrincipal{}, ErrPrincipalExpired
	}
	if store == nil {
		return RevalidatedPrincipal{}, fmt.Errorf("%w: principal store is required", ErrInvalidPrincipal)
	}

	current, err := store.Revalidate(ctx, pinned.credentialRef)
	if err != nil {
		return RevalidatedPrincipal{}, err
	}
	if !current.valid {
		return RevalidatedPrincipal{}, ErrInvalidPrincipal
	}
	if current.ExpiredAt(now) {
		return RevalidatedPrincipal{}, ErrPrincipalExpired
	}
	if !pinned.claimsEqual(current) {
		return RevalidatedPrincipal{}, ErrClaimsChanged
	}
	return RevalidatedPrincipal{principal: current}, nil
}

// SessionPin binds a session to exactly one immutable principal.
type SessionPin struct {
	principal Principal
}

func NewSessionPin(principal RevalidatedPrincipal) (SessionPin, error) {
	if !principal.principal.valid {
		return SessionPin{}, ErrInvalidPrincipal
	}
	return SessionPin{principal: principal.principal}, nil
}

// Revalidate refreshes the pinned principal before one request or stream tick.
func (s SessionPin) Revalidate(ctx context.Context, store PrincipalStore) (RevalidatedPrincipal, error) {
	if !s.principal.valid {
		return RevalidatedPrincipal{}, ErrInvalidPrincipal
	}
	return RevalidatePinned(ctx, store, s.principal)
}

// resolveVault accepts an omitted vault or the exact revalidated vault. It
// rejects invalid and cross-vault values before an engine, cache, or receipt
// lookup.
func (p RevalidatedPrincipal) resolveVault(requested string) (string, error) {
	if !p.principal.valid {
		return "", ErrInvalidPrincipal
	}
	if requested == "" || requested == p.principal.vault {
		return p.principal.vault, nil
	}
	if !auth.ValidVaultName(requested) {
		return "", fmt.Errorf("%w: invalid requested vault", ErrVaultMismatch)
	}
	return "", fmt.Errorf(
		"%w: session is pinned to %q and request named %q",
		ErrVaultMismatch,
		p.principal.vault,
		requested,
	)
}

package authz

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/scrypster/muninndb/internal/auth"
)

var (
	ErrMissingPrincipal = errors.New("mcp authz: authenticated principal missing from context")
	ErrInvalidTimeout   = errors.New("mcp authz: detached-work timeout must be positive")
)

type principalContextKey struct{}

// bindPrincipal adds the immutable principal and the existing engine auth
// values to ctx. In particular, observe mode reaches auth.ObserveFromContext
// so read handlers can suppress cognitive mutations.
func bindPrincipal(ctx context.Context, current RevalidatedPrincipal) (context.Context, error) {
	principal := current.principal
	if ctx == nil || !principal.valid {
		return nil, ErrInvalidPrincipal
	}
	ctx = context.WithValue(ctx, principalContextKey{}, current)
	ctx = context.WithValue(ctx, auth.ContextVault, principal.vault)
	ctx = context.WithValue(ctx, auth.ContextMode, principal.mode)
	ctx = context.WithValue(ctx, auth.ContextPrincipal, principal.kind)
	return ctx, nil
}

// AuthorizeRequest is the fail-closed entry point for one MCP request or
// stream authorization tick. It revalidates the session's exact claims,
// resolves the requested vault against the pin, applies mode plus entity
// policy, and only then returns an authenticated context.
func AuthorizeRequest(
	ctx context.Context,
	store PrincipalStore,
	session SessionPin,
	requestedVault string,
	tool string,
) (context.Context, string, Decision, error) {
	if ctx == nil {
		return nil, "", Decision{}, ErrInvalidPrincipal
	}
	current, err := session.Revalidate(ctx, store)
	if err != nil {
		return nil, "", Decision{}, err
	}
	vault, err := current.resolveVault(requestedVault)
	if err != nil {
		return nil, "", Decision{}, err
	}
	decision, err := authorizeTool(current, tool)
	if err != nil {
		return nil, "", Decision{}, err
	}
	authorizedContext, err := bindPrincipal(ctx, current)
	if err != nil {
		return nil, "", Decision{}, err
	}
	return authorizedContext, vault, decision, nil
}

func PrincipalFromContext(ctx context.Context) (RevalidatedPrincipal, bool) {
	if ctx == nil {
		return RevalidatedPrincipal{}, false
	}
	principal, ok := ctx.Value(principalContextKey{}).(RevalidatedPrincipal)
	return principal, ok && principal.principal.valid
}

// DetachedContext preserves authenticated values while detaching work from
// request cancellation. A mandatory timeout prevents detached work from
// becoming unbounded. The caller must invoke the returned cancel function.
func DetachedContext(
	requestContext context.Context,
	timeout time.Duration,
) (context.Context, context.CancelFunc, error) {
	if timeout <= 0 {
		return nil, nil, ErrInvalidTimeout
	}
	principal, ok := PrincipalFromContext(requestContext)
	if !ok {
		return nil, nil, ErrMissingPrincipal
	}
	detachedBase := context.WithoutCancel(requestContext)
	var (
		detached context.Context
		cancel   context.CancelFunc
	)
	if expiresAt, hasExpiry := principal.ExpiresAt(); hasExpiry {
		now := time.Now()
		if !now.Before(expiresAt) {
			return nil, nil, ErrPrincipalExpired
		}
		if expiresAt.Before(now.Add(timeout)) {
			detached, cancel = context.WithDeadline(detachedBase, expiresAt)
		}
	}
	if detached == nil {
		detached, cancel = context.WithTimeout(detachedBase, timeout)
	}
	if _, ok := PrincipalFromContext(detached); !ok {
		cancel()
		return nil, nil, fmt.Errorf("%w after detaching request", ErrMissingPrincipal)
	}
	return detached, cancel, nil
}

package authz

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/scrypster/muninndb/internal/auth"
)

func TestBindPrincipalPropagatesEngineClaims(t *testing.T) {
	principal := testRevalidatedPrincipal(t, auth.ModeObserve)
	ctx, err := bindPrincipal(context.Background(), principal)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := PrincipalFromContext(ctx)
	if !ok || !got.principal.claimsEqual(principal.principal) {
		t.Fatal("immutable principal missing from context")
	}
	if !auth.ObserveFromContext(ctx) {
		t.Fatal("observe mode was not propagated to engine auth context")
	}
	if vault, _ := ctx.Value(auth.ContextVault).(string); vault != "client-a" {
		t.Fatalf("context vault = %q, want client-a", vault)
	}
	if kind := auth.PrincipalFromContext(ctx); kind != auth.PrincipalAPIKey {
		t.Fatalf("context principal kind = %q, want api_key", kind)
	}
}

func TestAuthorizeRequestEnforcesFullBoundary(t *testing.T) {
	session, store := testSession(t, auth.ModeObserve)
	ctx, vault, decision, err := AuthorizeRequest(
		context.Background(),
		store,
		session,
		"client-a",
		"muninn_status",
	)
	if err != nil {
		t.Fatalf("AuthorizeRequest: %v", err)
	}
	if vault != "client-a" || decision.Tool != "muninn_status" || !decision.Observe {
		t.Fatalf("authorization result = vault %q, decision %+v", vault, decision)
	}
	if _, ok := PrincipalFromContext(ctx); !ok || !auth.ObserveFromContext(ctx) {
		t.Fatal("authorized context is missing revalidated observe claims")
	}

	if _, _, _, err := AuthorizeRequest(context.Background(), store, session, "client-b", "muninn_status"); !errors.Is(err, ErrVaultMismatch) {
		t.Fatalf("cross-vault error = %v, want ErrVaultMismatch", err)
	}
	if _, _, _, err := AuthorizeRequest(context.Background(), store, session, "client-a", "muninn_recall"); !errors.Is(err, ErrEntityPolicyDisabled) {
		t.Fatalf("entity path error = %v, want ErrEntityPolicyDisabled", err)
	}
	if _, _, _, err := AuthorizeRequest(context.Background(), store, session, "client-a", "muninn_future_tool"); !errors.Is(err, ErrUnknownTool) {
		t.Fatalf("unknown tool error = %v, want ErrUnknownTool", err)
	}

	store.errs["sha256:key-a"] = errNotAuthorized
	if _, _, _, err := AuthorizeRequest(context.Background(), store, session, "client-a", "muninn_status"); !errors.Is(err, errNotAuthorized) {
		t.Fatalf("revoked session error = %v, want store error", err)
	}
}

func TestAuthorizeRequestRejectsZeroInputs(t *testing.T) {
	if _, _, _, err := AuthorizeRequest(nil, nil, SessionPin{}, "", "muninn_status"); !errors.Is(err, ErrInvalidPrincipal) {
		t.Fatalf("nil context error = %v, want ErrInvalidPrincipal", err)
	}
	if _, _, _, err := AuthorizeRequest(context.Background(), nil, SessionPin{}, "", "muninn_status"); !errors.Is(err, ErrInvalidPrincipal) {
		t.Fatalf("zero session error = %v, want ErrInvalidPrincipal", err)
	}
}

func TestDetachedContextPreservesClaimsAndDropsRequestCancellation(t *testing.T) {
	request, cancelRequest := context.WithCancel(context.Background())
	bound, err := bindPrincipal(request, testRevalidatedPrincipal(t, auth.ModeObserve))
	if err != nil {
		t.Fatal(err)
	}
	detached, cancelDetached, err := DetachedContext(bound, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer cancelDetached()
	cancelRequest()

	select {
	case <-detached.Done():
		t.Fatalf("request cancellation leaked into detached work: %v", detached.Err())
	default:
	}
	if _, ok := PrincipalFromContext(detached); !ok {
		t.Fatal("principal missing from detached context")
	}
	if !auth.ObserveFromContext(detached) {
		t.Fatal("observe claim missing from detached context")
	}
	if _, ok := detached.Deadline(); !ok {
		t.Fatal("detached work must have a deadline")
	}
}

func TestDetachedContextFailsClosed(t *testing.T) {
	if _, _, err := DetachedContext(context.Background(), time.Minute); !errors.Is(err, ErrMissingPrincipal) {
		t.Fatalf("missing principal error = %v", err)
	}
	ctx, err := bindPrincipal(context.Background(), testRevalidatedPrincipal(t, auth.ModeFull))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := DetachedContext(ctx, 0); !errors.Is(err, ErrInvalidTimeout) {
		t.Fatalf("zero timeout error = %v", err)
	}
}

func TestDetachedContextCannotOutlivePrincipal(t *testing.T) {
	expires := time.Now().Add(time.Hour)
	principal, err := NewPrincipal(PrincipalClaims{
		Kind:          auth.PrincipalAPIKey,
		Vault:         "client-a",
		Mode:          auth.ModeObserve,
		CredentialRef: "sha256:expiring",
		KeyID:         "expiring",
		ExpiresAt:     &expires,
	})
	if err != nil {
		t.Fatal(err)
	}
	store := &fakePrincipalStore{
		principals: map[string]Principal{"sha256:expiring": principal},
		errs:       make(map[string]error),
	}
	current, err := RevalidatePinned(context.Background(), store, principal)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := bindPrincipal(context.Background(), current)
	if err != nil {
		t.Fatal(err)
	}
	detached, cancel, err := DetachedContext(bound, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	deadline, ok := detached.Deadline()
	if !ok || deadline.After(expires) {
		t.Fatalf("detached deadline = %v, want no later than principal expiry %v", deadline, expires)
	}
}

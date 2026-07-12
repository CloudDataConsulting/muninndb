package authz

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/scrypster/muninndb/internal/auth"
)

var errNotAuthorized = errors.New("not authorized")

type fakePrincipalStore struct {
	principals map[string]Principal
	errs       map[string]error
}

func (s *fakePrincipalStore) Revalidate(_ context.Context, ref string) (Principal, error) {
	if err := s.errs[ref]; err != nil {
		return Principal{}, err
	}
	principal, ok := s.principals[ref]
	if !ok {
		return Principal{}, errNotAuthorized
	}
	return principal, nil
}

func testPrincipal(t *testing.T, mode string) Principal {
	t.Helper()
	principal, err := NewPrincipal(PrincipalClaims{
		Kind:          auth.PrincipalAPIKey,
		Vault:         "client-a",
		Mode:          mode,
		CredentialRef: "sha256:key-a",
		KeyID:         "key-a",
	})
	if err != nil {
		t.Fatalf("NewPrincipal: %v", err)
	}
	return principal
}

func testRevalidatedPrincipal(t *testing.T, mode string) RevalidatedPrincipal {
	t.Helper()
	principal := testPrincipal(t, mode)
	store := &fakePrincipalStore{
		principals: map[string]Principal{principal.CredentialRef(): principal},
		errs:       make(map[string]error),
	}
	current, err := RevalidatePinned(context.Background(), store, principal)
	if err != nil {
		t.Fatalf("RevalidatePinned: %v", err)
	}
	return current
}

func testSession(t *testing.T, mode string) (SessionPin, *fakePrincipalStore) {
	t.Helper()
	principal := testPrincipal(t, mode)
	store := &fakePrincipalStore{
		principals: map[string]Principal{principal.CredentialRef(): principal},
		errs:       make(map[string]error),
	}
	current, err := RevalidatePinned(context.Background(), store, principal)
	if err != nil {
		t.Fatalf("RevalidatePinned: %v", err)
	}
	session, err := NewSessionPin(current)
	if err != nil {
		t.Fatalf("NewSessionPin: %v", err)
	}
	return session, store
}

func TestNewPrincipalRejectsInvalidClaims(t *testing.T) {
	valid := PrincipalClaims{
		Kind:          auth.PrincipalAPIKey,
		Vault:         "client-a",
		Mode:          auth.ModeFull,
		CredentialRef: "sha256:key-a",
		KeyID:         "key-a",
	}
	tests := []struct {
		name   string
		mutate func(*PrincipalClaims)
	}{
		{"unknown kind", func(c *PrincipalClaims) { c.Kind = auth.PrincipalKind("legacy") }},
		{"invalid vault", func(c *PrincipalClaims) { c.Vault = "Client A" }},
		{"invalid mode", func(c *PrincipalClaims) { c.Mode = "admin" }},
		{"missing reference", func(c *PrincipalClaims) { c.CredentialRef = "" }},
		{"api key missing ID", func(c *PrincipalClaims) { c.KeyID = "" }},
		{"admin kind reserved", func(c *PrincipalClaims) { c.Kind = auth.PrincipalAdmin }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims := valid
			tc.mutate(&claims)
			if _, err := NewPrincipal(claims); !errors.Is(err, ErrInvalidPrincipal) {
				t.Fatalf("error = %v, want ErrInvalidPrincipal", err)
			}
		})
	}
}

func TestPublicPrincipalRejectsKeyAndRestrictedModes(t *testing.T) {
	base := PrincipalClaims{
		Kind:          auth.PrincipalPublic,
		Vault:         "default",
		Mode:          auth.ModeFull,
		CredentialRef: "vault-config:default",
	}
	if _, err := NewPrincipal(base); err != nil {
		t.Fatalf("full public principal rejected: %v", err)
	}
	withKey := base
	withKey.KeyID = "not-applicable"
	if _, err := NewPrincipal(withKey); !errors.Is(err, ErrInvalidPrincipal) {
		t.Fatalf("public key ID error = %v, want ErrInvalidPrincipal", err)
	}
	for _, mode := range []string{auth.ModeObserve, auth.ModeWrite} {
		claims := base
		claims.Mode = mode
		if _, err := NewPrincipal(claims); !errors.Is(err, ErrInvalidPrincipal) {
			t.Fatalf("public mode %q error = %v, want ErrInvalidPrincipal", mode, err)
		}
	}
}

func TestPrincipalExpiryIsCopiedAndInclusive(t *testing.T) {
	expiry := time.Now().Add(time.Hour).In(time.FixedZone("local", -6*60*60))
	principal, err := NewPrincipal(PrincipalClaims{
		Kind:          auth.PrincipalPublic,
		Vault:         "default",
		Mode:          auth.ModeFull,
		CredentialRef: "vault-config:default",
		ExpiresAt:     &expiry,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := expiry.UTC()
	expiry = expiry.Add(24 * time.Hour)
	got, ok := principal.ExpiresAt()
	if !ok || !got.Equal(want) {
		t.Fatalf("expiry = %v, %v; want %v, true", got, ok, want)
	}
	if !principal.ExpiredAt(want) {
		t.Fatal("principal must be expired at its exact expiry")
	}
}

func TestNewPrincipalRejectsAlreadyExpiredClaims(t *testing.T) {
	expiry := time.Now().Add(-time.Hour)
	_, err := NewPrincipal(PrincipalClaims{
		Kind:          auth.PrincipalAPIKey,
		Vault:         "client-a",
		Mode:          auth.ModeFull,
		CredentialRef: "sha256:key-a",
		KeyID:         "key-a",
		ExpiresAt:     &expiry,
	})
	if !errors.Is(err, ErrPrincipalExpired) {
		t.Fatalf("expired principal error = %v, want ErrPrincipalExpired", err)
	}
}

func TestRevalidatePinned(t *testing.T) {
	now := time.Now().UTC().Round(0)
	expires := now.Add(time.Hour)
	pinned, err := NewPrincipal(PrincipalClaims{
		Kind:          auth.PrincipalAPIKey,
		Vault:         "client-a",
		Mode:          auth.ModeObserve,
		CredentialRef: "sha256:key-a",
		KeyID:         "key-a",
		ExpiresAt:     &expires,
	})
	if err != nil {
		t.Fatal(err)
	}

	store := &fakePrincipalStore{
		principals: map[string]Principal{"sha256:key-a": pinned},
		errs:       make(map[string]error),
	}
	if got, err := revalidatePinnedAt(context.Background(), store, pinned, now); err != nil || !got.principal.claimsEqual(pinned) {
		t.Fatalf("valid revalidation = (%v, %v)", got, err)
	}

	store.errs["sha256:key-a"] = errNotAuthorized
	if _, err := revalidatePinnedAt(context.Background(), store, pinned, now); !errors.Is(err, errNotAuthorized) {
		t.Fatalf("revoked error = %v, want store error", err)
	}
	delete(store.errs, "sha256:key-a")

	changed := testPrincipal(t, auth.ModeFull)
	store.principals["sha256:key-a"] = changed
	if _, err := revalidatePinnedAt(context.Background(), store, pinned, now); !errors.Is(err, ErrClaimsChanged) {
		t.Fatalf("claim drift error = %v, want ErrClaimsChanged", err)
	}

	store.principals["sha256:key-a"] = pinned
	if _, err := revalidatePinnedAt(context.Background(), store, pinned, expires); !errors.Is(err, ErrPrincipalExpired) {
		t.Fatalf("expiry error = %v, want ErrPrincipalExpired", err)
	}
}

func TestRevalidatePublicPrincipalFailsWhenVaultLocks(t *testing.T) {
	principal, err := NewPrincipal(PrincipalClaims{
		Kind:          auth.PrincipalPublic,
		Vault:         "default",
		Mode:          auth.ModeFull,
		CredentialRef: "vault-config:default",
	})
	if err != nil {
		t.Fatal(err)
	}
	store := &fakePrincipalStore{
		principals: map[string]Principal{"vault-config:default": principal},
		errs:       map[string]error{"vault-config:default": errNotAuthorized},
	}
	if _, err := RevalidatePinned(context.Background(), store, principal); !errors.Is(err, errNotAuthorized) {
		t.Fatalf("locked public vault error = %v, want store authorization error", err)
	}
}

func TestRevalidatePinnedRejectsEveryClaimChange(t *testing.T) {
	now := time.Now().UTC().Round(0)
	expires := now.Add(time.Hour)
	base := PrincipalClaims{
		Kind:          auth.PrincipalAPIKey,
		Vault:         "client-a",
		Mode:          auth.ModeFull,
		CredentialRef: "sha256:key-a",
		KeyID:         "key-a",
		ExpiresAt:     &expires,
	}
	pinned, err := NewPrincipal(base)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*PrincipalClaims)
	}{
		{"kind", func(c *PrincipalClaims) { c.Kind = auth.PrincipalPublic; c.KeyID = "" }},
		{"vault", func(c *PrincipalClaims) { c.Vault = "client-b" }},
		{"mode", func(c *PrincipalClaims) { c.Mode = auth.ModeObserve }},
		{"reference", func(c *PrincipalClaims) { c.CredentialRef = "sha256:key-b" }},
		{"key ID", func(c *PrincipalClaims) { c.KeyID = "key-b" }},
		{"expiry", func(c *PrincipalClaims) { later := expires.Add(time.Hour); c.ExpiresAt = &later }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims := base
			tc.mutate(&claims)
			current, err := NewPrincipal(claims)
			if err != nil {
				t.Fatal(err)
			}
			store := &fakePrincipalStore{principals: map[string]Principal{base.CredentialRef: current}, errs: map[string]error{}}
			if _, err := revalidatePinnedAt(context.Background(), store, pinned, now); !errors.Is(err, ErrClaimsChanged) {
				t.Fatalf("error = %v, want ErrClaimsChanged", err)
			}
		})
	}
}

func TestSessionPinResolveVault(t *testing.T) {
	principal := testPrincipal(t, auth.ModeFull)
	store := &fakePrincipalStore{
		principals: map[string]Principal{principal.CredentialRef(): principal},
		errs:       make(map[string]error),
	}
	current, err := RevalidatePinned(context.Background(), store, principal)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := NewSessionPin(current)
	if err != nil {
		t.Fatal(err)
	}
	current, err = pin.Revalidate(context.Background(), store)
	if err != nil {
		t.Fatal(err)
	}
	for _, requested := range []string{"", "client-a"} {
		vault, err := current.resolveVault(requested)
		if err != nil || vault != "client-a" {
			t.Fatalf("ResolveVault(%q) = %q, %v", requested, vault, err)
		}
	}
	for _, requested := range []string{"client-b", "Client A"} {
		if _, err := current.resolveVault(requested); !errors.Is(err, ErrVaultMismatch) {
			t.Fatalf("ResolveVault(%q) error = %v, want ErrVaultMismatch", requested, err)
		}
	}
	store.errs[principal.CredentialRef()] = errNotAuthorized
	if _, err := pin.Revalidate(context.Background(), store); !errors.Is(err, errNotAuthorized) {
		t.Fatalf("revoked session revalidation error = %v, want store error", err)
	}
}

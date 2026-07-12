package authz

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/vfs"
	"github.com/scrypster/muninndb/internal/auth"
)

func openAdapterTestStore(t *testing.T) (*auth.Store, *pebble.DB) {
	t.Helper()
	db, err := pebble.Open("", &pebble.Options{FS: vfs.NewMem()})
	if err != nil {
		t.Fatalf("open Pebble: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return auth.NewStore(db), db
}

func TestAuthStoreAdapterAPIKeyLifecycle(t *testing.T) {
	store, _ := openAdapterTestStore(t)
	token, key, err := store.GenerateAPIKey("client-a", "agent", auth.ModeObserve, nil)
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	ref, err := APIKeyCredentialRef(key)
	if err != nil {
		t.Fatalf("APIKeyCredentialRef: %v", err)
	}
	if strings.Contains(ref, token) || strings.Contains(fmt.Sprintf("%#v", NewAuthStoreAdapter(store)), token) {
		t.Fatal("raw bearer token was retained")
	}

	adapter := NewAuthStoreAdapter(store)
	principal, err := adapter.Revalidate(context.Background(), ref)
	if err != nil {
		t.Fatalf("Revalidate: %v", err)
	}
	if principal.Kind() != auth.PrincipalAPIKey || principal.Vault() != "client-a" ||
		principal.Mode() != auth.ModeObserve || principal.KeyID() != key.ID ||
		principal.CredentialRef() != ref {
		t.Fatalf("principal = %#v, want generated key identity", principal)
	}

	if _, err := adapter.Revalidate(context.Background(), token); err != ErrUnauthorized {
		t.Fatalf("raw token error = %v, want uniform ErrUnauthorized", err)
	}
	if err := store.RevokeAPIKey(key.Vault, key.ID); err != nil {
		t.Fatalf("RevokeAPIKey: %v", err)
	}
	if _, err := adapter.Revalidate(context.Background(), ref); err != ErrUnauthorized {
		t.Fatalf("revoked error = %v, want uniform ErrUnauthorized", err)
	}
}

func TestAuthStoreAdapterExpiryIsDeterministicAndInclusive(t *testing.T) {
	store, _ := openAdapterTestStore(t)
	expires := time.Now().UTC().Round(0).Add(24 * time.Hour)
	_, key, err := store.GenerateAPIKey("client-a", "agent", auth.ModeFull, &expires)
	if err != nil {
		t.Fatal(err)
	}
	ref, err := APIKeyCredentialRef(key)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		now     time.Time
		wantErr bool
	}{
		{name: "before", now: expires.Add(-time.Nanosecond)},
		{name: "at", now: expires, wantErr: true},
		{name: "after", now: expires.Add(time.Nanosecond), wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			adapter := newAuthStoreAdapter(store, func() time.Time { return tc.now })
			_, err := adapter.Revalidate(context.Background(), ref)
			if tc.wantErr && err != ErrUnauthorized {
				t.Fatalf("error = %v, want ErrUnauthorized", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestAuthStoreAdapterPublicVaultLifecycle(t *testing.T) {
	store, _ := openAdapterTestStore(t)
	if err := store.SetVaultConfig(auth.VaultConfig{Name: "client-a", Public: true}); err != nil {
		t.Fatal(err)
	}
	ref, err := PublicVaultCredentialRef("client-a")
	if err != nil {
		t.Fatal(err)
	}
	adapter := NewAuthStoreAdapter(store)
	principal, err := adapter.Revalidate(context.Background(), ref)
	if err != nil {
		t.Fatalf("public revalidation: %v", err)
	}
	if principal.Kind() != auth.PrincipalPublic || principal.Vault() != "client-a" || principal.Mode() != auth.ModeFull {
		t.Fatalf("public principal = %#v", principal)
	}

	if err := store.SetVaultConfig(auth.VaultConfig{Name: "client-a", Public: false}); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Revalidate(context.Background(), ref); err != ErrUnauthorized {
		t.Fatalf("locked error = %v, want ErrUnauthorized", err)
	}
	if err := store.SetVaultConfig(auth.VaultConfig{Name: "client-a", Public: true}); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteVaultConfig("client-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Revalidate(context.Background(), ref); err != ErrUnauthorized {
		t.Fatalf("deleted error = %v, want ErrUnauthorized", err)
	}

	if err := store.SetVaultConfig(auth.VaultConfig{Name: "client-a", Public: true}); err != nil {
		t.Fatal(err)
	}
	if err := store.RenameVaultConfig("client-a", "client-b"); err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Revalidate(context.Background(), ref); err != ErrUnauthorized {
		t.Fatalf("renamed old reference error = %v, want ErrUnauthorized", err)
	}
	newRef, err := PublicVaultCredentialRef("client-b")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.Revalidate(context.Background(), newRef); err != nil {
		t.Fatalf("renamed exact reference rejected: %v", err)
	}
}

func TestAuthStoreAdapterRejectsMalformedReferencesUniformly(t *testing.T) {
	store, _ := openAdapterTestStore(t)
	adapter := NewAuthStoreAdapter(store)
	malformed := []string{
		"",
		"mk_secret",
		"Bearer mk_secret",
		"api-key:v0:AAAAAAAAAAAAAAAAAAAAAA",
		"api-key:v1:",
		"api-key:v1:AAAAAAAAAAAAAAAAAAAAA",
		"api-key:v1:AAAAAAAAAAAAAAAAAAAAAAA",
		"api-key:v1:AAAAAAAAAAAAAAAAAAAAAA=",
		"api-key:v1:AAAAAAAAAAAAAAAAAAAAA!",
		"public-vault:v0:client-a",
		"public-vault:v1:",
		"public-vault:v1:Client-A",
		"public-vault:v1:client/a",
	}
	for _, ref := range malformed {
		t.Run(ref, func(t *testing.T) {
			if _, err := adapter.Revalidate(context.Background(), ref); err != ErrUnauthorized {
				t.Fatalf("error = %v, want exact ErrUnauthorized", err)
			}
		})
	}

	if _, err := (*AuthStoreAdapter)(nil).Revalidate(context.Background(), "anything"); err != ErrUnauthorized {
		t.Fatalf("nil adapter error = %v", err)
	}
	if _, err := newAuthStoreAdapter(nil, time.Now).Revalidate(context.Background(), "anything"); err != ErrUnauthorized {
		t.Fatalf("nil store error = %v", err)
	}
	if _, err := newAuthStoreAdapter(store, nil).Revalidate(context.Background(), "anything"); err != ErrUnauthorized {
		t.Fatalf("nil clock error = %v", err)
	}
}

type adapterTestMetadataStore struct {
	lookupKey    func([]byte) (auth.APIKey, error)
	lookupPublic func(string) (auth.VaultConfig, error)
}

func (s adapterTestMetadataStore) LookupAPIKeyByStorageHash(hash []byte) (auth.APIKey, error) {
	return s.lookupKey(hash)
}

func (s adapterTestMetadataStore) LookupPublicVaultConfig(vault string) (auth.VaultConfig, error) {
	return s.lookupPublic(vault)
}

func TestAuthStoreAdapterChecksContextBeforeAndAfterLookup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	source := adapterTestMetadataStore{
		lookupKey: func([]byte) (auth.APIKey, error) {
			called = true
			return auth.APIKey{}, errors.New("must not run")
		},
		lookupPublic: func(string) (auth.VaultConfig, error) {
			called = true
			return auth.VaultConfig{}, errors.New("must not run")
		},
	}
	adapter := newAuthStoreAdapter(source, time.Now)
	if _, err := adapter.Revalidate(ctx, "public-vault:v1:client-a"); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled error = %v, want context.Canceled", err)
	}
	if called {
		t.Fatal("store was called for a pre-canceled request")
	}

	ctx, cancel = context.WithCancel(context.Background())
	key := auth.APIKey{
		ID:          "AQIDBAUGBwg",
		Vault:       "client-a",
		Mode:        auth.ModeFull,
		StorageHash: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	}
	ref, err := APIKeyCredentialRef(key)
	if err != nil {
		t.Fatal(err)
	}
	source.lookupKey = func([]byte) (auth.APIKey, error) {
		cancel()
		return key, nil
	}
	adapter = newAuthStoreAdapter(source, time.Now)
	if _, err := adapter.Revalidate(ctx, ref); !errors.Is(err, context.Canceled) {
		t.Fatalf("post-lookup cancellation error = %v, want context.Canceled", err)
	}
}

func TestAuthStoreAdapterMasksStoreAndMetadataFailures(t *testing.T) {
	storageHash := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	key := auth.APIKey{
		ID:          "AQIDBAUGBwg",
		Vault:       "client-a",
		Mode:        auth.ModeFull,
		StorageHash: storageHash,
	}
	ref, err := APIKeyCredentialRef(key)
	if err != nil {
		t.Fatal(err)
	}
	storeFailure := errors.New("pebble read failed")
	tests := []struct {
		name string
		key  auth.APIKey
		err  error
	}{
		{name: "store failure", err: storeFailure},
		{name: "storage hash changed", key: func() auth.APIKey {
			changed := key
			changed.StorageHash = append([]byte(nil), storageHash...)
			changed.StorageHash[15] ^= 0xff
			return changed
		}()},
		{name: "ID changed", key: func() auth.APIKey {
			changed := key
			changed.ID = "CAcGBQQDAgE"
			return changed
		}()},
		{name: "vault corrupt", key: func() auth.APIKey {
			changed := key
			changed.Vault = "Client B"
			return changed
		}()},
		{name: "mode corrupt", key: func() auth.APIKey {
			changed := key
			changed.Mode = "admin"
			return changed
		}()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			source := adapterTestMetadataStore{
				lookupKey: func([]byte) (auth.APIKey, error) { return tc.key, tc.err },
				lookupPublic: func(string) (auth.VaultConfig, error) {
					return auth.VaultConfig{}, storeFailure
				},
			}
			adapter := newAuthStoreAdapter(source, time.Now)
			if _, err := adapter.Revalidate(context.Background(), ref); err != ErrUnauthorized {
				t.Fatalf("error = %v, want exact ErrUnauthorized", err)
			}
		})
	}

	publicTests := []struct {
		name string
		cfg  auth.VaultConfig
		err  error
	}{
		{name: "store failure", err: storeFailure},
		{name: "locked", cfg: auth.VaultConfig{Name: "client-a", Public: false}},
		{name: "name mismatch", cfg: auth.VaultConfig{Name: "client-b", Public: true}},
	}
	for _, tc := range publicTests {
		t.Run("public "+tc.name, func(t *testing.T) {
			publicSource := adapterTestMetadataStore{
				lookupKey:    func([]byte) (auth.APIKey, error) { return auth.APIKey{}, storeFailure },
				lookupPublic: func(string) (auth.VaultConfig, error) { return tc.cfg, tc.err },
			}
			if _, err := newAuthStoreAdapter(publicSource, time.Now).Revalidate(
				context.Background(), "public-vault:v1:client-a",
			); err != ErrUnauthorized {
				t.Fatalf("error = %v, want ErrUnauthorized", err)
			}
		})
	}
}

func TestAuthStoreAdapterPinnedSessionRejectsValidClaimMutation(t *testing.T) {
	key := auth.APIKey{
		ID:          "AQIDBAUGBwg",
		Vault:       "client-a",
		Mode:        auth.ModeFull,
		StorageHash: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	}
	ref, err := APIKeyCredentialRef(key)
	if err != nil {
		t.Fatal(err)
	}
	current := key
	source := adapterTestMetadataStore{
		lookupKey: func([]byte) (auth.APIKey, error) { return current, nil },
		lookupPublic: func(string) (auth.VaultConfig, error) {
			return auth.VaultConfig{}, errors.New("not public")
		},
	}
	adapter := newAuthStoreAdapter(source, time.Now)
	pinned, err := adapter.Revalidate(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	revalidated, err := RevalidatePinned(context.Background(), adapter, pinned)
	if err != nil {
		t.Fatal(err)
	}
	session, err := NewSessionPin(revalidated)
	if err != nil {
		t.Fatal(err)
	}

	current.Mode = auth.ModeObserve
	if _, err := session.Revalidate(context.Background(), adapter); !errors.Is(err, ErrClaimsChanged) {
		t.Fatalf("mode mutation error = %v, want ErrClaimsChanged", err)
	}
	current = key
	current.Vault = "client-b"
	if _, err := session.Revalidate(context.Background(), adapter); !errors.Is(err, ErrClaimsChanged) {
		t.Fatalf("vault mutation error = %v, want ErrClaimsChanged", err)
	}
}

func TestCredentialReferenceConstructorsRejectInvalidMetadata(t *testing.T) {
	valid := auth.APIKey{
		ID:          "AQIDBAUGBwg",
		Vault:       "client-a",
		Mode:        auth.ModeFull,
		StorageHash: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
	}
	tests := []struct {
		name   string
		mutate func(*auth.APIKey)
	}{
		{name: "short hash", mutate: func(k *auth.APIKey) { k.StorageHash = k.StorageHash[:15] }},
		{name: "wrong ID", mutate: func(k *auth.APIKey) { k.ID = "CAcGBQQDAgE" }},
		{name: "invalid vault", mutate: func(k *auth.APIKey) { k.Vault = "Client A" }},
		{name: "invalid mode", mutate: func(k *auth.APIKey) { k.Mode = "admin" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key := valid
			tc.mutate(&key)
			if _, err := APIKeyCredentialRef(key); !errors.Is(err, ErrInvalidPrincipal) {
				t.Fatalf("error = %v, want ErrInvalidPrincipal", err)
			}
		})
	}
	for _, vault := range []string{"", "Client-A", "client/a"} {
		if _, err := PublicVaultCredentialRef(vault); !errors.Is(err, ErrInvalidPrincipal) {
			t.Fatalf("PublicVaultCredentialRef(%q) error = %v", vault, err)
		}
	}
}

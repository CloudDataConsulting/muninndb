package auth

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/vfs"
)

func openLookupTestStore(t *testing.T) (*Store, *pebble.DB) {
	t.Helper()
	db, err := pebble.Open("", &pebble.Options{FS: vfs.NewMem()})
	if err != nil {
		t.Fatalf("open Pebble: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return NewStore(db), db
}

func TestLookupAPIKeyByStorageHashValidatesIdentityAndInclusiveExpiry(t *testing.T) {
	store, db := openLookupTestStore(t)
	expires := time.Now().UTC().Round(0).Add(24 * time.Hour)
	_, generated, err := store.GenerateAPIKey("client-a", "agent", ModeObserve, &expires)
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}

	if got, err := store.lookupAPIKeyByStorageHashAt(generated.StorageHash, expires.Add(-time.Nanosecond)); err != nil {
		t.Fatalf("lookup before expiry: %v", err)
	} else if got.ID != generated.ID || got.Vault != generated.Vault || got.Mode != generated.Mode {
		t.Fatalf("lookup metadata = %#v, want generated identity", got)
	}
	for name, now := range map[string]time.Time{
		"at expiry":    expires,
		"after expiry": expires.Add(time.Nanosecond),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := store.lookupAPIKeyByStorageHashAt(generated.StorageHash, now); err == nil {
				t.Fatal("expired key was accepted")
			}
		})
	}

	originalData, closer, err := db.Get(apiKeyStorageKey(generated.StorageHash))
	if err != nil {
		t.Fatalf("read generated metadata: %v", err)
	}
	original := append([]byte(nil), originalData...)
	closer.Close()

	tests := []struct {
		name   string
		mutate func(*APIKey) []byte
	}{
		{
			name: "storage hash mismatch",
			mutate: func(key *APIKey) []byte {
				key.StorageHash = append([]byte(nil), key.StorageHash...)
				key.StorageHash[0] ^= 0xff
				data, _ := json.Marshal(key)
				return data
			},
		},
		{
			name: "display ID mismatch",
			mutate: func(key *APIKey) []byte {
				key.ID = base64.RawURLEncoding.EncodeToString([]byte("12345678"))
				data, _ := json.Marshal(key)
				return data
			},
		},
		{
			name: "noncanonical display ID",
			mutate: func(key *APIKey) []byte {
				key.ID += "="
				data, _ := json.Marshal(key)
				return data
			},
		},
		{
			name: "invalid vault",
			mutate: func(key *APIKey) []byte {
				key.Vault = "Client A"
				data, _ := json.Marshal(key)
				return data
			},
		},
		{
			name: "invalid mode",
			mutate: func(key *APIKey) []byte {
				key.Mode = "admin"
				data, _ := json.Marshal(key)
				return data
			},
		},
		{
			name:   "invalid JSON",
			mutate: func(*APIKey) []byte { return []byte("{") },
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var key APIKey
			if err := json.Unmarshal(original, &key); err != nil {
				t.Fatal(err)
			}
			if err := db.Set(apiKeyStorageKey(generated.StorageHash), tc.mutate(&key), pebble.Sync); err != nil {
				t.Fatalf("write mutation: %v", err)
			}
			t.Cleanup(func() {
				_ = db.Set(apiKeyStorageKey(generated.StorageHash), original, pebble.Sync)
			})
			if _, err := store.lookupAPIKeyByStorageHashAt(generated.StorageHash, expires.Add(-time.Hour)); err == nil {
				t.Fatal("corrupt key metadata was accepted")
			}
			if err := db.Set(apiKeyStorageKey(generated.StorageHash), original, pebble.Sync); err != nil {
				t.Fatalf("restore metadata: %v", err)
			}
		})
	}

	if _, err := store.LookupAPIKeyByStorageHash(generated.StorageHash[:15]); err == nil {
		t.Fatal("short storage hash was accepted")
	}
	missing := append([]byte(nil), generated.StorageHash...)
	missing[0] ^= 0xff
	if _, err := store.LookupAPIKeyByStorageHash(missing); err == nil {
		t.Fatal("missing storage hash was accepted")
	}
}

func TestLookupPublicVaultConfigRequiresExactPersistedPublicRecord(t *testing.T) {
	store, db := openLookupTestStore(t)
	if err := store.SetVaultConfig(VaultConfig{Name: "client-a", Public: true}); err != nil {
		t.Fatal(err)
	}
	if cfg, err := store.LookupPublicVaultConfig("client-a"); err != nil || cfg.Name != "client-a" || !cfg.Public {
		t.Fatalf("public lookup = (%#v, %v)", cfg, err)
	}

	if err := store.SetVaultConfig(VaultConfig{Name: "client-a", Public: false}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LookupPublicVaultConfig("client-a"); err == nil {
		t.Fatal("locked vault was accepted")
	}
	if err := store.DeleteVaultConfig("client-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LookupPublicVaultConfig("client-a"); err == nil {
		t.Fatal("deleted vault was accepted")
	}

	if err := store.SetVaultConfig(VaultConfig{Name: "client-a", Public: true}); err != nil {
		t.Fatal(err)
	}
	if err := store.RenameVaultConfig("client-a", "client-b"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LookupPublicVaultConfig("client-a"); err == nil {
		t.Fatal("old name was accepted after rename")
	}
	if _, err := store.LookupPublicVaultConfig("client-b"); err != nil {
		t.Fatalf("renamed public vault rejected: %v", err)
	}

	corrupt, err := json.Marshal(VaultConfig{Name: "client-c", Public: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Set(vaultConfigKey("client-b"), corrupt, pebble.Sync); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LookupPublicVaultConfig("client-b"); err == nil {
		t.Fatal("config whose stored name differs from its key was accepted")
	}
}

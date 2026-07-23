package auth

import (
	"encoding/base64"
	"errors"
	"testing"

	"github.com/cockroachdb/pebble"
)

func TestDeleteVaultLifecycle_RevokesIndexedAndUnindexedRecords(t *testing.T) {
	db := openAuthTestDB(t)
	store := NewStore(db)
	const target = "lifecycle-target"
	const other = "lifecycle-other"

	if err := store.SetVaultConfig(VaultConfig{Name: target, Public: false}); err != nil {
		t.Fatal(err)
	}
	indexedToken, indexedKey, err := store.GenerateAPIKey(target, "indexed", ModeFull, nil)
	if err != nil {
		t.Fatal(err)
	}
	orphanToken, orphanKey, err := store.GenerateAPIKey(target, "orphan", ModeObserve, nil)
	if err != nil {
		t.Fatal(err)
	}
	otherToken, _, err := store.GenerateAPIKey(other, "preserve", ModeFull, nil)
	if err != nil {
		t.Fatal(err)
	}

	orphanID, err := base64.RawURLEncoding.DecodeString(orphanKey.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Delete(apiKeyVaultIdxKey(target, orphanID), pebble.Sync); err != nil {
		t.Fatalf("orphan target API-key record: %v", err)
	}

	if err := store.DeleteVaultLifecycle(target); err != nil {
		t.Fatalf("DeleteVaultLifecycle: %v", err)
	}
	for label, token := range map[string]string{"indexed": indexedToken, "unindexed": orphanToken} {
		if _, err := store.ValidateAPIKey(token); err == nil {
			t.Errorf("%s target token still validates after lifecycle deletion", label)
		}
	}
	if _, err := store.ValidateAPIKey(otherToken); err != nil {
		t.Errorf("other-vault token was affected: %v", err)
	}
	if _, closer, err := db.Get(vaultConfigKey(target)); err == nil {
		closer.Close()
		t.Error("target config survived lifecycle deletion")
	} else if !errors.Is(err, pebble.ErrNotFound) {
		t.Fatalf("read target config: %v", err)
	}
	for _, key := range []APIKey{indexedKey, orphanKey} {
		if _, closer, err := db.Get(apiKeyStorageKey(key.StorageHash)); err == nil {
			closer.Close()
			t.Errorf("target API-key record %s survived lifecycle deletion", key.ID)
		} else if !errors.Is(err, pebble.ErrNotFound) {
			t.Fatalf("read target API-key record %s: %v", key.ID, err)
		}
	}
}

func TestDeleteVaultLifecycle_CorruptIndexAbortsBeforeCommit(t *testing.T) {
	db := openAuthTestDB(t)
	store := NewStore(db)
	const vault = "lifecycle-corrupt"
	if err := store.SetVaultConfig(VaultConfig{Name: vault, Public: false}); err != nil {
		t.Fatal(err)
	}
	token, _, err := store.GenerateAPIKey(vault, "must survive abort", ModeFull, nil)
	if err != nil {
		t.Fatal(err)
	}
	malformedIndex := apiKeyVaultIdxKey(vault, []byte{0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA})
	if err := db.Set(malformedIndex, make([]byte, 15), pebble.Sync); err != nil {
		t.Fatal(err)
	}

	if err := store.DeleteVaultLifecycle(vault); err == nil {
		t.Fatal("DeleteVaultLifecycle succeeded with malformed API-key index")
	}
	if _, err := store.ValidateAPIKey(token); err != nil {
		t.Fatalf("valid token was deleted despite aborted lifecycle batch: %v", err)
	}
	if _, closer, err := db.Get(vaultConfigKey(vault)); err != nil {
		t.Fatalf("vault config was deleted despite aborted lifecycle batch: %v", err)
	} else {
		closer.Close()
	}
}

func TestRevokeVaultAPIKeys_PreservesConfigAndOtherVault(t *testing.T) {
	store := NewStore(openAuthTestDB(t))
	const target = "rename-source"
	if err := store.SetVaultConfig(VaultConfig{Name: target, Public: true}); err != nil {
		t.Fatal(err)
	}
	targetToken, _, err := store.GenerateAPIKey(target, "target", ModeFull, nil)
	if err != nil {
		t.Fatal(err)
	}
	otherToken, _, err := store.GenerateAPIKey("rename-other", "other", ModeFull, nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := store.RevokeVaultAPIKeys(target); err != nil {
		t.Fatalf("RevokeVaultAPIKeys: %v", err)
	}
	if _, err := store.ValidateAPIKey(targetToken); err == nil {
		t.Error("target token still validates after vault-wide revocation")
	}
	if _, err := store.ValidateAPIKey(otherToken); err != nil {
		t.Errorf("other-vault token was affected: %v", err)
	}
	cfg, err := store.GetVaultConfig(target)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Public || cfg.Name != target {
		t.Errorf("target config changed during credential-only revocation: %+v", cfg)
	}
}

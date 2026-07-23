package auth_test

import (
	"testing"

	"github.com/scrypster/muninndb/internal/auth"
)

func TestVaultLifecycleCharacterization_DeletedVaultKeyCannotAuthorizeSameNameRecreation(t *testing.T) {
	store := auth.NewStore(openTestDB(t))
	const vault = "deleted-then-recreated"

	if err := store.SetVaultConfig(auth.VaultConfig{Name: vault, Public: false}); err != nil {
		t.Fatalf("create original vault config: %v", err)
	}
	token, _, err := store.GenerateAPIKey(vault, "original lifecycle", auth.ModeFull, nil)
	if err != nil {
		t.Fatalf("generate original lifecycle key: %v", err)
	}

	if err := store.DeleteVaultLifecycle(vault); err != nil {
		t.Fatalf("delete original vault lifecycle: %v", err)
	}
	if err := store.SetVaultConfig(auth.VaultConfig{Name: vault, Public: false}); err != nil {
		t.Fatalf("create same-name replacement vault config: %v", err)
	}

	if key, err := store.ValidateAPIKey(token); err == nil {
		t.Fatalf("API key from deleted vault lifecycle still validates for same-name recreation: key_id=%s vault=%s", key.ID, key.Vault)
	}
}

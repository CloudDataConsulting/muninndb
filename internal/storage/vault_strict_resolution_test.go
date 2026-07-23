package storage

import (
	"testing"

	"github.com/cockroachdb/pebble"
	"github.com/scrypster/muninndb/internal/storage/keys"
)

func TestResolveExistingVaultPrefix_BypassesStaleCacheAndFailsClosed(t *testing.T) {
	t.Run("missing name index", func(t *testing.T) {
		store := newTestStore(t)
		const name = "strict-missing-index"
		ws := store.VaultPrefix(name)
		if err := store.WriteVaultName(ws, name); err != nil {
			t.Fatal(err)
		}
		_ = store.ResolveVaultPrefix(name) // populate the permissive cache
		if err := store.db.Delete(keys.VaultNameIndexKey(name), pebble.Sync); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ResolveExistingVaultPrefix(name); err == nil {
			t.Fatal("strict resolution trusted stale cache after persisted index deletion")
		}
	})

	t.Run("malformed name index", func(t *testing.T) {
		store := newTestStore(t)
		const name = "strict-malformed-index"
		ws := store.VaultPrefix(name)
		if err := store.WriteVaultName(ws, name); err != nil {
			t.Fatal(err)
		}
		if err := store.db.Set(keys.VaultNameIndexKey(name), []byte{1, 2, 3}, pebble.Sync); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ResolveExistingVaultPrefix(name); err == nil {
			t.Fatal("strict resolution accepted malformed persisted index")
		}
	})

	t.Run("mismatched metadata", func(t *testing.T) {
		store := newTestStore(t)
		const name = "strict-mismatched-metadata"
		ws := store.VaultPrefix(name)
		if err := store.WriteVaultName(ws, name); err != nil {
			t.Fatal(err)
		}
		_ = store.ResolveVaultPrefix(name) // populate the permissive cache
		if err := store.db.Set(keys.VaultMetaKey(ws), []byte("different-name"), pebble.Sync); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ResolveExistingVaultPrefix(name); err == nil {
			t.Fatal("strict resolution accepted mismatched persisted metadata")
		}
	})
}

func TestResolveExistingVaultPrefix_RenamePreservesWorkspace(t *testing.T) {
	store := newTestStore(t)
	const oldName = "strict-before-rename"
	const newName = "strict-after-rename"
	ws := store.VaultPrefix(oldName)
	if err := store.WriteVaultName(ws, oldName); err != nil {
		t.Fatal(err)
	}
	if err := store.RenameVault(ws, oldName, newName); err != nil {
		t.Fatal(err)
	}
	resolved, err := store.ResolveExistingVaultPrefix(newName)
	if err != nil {
		t.Fatalf("strict resolution after rename: %v", err)
	}
	if resolved != ws {
		t.Fatalf("strict resolution after rename = %x, want preserved workspace %x", resolved, ws)
	}
}

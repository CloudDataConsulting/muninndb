package storage

import (
	"errors"
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
		_ = store.ResolveVaultPrefix(name)
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
		_ = store.ResolveVaultPrefix(name)
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

func TestResolveExistingVaultPrefix_DoesNotPopulatePermissiveCache(t *testing.T) {
	store := newTestStore(t)
	const name = "strict-no-cache"
	ws := store.VaultPrefix(name)
	if err := store.WriteVaultName(ws, name); err != nil {
		t.Fatal(err)
	}
	store.vaultPrefixCache.Remove(name)

	resolved, err := store.ResolveExistingVaultPrefix(name)
	if err != nil {
		t.Fatalf("strict resolution: %v", err)
	}
	if resolved != ws {
		t.Fatalf("strict resolution = %x, want %x", resolved, ws)
	}
	if _, ok := store.vaultPrefixCache.Get(name); ok {
		t.Fatal("strict resolver populated the permissive cache")
	}
}

func TestVaultWorkspaceOwner(t *testing.T) {
	store := newTestStore(t)
	const name = "workspace-owner"
	ws := store.VaultPrefix(name)

	if owner, occupied, err := store.VaultWorkspaceOwner(ws); err != nil {
		t.Fatalf("inspect unowned workspace: %v", err)
	} else if occupied || owner != "" {
		t.Fatalf("unowned workspace returned owner=%q occupied=%v", owner, occupied)
	}
	if err := store.WriteVaultName(ws, name); err != nil {
		t.Fatal(err)
	}
	owner, occupied, err := store.VaultWorkspaceOwner(ws)
	if err != nil {
		t.Fatalf("inspect owned workspace: %v", err)
	}
	if !occupied || owner != name {
		t.Fatalf("owned workspace returned owner=%q occupied=%v, want %q/true", owner, occupied, name)
	}
}

func TestReserveVaultNameBypassesHotPathCacheAndFailsClosed(t *testing.T) {
	t.Run("recreates persisted mapping despite stale written cache", func(t *testing.T) {
		store := newTestStore(t)
		const name = "reserve-stale-cache"
		ws := store.VaultPrefix(name)
		if err := store.WriteVaultName(ws, name); err != nil {
			t.Fatal(err)
		}
		if err := store.db.Delete(keys.VaultMetaKey(ws), pebble.Sync); err != nil {
			t.Fatal(err)
		}
		if err := store.db.Delete(keys.VaultNameIndexKey(name), pebble.Sync); err != nil {
			t.Fatal(err)
		}
		if err := store.ReserveVaultName(ws, name); err != nil {
			t.Fatalf("reserve with stale hot-path cache: %v", err)
		}
		resolved, err := store.ResolveExistingVaultPrefix(name)
		if err != nil {
			t.Fatalf("strict resolve after reservation: %v", err)
		}
		if resolved != ws {
			t.Fatalf("reserved workspace = %x, want %x", resolved, ws)
		}
	})

	t.Run("rejects existing name index", func(t *testing.T) {
		store := newTestStore(t)
		const name = "reserve-existing-index"
		ws := store.VaultPrefix(name)
		if err := store.db.Set(keys.VaultNameIndexKey(name), ws[:], pebble.Sync); err != nil {
			t.Fatal(err)
		}
		if err := store.ReserveVaultName(ws, name); err == nil {
			t.Fatal("reservation overwrote an existing name index")
		}
	})

	t.Run("rejects workspace owner", func(t *testing.T) {
		store := newTestStore(t)
		ws := store.VaultPrefix("reserve-workspace-owner")
		if err := store.db.Set(keys.VaultMetaKey(ws), []byte("current-owner"), pebble.Sync); err != nil {
			t.Fatal(err)
		}
		if err := store.ReserveVaultName(ws, "new-owner"); err == nil {
			t.Fatal("reservation overwrote an existing workspace owner")
		}
	})
}

func TestScanVaultNamesDiscardsPartialResultsOnIteratorError(t *testing.T) {
	wantErr := errors.New("injected iterator failure")
	iter := &failingVaultNameIterator{
		keys:   [][]byte{{0x0E, 0, 0, 0, 0, 0, 0, 0, 1}},
		values: [][]byte{[]byte("partial-vault")},
		err:    wantErr,
	}
	names, err := scanVaultNames(iter)
	if !errors.Is(err, wantErr) {
		t.Fatalf("scanVaultNames error = %v, want %v", err, wantErr)
	}
	if names != nil {
		t.Fatalf("scanVaultNames returned partial results on error: %v", names)
	}
}

type failingVaultNameIterator struct {
	keys   [][]byte
	values [][]byte
	index  int
	err    error
}

func (i *failingVaultNameIterator) First() bool {
	i.index = 0
	return len(i.keys) > 0
}

func (i *failingVaultNameIterator) Next() bool {
	i.index++
	return i.index < len(i.keys)
}

func (i *failingVaultNameIterator) Key() []byte   { return i.keys[i.index] }
func (i *failingVaultNameIterator) Value() []byte { return i.values[i.index] }
func (i *failingVaultNameIterator) Error() error  { return i.err }

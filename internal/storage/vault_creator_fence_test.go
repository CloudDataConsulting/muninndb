package storage

import (
	"errors"
	"sync"
	"testing"

	"github.com/cockroachdb/pebble"
	"github.com/scrypster/muninndb/internal/storage/keys"
)

func TestResolveOrCreateVaultPrefixConcurrentSinglePair(t *testing.T) {
	store := openTestStore(t)
	const name = "concurrent-runtime-creator"
	want := store.VaultPrefix(name)

	const workers = 64
	start := make(chan struct{})
	results := make(chan [8]byte, workers)
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ws, err := store.ResolveOrCreateVaultPrefix(name)
			results <- ws
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("ResolveOrCreateVaultPrefix: %v", err)
		}
	}
	for got := range results {
		if got != want {
			t.Fatalf("workspace = %x, want %x", got, want)
		}
	}
	resolved, err := store.ResolveExistingVaultPrefix(name)
	if err != nil {
		t.Fatalf("strict resolution: %v", err)
	}
	if resolved != want {
		t.Fatalf("strict workspace = %x, want %x", resolved, want)
	}
	if got := countVaultMetadataName(t, store, name); got != 1 {
		t.Fatalf("metadata owners named %q = %d, want 1", name, got)
	}
}

func TestResolveOrCreateVaultPrefixRejectsOneSidedMappings(t *testing.T) {
	tests := []struct {
		name string
		seed func(t *testing.T, store *PebbleStore, vault string, ws [8]byte)
	}{
		{
			name: "metadata only",
			seed: func(t *testing.T, store *PebbleStore, vault string, ws [8]byte) {
				t.Helper()
				if err := store.db.Set(keys.VaultMetaKey(ws), []byte(vault), pebble.Sync); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "index only",
			seed: func(t *testing.T, store *PebbleStore, vault string, ws [8]byte) {
				t.Helper()
				if err := store.db.Set(keys.VaultNameIndexKey(vault), ws[:], pebble.Sync); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "malformed index",
			seed: func(t *testing.T, store *PebbleStore, vault string, _ [8]byte) {
				t.Helper()
				if err := store.db.Set(keys.VaultNameIndexKey(vault), []byte{1, 2, 3}, pebble.Sync); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := openTestStore(t)
			vault := "corrupt-" + tc.name
			ws := store.VaultPrefix(vault)
			tc.seed(t, store, vault, ws)

			if _, err := store.ResolveOrCreateVaultPrefix(vault); !errors.Is(err, ErrVaultCatalogCorrupt) {
				t.Fatalf("error = %v, want ErrVaultCatalogCorrupt", err)
			}
			if tc.name != "index only" && tc.name != "malformed index" {
				if exists, err := store.VaultNameIndexExists(vault); err != nil || exists {
					t.Fatalf("failed creation changed index: exists=%v err=%v", exists, err)
				}
			}
		})
	}
}

func TestCatalogClaimsCannotSplitOneNameAcrossWorkspaces(t *testing.T) {
	store := openTestStore(t)
	const name = "serialized-catalog-claim"
	derived := store.VaultPrefix(name)

	start := make(chan struct{})
	errCh := make(chan error, 3)
	var wg sync.WaitGroup
	claims := []func() error{
		func() error {
			_, err := store.ResolveOrCreateVaultPrefix(name)
			return err
		},
		func() error { return store.ReserveVaultName(derived, name) },
		func() error { return store.WriteVaultName(derived, name) },
	}
	for _, claim := range claims {
		claim := claim
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errCh <- claim()
		}()
	}
	close(start)
	wg.Wait()
	close(errCh)

	successes := 0
	for err := range errCh {
		if err == nil {
			successes++
		}
	}
	if successes == 0 {
		t.Fatal("all catalog claims failed")
	}
	resolved, err := store.ResolveExistingVaultPrefix(name)
	if err != nil {
		t.Fatalf("strict resolution: %v", err)
	}
	owner, occupied, err := store.VaultWorkspaceOwner(resolved)
	if err != nil || !occupied || owner != name {
		t.Fatalf("resolved owner = %q/%v err=%v", owner, occupied, err)
	}
	if got := countVaultMetadataName(t, store, name); got != 1 {
		t.Fatalf("metadata owners named %q = %d, want 1", name, got)
	}
}

func TestVerifiedCatalogCacheInvalidatesAcrossDeleteAndBackfill(t *testing.T) {
	t.Run("delete then recreate", func(t *testing.T) {
		store := openTestStore(t)
		const name = "verified-cache-delete-recreate"
		ws, err := store.ResolveOrCreateVaultPrefix(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := store.vaultVerifiedCache.Get(name); !ok {
			t.Fatal("creator did not cache verified pair")
		}
		if err := store.DeleteVaultNameOnly(t.Context(), name, ws); err != nil {
			t.Fatal(err)
		}
		if _, ok := store.vaultVerifiedCache.Get(name); ok {
			t.Fatal("delete retained verified pair")
		}
		recreated, err := store.ResolveOrCreateVaultPrefix(name)
		if err != nil {
			t.Fatal(err)
		}
		if recreated != ws {
			t.Fatalf("recreated workspace = %x, want %x", recreated, ws)
		}
		if resolved, err := store.ResolveExistingVaultPrefix(name); err != nil || resolved != ws {
			t.Fatalf("recreated pair = %x err=%v, want %x", resolved, err, ws)
		}
	})

	t.Run("backfill purge then revalidate", func(t *testing.T) {
		store := openTestStore(t)
		const name = "verified-cache-backfill-purge"
		ws, err := store.ResolveOrCreateVaultPrefix(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := store.vaultVerifiedCache.Get(name); !ok {
			t.Fatal("creator did not cache verified pair")
		}
		if err := store.BackfillVaultNames(); err != nil {
			t.Fatal(err)
		}
		if _, ok := store.vaultVerifiedCache.Get(name); ok {
			t.Fatal("backfill retained a pre-repair verification claim")
		}
		resolved, err := store.ResolveOrCreateVaultPrefix(name)
		if err != nil || resolved != ws {
			t.Fatalf("revalidation = %x err=%v, want %x", resolved, err, ws)
		}
		if cached, ok := store.vaultVerifiedCache.Get(name); !ok || cached != ws {
			t.Fatalf("revalidated cache = %x/%v, want %x/true", cached, ok, ws)
		}
	})
}

func TestCatalogCreatorRacesWithRenameAndDelete(t *testing.T) {
	t.Run("rename target", func(t *testing.T) {
		store := openTestStore(t)
		const oldName = "creator-race-rename-old"
		const targetName = "creator-race-rename-target"
		sourceWS, err := store.ResolveOrCreateVaultPrefix(oldName)
		if err != nil {
			t.Fatal(err)
		}

		start := make(chan struct{})
		var creatorWS [8]byte
		var creatorErr, renameErr error
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			creatorWS, creatorErr = store.ResolveOrCreateVaultPrefix(targetName)
		}()
		go func() {
			defer wg.Done()
			<-start
			renameErr = store.RenameVault(sourceWS, oldName, targetName)
		}()
		close(start)
		wg.Wait()
		if creatorErr != nil {
			t.Fatalf("creator error: %v", creatorErr)
		}

		targetWS, err := store.ResolveExistingVaultPrefix(targetName)
		if err != nil {
			t.Fatalf("target pair: %v", err)
		}
		if targetWS != creatorWS {
			t.Fatalf("target workspace = %x, creator returned %x", targetWS, creatorWS)
		}
		if renameErr == nil {
			if targetWS != sourceWS {
				t.Fatalf("successful rename target = %x, want source %x", targetWS, sourceWS)
			}
			if _, err := store.ResolveExistingVaultPrefix(oldName); !errors.Is(err, pebble.ErrNotFound) {
				t.Fatalf("old pair after rename = %v, want absent", err)
			}
		} else {
			if oldWS, err := store.ResolveExistingVaultPrefix(oldName); err != nil || oldWS != sourceWS {
				t.Fatalf("failed rename changed source = %x err=%v, want %x", oldWS, err, sourceWS)
			}
			if targetWS != store.VaultPrefix(targetName) {
				t.Fatalf("creator target = %x, want derived %x", targetWS, store.VaultPrefix(targetName))
			}
		}
	})

	t.Run("delete same name", func(t *testing.T) {
		store := openTestStore(t)
		const name = "creator-race-delete"
		ws, err := store.ResolveOrCreateVaultPrefix(name)
		if err != nil {
			t.Fatal(err)
		}

		start := make(chan struct{})
		var creatorWS [8]byte
		var creatorErr, deleteErr error
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			creatorWS, creatorErr = store.ResolveOrCreateVaultPrefix(name)
		}()
		go func() {
			defer wg.Done()
			<-start
			deleteErr = store.DeleteVaultNameOnly(t.Context(), name, ws)
		}()
		close(start)
		wg.Wait()
		if creatorErr != nil {
			t.Fatalf("creator error: %v", creatorErr)
		}
		if deleteErr != nil {
			t.Fatalf("delete error: %v", deleteErr)
		}
		if creatorWS != ws {
			t.Fatalf("creator workspace = %x, want %x", creatorWS, ws)
		}

		resolved, err := store.ResolveExistingVaultPrefix(name)
		if err == nil {
			if resolved != ws {
				t.Fatalf("final pair = %x, want %x", resolved, ws)
			}
			return
		}
		if !errors.Is(err, pebble.ErrNotFound) {
			t.Fatalf("final catalog state = %v, want absent or exact pair", err)
		}
		if _, occupied, err := store.VaultWorkspaceOwner(ws); err != nil || occupied {
			t.Fatalf("absent final state retained metadata: occupied=%v err=%v", occupied, err)
		}
	})
}

func TestDeleteVaultNameOnlyRemovesExactPair(t *testing.T) {
	store := openTestStore(t)
	const name = "atomic-catalog-delete"
	ws, err := store.ResolveOrCreateVaultPrefix(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteVaultNameOnly(t.Context(), name, ws); err != nil {
		t.Fatalf("DeleteVaultNameOnly: %v", err)
	}
	if _, err := store.ResolveExistingVaultPrefix(name); !errors.Is(err, pebble.ErrNotFound) {
		t.Fatalf("strict resolution after delete = %v, want not found", err)
	}
	if _, occupied, err := store.VaultWorkspaceOwner(ws); err != nil || occupied {
		t.Fatalf("workspace owner after delete: occupied=%v err=%v", occupied, err)
	}
}

func TestCatalogRejectsDuplicateNameAndWorkspaceAliases(t *testing.T) {
	tests := []struct {
		name string
		seed func(t *testing.T, store *PebbleStore, vault string, ws [8]byte)
	}{
		{
			name: "duplicate metadata owner",
			seed: func(t *testing.T, store *PebbleStore, vault string, _ [8]byte) {
				t.Helper()
				other := store.VaultPrefix(vault + "-other-workspace")
				if err := store.db.Set(keys.VaultMetaKey(other), []byte(vault), pebble.Sync); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "foreign index alias",
			seed: func(t *testing.T, store *PebbleStore, vault string, ws [8]byte) {
				t.Helper()
				if err := store.db.Set(keys.VaultNameIndexKey(vault+"-alias"), ws[:], pebble.Sync); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := openTestStore(t)
			vault := "valid-pair-with-" + tc.name
			ws := store.VaultPrefix(vault)
			seedVaultPairRaw(t, store, vault, ws)
			tc.seed(t, store, vault, ws)

			if _, err := store.ResolveExistingVaultPrefix(vault); !errors.Is(err, ErrVaultCatalogCorrupt) {
				t.Fatalf("strict resolution error = %v, want corruption", err)
			}
			if _, err := store.ResolveOrCreateVaultPrefix(vault); !errors.Is(err, ErrVaultCatalogCorrupt) {
				t.Fatalf("creator error = %v, want corruption", err)
			}
			if err := store.DeleteVaultNameOnly(t.Context(), vault, ws); !errors.Is(err, ErrVaultCatalogCorrupt) {
				t.Fatalf("delete error = %v, want corruption", err)
			}
		})
	}
}

func seedVaultPairRaw(t *testing.T, store *PebbleStore, name string, ws [8]byte) {
	t.Helper()
	batch := store.db.NewBatch()
	defer batch.Close()
	if err := batch.Set(keys.VaultMetaKey(ws), []byte(name), nil); err != nil {
		t.Fatal(err)
	}
	if err := batch.Set(keys.VaultNameIndexKey(name), ws[:], nil); err != nil {
		t.Fatal(err)
	}
	if err := batch.Commit(pebble.Sync); err != nil {
		t.Fatal(err)
	}
}

func TestCatalogCreationRejectsOrphanIndexAliasToDerivedWorkspace(t *testing.T) {
	store := openTestStore(t)
	const vault = "new-name-with-orphan-alias"
	ws := store.VaultPrefix(vault)
	if err := store.db.Set(keys.VaultNameIndexKey("orphan-foreign-name"), ws[:], pebble.Sync); err != nil {
		t.Fatal(err)
	}

	if _, err := store.ResolveOrCreateVaultPrefix(vault); !errors.Is(err, ErrVaultCatalogCorrupt) {
		t.Fatalf("creator error = %v, want corruption", err)
	}
	if _, occupied, err := store.VaultWorkspaceOwner(ws); err != nil || occupied {
		t.Fatalf("failed creator wrote metadata: occupied=%v err=%v", occupied, err)
	}
	if exists, err := store.VaultNameIndexExists(vault); err != nil || exists {
		t.Fatalf("failed creator wrote name index: exists=%v err=%v", exists, err)
	}
}

func countVaultMetadataName(t *testing.T, store *PebbleStore, name string) int {
	t.Helper()
	iter, err := store.db.NewIter(&pebble.IterOptions{
		LowerBound: []byte{0x0E},
		UpperBound: []byte{0x0F},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer iter.Close()
	count := 0
	for valid := iter.First(); valid; valid = iter.Next() {
		if string(iter.Value()) == name {
			count++
		}
	}
	if err := iter.Error(); err != nil {
		t.Fatal(err)
	}
	return count
}

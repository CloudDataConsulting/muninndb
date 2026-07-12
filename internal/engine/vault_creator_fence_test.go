package engine

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/cockroachdb/pebble"
	"github.com/scrypster/muninndb/internal/auth"
	"github.com/scrypster/muninndb/internal/storage"
	"github.com/scrypster/muninndb/internal/storage/keys"
	"github.com/scrypster/muninndb/internal/transport/mbp"
)

func TestRuntimeCreatorsCanonicalizeEmptyVaultToDefault(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()

	hello, err := eng.Hello(ctx, &mbp.HelloRequest{Version: "1"})
	if err != nil {
		t.Fatalf("Hello: %v", err)
	}
	if hello.VaultID != "default" {
		t.Fatalf("Hello empty vault ID = %q, want canonical default", hello.VaultID)
	}
	if _, err := eng.Write(ctx, writeReq("", "default-write", "one")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	responses, errs := eng.WriteBatch(ctx, []*mbp.WriteRequest{writeReq("", "default-batch", "two")})
	if errs[0] != nil || responses[0] == nil {
		t.Fatalf("WriteBatch response=%v err=%v", responses[0], errs[0])
	}
	if _, err := eng.RememberTree(ctx, &RememberTreeRequest{
		Root: TreeNodeInput{Concept: "default-tree", Content: "three"},
	}); err != nil {
		t.Fatalf("RememberTree: %v", err)
	}

	want := eng.store.VaultPrefix("default")
	got, err := eng.store.ResolveExistingVaultPrefix("default")
	if err != nil {
		t.Fatalf("strict default resolution: %v", err)
	}
	if got != want {
		t.Fatalf("default workspace = %x, want %x", got, want)
	}
	emptyWS := eng.store.VaultPrefix("")
	if emptyWS == want {
		t.Fatal("test assumption failed: empty and default derive the same workspace")
	}
	if _, closer, err := eng.store.GetDB().Get(keys.VaultMetaKey(emptyWS)); err == nil {
		closer.Close()
		t.Fatalf("empty-name workspace %x received catalog metadata", emptyWS)
	} else if !errors.Is(err, pebble.ErrNotFound) {
		t.Fatalf("read empty-name workspace metadata: %v", err)
	}
	if got := countWorkspaceEngrams(t, eng, ctx, want); got != 3 {
		t.Fatalf("default workspace engram count = %d, want 3", got)
	}
	vaults, err := eng.ListVaults(ctx)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, vault := range vaults {
		if vault == "default" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("default catalog entries = %d, want 1; vaults=%v", count, vaults)
	}
}

func TestEmptyVaultPreservesHealthyLegacyDefaultWorkspace(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()
	legacyWS := eng.store.VaultPrefix("")
	derivedDefault := eng.store.VaultPrefix("default")
	batch := eng.store.GetDB().NewBatch()
	if err := batch.Set(keys.VaultMetaKey(legacyWS), []byte("default"), nil); err != nil {
		batch.Close()
		t.Fatalf("seed legacy metadata: %v", err)
	}
	if err := batch.Set(keys.VaultNameIndexKey("default"), legacyWS[:], nil); err != nil {
		batch.Close()
		t.Fatalf("seed legacy name index: %v", err)
	}
	if err := batch.Commit(pebble.Sync); err != nil {
		batch.Close()
		t.Fatalf("seed legacy default mapping: %v", err)
	}
	batch.Close()
	if _, err := eng.Write(ctx, writeReq("", "legacy-default", "content")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	resolved, err := eng.store.ResolveExistingVaultPrefix("default")
	if err != nil {
		t.Fatal(err)
	}
	if resolved != legacyWS {
		t.Fatalf("default workspace = %x, want legacy %x", resolved, legacyWS)
	}
	if got := countWorkspaceEngrams(t, eng, ctx, legacyWS); got != 1 {
		t.Fatalf("legacy workspace count = %d, want 1", got)
	}
	if _, occupied, err := eng.store.VaultWorkspaceOwner(derivedDefault); err != nil || occupied {
		t.Fatalf("name-derived default workspace unexpectedly claimed: occupied=%v err=%v", occupied, err)
	}
}

func TestEmptyVaultPublicFlowsUseCanonicalDefaultMapping(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()

	written, err := eng.Write(ctx, writeReq("", "round-trip-default", "canonical default content"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	read, err := eng.Read(ctx, &mbp.ReadRequest{Vault: "", ID: written.ID})
	if err != nil {
		t.Fatalf("Read empty vault after Write: %v", err)
	}
	if read.ID != written.ID {
		t.Fatalf("Read returned %+v, want engram %s", read, written.ID)
	}
	awaitFTS(t, eng)
	activated, err := eng.Activate(ctx, &mbp.ActivateRequest{
		Vault:      "",
		Context:    []string{"canonical default content"},
		MaxResults: 10,
		Threshold:  0.01,
	})
	if err != nil {
		t.Fatalf("Activate empty vault after Write: %v", err)
	}
	found := false
	for _, item := range activated.Activations {
		if item.ID == written.ID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Activate did not return written engram %s: %+v", written.ID, activated.Activations)
	}
	if _, err := eng.Forget(ctx, &mbp.ForgetRequest{Vault: "", ID: written.ID, Hard: false}); err != nil {
		t.Fatalf("Forget empty vault after Write: %v", err)
	}

	tree, err := eng.RememberTree(ctx, &RememberTreeRequest{
		Root: TreeNodeInput{
			Concept:  "round-trip-tree",
			Content:  "root",
			Children: []TreeNodeInput{{Concept: "child", Content: "child"}},
		},
	})
	if err != nil {
		t.Fatalf("RememberTree: %v", err)
	}
	if count, err := eng.CountChildren(ctx, "", tree.RootID); err != nil || count != 1 {
		t.Fatalf("CountChildren empty vault = %d err=%v, want 1", count, err)
	}
	if recalled, err := eng.RecallTree(ctx, "", tree.RootID, 0, 0, true); err != nil || recalled == nil || recalled.ID != tree.RootID {
		t.Fatalf("RecallTree empty vault = %+v err=%v", recalled, err)
	}
}

func TestEmptyVaultResolvesDefaultPlasticityConfig(t *testing.T) {
	eng, authStore, _, cleanup := testEnvWithAuth(t)
	defer cleanup()
	enabled := true
	if err := authStore.SetVaultConfig(auth.VaultConfig{
		Name: "default",
		Plasticity: &auth.PlasticityConfig{
			PredictiveActivation: &enabled,
		},
	}); err != nil {
		t.Fatal(err)
	}
	if got := eng.ResolveVaultPlasticity(""); !got.PredictiveActivation {
		t.Fatal("empty vault ignored the canonical default plasticity config")
	}
}

func TestRuntimeCreatorsFailBeforeDataOnCorruptCatalog(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()
	const vault = "creator-corrupt-metadata-only"
	ws := eng.store.VaultPrefix(vault)
	if err := eng.store.GetDB().Set(keys.VaultMetaKey(ws), []byte(vault), pebble.Sync); err != nil {
		t.Fatal(err)
	}

	if _, err := eng.Hello(ctx, &mbp.HelloRequest{Version: "1", Vault: vault}); !errors.Is(err, storage.ErrVaultCatalogCorrupt) {
		t.Fatalf("Hello error = %v, want catalog corruption", err)
	}
	if _, err := eng.Write(ctx, writeReq(vault, "must-not-write", "one")); !errors.Is(err, storage.ErrVaultCatalogCorrupt) {
		t.Fatalf("Write error = %v, want catalog corruption", err)
	}
	responses, errs := eng.WriteBatch(ctx, []*mbp.WriteRequest{writeReq(vault, "must-not-batch", "two")})
	if responses[0] != nil || !errors.Is(errs[0], storage.ErrVaultCatalogCorrupt) {
		t.Fatalf("WriteBatch response=%v err=%v", responses[0], errs[0])
	}
	if _, err := eng.RememberTree(ctx, &RememberTreeRequest{
		Vault: vault,
		Root:  TreeNodeInput{Concept: "must-not-tree", Content: "three"},
	}); !errors.Is(err, storage.ErrVaultCatalogCorrupt) {
		t.Fatalf("RememberTree error = %v, want catalog corruption", err)
	}
	if got := countWorkspaceEngrams(t, eng, ctx, ws); got != 0 {
		t.Fatalf("corrupt workspace engram count = %d, want 0", got)
	}
}

func TestWriteBatchPreservesMixedCatalogErrors(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()
	badVaults := []string{"batch-corrupt-first", "batch-corrupt-middle"}
	badWorkspaces := make([][8]byte, len(badVaults))
	for i, vault := range badVaults {
		badWorkspaces[i] = eng.store.VaultPrefix(vault)
		if err := eng.store.GetDB().Set(keys.VaultMetaKey(badWorkspaces[i]), []byte(vault), pebble.Sync); err != nil {
			t.Fatal(err)
		}
	}

	responses, errs := eng.WriteBatch(ctx, []*mbp.WriteRequest{
		writeReq(badVaults[0], "invalid-first", "zero"),
		writeReq("batch-valid-one", "valid-one", "one"),
		writeReq(badVaults[1], "invalid-middle", "two"),
		writeReq("batch-valid-two", "valid-two", "three"),
	})
	for _, index := range []int{0, 2} {
		if responses[index] != nil || !errors.Is(errs[index], storage.ErrVaultCatalogCorrupt) {
			t.Fatalf("invalid item %d response=%v err=%v", index, responses[index], errs[index])
		}
	}
	for _, index := range []int{1, 3} {
		if errs[index] != nil || responses[index] == nil {
			t.Fatalf("valid item %d response=%v err=%v", index, responses[index], errs[index])
		}
	}
	for index, vault := range []string{"batch-valid-one", "batch-valid-two"} {
		ws, err := eng.store.ResolveExistingVaultPrefix(vault)
		if err != nil {
			t.Fatal(err)
		}
		if got := countWorkspaceEngrams(t, eng, ctx, ws); got != 1 {
			t.Fatalf("valid vault %d count = %d, want 1", index, got)
		}
		read, err := eng.Read(ctx, &mbp.ReadRequest{Vault: vault, ID: responses[index*2+1].ID})
		if err != nil || read.ID != responses[index*2+1].ID {
			t.Fatalf("valid vault %d read=%+v err=%v", index, read, err)
		}
	}
	for i, ws := range badWorkspaces {
		if got := countWorkspaceEngrams(t, eng, ctx, ws); got != 0 {
			t.Fatalf("corrupt vault %d count = %d, want 0", i, got)
		}
	}
}

func TestWriteBatchAllCatalogErrorsWritesNothing(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()
	vaults := []string{"batch-all-invalid-one", "batch-all-invalid-two"}
	for _, vault := range vaults {
		ws := eng.store.VaultPrefix(vault)
		if err := eng.store.GetDB().Set(keys.VaultMetaKey(ws), []byte(vault), pebble.Sync); err != nil {
			t.Fatal(err)
		}
	}
	responses, errs := eng.WriteBatch(ctx, []*mbp.WriteRequest{
		writeReq(vaults[0], "invalid-one", "one"),
		writeReq(vaults[1], "invalid-two", "two"),
	})
	for i, vault := range vaults {
		if responses[i] != nil || !errors.Is(errs[i], storage.ErrVaultCatalogCorrupt) {
			t.Fatalf("item %d response=%v err=%v", i, responses[i], errs[i])
		}
		if got := countWorkspaceEngrams(t, eng, ctx, eng.store.VaultPrefix(vault)); got != 0 {
			t.Fatalf("invalid vault %d count = %d, want 0", i, got)
		}
	}
}

func TestRememberTreeRegistersRequestedVault(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()
	const vault = "remember-tree-first-creator"
	result, err := eng.RememberTree(ctx, &RememberTreeRequest{
		Vault: vault,
		Root: TreeNodeInput{
			Concept:  "root",
			Content:  "root content",
			Children: []TreeNodeInput{{Concept: "child", Content: "child content"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.RootID == "" {
		t.Fatal("RememberTree returned no root ID")
	}
	ws, err := eng.store.ResolveExistingVaultPrefix(vault)
	if err != nil {
		t.Fatalf("strict tree vault resolution: %v", err)
	}
	if got := countWorkspaceEngrams(t, eng, ctx, ws); got != 2 {
		t.Fatalf("tree vault count = %d, want 2", got)
	}
	if err := eng.store.BackfillVaultNames(); err != nil {
		t.Fatalf("startup backfill changed healthy tree catalog: %v", err)
	}
	if resolved, err := eng.store.ResolveExistingVaultPrefix(vault); err != nil || resolved != ws {
		t.Fatalf("tree vault after backfill = %x err=%v, want %x", resolved, err, ws)
	}
}

func TestExistingVaultMutatorsRejectFreedRenameName(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()
	const oldName = "mutator-old-name"
	const currentName = "mutator-current-name"
	write, err := eng.Write(ctx, writeReq(oldName, "original", "content"))
	if err != nil {
		t.Fatal(err)
	}
	ws, err := eng.store.ResolveExistingVaultPrefix(oldName)
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.RenameVault(ctx, oldName, currentName); err != nil {
		t.Fatal(err)
	}
	before := countWorkspaceEngrams(t, eng, ctx, ws)

	if _, err := eng.AddChild(ctx, oldName, write.ID, &AddChildInput{Concept: "forbidden-child", Content: "content"}); err == nil {
		t.Fatal("AddChild through freed name succeeded")
	}
	if _, err := eng.Evolve(ctx, oldName, write.ID, "forbidden evolution", "test"); err == nil {
		t.Fatal("Evolve through freed name succeeded")
	}
	if got := countWorkspaceEngrams(t, eng, ctx, ws); got != before {
		t.Fatalf("workspace count after rejected mutations = %d, want %d", got, before)
	}
	id, err := storage.ParseULID(write.ID)
	if err != nil {
		t.Fatal(err)
	}
	engram, err := eng.store.GetEngram(ctx, ws, id)
	if err != nil {
		t.Fatal(err)
	}
	if engram.State != storage.StateActive {
		t.Fatalf("original state = %v, want active", engram.State)
	}
}

func TestRuntimeCreatorsRejectFreedNameAndPreserveRenamedWorkspace(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()
	const oldName = "creator-freed-old"
	const currentName = "creator-freed-current"
	if _, err := eng.Write(ctx, writeReq(oldName, "original", "content")); err != nil {
		t.Fatal(err)
	}
	ws, err := eng.store.ResolveExistingVaultPrefix(oldName)
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.RenameVault(ctx, oldName, currentName); err != nil {
		t.Fatal(err)
	}
	before := countWorkspaceEngrams(t, eng, ctx, ws)

	if _, err := eng.Hello(ctx, &mbp.HelloRequest{Version: "1", Vault: oldName}); !errors.Is(err, storage.ErrVaultCatalogCorrupt) {
		t.Fatalf("Hello freed name error = %v, want corruption", err)
	}
	if _, err := eng.Write(ctx, writeReq(oldName, "forbidden-write", "content")); !errors.Is(err, storage.ErrVaultCatalogCorrupt) {
		t.Fatalf("Write freed name error = %v, want corruption", err)
	}
	responses, errs := eng.WriteBatch(ctx, []*mbp.WriteRequest{writeReq(oldName, "forbidden-batch", "content")})
	if responses[0] != nil || !errors.Is(errs[0], storage.ErrVaultCatalogCorrupt) {
		t.Fatalf("WriteBatch freed name response=%v err=%v", responses[0], errs[0])
	}
	if _, err := eng.RememberTree(ctx, &RememberTreeRequest{
		Vault: oldName,
		Root:  TreeNodeInput{Concept: "forbidden-tree", Content: "content"},
	}); !errors.Is(err, storage.ErrVaultCatalogCorrupt) {
		t.Fatalf("RememberTree freed name error = %v, want corruption", err)
	}
	if got := countWorkspaceEngrams(t, eng, ctx, ws); got != before {
		t.Fatalf("renamed workspace count after rejected creators = %d, want %d", got, before)
	}
	if eng.store.VaultNameExists(oldName) {
		t.Fatalf("freed name %q was recreated", oldName)
	}

	if _, err := eng.Hello(ctx, &mbp.HelloRequest{Version: "1", Vault: currentName}); err != nil {
		t.Fatalf("Hello current name: %v", err)
	}
	if _, err := eng.Write(ctx, writeReq(currentName, "allowed-write", "content")); err != nil {
		t.Fatalf("Write current name: %v", err)
	}
	responses, errs = eng.WriteBatch(ctx, []*mbp.WriteRequest{writeReq(currentName, "allowed-batch", "content")})
	if errs[0] != nil || responses[0] == nil {
		t.Fatalf("WriteBatch current name response=%v err=%v", responses[0], errs[0])
	}
	if _, err := eng.RememberTree(ctx, &RememberTreeRequest{
		Vault: currentName,
		Root:  TreeNodeInput{Concept: "allowed-tree", Content: "content"},
	}); err != nil {
		t.Fatalf("RememberTree current name: %v", err)
	}
	resolved, err := eng.store.ResolveExistingVaultPrefix(currentName)
	if err != nil || resolved != ws {
		t.Fatalf("current name workspace = %x err=%v, want %x", resolved, err, ws)
	}
	if got := countWorkspaceEngrams(t, eng, ctx, ws); got != before+3 {
		t.Fatalf("renamed workspace count after valid creators = %d, want %d", got, before+3)
	}
	derivedCurrent := eng.store.VaultPrefix(currentName)
	if derivedCurrent != ws {
		if _, occupied, err := eng.store.VaultWorkspaceOwner(derivedCurrent); err != nil || occupied {
			t.Fatalf("current-name derived workspace unexpectedly claimed: occupied=%v err=%v", occupied, err)
		}
	}
}

func TestConcurrentRuntimeCreatorsShareOneCatalogPair(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()
	const vault = "engine-concurrent-creators"

	start := make(chan struct{})
	errCh := make(chan error, 4)
	var wg sync.WaitGroup
	creators := []func() error{
		func() error {
			_, err := eng.Hello(ctx, &mbp.HelloRequest{Version: "1", Vault: vault})
			return err
		},
		func() error {
			_, err := eng.Write(ctx, writeReq(vault, "write", "one"))
			return err
		},
		func() error {
			_, errs := eng.WriteBatch(ctx, []*mbp.WriteRequest{writeReq(vault, "batch", "two")})
			return errs[0]
		},
		func() error {
			_, err := eng.RememberTree(ctx, &RememberTreeRequest{
				Vault: vault,
				Root:  TreeNodeInput{Concept: "tree", Content: "three"},
			})
			return err
		},
	}
	for _, creator := range creators {
		creator := creator
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errCh <- creator()
		}()
	}
	close(start)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("concurrent creator: %v", err)
		}
	}
	ws, err := eng.store.ResolveExistingVaultPrefix(vault)
	if err != nil {
		t.Fatal(err)
	}
	if got := countWorkspaceEngrams(t, eng, ctx, ws); got != 3 {
		t.Fatalf("creator workspace count = %d, want 3", got)
	}
	vaults, err := eng.ListVaults(ctx)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, name := range vaults {
		if name == vault {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("catalog entries named %q = %d, want 1", vault, count)
	}
}

func countWorkspaceEngrams(t *testing.T, eng *Engine, ctx context.Context, ws [8]byte) int {
	t.Helper()
	count := 0
	if err := eng.store.ScanEngrams(ctx, ws, func(*storage.Engram) error {
		count++
		return nil
	}); err != nil {
		t.Fatalf("scan workspace %x: %v", ws, err)
	}
	return count
}

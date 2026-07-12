package engine

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/scrypster/muninndb/internal/auth"
	"github.com/scrypster/muninndb/internal/engine/vaultjob"
	"github.com/scrypster/muninndb/internal/storage"
	"github.com/scrypster/muninndb/internal/storage/keys"
	"github.com/scrypster/muninndb/internal/transport/mbp"
)

func TestVaultResolution_RenameThenClearUsesPreservedWorkspace(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()

	ctx := context.Background()
	const oldName = "resolution-clear-before-rename"
	const newName = "resolution-clear-after-rename"

	resp, err := eng.Write(ctx, writeReq(oldName, "rename-clear", "must be removed from the original workspace"))
	if err != nil {
		t.Fatalf("write source engram: %v", err)
	}
	originalWorkspace := eng.store.ResolveVaultPrefix(oldName)
	if err := eng.RenameVault(ctx, oldName, newName); err != nil {
		t.Fatalf("rename vault: %v", err)
	}
	if err := eng.ClearVault(ctx, newName); err != nil {
		t.Fatalf("clear renamed vault: %v", err)
	}

	id, err := storage.ParseULID(resp.ID)
	if err != nil {
		t.Fatalf("parse written engram ID: %v", err)
	}
	if _, err := eng.store.GetEngram(ctx, originalWorkspace, id); err == nil {
		t.Fatalf("ClearVault(%q) left engram %s in the preserved original workspace", newName, resp.ID)
	}
}

func TestVaultResolution_RenameThenDeleteRemovesPreservedWorkspaceAndName(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()

	ctx := context.Background()
	const oldName = "resolution-delete-before-rename"
	const newName = "resolution-delete-after-rename"

	resp, err := eng.Write(ctx, writeReq(oldName, "rename-delete", "must be removed with the renamed vault"))
	if err != nil {
		t.Fatalf("write source engram: %v", err)
	}
	originalWorkspace := eng.store.ResolveVaultPrefix(oldName)
	if err := eng.RenameVault(ctx, oldName, newName); err != nil {
		t.Fatalf("rename vault: %v", err)
	}
	if err := eng.DeleteVault(ctx, newName); err != nil {
		t.Fatalf("delete renamed vault: %v", err)
	}

	id, err := storage.ParseULID(resp.ID)
	if err != nil {
		t.Fatalf("parse written engram ID: %v", err)
	}
	if _, err := eng.store.GetEngram(ctx, originalWorkspace, id); err == nil {
		t.Errorf("DeleteVault(%q) left engram %s in the preserved original workspace", newName, resp.ID)
	}

	names, err := eng.store.ListVaultNames()
	if err != nil {
		t.Fatalf("list vault names: %v", err)
	}
	for _, name := range names {
		if name == newName || name == oldName {
			t.Errorf("DeleteVault(%q) left vault metadata listed as %q", newName, name)
		}
	}
}

func TestVaultResolution_RenamePreservedWorkspace_ExportVault(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()
	ws, _ := writeAndRenameResolutionVault(t, eng, ctx, "resolution-export-old", "resolution-export-new", "exported")

	var archive bytes.Buffer
	result, err := eng.ExportVault(ctx, "resolution-export-new", "", 0, false, &archive)
	if err != nil {
		t.Fatalf("ExportVault renamed vault: %v", err)
	}
	if result.EngramCount != 1 {
		t.Fatalf("ExportVault renamed vault count = %d, want 1 from workspace %x", result.EngramCount, ws)
	}
	if archive.Len() == 0 {
		t.Fatal("ExportVault renamed vault returned an empty archive")
	}
}

func TestVaultResolution_RenamePreservedWorkspace_StartCloneSource(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()
	_, _ = writeAndRenameResolutionVault(t, eng, ctx, "resolution-clone-old", "resolution-clone-new", "clone-source")

	job, err := eng.StartClone(ctx, "resolution-clone-new", "resolution-clone-target")
	if err != nil {
		t.Fatalf("StartClone renamed source: %v", err)
	}
	assertResolutionJobDone(t, eng, job)
	targetWS, err := eng.store.ResolveExistingVaultPrefix("resolution-clone-target")
	if err != nil {
		t.Fatalf("resolve clone target: %v", err)
	}
	if got := countResolutionEngrams(t, eng.store, ctx, targetWS); got != 1 {
		t.Fatalf("clone target count = %d, want 1 from renamed source", got)
	}
}

func TestVaultResolution_RenamePreservedWorkspace_StartMergeSourceAndTarget(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()
	sourceWS, _ := writeAndRenameResolutionVault(t, eng, ctx, "resolution-merge-source-old", "resolution-merge-source-new", "source")
	targetWS, _ := writeAndRenameResolutionVault(t, eng, ctx, "resolution-merge-target-old", "resolution-merge-target-new", "target")

	job, err := eng.StartMerge(ctx, "resolution-merge-source-new", "resolution-merge-target-new", false)
	if err != nil {
		t.Fatalf("StartMerge renamed source and target: %v", err)
	}
	assertResolutionJobDone(t, eng, job)
	if got := countResolutionEngrams(t, eng.store, ctx, targetWS); got != 2 {
		t.Fatalf("renamed merge target count = %d, want 2", got)
	}
	if got := countResolutionEngrams(t, eng.store, ctx, sourceWS); got != 1 {
		t.Fatalf("renamed merge source count = %d, want 1 with deleteSource=false", got)
	}
}

func TestVaultResolution_RenamePreservedWorkspace_StartMergeDeletesSource(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()
	sourceWS, _ := writeAndRenameResolutionVault(t, eng, ctx, "resolution-merge-delete-old", "resolution-merge-delete-new", "source")
	targetWS, _ := writeAndRenameResolutionVault(t, eng, ctx, "resolution-merge-delete-target-old", "resolution-merge-delete-target-new", "target")

	job, err := eng.StartMerge(ctx, "resolution-merge-delete-new", "resolution-merge-delete-target-new", true)
	if err != nil {
		t.Fatalf("StartMerge renamed source with deleteSource=true: %v", err)
	}
	assertResolutionJobDone(t, eng, job)
	if got := countResolutionEngrams(t, eng.store, ctx, targetWS); got != 2 {
		t.Fatalf("renamed merge target count = %d, want 2", got)
	}
	if got := countResolutionEngrams(t, eng.store, ctx, sourceWS); got != 0 {
		t.Fatalf("renamed merge source count = %d, want 0 after deleteSource=true", got)
	}
	if _, err := eng.store.ResolveExistingVaultPrefix("resolution-merge-delete-new"); err == nil {
		t.Fatal("renamed merge source mapping survived deleteSource=true")
	}
}

func TestVaultResolution_RenamePreservedWorkspace_ReindexFTSVault(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()
	ws, _ := writeAndRenameResolutionVault(t, eng, ctx, "resolution-reindex-old", "resolution-reindex-new", "running dogs")

	count, err := eng.ReindexFTSVault(ctx, "resolution-reindex-new")
	if err != nil {
		t.Fatalf("ReindexFTSVault renamed vault: %v", err)
	}
	if count != 1 {
		t.Fatalf("ReindexFTSVault renamed vault count = %d, want 1", count)
	}
	value, closer, err := eng.store.GetDB().Get(keys.FTSVersionKey(ws))
	if err != nil {
		t.Fatalf("read original-workspace FTS version: %v", err)
	}
	defer closer.Close()
	if len(value) != 1 || value[0] != 1 {
		t.Fatalf("original-workspace FTS version = %v, want [1]", value)
	}
}

func TestVaultResolution_RenamePreservedWorkspace_StartReembedVault(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()
	_, id := writeAndRenameResolutionVault(t, eng, ctx, "resolution-reembed-old", "resolution-reembed-new", "reembed")
	const digestEmbed uint8 = 0x02
	if err := eng.store.SetDigestFlag(ctx, id, digestEmbed); err != nil {
		t.Fatalf("set embed digest flag: %v", err)
	}

	job, err := eng.StartReembedVault(ctx, "resolution-reembed-new", "test-model")
	if err != nil {
		t.Fatalf("StartReembedVault renamed vault: %v", err)
	}
	assertResolutionJobDone(t, eng, job)
	flags, err := eng.store.GetDigestFlags(ctx, id)
	if err != nil {
		t.Fatalf("read embed digest flags: %v", err)
	}
	if flags&digestEmbed != 0 {
		t.Fatalf("renamed-vault reembed left DigestEmbed set: flags=0x%02X", flags)
	}
}

func TestVaultResolution_RenamePreservedWorkspace_PruneVault(t *testing.T) {
	eng, authStore, _, cleanup := testEnvWithAuth(t)
	defer cleanup()
	ctx := context.Background()
	ws, _ := writeAndRenameResolutionVault(t, eng, ctx, "resolution-prune-old", "resolution-prune-new", "prune-one")
	if _, err := eng.Write(ctx, writeReq("resolution-prune-new", "prune-two", "second engram in preserved workspace")); err != nil {
		t.Fatalf("write second renamed-vault engram: %v", err)
	}
	before := countResolutionEngrams(t, eng.store, ctx, ws)
	if before < 2 {
		t.Fatalf("renamed prune workspace count before prune = %d, want at least 2", before)
	}
	maxEngrams := 1
	if err := authStore.SetVaultConfig(auth.VaultConfig{
		Name: "resolution-prune-new",
		Plasticity: &auth.PlasticityConfig{
			MaxEngrams: &maxEngrams,
		},
	}); err != nil {
		t.Fatalf("set prune config: %v", err)
	}

	pruned, err := eng.PruneVault(ctx, "resolution-prune-new")
	if err != nil {
		t.Fatalf("PruneVault renamed vault: %v", err)
	}
	if pruned < 1 {
		t.Fatalf("PruneVault renamed vault pruned %d, want at least 1", pruned)
	}
	if got := countResolutionEngrams(t, eng.store, ctx, ws); got >= before || got > int64(maxEngrams) {
		t.Fatalf("renamed prune workspace count = %d after pruning %d from %d, want a reduced count <= %d", got, pruned, before, maxEngrams)
	}
}

func TestVaultResolution_RenamePreservedWorkspace_ReplayEnrichment(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()
	_, _ = writeAndRenameResolutionVault(t, eng, ctx, "resolution-replay-old", "resolution-replay-new", "unenriched")

	result, err := eng.ReplayEnrichment(ctx, "resolution-replay-new", []string{"entities"}, 10, true)
	if err != nil {
		t.Fatalf("ReplayEnrichment renamed vault: %v", err)
	}
	if !result.DryRun || result.Processed != 1 || result.Skipped != 0 {
		t.Fatalf("ReplayEnrichment renamed vault result = %+v, want one dry-run candidate", result)
	}
}

func TestVaultResolution_RenamePreservedWorkspace_MergeEntity(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()
	const oldName = "resolution-entity-merge-old"
	const newName = "resolution-entity-merge-new"
	const alias = "Resolution Postgre SQL"
	const canonical = "Resolution PostgreSQL"

	aliasID := writeEntityEngram(t, eng, oldName, "legacy alias", mbp.InlineEntity{Name: alias, Type: "database"})
	writeEntityEngram(t, eng, oldName, "canonical entity", mbp.InlineEntity{Name: canonical, Type: "database"})
	ws := eng.store.ResolveVaultPrefix(oldName)
	if err := eng.RenameVault(ctx, oldName, newName); err != nil {
		t.Fatalf("rename entity-merge vault: %v", err)
	}

	result, err := eng.MergeEntity(ctx, newName, alias, canonical, false)
	if err != nil {
		t.Fatalf("MergeEntity renamed vault: %v", err)
	}
	if result.EngramsRelinked != 1 {
		t.Fatalf("MergeEntity renamed vault relinked %d engrams, want 1", result.EngramsRelinked)
	}
	id, err := storage.ParseULID(aliasID)
	if err != nil {
		t.Fatal(err)
	}
	var foundAlias, foundCanonical bool
	if err := eng.store.ScanEngramEntities(ctx, ws, id, func(name string) error {
		foundAlias = foundAlias || name == alias
		foundCanonical = foundCanonical || name == canonical
		return nil
	}); err != nil {
		t.Fatalf("scan merged engram entities: %v", err)
	}
	if foundAlias || !foundCanonical {
		t.Fatalf("renamed-vault entity links after merge: alias=%v canonical=%v", foundAlias, foundCanonical)
	}
}

func TestVaultResolution_RenamePreservedWorkspace_ExportGraph(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()
	const oldName = "resolution-graph-export-old"
	const newName = "resolution-graph-export-new"
	writeEntityRelationship(t, eng, oldName, "Resolution PostgreSQL", "database", "Resolution Redis", "cache", "uses")
	if err := eng.RenameVault(ctx, oldName, newName); err != nil {
		t.Fatalf("rename graph-export vault: %v", err)
	}

	graph, err := eng.ExportGraph(ctx, newName, false)
	if err != nil {
		t.Fatalf("ExportGraph renamed vault: %v", err)
	}
	if len(graph.Edges) == 0 {
		t.Fatal("ExportGraph renamed vault returned no edges from preserved workspace")
	}
}

func TestVaultResolution_EngineCallsFailClosedOnPersistedMappingDamage(t *testing.T) {
	t.Run("engine classification preserves one-sided corruption", func(t *testing.T) {
		eng, cleanup := testEnv(t)
		defer cleanup()
		ctx := context.Background()
		const vault = "resolution-fail-classification"
		if _, err := eng.Write(ctx, writeReq(vault, "preserve", "mapping evidence must survive classification")); err != nil {
			t.Fatal(err)
		}
		if err := eng.store.GetDB().Delete(keys.VaultNameIndexKey(vault), pebble.Sync); err != nil {
			t.Fatal(err)
		}
		if _, err := eng.resolveExistingVaultPrefix(vault); err == nil {
			t.Fatal("engine resolution succeeded with a one-sided persisted mapping")
		} else if errors.Is(err, ErrVaultNotFound) {
			t.Fatalf("one-sided persisted mapping was misclassified as an absent vault: %v", err)
		}
	})

	t.Run("export missing name index", func(t *testing.T) {
		eng, cleanup := testEnv(t)
		defer cleanup()
		ctx := context.Background()
		const vault = "resolution-fail-export"
		if _, err := eng.Write(ctx, writeReq(vault, "preserve", "export must fail")); err != nil {
			t.Fatal(err)
		}
		if err := eng.store.GetDB().Delete(keys.VaultNameIndexKey(vault), pebble.Sync); err != nil {
			t.Fatal(err)
		}
		var archive bytes.Buffer
		if _, err := eng.ExportVault(ctx, vault, "", 0, false, &archive); err == nil {
			t.Fatal("ExportVault succeeded with missing persisted name index")
		} else if errors.Is(err, ErrVaultNotFound) {
			t.Fatalf("one-sided persisted mapping was misclassified as an absent vault: %v", err)
		}
		if archive.Len() != 0 {
			t.Fatalf("ExportVault wrote %d bytes before strict-resolution failure", archive.Len())
		}
	})

	t.Run("clone malformed source index does not reserve target", func(t *testing.T) {
		eng, cleanup := testEnv(t)
		defer cleanup()
		ctx := context.Background()
		const source = "resolution-fail-clone-source"
		const target = "resolution-fail-clone-target"
		if _, err := eng.Write(ctx, writeReq(source, "preserve", "clone must fail")); err != nil {
			t.Fatal(err)
		}
		if err := eng.store.GetDB().Set(keys.VaultNameIndexKey(source), []byte{1, 2, 3}, pebble.Sync); err != nil {
			t.Fatal(err)
		}
		if _, err := eng.StartClone(ctx, source, target); err == nil {
			t.Fatal("StartClone succeeded with malformed persisted source index")
		}
		if eng.store.VaultNameExists(target) {
			t.Fatal("StartClone reserved target before strict source resolution")
		}
	})

	t.Run("reindex mismatched metadata does not clear indexes", func(t *testing.T) {
		eng, cleanup := testEnv(t)
		defer cleanup()
		ctx := context.Background()
		const vault = "resolution-fail-reindex"
		resp, err := eng.Write(ctx, writeReq(vault, "preserve", "reindex must fail"))
		if err != nil {
			t.Fatal(err)
		}
		ws := eng.store.ResolveVaultPrefix(vault)
		id, err := storage.ParseULID(resp.ID)
		if err != nil {
			t.Fatal(err)
		}
		marker := keys.FTSPostingKey(ws, "sentinel", [16]byte(id))
		if err := eng.store.GetDB().Set(marker, nil, pebble.Sync); err != nil {
			t.Fatal(err)
		}
		if err := eng.store.GetDB().Set(keys.VaultMetaKey(ws), []byte("different-name"), pebble.Sync); err != nil {
			t.Fatal(err)
		}
		decoyWS := eng.store.VaultPrefix("resolution-fail-reindex-decoy")
		if err := eng.store.GetDB().Set(keys.VaultMetaKey(decoyWS), []byte(vault), pebble.Sync); err != nil {
			t.Fatal(err)
		}
		if _, err := eng.ReindexFTSVault(ctx, vault); err == nil {
			t.Fatal("ReindexFTSVault succeeded with mismatched persisted metadata")
		} else if !strings.Contains(err.Error(), "metadata") {
			t.Fatalf("ReindexFTSVault error does not identify metadata failure: %v", err)
		}
		if _, closer, err := eng.store.GetDB().Get(marker); err != nil {
			t.Fatalf("ReindexFTSVault cleared FTS data before strict-resolution failure: %v", err)
		} else {
			closer.Close()
		}
	})
}

func TestVaultResolution_IndexOnlyMappingsFailClosed(t *testing.T) {
	t.Run("clear source", func(t *testing.T) {
		eng, cleanup := testEnv(t)
		defer cleanup()
		makeIndexOnlyResolutionVault(t, eng, "index-only-clear")
		assertResolutionCorruption(t, eng.ClearVault(context.Background(), "index-only-clear"))
	})

	t.Run("export source", func(t *testing.T) {
		eng, cleanup := testEnv(t)
		defer cleanup()
		makeIndexOnlyResolutionVault(t, eng, "index-only-export")
		var archive bytes.Buffer
		_, err := eng.ExportVault(context.Background(), "index-only-export", "", 0, false, &archive)
		assertResolutionCorruption(t, err)
	})

	t.Run("reembed source", func(t *testing.T) {
		eng, cleanup := testEnv(t)
		defer cleanup()
		makeIndexOnlyResolutionVault(t, eng, "index-only-reembed")
		_, err := eng.StartReembedVault(context.Background(), "index-only-reembed", "test-model")
		assertResolutionCorruption(t, err)
	})

	t.Run("reindex source", func(t *testing.T) {
		eng, cleanup := testEnv(t)
		defer cleanup()
		makeIndexOnlyResolutionVault(t, eng, "index-only-reindex")
		_, err := eng.ReindexFTSVault(context.Background(), "index-only-reindex")
		assertResolutionCorruption(t, err)
	})

	t.Run("rename source", func(t *testing.T) {
		eng, cleanup := testEnv(t)
		defer cleanup()
		makeIndexOnlyResolutionVault(t, eng, "index-only-rename-source")
		assertResolutionCorruption(t, eng.RenameVault(context.Background(), "index-only-rename-source", "index-only-rename-target"))
	})

	t.Run("rename target", func(t *testing.T) {
		eng, cleanup := testEnv(t)
		defer cleanup()
		ctx := context.Background()
		if _, err := eng.Write(ctx, writeReq("index-only-rename-valid-source", "source", "valid source")); err != nil {
			t.Fatal(err)
		}
		ws := makeRenamedIndexOnlyResolutionVault(t, eng, "index-only-rename-target-old", "index-only-rename-broken-target")
		err := eng.RenameVault(ctx, "index-only-rename-valid-source", "index-only-rename-broken-target")
		assertResolutionCorruption(t, err)
		assertResolutionIndexUnchanged(t, eng, "index-only-rename-broken-target", ws)
	})

	t.Run("clone source", func(t *testing.T) {
		eng, cleanup := testEnv(t)
		defer cleanup()
		makeIndexOnlyResolutionVault(t, eng, "index-only-clone-source")
		_, err := eng.StartClone(context.Background(), "index-only-clone-source", "index-only-clone-new")
		assertResolutionCorruption(t, err)
	})

	t.Run("merge source", func(t *testing.T) {
		eng, cleanup := testEnv(t)
		defer cleanup()
		ctx := context.Background()
		makeIndexOnlyResolutionVault(t, eng, "index-only-merge-source")
		if _, err := eng.Write(ctx, writeReq("index-only-merge-target", "target", "valid target")); err != nil {
			t.Fatal(err)
		}
		_, err := eng.StartMerge(ctx, "index-only-merge-source", "index-only-merge-target", false)
		assertResolutionCorruption(t, err)
	})

	t.Run("merge target", func(t *testing.T) {
		eng, cleanup := testEnv(t)
		defer cleanup()
		ctx := context.Background()
		if _, err := eng.Write(ctx, writeReq("index-only-merge-valid-source", "source", "valid source")); err != nil {
			t.Fatal(err)
		}
		makeIndexOnlyResolutionVault(t, eng, "index-only-merge-broken-target")
		_, err := eng.StartMerge(ctx, "index-only-merge-valid-source", "index-only-merge-broken-target", false)
		assertResolutionCorruption(t, err)
	})

	t.Run("clone target reservation", func(t *testing.T) {
		eng, cleanup := testEnv(t)
		defer cleanup()
		ctx := context.Background()
		if _, err := eng.Write(ctx, writeReq("index-only-clone-valid-source", "source", "valid source")); err != nil {
			t.Fatal(err)
		}
		ws := makeRenamedIndexOnlyResolutionVault(t, eng, "index-only-clone-target-old", "index-only-clone-target")
		_, err := eng.StartClone(ctx, "index-only-clone-valid-source", "index-only-clone-target")
		assertResolutionCorruption(t, err)
		assertResolutionIndexUnchanged(t, eng, "index-only-clone-target", ws)
	})

	t.Run("import target reservation", func(t *testing.T) {
		eng, cleanup := testEnv(t)
		defer cleanup()
		ws := makeRenamedIndexOnlyResolutionVault(t, eng, "index-only-import-target-old", "index-only-import-target")
		_, err := eng.StartImport(context.Background(), "index-only-import-target", "", 0, false, bytes.NewReader(nil))
		assertResolutionCorruption(t, err)
		assertResolutionIndexUnchanged(t, eng, "index-only-import-target", ws)
	})
}

func TestVaultResolution_MetadataOnlyTargetIsCorruption(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	const vault = "metadata-only-target"
	if _, err := eng.Write(context.Background(), writeReq(vault, "metadata-only", "target mapping evidence")); err != nil {
		t.Fatal(err)
	}
	if err := eng.store.GetDB().Delete(keys.VaultNameIndexKey(vault), pebble.Sync); err != nil {
		t.Fatal(err)
	}
	assertResolutionCorruption(t, eng.ensureVaultNameAvailable(vault, nil))
}

func TestVaultResolution_FreedNameCannotReuseRenamedWorkspace(t *testing.T) {
	t.Run("clone target", func(t *testing.T) {
		eng, cleanup := testEnv(t)
		defer cleanup()
		ctx := context.Background()
		if _, err := eng.Write(ctx, writeReq("freed-name-clone-source", "source", "valid clone source")); err != nil {
			t.Fatal(err)
		}
		ws, _ := writeAndRenameResolutionVault(t, eng, ctx, "freed-name-clone-old", "freed-name-clone-current", "preserved")
		_, err := eng.StartClone(ctx, "freed-name-clone-source", "freed-name-clone-old")
		assertResolutionCorruption(t, err)
		assertFreedResolutionNameBlocked(t, eng, "freed-name-clone-old", "freed-name-clone-current", ws)
	})

	t.Run("import target", func(t *testing.T) {
		eng, cleanup := testEnv(t)
		defer cleanup()
		ctx := context.Background()
		ws, _ := writeAndRenameResolutionVault(t, eng, ctx, "freed-name-import-old", "freed-name-import-current", "preserved")
		_, err := eng.StartImport(ctx, "freed-name-import-old", "", 0, false, bytes.NewReader(nil))
		assertResolutionCorruption(t, err)
		assertFreedResolutionNameBlocked(t, eng, "freed-name-import-old", "freed-name-import-current", ws)
	})

	t.Run("unrelated rename target", func(t *testing.T) {
		eng, cleanup := testEnv(t)
		defer cleanup()
		ctx := context.Background()
		ws, _ := writeAndRenameResolutionVault(t, eng, ctx, "freed-name-rename-old", "freed-name-rename-current", "preserved")
		if _, err := eng.Write(ctx, writeReq("freed-name-rename-other", "source", "unrelated source")); err != nil {
			t.Fatal(err)
		}
		err := eng.RenameVault(ctx, "freed-name-rename-other", "freed-name-rename-old")
		assertResolutionCorruption(t, err)
		assertFreedResolutionNameBlocked(t, eng, "freed-name-rename-old", "freed-name-rename-current", ws)
	})

	t.Run("same vault may rename back", func(t *testing.T) {
		eng, cleanup := testEnv(t)
		defer cleanup()
		ctx := context.Background()
		ws, _ := writeAndRenameResolutionVault(t, eng, ctx, "freed-name-back-old", "freed-name-back-current", "preserved")
		if err := eng.RenameVault(ctx, "freed-name-back-current", "freed-name-back-old"); err != nil {
			t.Fatalf("rename back to source-owned derived workspace: %v", err)
		}
		resolved, err := eng.store.ResolveExistingVaultPrefix("freed-name-back-old")
		if err != nil {
			t.Fatalf("resolve renamed-back vault: %v", err)
		}
		if resolved != ws {
			t.Fatalf("renamed-back workspace = %x, want %x", resolved, ws)
		}
	})
}

func writeAndRenameResolutionVault(t *testing.T, eng *Engine, ctx context.Context, oldName, newName, concept string) ([8]byte, storage.ULID) {
	t.Helper()
	resp, err := eng.Write(ctx, writeReq(oldName, concept, "strict resolution characterization"))
	if err != nil {
		t.Fatalf("write %q: %v", oldName, err)
	}
	ws := eng.store.ResolveVaultPrefix(oldName)
	if ws == eng.store.VaultPrefix(newName) {
		t.Fatalf("test names unexpectedly derived the same workspace: %q and %q", oldName, newName)
	}
	id, err := storage.ParseULID(resp.ID)
	if err != nil {
		t.Fatalf("parse %q engram ID: %v", oldName, err)
	}
	if err := eng.RenameVault(ctx, oldName, newName); err != nil {
		t.Fatalf("rename %q to %q: %v", oldName, newName, err)
	}
	return ws, id
}

func countResolutionEngrams(t *testing.T, store *storage.PebbleStore, ctx context.Context, ws [8]byte) int64 {
	t.Helper()
	var count int64
	if err := store.ScanEngrams(ctx, ws, func(*storage.Engram) error {
		count++
		return nil
	}); err != nil {
		t.Fatalf("scan workspace %x: %v", ws, err)
	}
	return count
}

func assertResolutionJobDone(t *testing.T, eng *Engine, job *vaultjob.Job) {
	t.Helper()
	if job == nil {
		t.Fatal("expected non-nil vault job")
	}
	finalJob := waitForJob(t, eng, job.ID, 5*time.Second)
	if finalJob.GetStatus() != vaultjob.StatusDone {
		t.Fatalf("job %s status = %s, want %s; err: %s", job.ID, finalJob.GetStatus(), vaultjob.StatusDone, finalJob.GetErr())
	}
}

func makeIndexOnlyResolutionVault(t *testing.T, eng *Engine, vault string) [8]byte {
	t.Helper()
	if _, err := eng.Write(context.Background(), writeReq(vault, "index-only", "persisted mapping corruption")); err != nil {
		t.Fatalf("write %q: %v", vault, err)
	}
	ws := eng.store.ResolveVaultPrefix(vault)
	if err := eng.store.GetDB().Delete(keys.VaultMetaKey(ws), pebble.Sync); err != nil {
		t.Fatalf("delete %q metadata: %v", vault, err)
	}
	return ws
}

func makeRenamedIndexOnlyResolutionVault(t *testing.T, eng *Engine, oldName, newName string) [8]byte {
	t.Helper()
	if _, err := eng.Write(context.Background(), writeReq(oldName, "index-only", "preserved renamed workspace")); err != nil {
		t.Fatalf("write %q: %v", oldName, err)
	}
	ws := eng.store.ResolveVaultPrefix(oldName)
	if err := eng.RenameVault(context.Background(), oldName, newName); err != nil {
		t.Fatalf("rename %q to %q: %v", oldName, newName, err)
	}
	if derived := eng.store.VaultPrefix(newName); derived == ws {
		t.Fatalf("test names unexpectedly share workspace %x", ws)
	}
	if err := eng.store.GetDB().Delete(keys.VaultMetaKey(ws), pebble.Sync); err != nil {
		t.Fatalf("delete renamed %q metadata: %v", newName, err)
	}
	return ws
}

func assertResolutionCorruption(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("operation succeeded with an index-only persisted mapping")
	}
	if errors.Is(err, ErrVaultNotFound) {
		t.Fatalf("index-only persisted mapping was misclassified as absent: %v", err)
	}
	if errors.Is(err, ErrVaultNameCollision) {
		t.Fatalf("index-only persisted mapping was misclassified as an ordinary collision: %v", err)
	}
}

func assertResolutionIndexUnchanged(t *testing.T, eng *Engine, vault string, want [8]byte) {
	t.Helper()
	value, closer, err := eng.store.GetDB().Get(keys.VaultNameIndexKey(vault))
	if err != nil {
		t.Fatalf("read %q name index: %v", vault, err)
	}
	defer closer.Close()
	if !bytes.Equal(value, want[:]) {
		t.Fatalf("%q name index changed to %x, want preserved workspace %x", vault, value, want)
	}
	derived := eng.store.VaultPrefix(vault)
	if _, metaCloser, err := eng.store.GetDB().Get(keys.VaultMetaKey(derived)); err == nil {
		metaCloser.Close()
		t.Fatalf("failed reservation created metadata at derived workspace %x", derived)
	} else if !errors.Is(err, pebble.ErrNotFound) {
		t.Fatalf("read derived workspace metadata: %v", err)
	}
}

func assertFreedResolutionNameBlocked(t *testing.T, eng *Engine, freedName, currentName string, want [8]byte) {
	t.Helper()
	if eng.store.VaultNameExists(freedName) {
		t.Fatalf("failed reservation recreated freed name %q", freedName)
	}
	resolved, err := eng.store.ResolveExistingVaultPrefix(currentName)
	if err != nil {
		t.Fatalf("resolve preserved renamed vault %q: %v", currentName, err)
	}
	if resolved != want {
		t.Fatalf("preserved renamed vault %q workspace = %x, want %x", currentName, resolved, want)
	}
	if got := countResolutionEngrams(t, eng.store, context.Background(), want); got != 1 {
		t.Fatalf("preserved renamed vault %q count = %d, want 1", currentName, got)
	}
}

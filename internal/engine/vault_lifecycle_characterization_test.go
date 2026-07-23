package engine

import (
	"context"
	"testing"

	"github.com/scrypster/muninndb/internal/storage"
)

func TestVaultLifecycleCharacterization_RenameThenClearUsesPreservedWorkspace(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()

	ctx := context.Background()
	const oldName = "lifecycle-clear-before-rename"
	const newName = "lifecycle-clear-after-rename"

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

func TestVaultLifecycleCharacterization_RenameThenDeleteRemovesPreservedWorkspaceAndName(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()

	ctx := context.Background()
	const oldName = "lifecycle-delete-before-rename"
	const newName = "lifecycle-delete-after-rename"

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

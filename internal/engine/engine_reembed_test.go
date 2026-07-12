package engine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/scrypster/muninndb/internal/engine/vaultjob"
	"github.com/scrypster/muninndb/internal/storage"
	"github.com/scrypster/muninndb/internal/transport/mbp"
)

// TestStartReembedVault_VaultNotFound verifies that StartReembedVault with a
// vault that does not exist returns an error wrapping ErrVaultNotFound.
func TestStartReembedVault_VaultNotFound(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()

	_, err := eng.StartReembedVault(ctx, "does-not-exist", "test-model")
	if err == nil {
		t.Fatal("expected error for nonexistent vault, got nil")
	}
	if !errors.Is(err, ErrVaultNotFound) {
		t.Errorf("expected error to wrap ErrVaultNotFound, got: %v", err)
	}
}

// TestStartReembedVault_Success writes engrams, sets embed flags, then runs
// the reembed pipeline and verifies the flags are cleared and the job completes.
func TestStartReembedVault_Success(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()

	const vaultName = "reembed-success"
	const DigestEmbed uint8 = 0x02

	// Write a few engrams.
	idStrings := make([]string, 3)
	for i := range idStrings {
		resp, err := eng.Write(ctx, &mbp.WriteRequest{
			Vault:   vaultName,
			Concept: "concept",
			Content: "content for reembed test",
		})
		if err != nil {
			t.Fatalf("Write[%d]: %v", i, err)
		}
		idStrings[i] = resp.ID
	}

	// Parse string IDs to storage.ULID for flag operations.
	storeIDs := make([]storage.ULID, len(idStrings))
	for i, s := range idStrings {
		parsed, err := storage.ParseULID(s)
		if err != nil {
			t.Fatalf("ParseULID[%d]: %v", i, err)
		}
		storeIDs[i] = parsed
	}

	// Set embed flags on each engram.
	for i, id := range storeIDs {
		if err := eng.store.SetDigestFlag(ctx, id, DigestEmbed); err != nil {
			t.Fatalf("SetDigestFlag[%d]: %v", i, err)
		}
	}

	// Call StartReembedVault.
	job, err := eng.StartReembedVault(ctx, vaultName, "test-model")
	if err != nil {
		t.Fatalf("StartReembedVault: %v", err)
	}
	if job == nil {
		t.Fatal("StartReembedVault returned nil job")
	}
	if job.ID == "" {
		t.Error("expected non-empty job ID")
	}

	// Wait for job to complete.
	finalJob := waitForJob(t, eng, job.ID, 5*time.Second)
	if finalJob.GetStatus() != vaultjob.StatusDone {
		t.Fatalf("reembed job status = %s, want %s; err: %s",
			finalJob.GetStatus(), vaultjob.StatusDone, finalJob.GetErr())
	}

	// Verify: embed flags are cleared.
	for i, id := range storeIDs {
		flags, err := eng.store.GetDigestFlags(ctx, id)
		if err != nil {
			t.Fatalf("GetDigestFlags[%d] after reembed: %v", i, err)
		}
		if flags&DigestEmbed != 0 {
			t.Errorf("engram %d still has DigestEmbed set after reembed", i)
		}
	}
}

// TestStartReembedVault_BlocksRenameAndDelete keeps a real reembed job in its
// final callback so lifecycle guards can be checked deterministically while the
// job is still running.
func TestStartReembedVault_BlocksRenameAndDelete(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()

	const vaultName = "reembed-lifecycle-guard"
	if _, err := eng.Write(ctx, writeReq(vaultName, "concept", "content")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	callbackEntered := make(chan struct{})
	releaseCallback := make(chan struct{})
	eng.SetOnWrite(func() {
		close(callbackEntered)
		<-releaseCallback
	})

	job, err := eng.StartReembedVault(ctx, vaultName, "test-model")
	if err != nil {
		close(releaseCallback)
		t.Fatalf("StartReembedVault: %v", err)
	}

	select {
	case <-callbackEntered:
	case <-time.After(5 * time.Second):
		close(releaseCallback)
		t.Fatal("reembed job did not reach blocking callback")
	}

	if err := eng.RenameVault(ctx, vaultName, vaultName+"-renamed"); !errors.Is(err, ErrVaultJobActive) {
		close(releaseCallback)
		t.Fatalf("RenameVault during reembed error = %v, want ErrVaultJobActive", err)
	}
	if err := eng.DeleteVault(ctx, vaultName); !errors.Is(err, ErrVaultJobActive) {
		close(releaseCallback)
		t.Fatalf("DeleteVault during reembed error = %v, want ErrVaultJobActive", err)
	}

	close(releaseCallback)
	finalJob := waitForJob(t, eng, job.ID, 5*time.Second)
	if finalJob.GetStatus() != vaultjob.StatusDone {
		t.Fatalf("reembed job status = %s, want %s; err: %s",
			finalJob.GetStatus(), vaultjob.StatusDone, finalJob.GetErr())
	}
}

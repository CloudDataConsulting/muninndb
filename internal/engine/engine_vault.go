package engine

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"

	"github.com/cockroachdb/pebble"
)

// ErrVaultNotFound is returned when an operation references a vault that does not exist.
// Use errors.Is to check for this error in callers.
var ErrVaultNotFound = errors.New("vault not found")

// ErrEngramNotFound is returned when an operation references an engram that does not exist.
// Use errors.Is to check for this error in callers.
var ErrEngramNotFound = errors.New("engram not found")

// ErrEngramSoftDeleted is returned when an operation targets an engram that has
// been soft-deleted. Use errors.Is to check for this error in callers.
var ErrEngramSoftDeleted = errors.New("engram is soft-deleted")

// ErrVaultNameCollision is returned when a rename or clone targets a vault name
// that already exists. Use errors.Is to check for this error in callers.
var ErrVaultNameCollision = errors.New("vault name already exists")

// resolveExistingVaultPrefix preserves the public distinction between a vault
// that is genuinely absent and a persisted lifecycle mapping that is damaged.
// ResolveExistingVaultPrefix deliberately returns the underlying storage error
// for both cases; engine callers need ErrVaultNotFound only when neither side
// of the 0x0E/0x0F mapping survives. Any one-sided or malformed mapping remains
// a storage failure so destructive callers fail closed instead of treating
// corruption as an ordinary 404.
func (e *Engine) resolveExistingVaultPrefix(vaultName string) ([8]byte, error) {
	ws, err := e.store.ResolveExistingVaultPrefix(vaultName)
	if err == nil {
		return ws, nil
	}
	if !errors.Is(err, pebble.ErrNotFound) {
		return [8]byte{}, err
	}

	indexExists, indexErr := e.store.VaultNameIndexExists(vaultName)
	if indexErr != nil {
		return [8]byte{}, fmt.Errorf("resolve existing vault %q: %w (inspect name index evidence: %v)", vaultName, err, indexErr)
	}
	if indexExists {
		return [8]byte{}, err
	}
	names, listErr := e.store.ListVaultNames()
	if listErr != nil {
		return [8]byte{}, fmt.Errorf("resolve existing vault %q: %w (list vault names: %v)", vaultName, err, listErr)
	}
	for _, name := range names {
		if name == vaultName {
			return [8]byte{}, err
		}
	}
	return [8]byte{}, fmt.Errorf("vault %q: %w", vaultName, ErrVaultNotFound)
}

// ensureVaultNameAvailable fails unless neither side of the persisted mapping
// contains evidence for vaultName and the name-derived workspace is unowned. A
// valid mapping is an ordinary collision; one-sided/malformed mappings and a
// workspace retained by a renamed vault are corruption and must not be reused.
// Rename may pass its resolved source workspace so renaming a vault back to its
// original derived name remains safe.
func (e *Engine) ensureVaultNameAvailable(vaultName string, allowedWorkspace *[8]byte) error {
	_, err := e.resolveExistingVaultPrefix(vaultName)
	if err == nil {
		return fmt.Errorf("vault %q: %w", vaultName, ErrVaultNameCollision)
	}
	if !errors.Is(err, ErrVaultNotFound) {
		return fmt.Errorf("vault %q has an invalid persisted lifecycle mapping: %w", vaultName, err)
	}

	derived := e.store.VaultPrefix(vaultName)
	owner, occupied, err := e.store.VaultWorkspaceOwner(derived)
	if err != nil {
		return fmt.Errorf("vault %q: inspect derived workspace: %w", vaultName, err)
	}
	if !occupied {
		return nil
	}
	if allowedWorkspace != nil && derived == *allowedWorkspace {
		return nil
	}
	return fmt.Errorf("vault %q: derived workspace %x is already owned by vault %q", vaultName, derived, owner)
}

// ClearVault removes all memories from a vault. The vault name remains registered.
// It evicts all in-memory state (HNSW, FTS IDF cache, novelty fingerprints, coherence
// counters, activity tracking) and adjusts the global engramCount.
func (e *Engine) ClearVault(ctx context.Context, vaultName string) error {
	mu := e.getVaultMutex(vaultName)
	mu.Lock()
	defer mu.Unlock()

	ws, err := e.resolveExistingVaultPrefix(vaultName)
	if err != nil {
		return fmt.Errorf("clear vault: resolve persisted workspace: %w", err)
	}

	// NOTE: Jobs already mid-flush may write ghost FTS entries after the range
	// tombstones land. This is harmless — activation filtering skips engrams
	// with no metadata, and ghost posting list entries are reclaimed by Pebble
	// compaction. A drain barrier was considered but rejected as disproportionate
	// complexity for a microsecond race with no correctness impact.

	// Prevent FTS worker from re-creating keys during the range delete.
	if e.ftsWorker != nil {
		e.ftsWorker.SetClearing(ws, true)
		defer e.ftsWorker.SetClearing(ws, false)
	}

	vaultCount, err := e.store.ClearVault(ctx, ws)
	if err != nil {
		return fmt.Errorf("clear vault %q: %w", vaultName, err)
	}

	e.engramCount.Add(-vaultCount)

	// Floor at zero — guards against counter skew in crash recovery scenarios.
	for {
		cur := e.engramCount.Load()
		if cur >= 0 {
			break
		}
		if e.engramCount.CompareAndSwap(cur, 0) {
			break
		}
	}

	if e.hnswRegistry != nil {
		e.hnswRegistry.ResetVault(ws)
	}
	if e.fts != nil {
		e.fts.InvalidateIDFCache()
	}
	if e.noveltyDet != nil {
		e.noveltyDet.PurgeVault(binary.BigEndian.Uint32(ws[:4]))
	}
	if e.coherence != nil {
		e.coherence.DeleteVault(vaultName)
	}
	if e.activity != nil {
		e.activity.Evict(ws)
	}
	return nil
}

// ErrVaultJobActive is returned when an asynchronous vault job is currently
// running against a lifecycle name that must remain stable.
var ErrVaultJobActive = fmt.Errorf("vault has an active job in progress")

// DeleteVault removes all memories and the vault name registration.
// Returns ErrVaultJobActive if any asynchronous job is currently writing to this vault.
// It calls ClearVault (which adjusts engramCount and in-memory state),
// then deletes the vault name keys from storage.
//
// Note: ws must be resolved BEFORE calling ClearVault because renamed vaults
// retain their original workspace.
func (e *Engine) DeleteVault(ctx context.Context, vaultName string) error {
	// Serialize the full delete lifecycle with rename and name-reserving
	// clone/merge/import setup. Without this lock, rename can move 0x0E/0x0F
	// after clear but before name cleanup, leaving a dangling name index.
	e.vaultOpsMu.Lock()
	defer e.vaultOpsMu.Unlock()

	// Reject deletion if a clone/merge job is actively writing into this vault
	// (i.e., the vault is the Target of a running job). Deleting a vault that is
	// a Source is allowed — the merge's own post-copy cleanup calls DeleteVault
	// on the source and must not be blocked.
	if e.jobManager != nil && e.jobManager.HasActiveJobTargeting(vaultName) {
		return fmt.Errorf("delete vault %q: %w", vaultName, ErrVaultJobActive)
	}

	// Capture ws BEFORE ClearVault evicts the in-memory name cache.
	ws, err := e.resolveExistingVaultPrefix(vaultName)
	if err != nil {
		return fmt.Errorf("delete vault: resolve persisted workspace: %w", err)
	}

	if err := e.ClearVault(ctx, vaultName); err != nil {
		return fmt.Errorf("delete vault (clear phase): %w", err)
	}

	if err := e.store.DeleteVaultNameOnly(ctx, vaultName, ws); err != nil {
		// Data is already gone (ClearVault succeeded). Only the name registration
		// remains. Retry of DeleteVault is idempotent — it will re-clear (0 engrams)
		// then attempt DeleteVaultNameOnly again.
		slog.Warn("vault data cleared but name registration not removed",
			"vault", vaultName, "err", err)
		return fmt.Errorf("delete vault (name cleanup): %w", err)
	}

	// NOTE: vaultMu.Delete runs outside the per-vault lock. Any concurrent
	// caller that reaches getVaultMutex after DeleteVaultNameOnly returns will
	// find the vault name gone from storage and abort via ErrVaultNotFound
	// before it ever uses the mutex. The re-insertion/deletion race window is
	// therefore harmless in practice.
	e.vaultMu.Delete(vaultName)

	// Auth config: remove config entry if present.
	if e.authStore != nil {
		if err := e.authStore.DeleteVaultConfig(vaultName); err != nil {
			slog.Warn("delete vault: auth config cleanup failed", "vault", vaultName, "err", err)
		}
	}

	return nil
}

// RenameVault atomically renames a vault. This is a metadata-only operation —
// no engram data is moved or modified. Returns ErrVaultNotFound if oldName
// doesn't exist, ErrVaultJobActive if an asynchronous job involves the vault,
// or an error if newName already exists.
func (e *Engine) RenameVault(ctx context.Context, oldName, newName string) error {
	e.vaultOpsMu.Lock()
	defer e.vaultOpsMu.Unlock()

	ws, err := e.resolveExistingVaultPrefix(oldName)
	if err != nil {
		return fmt.Errorf("rename vault: resolve source workspace: %w", err)
	}
	if err := e.ensureVaultNameAvailable(newName, &ws); err != nil {
		return fmt.Errorf("rename vault: target name unavailable: %w", err)
	}

	// Jobs retain source and target names captured at creation. Renaming either
	// side mid-job can make post-merge cleanup target the wrong lifecycle.
	if e.jobManager != nil && e.jobManager.HasActiveJobInvolving(oldName) {
		return fmt.Errorf("rename vault %q: %w", oldName, ErrVaultJobActive)
	}

	// Storage: atomic batch rename.
	if err := e.store.RenameVault(ws, oldName, newName); err != nil {
		return fmt.Errorf("rename vault storage: %w", err)
	}

	// Auth config: move config entry if present.
	if e.authStore != nil {
		if err := e.authStore.RenameVaultConfig(oldName, newName); err != nil {
			slog.Warn("rename vault: auth config rename failed", "err", err)
		}
	}

	// Coherence: move counters.
	if e.coherence != nil {
		e.coherence.RenameVault(oldName, newName)
	}

	// Per-vault mutex: move entry from old to new name.
	if mu, ok := e.vaultMu.LoadAndDelete(oldName); ok {
		e.vaultMu.Store(newName, mu)
	}

	return nil
}

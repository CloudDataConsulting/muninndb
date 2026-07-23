package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/cockroachdb/pebble"
	"github.com/scrypster/muninndb/internal/storage/keys"
)

// ClearVault deletes all data keys for a vault using Pebble range tombstones.
// The vault name registration (0x0E, 0x0F) is preserved — use DeleteVaultNameOnly
// to remove those after clearing.
// Returns the vault engram count captured before deletion.
//
// Every persistent delete is staged in one Pebble batch from the immutable
// keyspace registry. Shared auth/storage prefixes are never range-deleted:
// 0x12 and 0x13 use exact point deletes, while 0x14 uses a value-aware scan.
// The cross-vault 0x23 namespace is exact-length validated and point-deleted.
func (ps *PebbleStore) ClearVault(ctx context.Context, ws [8]byte) (int64, error) {
	// Capture count before anything is deleted.
	vaultCount := ps.GetVaultCount(ctx, ws)

	wsPlus, err := incrementWS(ws)
	if err != nil {
		return 0, fmt.Errorf("clear vault: %w", err)
	}

	batch := ps.db.NewBatch()
	defer batch.Close()
	for _, step := range vaultClearPlan() {
		switch step.action {
		case clearRangeDelete:
			if step.workspaceOffset != 1 {
				return 0, fmt.Errorf("clear vault: invalid range plan for prefix 0x%02X", step.prefix)
			}
			lo, hi := vaultFirstBounds(step.prefix, ws, wsPlus)
			if err := batch.DeleteRange(lo, hi, nil); err != nil {
				return 0, fmt.Errorf("clear vault: delete range 0x%02X: %w", step.prefix, err)
			}
		case clearExactPointDelete:
			if step.workspaceOffset != 1 || step.keyLength != 9 {
				return 0, fmt.Errorf("clear vault: invalid exact-point plan for prefix 0x%02X", step.prefix)
			}
			key := make([]byte, 9)
			key[0] = step.prefix
			copy(key[1:], ws[:])
			if err := batch.Delete(key, nil); err != nil {
				return 0, fmt.Errorf("clear vault: delete key 0x%02X: %w", step.prefix, err)
			}
		case clearValueAwarePointDelete:
			if err := ps.stageValueAwareVaultDeletes(batch, step, ws, wsPlus); err != nil {
				return 0, err
			}
		case clearFilteredPointDelete:
			if err := ps.stageCrossVaultDeletes(batch, step, ws); err != nil {
				return 0, err
			}
		default:
			return 0, fmt.Errorf("clear vault: unsupported clear action %d for prefix 0x%02X", step.action, step.prefix)
		}
	}

	// Drain any in-flight provenance writes (0x16 keys) so they land
	// BEFORE the range tombstones, not after. If they landed after the tombstones
	// they would be visible to iterators despite the vault being cleared.
	if ps.provWork != nil {
		ps.provWork.Drain()
	}

	// Prevent a pending coalesced count from being written after the clear batch.
	// A durable lifecycle write fence remains part of the follow-on catalog work.
	if ps.counterFlush != nil {
		ps.counterFlush.Delete(ws)
	}
	ps.vaultCounters.Delete(ws)

	if err := batch.Commit(pebble.Sync); err != nil {
		return 0, fmt.Errorf("clear vault: commit: %w", err)
	}

	// L1 engram cache — vault-scoped by hex prefix.
	ps.cache.DeleteByVault(ws)

	// assocCache: keys are [24]byte = ws[8] + engramID[16].
	// Purge all entries whose first 8 bytes match the cleared vault prefix.
	for _, k := range ps.assocCache.Keys() {
		if [8]byte(k[:8]) == ws {
			ps.assocCache.Remove(k)
		}
	}

	// metaCache: keys are [16]byte (engramID only — not vault-scoped).
	// We cannot filter by vault, so clear all entries. The cache is a
	// read-through; evicting unrelated vaults only costs one extra Pebble read
	// per metadata access, which is acceptable.
	ps.metaCache.Purge()

	// recentActiveCache: keys are [8]byte (wsPrefix).
	ps.recentActiveCache.Delete(ws)

	return vaultCount, nil
}

func vaultFirstBounds(prefix byte, ws, wsPlus [8]byte) ([]byte, []byte) {
	lo := make([]byte, 9)
	lo[0] = prefix
	copy(lo[1:], ws[:])
	hi := make([]byte, 9)
	hi[0] = prefix
	copy(hi[1:], wsPlus[:])
	return lo, hi
}

// stageValueAwareVaultDeletes handles current shared prefix 0x14. A storage
// association-weight record is exactly 41 key bytes with a four-byte float32
// value. Auth vault configs share 0x14 and have variable key/value lengths, so
// they are preserved. Namespace separation remains tracked by migration #138.
func (ps *PebbleStore) stageValueAwareVaultDeletes(batch *pebble.Batch, step vaultClearStep, ws, wsPlus [8]byte) error {
	if step.workspaceOffset != 1 || step.keyLength <= 9 || step.valueLength <= 0 {
		return fmt.Errorf("clear vault: invalid value-aware plan for prefix 0x%02X", step.prefix)
	}
	lo, hi := vaultFirstBounds(step.prefix, ws, wsPlus)
	iter, err := ps.db.NewIter(&pebble.IterOptions{LowerBound: lo, UpperBound: hi})
	if err != nil {
		return fmt.Errorf("clear vault: scan shared prefix 0x%02X: %w", step.prefix, err)
	}
	defer iter.Close()
	for valid := iter.First(); valid; valid = iter.Next() {
		if len(iter.Key()) != step.keyLength || len(iter.Value()) != step.valueLength {
			continue
		}
		key := append([]byte(nil), iter.Key()...)
		if err := batch.Delete(key, nil); err != nil {
			return fmt.Errorf("clear vault: delete shared-prefix key 0x%02X: %w", step.prefix, err)
		}
	}
	if err := iter.Error(); err != nil {
		return fmt.Errorf("clear vault: scan shared prefix 0x%02X: %w", step.prefix, err)
	}
	return nil
}

// stageCrossVaultDeletes scans the current 0x23 layout because its workspace
// lives at bytes 9:17 rather than immediately after the prefix. The namespace
// has one current exact layout, so malformed keys abort the entire clear before
// any staged deletion is committed.
func (ps *PebbleStore) stageCrossVaultDeletes(batch *pebble.Batch, step vaultClearStep, ws [8]byte) error {
	if step.workspaceOffset < 1 || step.keyLength < step.workspaceOffset+len(ws) {
		return fmt.Errorf("clear vault: invalid cross-vault plan for prefix 0x%02X", step.prefix)
	}
	iter, err := ps.db.NewIter(&pebble.IterOptions{
		LowerBound: []byte{step.prefix},
		UpperBound: []byte{step.prefix + 1},
	})
	if err != nil {
		return fmt.Errorf("clear vault: scan cross-vault prefix 0x%02X: %w", step.prefix, err)
	}
	defer iter.Close()
	for valid := iter.First(); valid; valid = iter.Next() {
		key := iter.Key()
		if len(key) != step.keyLength {
			return fmt.Errorf("clear vault: malformed cross-vault key 0x%02X: length %d, want %d", step.prefix, len(key), step.keyLength)
		}
		if !bytes.Equal(key[step.workspaceOffset:step.workspaceOffset+len(ws)], ws[:]) {
			continue
		}
		keyCopy := append([]byte(nil), key...)
		if err := batch.Delete(keyCopy, nil); err != nil {
			return fmt.Errorf("clear vault: delete cross-vault key 0x%02X: %w", step.prefix, err)
		}
	}
	if err := iter.Error(); err != nil {
		return fmt.Errorf("clear vault: scan cross-vault prefix 0x%02X: %w", step.prefix, err)
	}
	return nil
}

// DeleteVaultNameOnly removes the vault name registration keys (0x0E and 0x0F)
// and evicts the in-memory vault name caches.
// Must be called AFTER ClearVault so that the data keys are already gone.
func (ps *PebbleStore) DeleteVaultNameOnly(ctx context.Context, name string, ws [8]byte) error {
	// Point-delete 0x0E vault meta key (prefix → name mapping).
	if err := ps.db.Delete(keys.VaultMetaKey(ws), pebble.Sync); err != nil && !errors.Is(err, pebble.ErrNotFound) {
		return fmt.Errorf("delete vault name: remove meta key: %w", err)
	}
	// Point-delete 0x0F name index key (name → prefix mapping).
	if err := ps.db.Delete(keys.VaultNameIndexKey(name), pebble.Sync); err != nil && !errors.Is(err, pebble.ErrNotFound) {
		return fmt.Errorf("delete vault name: remove name index key: %w", err)
	}
	// Evict in-memory name caches.
	ps.vaultPrefixCache.Remove(name)
	ps.vaultNameWritten.Delete(ws)
	return nil
}

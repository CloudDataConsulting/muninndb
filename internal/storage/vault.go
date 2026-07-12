package storage

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/cockroachdb/pebble"
	"github.com/scrypster/muninndb/internal/storage/keys"
)

// ErrVaultCatalogCorrupt marks a one-sided, malformed, or contradictory
// 0x0E/0x0F vault catalog mapping. Callers must not treat it as ordinary
// absence or attempt an implicit repair.
var ErrVaultCatalogCorrupt = errors.New("vault catalog mapping is corrupt")

// WriteVaultName persists the vault name under two keys:
//
//	0x0E | wsPrefix → name   (prefix → name, for listing)
//	0x0F | siphash(name) → wsPrefix  (name → prefix, for resolution)
//
// It is idempotent only for the same exact pair. Any one-sided or conflicting
// mapping fails closed. New engine creators should use ResolveOrCreateVaultPrefix
// before writing canonical data instead of registering after commit.
func (ps *PebbleStore) WriteVaultName(wsPrefix [8]byte, name string) error {
	if name == "" {
		return fmt.Errorf("write vault name: name must not be empty")
	}
	ps.vaultCatalogMu.Lock()
	defer ps.vaultCatalogMu.Unlock()

	resolved, err := ps.resolveExistingVaultPrefixLocked(name)
	if err == nil {
		if resolved != wsPrefix {
			return fmt.Errorf("write vault name %q: existing workspace %x differs from requested %x", name, resolved, wsPrefix)
		}
		ps.vaultPrefixCache.Add(name, resolved)
		return nil
	}
	if !errors.Is(err, pebble.ErrNotFound) {
		return fmt.Errorf("write vault name %q: %w", name, err)
	}
	if derived := keys.VaultPrefix(name); wsPrefix != derived {
		return fmt.Errorf("write vault name %q: requested workspace %x differs from name-derived workspace %x", name, wsPrefix, derived)
	}
	if err := ps.ensureVaultWorkspaceUnclaimedLocked(wsPrefix); err != nil {
		return fmt.Errorf("write vault name %q: %w", name, err)
	}
	return ps.writeVaultPairLocked(wsPrefix, name)
}

// ReserveVaultName creates a new 0x0E/0x0F mapping. Lifecycle operations call
// this only after their engine-level availability checks. The store-owned
// catalog mutex makes the
// read/check/atomic pair commit serial within this PebbleStore. This is a
// process-local catalog transaction, not a distributed compare-and-set.
func (ps *PebbleStore) ReserveVaultName(wsPrefix [8]byte, name string) error {
	if name == "" {
		return fmt.Errorf("reserve vault name: name must not be empty")
	}
	if derived := keys.VaultPrefix(name); wsPrefix != derived {
		return fmt.Errorf("reserve vault name %q: requested workspace %x differs from name-derived workspace %x", name, wsPrefix, derived)
	}
	ps.vaultCatalogMu.Lock()
	defer ps.vaultCatalogMu.Unlock()

	if _, err := ps.resolveExistingVaultPrefixLocked(name); err == nil {
		return fmt.Errorf("reserve vault name %q: name index already exists", name)
	} else if !errors.Is(err, pebble.ErrNotFound) {
		return fmt.Errorf("reserve vault name %q: %w", name, err)
	}
	if err := ps.ensureVaultWorkspaceUnclaimedLocked(wsPrefix); err != nil {
		return fmt.Errorf("reserve vault name %q: %w", name, err)
	}
	return ps.writeVaultPairLocked(wsPrefix, name)
}

// ResolveOrCreateVaultPrefix strictly validates an existing catalog pair or
// reserves the name-derived workspace before a runtime creator writes data.
// Both mapping keys are committed together under the process-local catalog
// mutex. A failed later data write may leave an empty registered vault; it can
// never leave new canonical data without a valid catalog pair.
func (ps *PebbleStore) ResolveOrCreateVaultPrefix(name string) ([8]byte, error) {
	if name == "" {
		return [8]byte{}, fmt.Errorf("create vault: name must not be empty")
	}

	// Established vaults take only the shared read lock, so normal writes to
	// different vaults are not globally serialized. Absence upgrades by
	// releasing the read lock, taking the write lock, and rechecking.
	ps.vaultCatalogMu.RLock()
	if verified, ok := ps.vaultVerifiedCache.Get(name); ok {
		ps.vaultPrefixCache.Add(name, verified)
		ps.vaultCatalogMu.RUnlock()
		return verified, nil
	}
	ws, err := ps.resolveExistingVaultPrefixLocked(name)
	if err == nil {
		ps.vaultPrefixCache.Add(name, ws)
		ps.vaultVerifiedCache.Add(name, ws)
	}
	ps.vaultCatalogMu.RUnlock()
	if err == nil {
		return ws, nil
	}
	if !errors.Is(err, pebble.ErrNotFound) {
		return [8]byte{}, err
	}

	ps.vaultCatalogMu.Lock()
	defer ps.vaultCatalogMu.Unlock()

	ws, err = ps.resolveExistingVaultPrefixLocked(name)
	if err == nil {
		ps.vaultPrefixCache.Add(name, ws)
		ps.vaultVerifiedCache.Add(name, ws)
		return ws, nil
	}
	if !errors.Is(err, pebble.ErrNotFound) {
		return [8]byte{}, err
	}

	ws = keys.VaultPrefix(name)
	if err := ps.ensureVaultWorkspaceUnclaimedLocked(ws); err != nil {
		return [8]byte{}, fmt.Errorf("create vault %q: %w", name, err)
	}
	if err := ps.writeVaultPairLocked(ws, name); err != nil {
		return [8]byte{}, err
	}
	return ws, nil
}

// ResolveVaultPrefix looks up the actual workspace prefix for a vault name.
// Uses an in-memory cache to avoid Pebble reads on the common hot path.
func (ps *PebbleStore) ResolveVaultPrefix(name string) [8]byte {
	ps.vaultCatalogMu.RLock()
	defer ps.vaultCatalogMu.RUnlock()
	// Hot path: in-memory cache (populated by WriteVaultName and prior lookups).
	if ws, ok := ps.vaultPrefixCache.Get(name); ok {
		return ws
	}
	// Cold path: read from Pebble (once per vault name per process lifetime).
	idxKey := keys.VaultNameIndexKey(name)
	val, closer, err := ps.db.Get(idxKey)
	if err == nil {
		defer closer.Close()
		if len(val) == 8 {
			var ws [8]byte
			copy(ws[:], val)
			ps.vaultPrefixCache.Add(name, ws)
			return ws
		}
	}
	// A fallback is intentionally not cached: it is not confirmed catalog
	// evidence and must never make a later creator skip persisted validation.
	return keys.VaultPrefix(name)
}

// ResolveExistingVaultPrefix strictly resolves an already-registered vault.
// Unlike ResolveVaultPrefix, it never falls back to a name-derived SipHash and
// never trusts the in-memory cache without re-reading persisted lifecycle keys.
// Destructive and bulk existing-vault operations use this path so a missing,
// corrupt, or mismatched 0x0F/0x0E pair fails closed.
func (ps *PebbleStore) ResolveExistingVaultPrefix(name string) ([8]byte, error) {
	ps.vaultCatalogMu.RLock()
	defer ps.vaultCatalogMu.RUnlock()
	return ps.resolveExistingVaultPrefixLocked(name)
}

func (ps *PebbleStore) resolveExistingVaultPrefixLocked(name string) ([8]byte, error) {
	idxKey := keys.VaultNameIndexKey(name)
	value, closer, err := ps.db.Get(idxKey)
	if err != nil {
		if !errors.Is(err, pebble.ErrNotFound) {
			return [8]byte{}, fmt.Errorf("resolve existing vault %q: name index: %w", name, err)
		}
		contains, scanErr := ps.vaultMetadataContainsNameLocked(name)
		if scanErr != nil {
			return [8]byte{}, fmt.Errorf("resolve existing vault %q: scan metadata evidence: %w", name, scanErr)
		}
		if contains {
			return [8]byte{}, fmt.Errorf("resolve existing vault %q: %w: metadata exists without its name index", name, ErrVaultCatalogCorrupt)
		}
		return [8]byte{}, fmt.Errorf("resolve existing vault %q: name index: %w", name, pebble.ErrNotFound)
	}
	if len(value) != 8 {
		closer.Close()
		return [8]byte{}, fmt.Errorf("resolve existing vault %q: %w: name index length %d, want 8", name, ErrVaultCatalogCorrupt, len(value))
	}
	var ws [8]byte
	copy(ws[:], value)
	closer.Close()

	metaValue, metaCloser, err := ps.db.Get(keys.VaultMetaKey(ws))
	if err != nil {
		return [8]byte{}, fmt.Errorf("resolve existing vault %q: %w: metadata for workspace %x: %v", name, ErrVaultCatalogCorrupt, ws, err)
	}
	storedName := string(metaValue)
	metaCloser.Close()
	if storedName != name {
		return [8]byte{}, fmt.Errorf("resolve existing vault %q: %w: metadata names %q", name, ErrVaultCatalogCorrupt, storedName)
	}
	if err := ps.validateVaultPairUniquenessLocked(name, ws); err != nil {
		return [8]byte{}, fmt.Errorf("resolve existing vault %q: %w", name, err)
	}

	return ws, nil
}

// validateVaultPairUniquenessLocked proves that the exact pair is the only
// catalog evidence for both its logical name and physical workspace. Pebble
// prevents duplicate keys, but corrupt stores can still contain another 0x0E
// row with the same name or another 0x0F row whose value aliases the same
// workspace. Accepting either would make one vault reachable through multiple
// lifecycle names.
func (ps *PebbleStore) validateVaultPairUniquenessLocked(name string, ws [8]byte) error {
	metaMatches := 0
	metaIter, err := ps.db.NewIter(&pebble.IterOptions{
		LowerBound: []byte{0x0E},
		UpperBound: []byte{0x0F},
	})
	if err != nil {
		return fmt.Errorf("%w: scan vault metadata: %v", ErrVaultCatalogCorrupt, err)
	}
	for valid := metaIter.First(); valid; valid = metaIter.Next() {
		if len(metaIter.Key()) != 9 {
			metaIter.Close()
			return fmt.Errorf("%w: malformed vault metadata key length %d", ErrVaultCatalogCorrupt, len(metaIter.Key()))
		}
		if string(metaIter.Value()) != name {
			continue
		}
		metaMatches++
		var candidate [8]byte
		copy(candidate[:], metaIter.Key()[1:])
		if candidate != ws {
			metaIter.Close()
			return fmt.Errorf("%w: vault name %q is also owned by workspace %x", ErrVaultCatalogCorrupt, name, candidate)
		}
	}
	if err := metaIter.Error(); err != nil {
		metaIter.Close()
		return fmt.Errorf("%w: scan vault metadata: %v", ErrVaultCatalogCorrupt, err)
	}
	metaIter.Close()
	if metaMatches != 1 {
		return fmt.Errorf("%w: vault name %q has %d metadata owners, want 1", ErrVaultCatalogCorrupt, name, metaMatches)
	}

	expectedIndexKey := keys.VaultNameIndexKey(name)
	indexMatches := 0
	indexIter, err := ps.db.NewIter(&pebble.IterOptions{
		LowerBound: []byte{0x0F},
		UpperBound: []byte{0x10},
	})
	if err != nil {
		return fmt.Errorf("%w: scan vault name indexes: %v", ErrVaultCatalogCorrupt, err)
	}
	for valid := indexIter.First(); valid; valid = indexIter.Next() {
		if len(indexIter.Key()) != 9 {
			indexIter.Close()
			return fmt.Errorf("%w: malformed vault name index key length %d", ErrVaultCatalogCorrupt, len(indexIter.Key()))
		}
		if len(indexIter.Value()) != 8 {
			indexKey := append([]byte(nil), indexIter.Key()...)
			valueLen := len(indexIter.Value())
			indexIter.Close()
			return fmt.Errorf("%w: vault name index %x has value length %d, want 8", ErrVaultCatalogCorrupt, indexKey, valueLen)
		}
		var candidate [8]byte
		copy(candidate[:], indexIter.Value())
		if candidate != ws {
			continue
		}
		indexMatches++
		if !bytes.Equal(indexIter.Key(), expectedIndexKey) {
			aliasKey := append([]byte(nil), indexIter.Key()...)
			indexIter.Close()
			return fmt.Errorf("%w: workspace %x is also referenced by name-index key %x", ErrVaultCatalogCorrupt, ws, aliasKey)
		}
	}
	if err := indexIter.Error(); err != nil {
		indexIter.Close()
		return fmt.Errorf("%w: scan vault name indexes: %v", ErrVaultCatalogCorrupt, err)
	}
	indexIter.Close()
	if indexMatches != 1 {
		return fmt.Errorf("%w: workspace %x has %d name indexes, want 1", ErrVaultCatalogCorrupt, ws, indexMatches)
	}
	return nil
}

// ensureVaultWorkspaceUnclaimedLocked rejects evidence on either side of the
// catalog before a new name claims its deterministic workspace. In particular,
// it catches orphan 0x0F values that a metadata-only owner check cannot see.
func (ps *PebbleStore) ensureVaultWorkspaceUnclaimedLocked(ws [8]byte) error {
	if owner, occupied, err := ps.vaultWorkspaceOwnerLocked(ws); err != nil {
		return fmt.Errorf("read workspace owner: %w", err)
	} else if occupied {
		return fmt.Errorf("%w: workspace %x is already owned by vault %q", ErrVaultCatalogCorrupt, ws, owner)
	}

	iter, err := ps.db.NewIter(&pebble.IterOptions{
		LowerBound: []byte{0x0F},
		UpperBound: []byte{0x10},
	})
	if err != nil {
		return fmt.Errorf("inspect workspace name indexes: %w", err)
	}
	defer iter.Close()
	for valid := iter.First(); valid; valid = iter.Next() {
		if len(iter.Key()) != 9 {
			return fmt.Errorf("%w: malformed vault name index key length %d", ErrVaultCatalogCorrupt, len(iter.Key()))
		}
		if len(iter.Value()) != 8 {
			return fmt.Errorf("%w: vault name index %x has value length %d, want 8", ErrVaultCatalogCorrupt, iter.Key(), len(iter.Value()))
		}
		var candidate [8]byte
		copy(candidate[:], iter.Value())
		if candidate == ws {
			return fmt.Errorf("%w: workspace %x is already referenced by name-index key %x", ErrVaultCatalogCorrupt, ws, iter.Key())
		}
	}
	if err := iter.Error(); err != nil {
		return fmt.Errorf("inspect workspace name indexes: %w", err)
	}
	return nil
}

func (ps *PebbleStore) vaultMetadataContainsNameLocked(name string) (bool, error) {
	iter, err := ps.db.NewIter(&pebble.IterOptions{
		LowerBound: []byte{0x0E},
		UpperBound: []byte{0x0F},
	})
	if err != nil {
		return false, err
	}
	defer iter.Close()
	for valid := iter.First(); valid; valid = iter.Next() {
		if len(iter.Key()) != 9 {
			return false, fmt.Errorf("%w: malformed vault metadata key length %d", ErrVaultCatalogCorrupt, len(iter.Key()))
		}
		if string(iter.Value()) == name {
			return true, nil
		}
	}
	if err := iter.Error(); err != nil {
		return false, err
	}
	return false, nil
}

func (ps *PebbleStore) writeVaultPairLocked(ws [8]byte, name string) error {
	batch := ps.db.NewBatch()
	defer batch.Close()
	if err := batch.Set(keys.VaultMetaKey(ws), []byte(name), nil); err != nil {
		return fmt.Errorf("write vault pair %q: set metadata: %w", name, err)
	}
	if err := batch.Set(keys.VaultNameIndexKey(name), ws[:], nil); err != nil {
		return fmt.Errorf("write vault pair %q: set name index: %w", name, err)
	}
	if err := batch.Commit(pebble.Sync); err != nil {
		return fmt.Errorf("write vault pair %q: commit: %w", name, err)
	}
	ps.vaultPrefixCache.Add(name, ws)
	ps.vaultVerifiedCache.Add(name, ws)
	return nil
}

// VaultWorkspaceOwner returns the persisted vault name that owns ws. The
// boolean is false only when no 0x0E metadata key exists. Callers use this to
// prevent a newly reserved name from reusing a workspace retained by a renamed
// vault.
func (ps *PebbleStore) VaultWorkspaceOwner(ws [8]byte) (string, bool, error) {
	ps.vaultCatalogMu.RLock()
	defer ps.vaultCatalogMu.RUnlock()
	return ps.vaultWorkspaceOwnerLocked(ws)
}

func (ps *PebbleStore) vaultWorkspaceOwnerLocked(ws [8]byte) (string, bool, error) {
	value, closer, err := ps.db.Get(keys.VaultMetaKey(ws))
	if errors.Is(err, pebble.ErrNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	owner := string(value)
	closer.Close()
	return owner, true, nil
}

// BackfillVaultNames scans all 0x01 engram keys, finds vault prefixes that have
// no 0x0E meta key, and writes a placeholder name for each. Called once on startup
// so that legacy data (written before vault-name persistence) is discoverable.
// Its legacy repair policy is deliberately not part of the runtime creator
// contract; replacing it with a fail-closed startup audit plus an explicit
// versioned repair migration remains a separate lifecycle gate.
func (ps *PebbleStore) BackfillVaultNames() error {
	ps.vaultCatalogMu.Lock()
	defer ps.vaultCatalogMu.Unlock()
	// The legacy repair routine predates strict pair validation. Never carry a
	// prior in-process verification claim across its direct catalog mutations.
	ps.vaultVerifiedCache.Purge()

	// Collect unique vault prefixes from 0x01 keys.
	seen := make(map[[8]byte]struct{})
	iter, err := ps.db.NewIter(&pebble.IterOptions{
		LowerBound: []byte{0x01},
		UpperBound: []byte{0x02},
	})
	if err != nil {
		return err
	}
	for valid := iter.First(); valid; valid = iter.Next() {
		k := iter.Key()
		if len(k) >= 25 {
			var ws [8]byte
			copy(ws[:], k[1:9])
			seen[ws] = struct{}{}
		}
	}
	iter.Close()

	// For each vault prefix, ensure both 0x0E (name) and 0x0F (forward index) are written.
	for ws := range seen {
		metaKey := keys.VaultMetaKey(ws)
		var name string

		// Determine the name (existing or new placeholder).
		val, closer, getErr := ps.db.Get(metaKey)
		if getErr == nil {
			name = string(val)
			closer.Close()
		} else {
			name = fmt.Sprintf("vault-%x", ws[:4]) // 4-byte abbreviation
		}

		// Check if forward index key exists.
		idxKey := keys.VaultNameIndexKey(name)
		_, idxCloser, idxErr := ps.db.Get(idxKey)
		if idxErr == nil {
			idxCloser.Close()
			continue // both keys already exist
		}

		// Write whichever keys are missing.
		batch := ps.db.NewBatch()
		if getErr != nil {
			batch.Set(metaKey, []byte(name), nil)
		}
		batch.Set(idxKey, ws[:], nil)
		if commitErr := batch.Commit(nil); commitErr != nil {
			batch.Close()
			return commitErr
		}
		batch.Close()
	}
	return nil
}

// VaultNameExists returns true if a vault with the given name is registered
// (i.e. a 0x0F index key exists for the name).
func (ps *PebbleStore) VaultNameExists(name string) bool {
	exists, _ := ps.VaultNameIndexExists(name)
	return exists
}

// VaultNameIndexExists reports persisted 0x0F evidence without collapsing a
// storage read failure into ordinary absence. Strict lifecycle classification
// uses this method; VaultNameExists remains the legacy boolean convenience API.
func (ps *PebbleStore) VaultNameIndexExists(name string) (bool, error) {
	ps.vaultCatalogMu.RLock()
	defer ps.vaultCatalogMu.RUnlock()
	return ps.vaultNameIndexExistsLocked(name)
}

func (ps *PebbleStore) vaultNameIndexExistsLocked(name string) (bool, error) {
	idxKey := keys.VaultNameIndexKey(name)
	_, closer, err := ps.db.Get(idxKey)
	if err == nil {
		closer.Close()
		return true, nil
	}
	if errors.Is(err, pebble.ErrNotFound) {
		return false, nil
	}
	return false, fmt.Errorf("read vault name index %q: %w", name, err)
}

// RenameVault atomically renames a vault by updating the two index keys
// (0x0E prefix→name and 0x0F nameHash→prefix). No engram data changes.
// Returns an error if oldName doesn't match the stored name for ws, or if
// newName already exists (collision).
func (ps *PebbleStore) RenameVault(ws [8]byte, oldName, newName string) error {
	if oldName == "" || newName == "" {
		return fmt.Errorf("rename vault: names must not be empty")
	}
	ps.vaultCatalogMu.Lock()
	defer ps.vaultCatalogMu.Unlock()

	resolved, err := ps.resolveExistingVaultPrefixLocked(oldName)
	if err != nil {
		return fmt.Errorf("rename vault: resolve source %q: %w", oldName, err)
	}
	if resolved != ws {
		return fmt.Errorf("rename vault: source workspace %x differs from requested %x", resolved, ws)
	}
	if _, err := ps.resolveExistingVaultPrefixLocked(newName); err == nil {
		return fmt.Errorf("vault name %q already exists", newName)
	} else if !errors.Is(err, pebble.ErrNotFound) {
		return fmt.Errorf("rename vault: inspect target %q: %w", newName, err)
	}
	derived := keys.VaultPrefix(newName)
	if derived != ws {
		if err := ps.ensureVaultWorkspaceUnclaimedLocked(derived); err != nil {
			return fmt.Errorf("rename vault: inspect target-derived workspace: %w", err)
		}
	}

	// Atomic batch: update 0x0E, set new 0x0F, delete old 0x0F.
	batch := ps.db.NewBatch()
	defer batch.Close()
	metaKey := keys.VaultMetaKey(ws)
	batch.Set(metaKey, []byte(newName), nil)
	batch.Set(keys.VaultNameIndexKey(newName), ws[:], nil)
	batch.Delete(keys.VaultNameIndexKey(oldName), nil)
	if err := batch.Commit(pebble.Sync); err != nil {
		return fmt.Errorf("rename vault commit: %w", err)
	}

	// Update cache: evict old, insert new.
	ps.vaultPrefixCache.Remove(oldName)
	ps.vaultPrefixCache.Add(newName, ws)
	ps.vaultVerifiedCache.Remove(oldName)
	ps.vaultVerifiedCache.Add(newName, ws)

	return nil
}

// ListVaultNames scans the 0x0E prefix and returns all known vault names.
func (ps *PebbleStore) ListVaultNames() ([]string, error) {
	ps.vaultCatalogMu.RLock()
	defer ps.vaultCatalogMu.RUnlock()
	iter, err := ps.db.NewIter(&pebble.IterOptions{
		LowerBound: []byte{0x0E},
		UpperBound: []byte{0x0F},
	})
	if err != nil {
		return nil, err
	}
	defer iter.Close()
	return scanVaultNames(iter)
}

type vaultNameIterator interface {
	First() bool
	Next() bool
	Key() []byte
	Value() []byte
	Error() error
}

func scanVaultNames(iter vaultNameIterator) ([]string, error) {
	var names []string
	for valid := iter.First(); valid; valid = iter.Next() {
		if len(iter.Key()) == 9 && iter.Key()[0] == 0x0E {
			val := make([]byte, len(iter.Value()))
			copy(val, iter.Value())
			names = append(names, string(val))
		}
	}
	if err := iter.Error(); err != nil {
		return nil, fmt.Errorf("list vault names: iterate: %w", err)
	}
	return names, nil
}

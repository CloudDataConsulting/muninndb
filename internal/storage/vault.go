package storage

import (
	"errors"
	"fmt"

	"github.com/cockroachdb/pebble"
	"github.com/scrypster/muninndb/internal/storage/keys"
)

// WriteVaultName persists the vault name under two keys:
//
//	0x0E | wsPrefix → name   (prefix → name, for listing)
//	0x0F | siphash(name) → wsPrefix  (name → prefix, for resolution)
//
// Idempotent — safe to call on every write.
func (ps *PebbleStore) WriteVaultName(wsPrefix [8]byte, name string) error {
	// Fast path: already written this session — skip Pebble existence check.
	if _, ok := ps.vaultNameWritten.Load(wsPrefix); ok {
		return nil
	}
	metaKey := keys.VaultMetaKey(wsPrefix)
	// Only write if key doesn't already exist.
	_, closer, err := ps.db.Get(metaKey)
	if err == nil {
		closer.Close()
		// Mark as written so future calls skip this check.
		ps.vaultNameWritten.Store(wsPrefix, struct{}{})
		ps.vaultPrefixCache.Add(name, wsPrefix)
		return nil
	}
	batch := ps.db.NewBatch()
	defer batch.Close()
	batch.Set(metaKey, []byte(name), nil)
	idxKey := keys.VaultNameIndexKey(name)
	batch.Set(idxKey, wsPrefix[:], nil)
	if err := batch.Commit(nil); err != nil {
		return err
	}
	ps.vaultNameWritten.Store(wsPrefix, struct{}{})
	ps.vaultPrefixCache.Add(name, wsPrefix)
	return nil
}

// ReserveVaultName creates a new 0x0E/0x0F mapping without using the
// vaultNameWritten fast path. Lifecycle operations call this only after their
// engine-level availability checks; the persisted rechecks here keep stale
// caches or already-occupied workspace/name keys from being treated as a
// successful reservation. This is not a compare-and-set boundary against
// callers outside the engine's vaultOpsMu lifecycle lock.
func (ps *PebbleStore) ReserveVaultName(wsPrefix [8]byte, name string) error {
	idxKey := keys.VaultNameIndexKey(name)
	_, idxCloser, err := ps.db.Get(idxKey)
	if err == nil {
		idxCloser.Close()
		return fmt.Errorf("reserve vault name %q: name index already exists", name)
	}
	if !errors.Is(err, pebble.ErrNotFound) {
		return fmt.Errorf("reserve vault name %q: read name index: %w", name, err)
	}

	metaKey := keys.VaultMetaKey(wsPrefix)
	value, metaCloser, err := ps.db.Get(metaKey)
	if err == nil {
		owner := string(value)
		metaCloser.Close()
		return fmt.Errorf("reserve vault name %q: workspace already owned by vault %q", name, owner)
	}
	if !errors.Is(err, pebble.ErrNotFound) {
		return fmt.Errorf("reserve vault name %q: read workspace owner: %w", name, err)
	}

	batch := ps.db.NewBatch()
	defer batch.Close()
	batch.Set(metaKey, []byte(name), nil)
	batch.Set(idxKey, wsPrefix[:], nil)
	if err := batch.Commit(nil); err != nil {
		return fmt.Errorf("reserve vault name %q: commit: %w", name, err)
	}
	ps.vaultNameWritten.Store(wsPrefix, struct{}{})
	ps.vaultPrefixCache.Add(name, wsPrefix)
	return nil
}

// ResolveVaultPrefix looks up the actual workspace prefix for a vault name.
// Uses an in-memory cache to avoid Pebble reads on the common hot path.
func (ps *PebbleStore) ResolveVaultPrefix(name string) [8]byte {
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
	// Fall back to computing the SipHash and cache it.
	ws := keys.VaultPrefix(name)
	ps.vaultPrefixCache.Add(name, ws)
	return ws
}

// ResolveExistingVaultPrefix strictly resolves an already-registered vault.
// Unlike ResolveVaultPrefix, it never falls back to a name-derived SipHash and
// never trusts the in-memory cache without re-reading persisted lifecycle keys.
// Destructive and bulk existing-vault operations use this path so a missing,
// corrupt, or mismatched 0x0F/0x0E pair fails closed.
func (ps *PebbleStore) ResolveExistingVaultPrefix(name string) ([8]byte, error) {
	idxKey := keys.VaultNameIndexKey(name)
	value, closer, err := ps.db.Get(idxKey)
	if err != nil {
		return [8]byte{}, fmt.Errorf("resolve existing vault %q: name index: %w", name, err)
	}
	if len(value) != 8 {
		closer.Close()
		return [8]byte{}, fmt.Errorf("resolve existing vault %q: name index length %d, want 8", name, len(value))
	}
	var ws [8]byte
	copy(ws[:], value)
	closer.Close()

	metaValue, metaCloser, err := ps.db.Get(keys.VaultMetaKey(ws))
	if err != nil {
		return [8]byte{}, fmt.Errorf("resolve existing vault %q: metadata: %w", name, err)
	}
	storedName := string(metaValue)
	metaCloser.Close()
	if storedName != name {
		return [8]byte{}, fmt.Errorf("resolve existing vault %q: metadata names %q", name, storedName)
	}

	return ws, nil
}

// VaultWorkspaceOwner returns the persisted vault name that owns ws. The
// boolean is false only when no 0x0E metadata key exists. Callers use this to
// prevent a newly reserved name from reusing a workspace retained by a renamed
// vault.
func (ps *PebbleStore) VaultWorkspaceOwner(ws [8]byte) (string, bool, error) {
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
func (ps *PebbleStore) BackfillVaultNames() error {
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
	// Verify 0x0E meta key exists and matches oldName.
	metaKey := keys.VaultMetaKey(ws)
	val, closer, err := ps.db.Get(metaKey)
	if err != nil {
		return fmt.Errorf("vault prefix not found: %w", err)
	}
	storedName := string(val)
	closer.Close()
	if storedName != oldName {
		return fmt.Errorf("vault name mismatch: stored %q, expected %q", storedName, oldName)
	}

	// Verify newName doesn't already exist (collision check), preserving any
	// storage read failure instead of treating it as an available name.
	targetExists, err := ps.VaultNameIndexExists(newName)
	if err != nil {
		return fmt.Errorf("rename vault: inspect target name index: %w", err)
	}
	if targetExists {
		return fmt.Errorf("vault name %q already exists", newName)
	}

	// Atomic batch: update 0x0E, set new 0x0F, delete old 0x0F.
	batch := ps.db.NewBatch()
	defer batch.Close()
	batch.Set(metaKey, []byte(newName), nil)
	batch.Set(keys.VaultNameIndexKey(newName), ws[:], nil)
	batch.Delete(keys.VaultNameIndexKey(oldName), nil)
	if err := batch.Commit(nil); err != nil {
		return fmt.Errorf("rename vault commit: %w", err)
	}

	// Update cache: evict old, insert new.
	ps.vaultPrefixCache.Remove(oldName)
	ps.vaultPrefixCache.Add(newName, ws)
	// Clear the written flag so WriteVaultName re-checks if called with the old name.
	ps.vaultNameWritten.Delete(ws)

	return nil
}

// ListVaultNames scans the 0x0E prefix and returns all known vault names.
func (ps *PebbleStore) ListVaultNames() ([]string, error) {
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

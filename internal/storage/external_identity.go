package storage

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/cockroachdb/pebble"
	"github.com/scrypster/muninndb/internal/storage/keys"
)

const (
	externalIdentityRecordVersion = 1
	maxExternalIdentityBytes      = 1024
	externalIdentityHeaderSize    = 1 + 16 + 32 + 2
)

var (
	// ErrExternalIdentityConflict means an external identity is already bound to
	// a different canonical payload. Callers must not silently create or return a
	// different engram for the same identity.
	ErrExternalIdentityConflict = errors.New("external identity already belongs to a different payload")
	// ErrExternalIdentityCorrupt means an on-disk identity record cannot be
	// trusted. Writes fail closed instead of overwriting an uncertain binding.
	ErrExternalIdentityCorrupt = errors.New("external identity record is corrupt")
	// ErrExternalIdentityDangling means an identity points at a missing engram.
	// This should only be possible after out-of-band store mutation or corruption.
	ErrExternalIdentityDangling = errors.New("external identity points to a missing engram")
	// ErrExternalIdentityLifecycleUnsupported protects identities from lifecycle
	// operations that cannot yet preserve their contract safely.
	ErrExternalIdentityLifecycleUnsupported = errors.New("vault lifecycle operation does not support durable external identities")
)

// ExternalIdentityRecord is the durable 0x27 value. ExternalID is retained in
// full so a theoretical SHA-256 key collision is detectable. PayloadHash is a
// deterministic digest of the caller-visible write payload, excluding vault
// (which is represented by the key scope) and the external identity itself.
type ExternalIdentityRecord struct {
	EngramID    ULID
	PayloadHash [32]byte
	ExternalID  string
}

// ValidateExternalIdentity enforces a bounded, unambiguous external identity.
func ValidateExternalIdentity(externalID string) error {
	if externalID == "" {
		return fmt.Errorf("external identity must not be empty")
	}
	if !utf8.ValidString(externalID) {
		return fmt.Errorf("external identity must be valid UTF-8")
	}
	if len(externalID) > maxExternalIdentityBytes {
		return fmt.Errorf("external identity exceeds %d bytes", maxExternalIdentityBytes)
	}
	return nil
}

func encodeExternalIdentityRecord(record ExternalIdentityRecord) ([]byte, error) {
	if err := ValidateExternalIdentity(record.ExternalID); err != nil {
		return nil, err
	}
	value := make([]byte, externalIdentityHeaderSize+len(record.ExternalID))
	value[0] = externalIdentityRecordVersion
	copy(value[1:17], record.EngramID[:])
	copy(value[17:49], record.PayloadHash[:])
	binary.BigEndian.PutUint16(value[49:51], uint16(len(record.ExternalID)))
	copy(value[51:], record.ExternalID)
	return value, nil
}

func decodeExternalIdentityRecord(value []byte) (*ExternalIdentityRecord, error) {
	if len(value) < externalIdentityHeaderSize {
		return nil, fmt.Errorf("%w: value length %d", ErrExternalIdentityCorrupt, len(value))
	}
	if value[0] != externalIdentityRecordVersion {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrExternalIdentityCorrupt, value[0])
	}
	idLen := int(binary.BigEndian.Uint16(value[49:51]))
	if idLen == 0 || idLen > maxExternalIdentityBytes || len(value) != externalIdentityHeaderSize+idLen {
		return nil, fmt.Errorf("%w: invalid external identity length %d", ErrExternalIdentityCorrupt, idLen)
	}
	record := &ExternalIdentityRecord{ExternalID: string(value[51:])}
	copy(record.EngramID[:], value[1:17])
	copy(record.PayloadHash[:], value[17:49])
	if err := ValidateExternalIdentity(record.ExternalID); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrExternalIdentityCorrupt, err)
	}
	return record, nil
}

// lockExternalIdentity waits for the single-node identity/lifecycle critical
// section, then re-checks cancellation before allowing any read or write.
func (ps *PebbleStore) lockExternalIdentity(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ps.externalIdentityMu.Lock()
	if err := ctx.Err(); err != nil {
		ps.externalIdentityMu.Unlock()
		return nil, err
	}
	return ps.externalIdentityMu.Unlock, nil
}

func (ps *PebbleStore) getExternalIdentityRecord(ws [8]byte, externalID string) (*ExternalIdentityRecord, error) {
	value, closer, err := ps.db.Get(keys.ExternalIdentityKey(ws, externalID))
	if errors.Is(err, pebble.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read external identity: %w", err)
	}
	defer closer.Close()
	record, err := decodeExternalIdentityRecord(value)
	if err != nil {
		return nil, err
	}
	if record.ExternalID != externalID {
		return nil, fmt.Errorf("%w: SHA-256 key collision", ErrExternalIdentityConflict)
	}
	return record, nil
}

func (ps *PebbleStore) validateExternalIdentityTarget(ws [8]byte, record *ExternalIdentityRecord) error {
	_, closer, err := ps.db.Get(keys.EngramKey(ws, [16]byte(record.EngramID)))
	if errors.Is(err, pebble.ErrNotFound) {
		return fmt.Errorf("%w: %s", ErrExternalIdentityDangling, record.EngramID.String())
	}
	if err != nil {
		return fmt.Errorf("validate external identity target: %w", err)
	}
	closer.Close()
	return nil
}

// LookupExternalIdentity returns a verified durable binding. Missing identities
// return nil, nil; corrupt, colliding, or dangling records fail closed.
func (ps *PebbleStore) LookupExternalIdentity(ctx context.Context, ws [8]byte, externalID string) (*ExternalIdentityRecord, error) {
	if err := ValidateExternalIdentity(externalID); err != nil {
		return nil, err
	}
	unlock, err := ps.lockExternalIdentity(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	record, err := ps.getExternalIdentityRecord(ws, externalID)
	if err != nil || record == nil {
		return record, err
	}
	if err := ps.validateExternalIdentityTarget(ws, record); err != nil {
		return nil, err
	}
	return record, nil
}

// hasExternalIdentities reports whether a vault contains any 0x27 bindings.
// The caller must hold externalIdentityMu when coordinating with writes.
func (ps *PebbleStore) hasExternalIdentities(ctx context.Context, ws [8]byte) (bool, error) {
	prefix := keys.ExternalIdentityPrefix(ws)
	iter, err := ps.db.NewIter(&pebble.IterOptions{
		LowerBound: prefix,
		UpperBound: keys.PrefixUpperBound(prefix),
	})
	if err != nil {
		return false, fmt.Errorf("scan external identities: %w", err)
	}
	defer iter.Close()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	found := iter.First()
	if err := iter.Error(); err != nil {
		return false, fmt.Errorf("scan external identities: %w", err)
	}
	return found, nil
}

// HasExternalIdentities reports whether a vault has any durable 0x27 binding.
func (ps *PebbleStore) HasExternalIdentities(ctx context.Context, ws [8]byte) (bool, error) {
	unlock, err := ps.lockExternalIdentity(ctx)
	if err != nil {
		return false, err
	}
	defer unlock()
	return ps.hasExternalIdentities(ctx, ws)
}

// HasAnyExternalIdentities reports whether the store contains any durable 0x27
// binding. Cluster activation uses this to fail before a non-replicated
// identity namespace can enter a multi-node topology.
func (ps *PebbleStore) HasAnyExternalIdentities(ctx context.Context) (bool, error) {
	unlock, err := ps.lockExternalIdentity(ctx)
	if err != nil {
		return false, err
	}
	defer unlock()
	iter, err := ps.db.NewIter(&pebble.IterOptions{LowerBound: []byte{0x27}, UpperBound: []byte{0x28}})
	if err != nil {
		return false, fmt.Errorf("scan external identity namespace: %w", err)
	}
	defer iter.Close()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	found := iter.First()
	if err := iter.Error(); err != nil {
		return false, fmt.Errorf("scan external identity namespace: %w", err)
	}
	return found, nil
}

// guardExternalIdentityLifecycle fails before a clone, merge, or export can
// partially proceed and retains the identity lock for the operation's duration.
// Those operations need an explicit collision/import policy before 0x27
// bindings can be copied safely.
func (ps *PebbleStore) guardExternalIdentityLifecycle(ctx context.Context, ws [8]byte, operation string) (func(), error) {
	unlock, err := ps.lockExternalIdentity(ctx)
	if err != nil {
		return nil, err
	}
	found, err := ps.hasExternalIdentities(ctx, ws)
	if err != nil {
		unlock()
		return nil, err
	}
	if found {
		unlock()
		return nil, fmt.Errorf("%w: %s", ErrExternalIdentityLifecycleUnsupported, operation)
	}
	return unlock, nil
}

// deleteExternalIdentityMappingsForEngram queues deletion of every 0x27 record
// targeting id. The caller must hold externalIdentityMu and commit batch with
// the canonical engram delete, so neither side can survive alone.
func (ps *PebbleStore) deleteExternalIdentityMappingsForEngram(ctx context.Context, ws [8]byte, id ULID, batch *pebble.Batch) error {
	prefix := keys.ExternalIdentityPrefix(ws)
	iter, err := ps.db.NewIter(&pebble.IterOptions{
		LowerBound: prefix,
		UpperBound: keys.PrefixUpperBound(prefix),
	})
	if err != nil {
		return fmt.Errorf("delete external identity: create iterator: %w", err)
	}
	defer iter.Close()
	for valid := iter.First(); valid; valid = iter.Next() {
		if err := ctx.Err(); err != nil {
			return err
		}
		record, err := decodeExternalIdentityRecord(iter.Value())
		if err != nil {
			return err
		}
		if bytes.Equal(record.EngramID[:], id[:]) {
			if err := batch.Delete(iter.Key(), nil); err != nil {
				return fmt.Errorf("delete external identity mapping: %w", err)
			}
		}
	}
	if err := iter.Error(); err != nil {
		return fmt.Errorf("delete external identity: iterate: %w", err)
	}
	return nil
}

package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/cockroachdb/pebble"
	"github.com/scrypster/muninndb/internal/storage/keys"
)

var (
	ErrEngramAlreadyExists = errors.New("engram already exists")
	ErrEngramChanged       = errors.New("engram changed while batch was pending")
)

// vaultCounterLock is the per-vault canonical-mutation lifecycle semaphore.
// Inserts, updates, deletes, clears, count reconciliation, and persisted count
// flushes share it. Unlike sync.Mutex, callers waiting behind a long operation
// can honor request cancellation.
type vaultCounterLock struct {
	token chan struct{}
}

// commitBatchWithVaultCountDelta serializes one canonical vault batch with its
// maintained count transition. The counter is initialized before commit, so
// the scan cannot include the batch and then apply its delta a second time.
func (ps *PebbleStore) commitBatchWithVaultCountDelta(
	ctx context.Context,
	ws [8]byte,
	batch *pebble.Batch,
	writeOptions *pebble.WriteOptions,
	newEngramIDs [][16]byte,
	delta int64,
) (int64, error) {
	if delta != int64(len(newEngramIDs)) {
		return 0, fmt.Errorf("vault count delta %d does not match %d canonical inserts", delta, len(newEngramIDs))
	}
	unlock, err := ps.lockVaultCounterSet(ctx, [][8]byte{ws})
	if err != nil {
		return 0, err
	}
	defer unlock()
	if err := ps.ensureEngramIDsAbsentLocked(ws, newEngramIDs); err != nil {
		return 0, err
	}

	vc, err := ps.getOrInitCounterLocked(ctx, ws)
	if err != nil {
		return 0, err
	}
	if err := batch.Commit(writeOptions); err != nil {
		return 0, err
	}
	newTotal := vc.count.Add(delta)
	if newTotal < 0 {
		vc.count.Store(0)
		newTotal = 0
	}
	if ps.counterFlush != nil {
		ps.counterFlush.Submit(ws, newTotal)
	}
	return newTotal, nil
}

// ensureEngramIDsAbsentLocked rejects both duplicate request IDs and existing
// canonical keys. The caller must hold ws's vault lock through the subsequent
// commit so the absence check and insert are one serialized transition.
func (ps *PebbleStore) ensureEngramIDsAbsentLocked(ws [8]byte, ids [][16]byte) error {
	seen := make(map[[16]byte]struct{}, len(ids))
	for _, id := range ids {
		if _, duplicate := seen[id]; duplicate {
			return fmt.Errorf("%w: %x (duplicate request ID)", ErrEngramAlreadyExists, id)
		}
		seen[id] = struct{}{}

		_, closer, err := ps.db.Get(keys.EngramKey(ws, id))
		if err == nil {
			closer.Close()
			return fmt.Errorf("%w: %x", ErrEngramAlreadyExists, id)
		}
		if !errors.Is(err, pebble.ErrNotFound) {
			return fmt.Errorf("check engram identity %x: %w", id, err)
		}
	}
	return nil
}

func newVaultCounterLock() *vaultCounterLock {
	lock := &vaultCounterLock{token: make(chan struct{}, 1)}
	lock.token <- struct{}{}
	return lock
}

func (l *vaultCounterLock) lock(ctx context.Context) error {
	// Preserve existing write semantics when the lock is immediately available,
	// even if the caller's context was canceled after its upstream work finished.
	// Cancellation is used to bound an actual wait, not to randomly lose a ready
	// token when both select cases are eligible.
	select {
	case <-l.token:
		return nil
	default:
	}
	select {
	case <-l.token:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *vaultCounterLock) unlock() {
	l.token <- struct{}{}
}

func (ps *PebbleStore) counterLockFor(ws [8]byte) *vaultCounterLock {
	candidate := newVaultCounterLock()
	actual, _ := ps.vaultCounterLocks.LoadOrStore(ws, candidate)
	return actual.(*vaultCounterLock)
}

// lockVaultCounterSet acquires unique canonical-mutation locks in byte-sorted
// order so a multi-vault batch cannot deadlock another multi-vault batch. The
// legacy name is retained because the lock also owns count reconciliation. The
// returned function releases locks in reverse order.
func (ps *PebbleStore) lockVaultCounterSet(ctx context.Context, vaults [][8]byte) (func(), error) {
	unique := make(map[[8]byte]struct{}, len(vaults))
	ordered := make([][8]byte, 0, len(vaults))
	for _, ws := range vaults {
		if _, exists := unique[ws]; exists {
			continue
		}
		unique[ws] = struct{}{}
		ordered = append(ordered, ws)
	}
	sort.Slice(ordered, func(i, j int) bool {
		return bytes.Compare(ordered[i][:], ordered[j][:]) < 0
	})

	locked := make([]*vaultCounterLock, 0, len(ordered))
	for _, ws := range ordered {
		lock := ps.counterLockFor(ws)
		if err := lock.lock(ctx); err != nil {
			for i := len(locked) - 1; i >= 0; i-- {
				locked[i].unlock()
			}
			return nil, err
		}
		locked = append(locked, lock)
	}

	return func() {
		for i := len(locked) - 1; i >= 0; i-- {
			locked[i].unlock()
		}
	}, nil
}

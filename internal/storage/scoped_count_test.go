package storage

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/scrypster/muninndb/internal/storage/keys"
)

type cancelAfterChecksContext struct {
	context.Context
	checks   int
	cancelAt int
}

func (c *cancelAfterChecksContext) Err() error {
	c.checks++
	if c.checks >= c.cancelAt {
		return context.Canceled
	}
	return nil
}

func assertVaultCounterStateAbsent(t *testing.T, store *PebbleStore, ws [8]byte) {
	t.Helper()
	if _, ok := store.vaultCounters.Load(ws); ok {
		t.Fatal("read-only count published an in-memory vault counter")
	}
	if _, ok := store.vaultCounterLocks.Load(ws); ok {
		t.Fatal("read-only count created a per-vault lifecycle lock")
	}
	if store.counterFlush != nil {
		if _, ok := store.counterFlush.m.Load(ws); ok {
			t.Fatal("read-only count queued a persisted counter update")
		}
	}
	value, err := Get(store.db, keys.VaultCountKey(ws))
	if err != nil {
		t.Fatalf("read persisted counter: %v", err)
	}
	if value != nil {
		t.Fatalf("read-only count persisted 0x15 state: %x", value)
	}
}

func TestGetVaultCountReadOnlyLeavesCounterStateAbsent(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	ws := store.VaultPrefix("read-only-counter")
	for i := 0; i < 2; i++ {
		id := NewULID()
		if err := store.db.Set(keys.EngramKey(ws, [16]byte(id)), []byte{byte(i + 1)}, pebble.Sync); err != nil {
			t.Fatalf("seed canonical engram[%d]: %v", i, err)
		}
	}

	assertVaultCounterStateAbsent(t, store, ws)
	for i := 0; i < 2; i++ {
		count, err := store.GetVaultCountReadOnly(ctx, ws)
		if err != nil {
			t.Fatalf("GetVaultCountReadOnly[%d]: %v", i, err)
		}
		if count != 2 {
			t.Fatalf("GetVaultCountReadOnly[%d] = %d, want 2", i, count)
		}
		assertVaultCounterStateAbsent(t, store, ws)
	}

	count, err := store.GetVaultCountChecked(ctx, ws)
	if err != nil {
		t.Fatalf("GetVaultCountChecked: %v", err)
	}
	if count != 2 {
		t.Fatalf("GetVaultCountChecked = %d, want 2", count)
	}
	if _, ok := store.vaultCounters.Load(ws); !ok {
		t.Fatal("normal checked count did not initialize the in-memory counter")
	}
	value, err := Get(store.db, keys.VaultCountKey(ws))
	if err != nil {
		t.Fatalf("read initialized counter: %v", err)
	}
	if len(value) != 8 || binary.BigEndian.Uint64(value) != 2 {
		t.Fatalf("initialized persisted counter = %x, want 2", value)
	}
}

func TestGetVaultCountReadOnlyHonorsExistingSnapshot(t *testing.T) {
	store := openTestStore(t)
	ws := store.VaultPrefix("read-only-counter-snapshot")
	seed := func(label byte) {
		t.Helper()
		id := NewULID()
		if err := store.db.Set(keys.EngramKey(ws, [16]byte(id)), []byte{label}, pebble.Sync); err != nil {
			t.Fatalf("seed canonical engram: %v", err)
		}
	}

	seed(1)
	snapshot := store.NewSnapshot()
	defer snapshot.Close()
	snapshotCtx := ContextWithSnapshot(context.Background(), snapshot)
	seed(2)

	count, err := store.GetVaultCountReadOnly(snapshotCtx, ws)
	if err != nil {
		t.Fatalf("snapshot count: %v", err)
	}
	if count != 1 {
		t.Fatalf("snapshot count = %d, want 1", count)
	}
	assertVaultCounterStateAbsent(t, store, ws)

	count, err = store.GetVaultCountReadOnly(context.Background(), ws)
	if err != nil {
		t.Fatalf("live read-only count: %v", err)
	}
	if count != 2 {
		t.Fatalf("live read-only count = %d, want 2", count)
	}
	assertVaultCounterStateAbsent(t, store, ws)
}

func TestCountEngramsForVaultHandlesMaxPrefixAndExactKeys(t *testing.T) {
	store := openTestStore(t)

	ctx := context.Background()
	ws := [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	for i := 0; i < 2; i++ {
		if _, err := store.WriteEngram(ctx, ws, &Engram{
			Concept: "scoped count",
			Content: "canonical engram",
		}); err != nil {
			t.Fatalf("WriteEngram[%d]: %v", i, err)
		}
	}

	// A longer key in the canonical namespace is not an engram record and must
	// not inflate the tenant-scoped count.
	malformed := make([]byte, 26)
	malformed[0] = 0x01
	copy(malformed[1:9], ws[:])
	malformed[25] = 0x01
	if err := store.db.Set(malformed, []byte("not an engram"), pebble.Sync); err != nil {
		t.Fatalf("write malformed fixture: %v", err)
	}
	foreignID := [16]byte{15: 0x01}
	if err := store.db.Set(
		keys.MetaKey([8]byte{}, foreignID),
		[]byte("foreign metadata"),
		pebble.Sync,
	); err != nil {
		t.Fatalf("write foreign metadata fixture: %v", err)
	}

	count, err := store.countEngramsForVault(ctx, ws)
	if err != nil {
		t.Fatalf("countEngramsForVault: %v", err)
	}
	if count != 2 {
		t.Fatalf("count = %d, want 2", count)
	}
}

func TestCountEngramsForVaultExcludesCarryNeighbor(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	target := [8]byte{6: 0x10, 7: 0xff}
	for i := 0; i < 2; i++ {
		if _, err := store.WriteEngram(ctx, target, &Engram{
			Concept: "scoped count",
			Content: "canonical target engram",
		}); err != nil {
			t.Fatalf("WriteEngram[%d]: %v", i, err)
		}
	}

	neighbor := [8]byte{6: 0x11}
	foreignID := [16]byte{15: 0x01}
	if err := store.db.Set(
		keys.EngramKey(neighbor, foreignID),
		[]byte("foreign neighboring-vault engram"),
		pebble.Sync,
	); err != nil {
		t.Fatalf("write neighboring-vault fixture: %v", err)
	}

	count, err := store.countEngramsForVault(ctx, target)
	if err != nil {
		t.Fatalf("countEngramsForVault: %v", err)
	}
	if count != 2 {
		t.Fatalf("count = %d, want 2", count)
	}
}

func TestCountEngramsForVaultHonorsCanceledContext(t *testing.T) {
	store := openTestStore(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := store.countEngramsForVault(ctx, store.VaultPrefix("canceled-scan"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestVaultCounterCanceledInitializationRetries(t *testing.T) {
	store := openTestStore(t)
	ws := store.VaultPrefix("canceled-counter-retry")
	id := [16]byte{15: 1}
	if err := store.db.Set(keys.EngramKey(ws, id), []byte("canonical"), pebble.Sync); err != nil {
		t.Fatalf("write canonical fixture: %v", err)
	}

	interrupted := &cancelAfterChecksContext{Context: context.Background(), cancelAt: 3}
	if _, err := store.GetVaultCountChecked(interrupted, ws); !errors.Is(err, context.Canceled) {
		t.Fatalf("first count error = %v, want context.Canceled", err)
	}
	if _, ok := store.vaultCounters.Load(ws); ok {
		t.Fatal("failed initialization remained cached")
	}

	got, err := store.GetVaultCountChecked(context.Background(), ws)
	if err != nil {
		t.Fatalf("retry count: %v", err)
	}
	if got != 1 {
		t.Fatalf("retry count = %d, want 1", got)
	}
}

func TestVaultCounterInitializationSerializesFirstWrite(t *testing.T) {
	store := openTestStore(t)
	ws := store.VaultPrefix("counter-init-barrier")
	id := [16]byte{15: 1}
	if err := store.db.Set(keys.EngramKey(ws, id), []byte("canonical"), pebble.Sync); err != nil {
		t.Fatalf("write canonical fixture: %v", err)
	}

	scanFinished := make(chan struct{})
	releaseScan := make(chan struct{})
	store.counterInitHook = func(got [8]byte) {
		if got != ws {
			return
		}
		close(scanFinished)
		<-releaseScan
	}

	countDone := make(chan error, 1)
	go func() {
		_, err := store.GetVaultCountChecked(context.Background(), ws)
		countDone <- err
	}()
	<-scanFinished

	writeDone := make(chan error, 1)
	go func() {
		_, err := store.WriteEngram(context.Background(), ws, &Engram{
			Concept: "serialized write",
			Content: "must wait for the first canonical scan",
		})
		writeDone <- err
	}()

	select {
	case err := <-writeDone:
		t.Fatalf("write passed initialization barrier early: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(releaseScan)
	if err := <-countDone; err != nil {
		t.Fatalf("initial count: %v", err)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("WriteEngram: %v", err)
	}

	got, err := store.GetVaultCountChecked(context.Background(), ws)
	if err != nil {
		t.Fatalf("final count: %v", err)
	}
	if got != 2 {
		t.Fatalf("final count = %d, want canonical 1 + concurrent write 1", got)
	}
}

func TestVaultCounterLockWaitHonorsCanceledContext(t *testing.T) {
	store := openTestStore(t)
	ws := store.VaultPrefix("counter-lock-cancel")
	lock := store.counterLockFor(ws)
	if err := lock.lock(context.Background()); err != nil {
		t.Fatalf("acquire fixture lock: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := store.GetVaultCountChecked(ctx, ws)
		done <- err
	}()

	select {
	case err := <-done:
		lock.unlock()
		t.Fatalf("count passed held lifecycle lock early: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			lock.unlock()
			t.Fatalf("count error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		lock.unlock()
		t.Fatal("canceled count remained blocked on lifecycle lock")
	}
	lock.unlock()
}

func TestMergeVaultDataCancellationKeepsCommittedCounterExact(t *testing.T) {
	store := openTestStore(t)
	wsSource := store.VaultPrefix("merge-cancel-source")
	wsTarget := store.VaultPrefix("merge-cancel-target")

	batch := store.db.NewBatch()
	for i := 0; i < cloneBatchSize+1; i++ {
		var id [16]byte
		binary.BigEndian.PutUint64(id[8:], uint64(i+1))
		if err := batch.Set(keys.EngramKey(wsSource, id), []byte("source"), nil); err != nil {
			batch.Close()
			t.Fatalf("set source fixture %d: %v", i, err)
		}
	}
	if err := batch.Commit(pebble.Sync); err != nil {
		batch.Close()
		t.Fatalf("commit source fixtures: %v", err)
	}
	batch.Close()

	ctx, cancel := context.WithCancel(context.Background())
	merged, err := store.MergeVaultData(ctx, wsSource, wsTarget, func(copied int64) {
		if copied == cloneBatchSize {
			cancel()
		}
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("MergeVaultData error = %v, want context.Canceled", err)
	}
	if merged != cloneBatchSize {
		t.Fatalf("committed merge count = %d, want %d", merged, cloneBatchSize)
	}

	maintained, err := store.GetVaultCountChecked(context.Background(), wsTarget)
	if err != nil {
		t.Fatalf("maintained target count: %v", err)
	}
	canonical, err := store.countEngramsForVault(context.Background(), wsTarget)
	if err != nil {
		t.Fatalf("canonical target count: %v", err)
	}
	if maintained != canonical || canonical != cloneBatchSize {
		t.Fatalf("target counts maintained=%d canonical=%d, want %d", maintained, canonical, cloneBatchSize)
	}
}

func TestClearVaultBlocksCountUntilCommit(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	ws := store.VaultPrefix("clear-blocks-count")
	for i := 0; i < 2; i++ {
		if _, err := store.WriteEngram(ctx, ws, &Engram{Concept: "clear", Content: "fixture"}); err != nil {
			t.Fatalf("WriteEngram[%d]: %v", i, err)
		}
	}

	beforeCommit := make(chan struct{})
	releaseCommit := make(chan struct{})
	store.clearBeforeCommitHook = func(got [8]byte) {
		if got != ws {
			return
		}
		close(beforeCommit)
		<-releaseCommit
	}
	type clearResult struct {
		count int64
		err   error
	}
	clearDone := make(chan clearResult, 1)
	go func() {
		count, err := store.ClearVault(ctx, ws)
		clearDone <- clearResult{count: count, err: err}
	}()
	<-beforeCommit

	type countResult struct {
		count int64
		err   error
	}
	countDone := make(chan countResult, 1)
	go func() {
		count, err := store.GetVaultCountChecked(ctx, ws)
		countDone <- countResult{count: count, err: err}
	}()
	select {
	case result := <-countDone:
		t.Fatalf("count crossed clear lifecycle barrier early: count=%d err=%v", result.count, result.err)
	case <-time.After(25 * time.Millisecond):
	}
	close(releaseCommit)
	result := <-clearDone
	if result.err != nil {
		t.Fatalf("ClearVault: %v", result.err)
	}
	if result.count != 2 {
		t.Fatalf("ClearVault returned count %d, want 2", result.count)
	}
	counted := <-countDone
	if counted.err != nil {
		t.Fatalf("post-clear count: %v", counted.err)
	}
	if counted.count != 0 {
		t.Fatalf("post-clear count = %d, want 0", counted.count)
	}
}

func TestClearVaultSerializesQueuedWriter(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	ws := store.VaultPrefix("clear-queued-writer")
	for i := 0; i < 2; i++ {
		if _, err := store.WriteEngram(ctx, ws, &Engram{Concept: "clear", Content: "fixture"}); err != nil {
			t.Fatalf("WriteEngram[%d]: %v", i, err)
		}
	}

	beforeCommit := make(chan struct{})
	releaseCommit := make(chan struct{})
	store.clearBeforeCommitHook = func(got [8]byte) {
		if got != ws {
			return
		}
		close(beforeCommit)
		<-releaseCommit
	}
	type clearResult struct {
		count int64
		err   error
	}
	clearDone := make(chan clearResult, 1)
	go func() {
		count, err := store.ClearVault(ctx, ws)
		clearDone <- clearResult{count: count, err: err}
	}()
	<-beforeCommit

	writeDone := make(chan error, 1)
	go func() {
		_, err := store.WriteEngram(ctx, ws, &Engram{
			Concept: "queued after clear",
			Content: "must survive the clear lifecycle transition",
		})
		writeDone <- err
	}()
	select {
	case err := <-writeDone:
		t.Fatalf("writer crossed clear lifecycle barrier early: %v", err)
	case <-time.After(25 * time.Millisecond):
	}

	close(releaseCommit)
	result := <-clearDone
	if result.err != nil {
		t.Fatalf("ClearVault: %v", result.err)
	}
	if result.count != 2 {
		t.Fatalf("ClearVault returned count %d, want 2", result.count)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("queued WriteEngram: %v", err)
	}

	maintained, err := store.GetVaultCountChecked(ctx, ws)
	if err != nil {
		t.Fatalf("maintained count: %v", err)
	}
	canonical, err := store.countEngramsForVault(ctx, ws)
	if err != nil {
		t.Fatalf("canonical count: %v", err)
	}
	if maintained != 1 || canonical != 1 {
		t.Fatalf("post-clear counts maintained=%d canonical=%d, want 1", maintained, canonical)
	}
}

func TestClearVaultSerializesCanonicalUpdater(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	ws := store.VaultPrefix("clear-canonical-updater")
	id, err := store.WriteEngram(ctx, ws, &Engram{Concept: "clear", Content: "fixture"})
	if err != nil {
		t.Fatalf("WriteEngram: %v", err)
	}

	beforeCommit := make(chan struct{})
	releaseCommit := make(chan struct{})
	store.clearBeforeCommitHook = func(got [8]byte) {
		if got == ws {
			close(beforeCommit)
			<-releaseCommit
		}
	}
	clearDone := make(chan error, 1)
	go func() {
		_, err := store.ClearVault(ctx, ws)
		clearDone <- err
	}()
	<-beforeCommit

	updateDone := make(chan error, 1)
	go func() { updateDone <- store.UpdateTags(ctx, ws, id, []string{"must-not-resurrect"}) }()
	select {
	case err := <-updateDone:
		t.Fatalf("updater crossed clear lifecycle barrier early: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(releaseCommit)
	if err := <-clearDone; err != nil {
		t.Fatalf("ClearVault: %v", err)
	}
	if err := <-updateDone; err == nil {
		t.Fatal("post-clear updater succeeded with a missing canonical parent")
	}

	maintained, err := store.GetVaultCountChecked(ctx, ws)
	if err != nil {
		t.Fatalf("maintained count: %v", err)
	}
	canonical, err := store.countEngramsForVault(ctx, ws)
	if err != nil {
		t.Fatalf("canonical count: %v", err)
	}
	if maintained != 0 || canonical != 0 {
		t.Fatalf("post-clear counts maintained=%d canonical=%d, want 0", maintained, canonical)
	}
}

func TestPreparedStateUpdateCannotResurrectClearedEngram(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	ws := store.VaultPrefix("clear-prepared-state-update")
	id, err := store.WriteEngram(ctx, ws, &Engram{Concept: "prepared", Content: "fixture"})
	if err != nil {
		t.Fatalf("WriteEngram: %v", err)
	}

	batch := store.NewBatch()
	defer batch.Discard()
	if err := batch.UpdateEngramState(ctx, ws, id, StateSoftDeleted); err != nil {
		t.Fatalf("prepare state update: %v", err)
	}
	if _, err := store.ClearVault(ctx, ws); err != nil {
		t.Fatalf("ClearVault: %v", err)
	}
	if err := batch.Commit(); !errors.Is(err, ErrEngramChanged) {
		t.Fatalf("stale batch commit error = %v, want ErrEngramChanged", err)
	}

	maintained, err := store.GetVaultCountChecked(ctx, ws)
	if err != nil {
		t.Fatalf("maintained count: %v", err)
	}
	canonical, err := store.countEngramsForVault(ctx, ws)
	if err != nil {
		t.Fatalf("canonical count: %v", err)
	}
	if maintained != 0 || canonical != 0 {
		t.Fatalf("stale update resurrected row: maintained=%d canonical=%d", maintained, canonical)
	}
}

func TestWriteEngramRejectsExistingIDWithoutCountDrift(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	ws := store.VaultPrefix("duplicate-single-write")
	id := NewULID()
	if _, err := store.WriteEngram(ctx, ws, &Engram{ID: id, Concept: "first", Content: "canonical"}); err != nil {
		t.Fatalf("first WriteEngram: %v", err)
	}
	if _, err := store.WriteEngram(ctx, ws, &Engram{ID: id, Concept: "second", Content: "must not overwrite"}); !errors.Is(err, ErrEngramAlreadyExists) {
		t.Fatalf("duplicate WriteEngram error = %v, want ErrEngramAlreadyExists", err)
	}
	got, err := store.GetEngram(ctx, ws, id)
	if err != nil {
		t.Fatalf("GetEngram: %v", err)
	}
	if got.Concept != "first" {
		t.Fatalf("duplicate overwrote canonical concept: %q", got.Concept)
	}
	count, err := store.GetVaultCountChecked(ctx, ws)
	if err != nil || count != 1 {
		t.Fatalf("count after duplicate = %d err=%v, want 1", count, err)
	}
}

func TestWriteEngramBatchRejectsDuplicateIDWithoutCountDrift(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	ws := store.VaultPrefix("duplicate-batch-write")
	id := NewULID()
	_, errs := store.WriteEngramBatch(ctx, []EngramBatchItem{
		{WSPrefix: ws, Engram: &Engram{ID: id, Concept: "first", Content: "canonical"}},
		{WSPrefix: ws, Engram: &Engram{ID: id, Concept: "second", Content: "must not overwrite"}},
	})
	if errs[0] != nil {
		t.Fatalf("first batch item: %v", errs[0])
	}
	if !errors.Is(errs[1], ErrEngramAlreadyExists) {
		t.Fatalf("duplicate batch item error = %v, want ErrEngramAlreadyExists", errs[1])
	}
	count, err := store.GetVaultCountChecked(ctx, ws)
	if err != nil || count != 1 {
		t.Fatalf("count after duplicate batch = %d err=%v, want 1", count, err)
	}
}

func TestTransactionalBatchRejectsExistingIDWithoutCountDrift(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	ws := store.VaultPrefix("duplicate-transactional-write")
	id := NewULID()
	if _, err := store.WriteEngram(ctx, ws, &Engram{ID: id, Concept: "first", Content: "canonical"}); err != nil {
		t.Fatalf("first WriteEngram: %v", err)
	}

	batch := store.NewBatch()
	defer batch.Discard()
	if err := batch.WriteEngram(ctx, ws, &Engram{ID: id, Concept: "second", Content: "must not overwrite"}); err != nil {
		t.Fatalf("queue duplicate: %v", err)
	}
	if err := batch.Commit(); !errors.Is(err, ErrEngramAlreadyExists) {
		t.Fatalf("duplicate transaction error = %v, want ErrEngramAlreadyExists", err)
	}
	count, err := store.GetVaultCountChecked(ctx, ws)
	if err != nil || count != 1 {
		t.Fatalf("count after duplicate transaction = %d err=%v, want 1", count, err)
	}
}

func TestCounterFlushSerializesWithClear(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	ws := store.VaultPrefix("flush-clear-serialization")
	flushLoaded := make(chan struct{})
	releaseFlush := make(chan struct{})
	var pauseOnce sync.Once
	store.counterFlush.beforeWriteHook = func(got [8]byte, _ int64) {
		if got == ws {
			pauseOnce.Do(func() {
				close(flushLoaded)
				<-releaseFlush
			})
		}
	}
	if _, err := store.WriteEngram(ctx, ws, &Engram{Concept: "flush", Content: "fixture"}); err != nil {
		t.Fatalf("WriteEngram: %v", err)
	}
	select {
	case <-flushLoaded:
	case <-time.After(2 * time.Second):
		t.Fatal("counter flush did not reach deterministic hook")
	}

	clearDone := make(chan error, 1)
	go func() {
		_, err := store.ClearVault(ctx, ws)
		clearDone <- err
	}()
	select {
	case err := <-clearDone:
		t.Fatalf("clear crossed in-flight counter flush early: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(releaseFlush)
	if err := <-clearDone; err != nil {
		t.Fatalf("ClearVault: %v", err)
	}
	value, err := Get(store.db, keys.VaultCountKey(ws))
	if err != nil {
		t.Fatalf("read persisted counter: %v", err)
	}
	if value != nil {
		t.Fatalf("stale counter flush survived clear: %x", value)
	}
}

func TestDeleteEngramSerializesConcurrentSameID(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	ws := store.VaultPrefix("concurrent-hard-delete")
	ids := make([]ULID, 3)
	for i := range ids {
		id, err := store.WriteEngram(ctx, ws, &Engram{Concept: "delete", Content: "fixture"})
		if err != nil {
			t.Fatalf("WriteEngram[%d]: %v", i, err)
		}
		ids[i] = id
	}

	firstRead := make(chan struct{})
	releaseDelete := make(chan struct{})
	store.deleteAfterReadHook = func(gotWS [8]byte, gotID ULID) {
		if gotWS == ws && gotID == ids[0] {
			close(firstRead)
			<-releaseDelete
		}
	}
	firstDone := make(chan error, 1)
	go func() { firstDone <- store.DeleteEngram(ctx, ws, ids[0]) }()
	<-firstRead
	secondDone := make(chan error, 1)
	go func() { secondDone <- store.DeleteEngram(ctx, ws, ids[0]) }()

	select {
	case err := <-secondDone:
		t.Fatalf("second delete bypassed same-engram transition lock: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(releaseDelete)
	if err := <-firstDone; err != nil {
		t.Fatalf("first DeleteEngram: %v", err)
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("second DeleteEngram: %v", err)
	}

	maintained, err := store.GetVaultCountChecked(ctx, ws)
	if err != nil {
		t.Fatalf("maintained count: %v", err)
	}
	canonical, err := store.countEngramsForVault(ctx, ws)
	if err != nil {
		t.Fatalf("canonical count: %v", err)
	}
	if maintained != 2 || canonical != 2 {
		t.Fatalf("post-delete counts maintained=%d canonical=%d, want 2", maintained, canonical)
	}
}

func TestDeleteCorruptEngramDecrementsMaintainedCounter(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	ws := store.VaultPrefix("corrupt-hard-delete")
	ids := make([]ULID, 2)
	for i := range ids {
		id, err := store.WriteEngram(ctx, ws, &Engram{Concept: "corrupt delete", Content: "fixture"})
		if err != nil {
			t.Fatalf("WriteEngram[%d]: %v", i, err)
		}
		ids[i] = id
	}
	if err := store.db.Set(keys.EngramKey(ws, [16]byte(ids[0])), []byte("corrupt-erf"), pebble.Sync); err != nil {
		t.Fatalf("corrupt canonical fixture: %v", err)
	}

	if err := store.DeleteEngram(ctx, ws, ids[0]); err != nil {
		t.Fatalf("DeleteEngram: %v", err)
	}
	maintained, err := store.GetVaultCountChecked(ctx, ws)
	if err != nil {
		t.Fatalf("maintained count: %v", err)
	}
	canonical, err := store.countEngramsForVault(ctx, ws)
	if err != nil {
		t.Fatalf("canonical count: %v", err)
	}
	if maintained != 1 || canonical != 1 {
		t.Fatalf("post-delete counts maintained=%d canonical=%d, want 1", maintained, canonical)
	}
}

func TestCloneVaultDataPreservesConcurrentTargetWrite(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	wsSource := store.VaultPrefix("clone-counter-source")
	wsTarget := store.VaultPrefix("clone-counter-target")
	for i := 0; i < 3; i++ {
		if _, err := store.WriteEngram(ctx, wsSource, &Engram{Concept: "clone", Content: "fixture"}); err != nil {
			t.Fatalf("WriteEngram source[%d]: %v", i, err)
		}
	}

	var callbackErr error
	copied, err := store.CloneVaultData(ctx, wsSource, wsTarget, func(count int64) {
		if count == 3 && callbackErr == nil {
			_, callbackErr = store.WriteEngram(ctx, wsTarget, &Engram{
				Concept: "concurrent target write",
				Content: "must survive clone count finalization",
			})
		}
	})
	if err != nil {
		t.Fatalf("CloneVaultData: %v", err)
	}
	if callbackErr != nil {
		t.Fatalf("concurrent WriteEngram: %v", callbackErr)
	}
	if copied != 3 {
		t.Fatalf("copied = %d, want 3", copied)
	}
	maintained, err := store.GetVaultCountChecked(ctx, wsTarget)
	if err != nil {
		t.Fatalf("maintained target count: %v", err)
	}
	canonical, err := store.countEngramsForVault(ctx, wsTarget)
	if err != nil {
		t.Fatalf("canonical target count: %v", err)
	}
	if maintained != 4 || canonical != 4 {
		t.Fatalf("target counts maintained=%d canonical=%d, want 4", maintained, canonical)
	}
}

func TestCloneVaultDataCancellationKeepsCommittedCounterExact(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	wsSource := store.VaultPrefix("clone-cancel-source")
	wsTarget := store.VaultPrefix("clone-cancel-target")
	items := make([]EngramBatchItem, cloneBatchSize+1)
	for i := range items {
		items[i] = EngramBatchItem{
			WSPrefix: wsSource,
			Engram: &Engram{
				Concept: "clone cancellation",
				Content: "valid encoded fixture",
			},
		}
	}
	_, writeErrs := store.WriteEngramBatch(ctx, items)
	for i, err := range writeErrs {
		if err != nil {
			t.Fatalf("WriteEngramBatch[%d]: %v", i, err)
		}
	}

	cloneCtx, cancel := context.WithCancel(ctx)
	copied, err := store.CloneVaultData(cloneCtx, wsSource, wsTarget, func(count int64) {
		if count == cloneBatchSize {
			cancel()
		}
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("CloneVaultData error = %v, want context.Canceled", err)
	}
	if copied != cloneBatchSize {
		t.Fatalf("committed clone count = %d, want %d", copied, cloneBatchSize)
	}
	maintained, err := store.GetVaultCountChecked(ctx, wsTarget)
	if err != nil {
		t.Fatalf("maintained target count: %v", err)
	}
	canonical, err := store.countEngramsForVault(ctx, wsTarget)
	if err != nil {
		t.Fatalf("canonical target count: %v", err)
	}
	if maintained != canonical || canonical != cloneBatchSize {
		t.Fatalf("target counts maintained=%d canonical=%d, want %d", maintained, canonical, cloneBatchSize)
	}
}

func TestVaultCounterDoesNotDoubleCountFirstWrite(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	ws := store.VaultPrefix("first-write-counter")

	for i := 0; i < 3; i++ {
		if _, err := store.WriteEngram(ctx, ws, &Engram{
			Concept: "counter",
			Content: "first access happens inside write",
		}); err != nil {
			t.Fatalf("WriteEngram[%d]: %v", i, err)
		}
	}
	if got := store.GetVaultCount(ctx, ws); got != 3 {
		t.Fatalf("GetVaultCount = %d, want 3", got)
	}
}

func TestVaultCounterDoesNotDoubleCountFirstBatch(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	ws := store.VaultPrefix("first-batch-counter")
	items := make([]EngramBatchItem, 3)
	for i := range items {
		items[i] = EngramBatchItem{
			WSPrefix: ws,
			Engram: &Engram{
				Concept: "counter batch",
				Content: "first access happens inside batch",
			},
		}
	}
	_, errs := store.WriteEngramBatch(ctx, items)
	for i, err := range errs {
		if err != nil {
			t.Fatalf("WriteEngramBatch[%d]: %v", i, err)
		}
	}
	if got := store.GetVaultCount(ctx, ws); got != 3 {
		t.Fatalf("GetVaultCount = %d, want 3", got)
	}
}

func TestVaultCounterDoesNotDoubleCountFirstTransactionalBatch(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	ws := store.VaultPrefix("first-transactional-batch-counter")
	batch := store.NewBatch()
	for i := 0; i < 3; i++ {
		if err := batch.WriteEngram(ctx, ws, &Engram{
			Concept: "transactional counter batch",
			Content: "first access happens inside commit",
		}); err != nil {
			t.Fatalf("batch.WriteEngram[%d]: %v", i, err)
		}
	}
	if err := batch.Commit(); err != nil {
		t.Fatalf("batch.Commit: %v", err)
	}
	if got := store.GetVaultCount(ctx, ws); got != 3 {
		t.Fatalf("GetVaultCount = %d, want 3", got)
	}
}

func TestVaultCounterInitializesBeforeFirstDelete(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	ws := store.VaultPrefix("first-delete-counter")
	ids := make([]ULID, 3)
	for i := range ids {
		id, err := store.WriteEngram(ctx, ws, &Engram{
			Concept: "counter delete",
			Content: "restart-style counter fixture",
		})
		if err != nil {
			t.Fatalf("WriteEngram[%d]: %v", i, err)
		}
		ids[i] = id
	}

	// Simulate a process restart whose in-memory counter has not been seeded and
	// whose optional persisted counter is absent, forcing a canonical scan.
	store.vaultCounters.Delete(ws)
	if store.counterFlush != nil {
		store.counterFlush.Delete(ws)
	}
	if err := store.db.Delete(keys.VaultCountKey(ws), pebble.Sync); err != nil {
		t.Fatalf("delete persisted counter: %v", err)
	}
	if err := store.DeleteEngram(ctx, ws, ids[0]); err != nil {
		t.Fatalf("DeleteEngram: %v", err)
	}
	if got := store.GetVaultCount(ctx, ws); got != 2 {
		t.Fatalf("GetVaultCount = %d, want 2", got)
	}
}

func TestVaultCounterRepairsPersistedDriftFromCanonicalRecords(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	ws := store.VaultPrefix("persisted-counter-drift")
	if _, err := store.WriteEngram(ctx, ws, &Engram{
		Concept: "counter repair",
		Content: "one canonical record",
	}); err != nil {
		t.Fatalf("WriteEngram: %v", err)
	}

	store.vaultCounters.Delete(ws)
	if store.counterFlush != nil {
		store.counterFlush.Delete(ws)
	}
	var stale [8]byte
	binary.BigEndian.PutUint64(stale[:], 99)
	if err := store.db.Set(keys.VaultCountKey(ws), stale[:], pebble.Sync); err != nil {
		t.Fatalf("write stale persisted counter: %v", err)
	}

	if got := store.GetVaultCount(ctx, ws); got != 1 {
		t.Fatalf("GetVaultCount = %d, want canonical count 1", got)
	}
	value, closer, err := store.db.Get(keys.VaultCountKey(ws))
	if err != nil {
		t.Fatalf("read repaired counter: %v", err)
	}
	defer closer.Close()
	if got := binary.BigEndian.Uint64(value); got != 1 {
		t.Fatalf("persisted counter = %d, want repaired value 1", got)
	}
}

package storage

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/scrypster/muninndb/internal/storage/keys"
)

func externalTestHash(payload string) [32]byte {
	return sha256.Sum256([]byte(payload))
}

func externalTestEngram(content string) *Engram {
	return &Engram{Concept: "external", Content: content, Confidence: 1, Stability: 30}
}

func actualExternalEngramCount(t *testing.T, store *PebbleStore, ws [8]byte) int64 {
	t.Helper()
	count, err := store.countEngramsForVault(context.Background(), ws)
	if err != nil {
		t.Fatal(err)
	}
	return count
}

func TestExternalIdentityRecordRoundTrip(t *testing.T) {
	record := ExternalIdentityRecord{
		EngramID:    NewULID(),
		PayloadHash: externalTestHash("payload"),
		ExternalID:  "source:event:123",
	}
	encoded, err := encodeExternalIdentityRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeExternalIdentityRecord(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if *decoded != record {
		t.Fatalf("round trip mismatch: got %+v want %+v", *decoded, record)
	}
}

func TestExternalIdentityRecordRejectsCorruption(t *testing.T) {
	for _, value := range [][]byte{
		nil,
		make([]byte, externalIdentityHeaderSize-1),
		append([]byte{99}, make([]byte, externalIdentityHeaderSize-1)...),
	} {
		if _, err := decodeExternalIdentityRecord(value); !errors.Is(err, ErrExternalIdentityCorrupt) {
			t.Fatalf("decode error = %v, want ErrExternalIdentityCorrupt", err)
		}
	}
}

func TestWriteEngramWithExternalIdentityRetryReturnsStableID(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	ws := store.VaultPrefix("identity-retry")
	hash := externalTestHash("same")

	id1, reused1, err := store.WriteEngramWithExternalIdentity(ctx, ws, externalTestEngram("same"), "event-1", hash)
	if err != nil {
		t.Fatal(err)
	}
	if reused1 {
		t.Fatal("first write unexpectedly reused")
	}
	id2, reused2, err := store.WriteEngramWithExternalIdentity(ctx, ws, externalTestEngram("same"), "event-1", hash)
	if err != nil {
		t.Fatal(err)
	}
	if !reused2 || id2 != id1 {
		t.Fatalf("retry = (%s, reused=%v), want (%s, true)", id2, reused2, id1)
	}
	if count := actualExternalEngramCount(t, store, ws); count != 1 {
		t.Fatalf("vault count = %d, want 1", count)
	}
	record, err := store.LookupExternalIdentity(ctx, ws, "event-1")
	if err != nil {
		t.Fatal(err)
	}
	if record == nil || record.EngramID != id1 || record.PayloadHash != hash {
		t.Fatalf("unexpected identity record: %+v", record)
	}
}

func TestWriteEngramWithExternalIdentityConflictFailsClosed(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	ws := store.VaultPrefix("identity-conflict")
	id, _, err := store.WriteEngramWithExternalIdentity(ctx, ws, externalTestEngram("first"), "event-1", externalTestHash("first"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.WriteEngramWithExternalIdentity(ctx, ws, externalTestEngram("changed"), "event-1", externalTestHash("changed")); !errors.Is(err, ErrExternalIdentityConflict) {
		t.Fatalf("conflict error = %v", err)
	}
	if count := actualExternalEngramCount(t, store, ws); count != 1 {
		t.Fatalf("vault count = %d, want 1", count)
	}
	eng, err := store.GetEngram(ctx, ws, id)
	if err != nil || eng.Content != "first" {
		t.Fatalf("original engram changed: eng=%+v err=%v", eng, err)
	}
}

func TestExternalIdentityIsVaultScoped(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	wsA := store.VaultPrefix("identity-a")
	wsB := store.VaultPrefix("identity-b")
	idA, _, err := store.WriteEngramWithExternalIdentity(ctx, wsA, externalTestEngram("a"), "shared", externalTestHash("a"))
	if err != nil {
		t.Fatal(err)
	}
	idB, _, err := store.WriteEngramWithExternalIdentity(ctx, wsB, externalTestEngram("b"), "shared", externalTestHash("b"))
	if err != nil {
		t.Fatal(err)
	}
	if idA == idB {
		t.Fatal("vault-scoped identities returned the same generated ID")
	}
}

func TestHasAnyExternalIdentities(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	found, err := store.HasAnyExternalIdentities(ctx)
	if err != nil || found {
		t.Fatalf("empty store: found=%v err=%v", found, err)
	}
	ws := store.VaultPrefix("identity-any")
	if _, _, err := store.WriteEngramWithExternalIdentity(ctx, ws, externalTestEngram("x"), "event", externalTestHash("x")); err != nil {
		t.Fatal(err)
	}
	found, err = store.HasAnyExternalIdentities(ctx)
	if err != nil || !found {
		t.Fatalf("populated store: found=%v err=%v", found, err)
	}
}

func TestExternalIdentityConcurrentIdenticalWritesCreateOneEngram(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	ws := store.VaultPrefix("identity-concurrent-same")
	hash := externalTestHash("same")
	const workers = 16
	ids := make([]ULID, workers)
	errs := make([]error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ids[i], _, errs[i] = store.WriteEngramWithExternalIdentity(ctx, ws, externalTestEngram("same"), "event", hash)
		}(i)
	}
	wg.Wait()
	for i := range errs {
		if errs[i] != nil {
			t.Fatalf("worker %d: %v", i, errs[i])
		}
		if ids[i] != ids[0] {
			t.Fatalf("worker %d ID = %s, want %s", i, ids[i], ids[0])
		}
	}
	if count := actualExternalEngramCount(t, store, ws); count != 1 {
		t.Fatalf("vault count = %d, want 1", count)
	}
}

func TestExternalIdentityConcurrentConflictHasOneWinner(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	ws := store.VaultPrefix("identity-concurrent-conflict")
	start := make(chan struct{})
	type result struct {
		hash [32]byte
		err  error
	}
	results := make(chan result, 2)
	for _, payload := range []string{"a", "b"} {
		payload := payload
		go func() {
			<-start
			hash := externalTestHash(payload)
			_, _, err := store.WriteEngramWithExternalIdentity(ctx, ws, externalTestEngram(payload), "event", hash)
			results <- result{hash: hash, err: err}
		}()
	}
	close(start)
	r1, r2 := <-results, <-results
	got := []result{r1, r2}
	winners := 0
	conflicts := 0
	var winnerHash [32]byte
	for _, result := range got {
		switch {
		case result.err == nil:
			winners++
			winnerHash = result.hash
		case errors.Is(result.err, ErrExternalIdentityConflict):
			conflicts++
		default:
			t.Fatalf("unexpected error: %v", result.err)
		}
	}
	if winners != 1 || conflicts != 1 {
		t.Fatalf("winners=%d conflicts=%d, want 1/1", winners, conflicts)
	}
	record, err := store.LookupExternalIdentity(ctx, ws, "event")
	if err != nil {
		t.Fatal(err)
	}
	if record.PayloadHash != winnerHash {
		t.Fatal("stored mapping does not match winning request")
	}
	if count := actualExternalEngramCount(t, store, ws); count != 1 {
		t.Fatalf("vault count = %d, want 1", count)
	}
}

func TestExternalIdentityCanceledContextDoesNotWrite(t *testing.T) {
	store := newTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ws := store.VaultPrefix("identity-canceled")
	if _, _, err := store.WriteEngramWithExternalIdentity(ctx, ws, externalTestEngram("x"), "event", externalTestHash("x")); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if count := actualExternalEngramCount(t, store, ws); count != 0 {
		t.Fatalf("vault count = %d, want 0", count)
	}
}

func TestExternalIdentityCancellationWhileWaitingForLockDoesNotWrite(t *testing.T) {
	store := newTestStore(t)
	ws := store.VaultPrefix("identity-canceled-lock")
	store.externalIdentityMu.Lock()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, _, err := store.WriteEngramWithExternalIdentity(ctx, ws, externalTestEngram("x"), "event", externalTestHash("x"))
		result <- err
	}()
	cancel()
	store.externalIdentityMu.Unlock()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if count := actualExternalEngramCount(t, store, ws); count != 0 {
		t.Fatalf("vault count = %d, want 0", count)
	}
}

func TestExternalIdentitySurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenPebble(dir, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	store := NewPebbleStore(db, PebbleStoreConfig{CacheSize: 10})
	ws := store.VaultPrefix("identity-reopen")
	hash := externalTestHash("persistent")
	id, _, err := store.WriteEngramWithExternalIdentity(context.Background(), ws, externalTestEngram("persistent"), "event", hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	db, err = OpenPebble(dir, DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	store = NewPebbleStore(db, PebbleStoreConfig{CacheSize: 10})
	t.Cleanup(func() { _ = store.Close() })
	record, err := store.LookupExternalIdentity(context.Background(), ws, "event")
	if err != nil {
		t.Fatal(err)
	}
	if record == nil || record.EngramID != id || record.PayloadHash != hash {
		t.Fatalf("reopened record = %+v", record)
	}
}

func TestWriteEngramBatchExternalIdentitySemantics(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	ws := store.VaultPrefix("identity-batch")
	hash := externalTestHash("same")
	items := []EngramBatchItem{
		{WSPrefix: ws, Engram: externalTestEngram("same"), ExternalID: "same", PayloadHash: hash},
		{WSPrefix: ws, Engram: externalTestEngram("same"), ExternalID: "same", PayloadHash: hash},
		{WSPrefix: ws, Engram: externalTestEngram("other"), ExternalID: "same", PayloadHash: externalTestHash("other")},
		{WSPrefix: ws, Engram: externalTestEngram("unique"), ExternalID: "unique", PayloadHash: externalTestHash("unique")},
	}
	ids, reused, errs := store.WriteEngramBatchWithExternalIdentity(ctx, items)
	if errs[0] != nil || errs[1] != nil || errs[3] != nil {
		t.Fatalf("unexpected batch errors: %v", errs)
	}
	if !errors.Is(errs[2], ErrExternalIdentityConflict) {
		t.Fatalf("conflicting item error = %v", errs[2])
	}
	if ids[0] != ids[1] || reused[0] || !reused[1] || reused[3] {
		t.Fatalf("unexpected ids/reused: ids=%v reused=%v", ids, reused)
	}
	if count := actualExternalEngramCount(t, store, ws); count != 2 {
		t.Fatalf("vault count = %d, want 2", count)
	}

	retryItems := []EngramBatchItem{
		{WSPrefix: ws, Engram: externalTestEngram("same"), ExternalID: "same", PayloadHash: hash},
		{WSPrefix: ws, Engram: externalTestEngram("unique"), ExternalID: "unique", PayloadHash: externalTestHash("unique")},
	}
	retryIDs, retryReused, retryErrs := store.WriteEngramBatchWithExternalIdentity(ctx, retryItems)
	if retryErrs[0] != nil || retryErrs[1] != nil || !retryReused[0] || !retryReused[1] {
		t.Fatalf("retry result ids=%v reused=%v errs=%v", retryIDs, retryReused, retryErrs)
	}
	if count := actualExternalEngramCount(t, store, ws); count != 2 {
		t.Fatalf("vault count after retry = %d, want 2", count)
	}
}

func TestHardDeleteAndClearRemoveExternalIdentity(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	ws := store.VaultPrefix("identity-delete")
	hash := externalTestHash("delete")
	id, _, err := store.WriteEngramWithExternalIdentity(ctx, ws, externalTestEngram("delete"), "event", hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteEngram(ctx, ws, id); err != nil {
		t.Fatal(err)
	}
	if record, err := store.LookupExternalIdentity(ctx, ws, "event"); err != nil || record != nil {
		t.Fatalf("mapping after hard delete: record=%+v err=%v", record, err)
	}

	if _, _, err := store.WriteEngramWithExternalIdentity(ctx, ws, externalTestEngram("delete"), "event", hash); err != nil {
		t.Fatalf("reuse after hard delete: %v", err)
	}
	if _, err := store.ClearVault(ctx, ws); err != nil {
		t.Fatal(err)
	}
	if record, err := store.LookupExternalIdentity(ctx, ws, "event"); err != nil || record != nil {
		t.Fatalf("mapping after clear: record=%+v err=%v", record, err)
	}
}

func TestExternalIdentityDanglingAndCorruptRecordsFailClosed(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	ws := store.VaultPrefix("identity-corrupt")
	externalID := "event"
	if err := store.db.Set(keys.ExternalIdentityKey(ws, externalID), []byte("bad"), pebble.Sync); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.WriteEngramWithExternalIdentity(ctx, ws, externalTestEngram("x"), externalID, externalTestHash("x")); !errors.Is(err, ErrExternalIdentityCorrupt) {
		t.Fatalf("corrupt record error = %v", err)
	}

	record := ExternalIdentityRecord{EngramID: NewULID(), PayloadHash: externalTestHash("x"), ExternalID: "dangling"}
	value, err := encodeExternalIdentityRecord(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.db.Set(keys.ExternalIdentityKey(ws, record.ExternalID), value, pebble.Sync); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.WriteEngramWithExternalIdentity(ctx, ws, externalTestEngram("x"), record.ExternalID, record.PayloadHash); !errors.Is(err, ErrExternalIdentityDangling) {
		t.Fatalf("dangling record error = %v", err)
	}
	if count := actualExternalEngramCount(t, store, ws); count != 0 {
		t.Fatalf("vault count = %d, want 0", count)
	}
}

func TestExternalIdentityLifecycleOperationsFailBeforeCopy(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	ws := store.VaultPrefix("identity-lifecycle")
	target := store.VaultPrefix("identity-lifecycle-target")
	if _, _, err := store.WriteEngramWithExternalIdentity(ctx, ws, externalTestEngram("x"), "event", externalTestHash("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CloneVaultData(ctx, ws, target, nil); !errors.Is(err, ErrExternalIdentityLifecycleUnsupported) {
		t.Fatalf("clone error = %v", err)
	}
	if _, err := store.MergeVaultData(ctx, ws, target, nil); !errors.Is(err, ErrExternalIdentityLifecycleUnsupported) {
		t.Fatalf("merge error = %v", err)
	}
	var exported bytes.Buffer
	if _, err := store.ExportVaultData(ctx, ws, "identity-lifecycle", ExportOpts{}, &exported); !errors.Is(err, ErrExternalIdentityLifecycleUnsupported) {
		t.Fatalf("export error = %v", err)
	}
	if exported.Len() != 0 {
		t.Fatalf("export wrote %d bytes before failing", exported.Len())
	}
	if count := actualExternalEngramCount(t, store, target); count != 0 {
		t.Fatalf("target count = %d, want 0", count)
	}
}

func TestImportRejectsExternalIdentityNamespace(t *testing.T) {
	store := newTestStore(t)
	manifest, err := json.Marshal(MuninnManifest{
		MuninnVersion: "1",
		SchemaVersion: MuninnSchemaVersion,
		Vault:         "source",
		CreatedAt:     time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	strippedKey := append([]byte{0x27}, make([]byte, 32)...)
	value := []byte("identity")
	var data bytes.Buffer
	if err := binary.Write(&data, binary.BigEndian, uint32(len(strippedKey))); err != nil {
		t.Fatal(err)
	}
	data.Write(strippedKey)
	if err := binary.Write(&data, binary.BigEndian, uint32(len(value))); err != nil {
		t.Fatal(err)
	}
	data.Write(value)

	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	for _, entry := range []struct {
		name string
		data []byte
	}{
		{name: "manifest.json", data: manifest},
		{name: "data.kvs", data: data.Bytes()},
	} {
		if err := tw.WriteHeader(&tar.Header{Name: entry.name, Mode: 0o644, Size: int64(len(entry.data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(entry.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}

	ws := store.VaultPrefix("target")
	_, err = store.ImportVaultData(context.Background(), ws, "target", ImportOpts{}, bytes.NewReader(archive.Bytes()))
	if !errors.Is(err, ErrExternalIdentityLifecycleUnsupported) {
		t.Fatalf("import error = %v", err)
	}
	if count := actualExternalEngramCount(t, store, ws); count != 0 {
		t.Fatalf("target count = %d, want 0", count)
	}
}

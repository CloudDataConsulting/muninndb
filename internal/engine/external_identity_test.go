package engine

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/scrypster/muninndb/internal/storage"
	"github.com/scrypster/muninndb/internal/transport/mbp"
)

func TestExternalIdentityPayloadHashCanonicalization(t *testing.T) {
	t1 := time.Date(2026, 7, 11, 12, 30, 0, 123, time.FixedZone("minus-six", -6*60*60))
	t2 := t1.UTC()
	a := &mbp.WriteRequest{
		Vault:        "vault-a",
		IdempotentID: "id-a",
		Concept:      "concept",
		Content:      "content",
		CreatedAt:    &t1,
		Tags:         nil,
	}
	b := &mbp.WriteRequest{
		Vault:        "renamed-vault",
		IdempotentID: "id-b",
		Concept:      "concept",
		Content:      "content",
		CreatedAt:    &t2,
		Tags:         []string{},
		Confidence:   1,
		Stability:    30,
	}
	hashA, err := externalIdentityPayloadHash(a)
	if err != nil {
		t.Fatal(err)
	}
	hashB, err := externalIdentityPayloadHash(b)
	if err != nil {
		t.Fatal(err)
	}
	if hashA != hashB {
		t.Fatal("vault, identity, timezone offset, or nil/empty slice affected canonical payload")
	}
	b.Content = "changed"
	hashChanged, err := externalIdentityPayloadHash(b)
	if err != nil {
		t.Fatal(err)
	}
	if hashChanged == hashA {
		t.Fatal("changed content did not affect canonical payload")
	}
}

func TestExternalIdentityPayloadHashNormalizesStorageDefaults(t *testing.T) {
	zeroTime := time.Time{}
	implicit := &mbp.WriteRequest{Content: "x"}
	explicit := &mbp.WriteRequest{Content: "x", Confidence: 1, Stability: 30, CreatedAt: &zeroTime}
	implicitHash, err := externalIdentityPayloadHash(implicit)
	if err != nil {
		t.Fatal(err)
	}
	explicitHash, err := externalIdentityPayloadHash(explicit)
	if err != nil {
		t.Fatal(err)
	}
	if implicitHash != explicitHash {
		t.Fatal("storage-equivalent default values produced different payload hashes")
	}
}

func TestExternalIdentityPayloadRejectsPostCommitCallerData(t *testing.T) {
	for name, req := range map[string]*mbp.WriteRequest{
		"entities":             {Content: "x", Entities: []mbp.InlineEntity{{Name: "A"}}},
		"relationships":        {Content: "x", Relationships: []mbp.InlineRelationship{{TargetID: storage.NewULID().String()}}},
		"entity relationships": {Content: "x", EntityRelationships: []mbp.InlineEntityRelationship{{FromEntity: "A", ToEntity: "B"}}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := externalIdentityPayloadHash(req); !errors.Is(err, ErrExternalIdentityUnsupportedPayload) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestEngineWriteExternalIdentityReturnsStableResponseAndSkipsSideEffects(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()
	var onWriteCalls atomic.Int32
	eng.SetOnWrite(func() { onWriteCalls.Add(1) })
	req := &mbp.WriteRequest{Vault: "identity-engine", Concept: "concept", Content: "content", IdempotentID: "event-1"}

	first, err := eng.Write(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := eng.Write(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if retry.ID != first.ID || retry.CreatedAt != first.CreatedAt {
		t.Fatalf("retry response = %+v, want stable %+v", retry, first)
	}
	if onWriteCalls.Load() != 1 {
		t.Fatalf("onWrite calls = %d, want 1", onWriteCalls.Load())
	}
	if eng.engramCount.Load() != 1 {
		t.Fatalf("engine engram count = %d, want 1", eng.engramCount.Load())
	}
}

func TestEngineWriteExternalIdentityConflictFailsClosed(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()
	first, err := eng.Write(ctx, &mbp.WriteRequest{Vault: "identity-conflict", Content: "first", IdempotentID: "event"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Write(ctx, &mbp.WriteRequest{Vault: "identity-conflict", Content: "changed", IdempotentID: "event"}); !errors.Is(err, ErrExternalIdentityConflict) {
		t.Fatalf("conflict error = %v", err)
	}
	stored, err := eng.Read(ctx, &mbp.ReadRequest{Vault: "identity-conflict", ID: first.ID})
	if err != nil {
		t.Fatal(err)
	}
	if stored.Content != "first" {
		t.Fatalf("stored content = %q, want first", stored.Content)
	}
}

func TestEngineWriteExternalIdentityDefaultAndCrossVaultScope(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()
	defaultResp, err := eng.Write(ctx, &mbp.WriteRequest{Content: "default", IdempotentID: "shared"})
	if err != nil {
		t.Fatal(err)
	}
	otherResp, err := eng.Write(ctx, &mbp.WriteRequest{Vault: "other", Content: "other", IdempotentID: "shared"})
	if err != nil {
		t.Fatal(err)
	}
	if defaultResp.ID == otherResp.ID {
		t.Fatal("cross-vault identity returned same ID")
	}
	defaultWS := eng.store.ResolveVaultPrefix("default")
	record, err := eng.store.LookupExternalIdentity(ctx, defaultWS, "shared")
	if err != nil {
		t.Fatal(err)
	}
	if record == nil || record.EngramID.String() != defaultResp.ID {
		t.Fatalf("default-vault identity record = %+v", record)
	}
}

func TestExternalIdentitySurvivesVaultRename(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()
	req := &mbp.WriteRequest{Vault: "identity-old-name", Content: "same", IdempotentID: "event"}
	first, err := eng.Write(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.RenameVault(ctx, "identity-old-name", "identity-new-name"); err != nil {
		t.Fatal(err)
	}
	retry, err := eng.Write(ctx, &mbp.WriteRequest{Vault: "identity-new-name", Content: "same", IdempotentID: "event"})
	if err != nil {
		t.Fatal(err)
	}
	if retry.ID != first.ID {
		t.Fatalf("ID after rename = %s, want %s", retry.ID, first.ID)
	}
}

func TestEngineWriteExternalIdentityRejectsClusterModeAndInvalidID(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	eng.setClusterModeForTest(true)
	if _, err := eng.Write(context.Background(), &mbp.WriteRequest{Vault: "cluster", Content: "x", IdempotentID: "event"}); !errors.Is(err, ErrExternalIdentityClusterUnsupported) {
		t.Fatalf("cluster error = %v", err)
	}
	eng.setClusterModeForTest(false)
	if _, err := eng.Write(context.Background(), &mbp.WriteRequest{Vault: "cluster", Content: "x", IdempotentID: strings.Repeat("x", 1025)}); err == nil {
		t.Fatal("oversized external identity was accepted")
	}
	ws := eng.store.ResolveVaultPrefix("cluster")
	if count := eng.store.GetVaultCount(context.Background(), ws); count != 0 {
		t.Fatalf("stored engrams = %d, want 0", count)
	}
}

func TestEnableClusterModeFailsWithExistingIdentityAndClosesWriteGate(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()
	if _, err := eng.Write(ctx, &mbp.WriteRequest{Vault: "existing", Content: "x", IdempotentID: "event"}); err != nil {
		t.Fatal(err)
	}
	if err := eng.EnableClusterMode(ctx); !errors.Is(err, ErrExternalIdentityClusterDataPresent) {
		t.Fatalf("activation error = %v", err)
	}

	eng2, cleanup2 := testEnv(t)
	defer cleanup2()
	if err := eng2.EnableClusterMode(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := eng2.Write(ctx, &mbp.WriteRequest{Vault: "new", Content: "x", IdempotentID: "event"}); !errors.Is(err, ErrExternalIdentityClusterUnsupported) {
		t.Fatalf("write after activation error = %v", err)
	}
}

func TestEnableClusterModeAndConcurrentWriteCannotBothSucceed(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()
	start := make(chan struct{})
	writeResult := make(chan error, 1)
	enableResult := make(chan error, 1)
	go func() {
		<-start
		_, err := eng.Write(ctx, &mbp.WriteRequest{Vault: "race", Content: "x", IdempotentID: "event"})
		writeResult <- err
	}()
	go func() {
		<-start
		enableResult <- eng.EnableClusterMode(ctx)
	}()
	close(start)
	writeErr := <-writeResult
	enableErr := <-enableResult
	if writeErr == nil && enableErr == nil {
		t.Fatal("external identity write and cluster activation both succeeded")
	}
	if writeErr != nil && !errors.Is(writeErr, ErrExternalIdentityClusterUnsupported) {
		t.Fatalf("write error = %v", writeErr)
	}
	if enableErr != nil && !errors.Is(enableErr, ErrExternalIdentityClusterDataPresent) {
		t.Fatalf("enable error = %v", enableErr)
	}
}

func TestEngineWriteBatchExternalIdentityStableAndConflict(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()
	var onWriteCalls atomic.Int32
	eng.SetOnWrite(func() { onWriteCalls.Add(1) })
	reqs := []*mbp.WriteRequest{
		{Vault: "batch-identity", Content: "same", IdempotentID: "same"},
		{Vault: "batch-identity", Content: "same", IdempotentID: "same"},
		{Vault: "batch-identity", Content: "changed", IdempotentID: "same"},
		{Vault: "batch-identity", Content: "unique", IdempotentID: "unique"},
	}
	responses, errs := eng.WriteBatch(ctx, reqs)
	if errs[0] != nil || errs[1] != nil || errs[3] != nil {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if !errors.Is(errs[2], ErrExternalIdentityConflict) {
		t.Fatalf("conflicting item error = %v", errs[2])
	}
	if responses[0].ID != responses[1].ID || responses[0].CreatedAt != responses[1].CreatedAt {
		t.Fatalf("duplicate batch responses not stable: %+v %+v", responses[0], responses[1])
	}
	if onWriteCalls.Load() != 2 || eng.engramCount.Load() != 2 {
		t.Fatalf("side effects: onWrite=%d engramCount=%d, want 2/2", onWriteCalls.Load(), eng.engramCount.Load())
	}

	retryResponses, retryErrs := eng.WriteBatch(ctx, []*mbp.WriteRequest{reqs[0], reqs[3]})
	if retryErrs[0] != nil || retryErrs[1] != nil {
		t.Fatalf("retry errors: %v", retryErrs)
	}
	if retryResponses[0].ID != responses[0].ID || retryResponses[1].ID != responses[3].ID {
		t.Fatalf("retry IDs changed: %v vs %v", retryResponses, responses)
	}
	if onWriteCalls.Load() != 2 || eng.engramCount.Load() != 2 {
		t.Fatalf("retry repeated side effects: onWrite=%d engramCount=%d", onWriteCalls.Load(), eng.engramCount.Load())
	}
}

func TestEngineWriteExternalIdentityConcurrentIdenticalAndConflict(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()
	const sameWorkers = 12
	ids := make([]string, sameWorkers)
	errs := make([]error, sameWorkers)
	var wg sync.WaitGroup
	for i := 0; i < sameWorkers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, err := eng.Write(ctx, &mbp.WriteRequest{Vault: "concurrent-identity", Content: "same", IdempotentID: "same"})
			errs[i] = err
			if resp != nil {
				ids[i] = resp.ID
			}
		}(i)
	}
	wg.Wait()
	for i := range errs {
		if errs[i] != nil || ids[i] != ids[0] {
			t.Fatalf("same worker %d: id=%q err=%v; first=%q", i, ids[i], errs[i], ids[0])
		}
	}

	start := make(chan struct{})
	conflictErrs := make(chan error, 2)
	for _, content := range []string{"a", "b"} {
		content := content
		go func() {
			<-start
			_, err := eng.Write(ctx, &mbp.WriteRequest{Vault: "concurrent-identity", Content: content, IdempotentID: "conflict"})
			conflictErrs <- err
		}()
	}
	close(start)
	errA, errB := <-conflictErrs, <-conflictErrs
	if !((errA == nil && errors.Is(errB, ErrExternalIdentityConflict)) || (errB == nil && errors.Is(errA, ErrExternalIdentityConflict))) {
		t.Fatalf("concurrent conflict errors = %v / %v", errA, errB)
	}
}

func TestMCPLegacyReceiptIsNotAuthoritativeForExternalIdentity(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()
	legacyID := storage.NewULID().String()
	if err := eng.WriteIdempotency(ctx, "legacy-op", legacyID); err != nil {
		t.Fatal(err)
	}
	resp, err := eng.Write(ctx, &mbp.WriteRequest{Vault: "legacy-receipt", Content: "new durable payload", IdempotentID: "legacy-op"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.ID == legacyID {
		t.Fatal("legacy receipt was treated as authoritative for new durable identity")
	}
	retry, err := eng.Write(ctx, &mbp.WriteRequest{Vault: "legacy-receipt", Content: "new durable payload", IdempotentID: "legacy-op"})
	if err != nil || retry.ID != resp.ID {
		t.Fatalf("durable retry = %+v err=%v, want ID %s", retry, err, resp.ID)
	}
}

func TestEngineVaultLifecycleRejectsExternalIdentityBeforeReservation(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()
	if _, err := eng.Write(ctx, &mbp.WriteRequest{Vault: "identity-source", Content: "x", IdempotentID: "event"}); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Write(ctx, &mbp.WriteRequest{Vault: "identity-target", Content: "target"}); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.StartClone(ctx, "identity-source", "should-not-exist"); !errors.Is(err, storage.ErrExternalIdentityLifecycleUnsupported) {
		t.Fatalf("clone error = %v", err)
	}
	if _, err := eng.StartMerge(ctx, "identity-source", "identity-target", false); !errors.Is(err, storage.ErrExternalIdentityLifecycleUnsupported) {
		t.Fatalf("merge error = %v", err)
	}
	names, err := eng.store.ListVaultNames()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if name == "should-not-exist" {
			t.Fatal("clone reserved target name before rejecting external identities")
		}
	}
}

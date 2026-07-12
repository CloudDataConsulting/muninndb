package trigger

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/scrypster/muninndb/internal/auth"
	"github.com/scrypster/muninndb/internal/storage"
)

// ---------------------------------------------------------------------------
// Mocks for TriggerWorker tests
// ---------------------------------------------------------------------------

type mockTriggerStore struct {
	mu      sync.Mutex
	metas   map[storage.ULID]*storage.EngramMeta
	engrams map[storage.ULID]*storage.Engram
}

func newMockTriggerStore() *mockTriggerStore {
	return &mockTriggerStore{
		metas:   make(map[storage.ULID]*storage.EngramMeta),
		engrams: make(map[storage.ULID]*storage.Engram),
	}
}

func (m *mockTriggerStore) GetMetadata(_ context.Context, _ [8]byte, ids []storage.ULID) ([]*storage.EngramMeta, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*storage.EngramMeta
	for _, id := range ids {
		if meta, ok := m.metas[id]; ok {
			out = append(out, meta)
		}
	}
	return out, nil
}

func (m *mockTriggerStore) GetEngrams(_ context.Context, _ [8]byte, ids []storage.ULID) ([]*storage.Engram, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*storage.Engram
	for _, id := range ids {
		if eng, ok := m.engrams[id]; ok {
			out = append(out, eng)
		}
	}
	return out, nil
}

func (m *mockTriggerStore) GetEmbedding(_ context.Context, _ [8]byte, _ storage.ULID) ([]float32, error) {
	return nil, nil
}

func (m *mockTriggerStore) VaultPrefix(_ string) [8]byte {
	return [8]byte{}
}

type cacheAccessRecord struct {
	mode       string
	workspace  [8]byte
	lastAccess int64
}

type cacheProbeStore struct {
	store   *storage.PebbleStore
	probeID storage.ULID
	mu      sync.Mutex
	records []cacheAccessRecord
}

func (s *cacheProbeStore) GetMetadata(ctx context.Context, ws [8]byte, ids []storage.ULID) ([]*storage.EngramMeta, error) {
	return s.store.GetMetadata(ctx, ws, ids)
}

func (s *cacheProbeStore) GetEngrams(ctx context.Context, ws [8]byte, ids []storage.ULID) ([]*storage.Engram, error) {
	engrams, err := s.store.GetEngrams(ctx, ws, ids)
	mode, _ := ctx.Value(auth.ContextMode).(string)
	s.mu.Lock()
	s.records = append(s.records, cacheAccessRecord{mode: mode, workspace: ws, lastAccess: s.store.EngramLastAccessNs(ws, s.probeID)})
	s.mu.Unlock()
	return engrams, err
}

func (s *cacheProbeStore) GetEmbedding(ctx context.Context, ws [8]byte, id storage.ULID) ([]float32, error) {
	return s.store.GetEmbedding(ctx, ws, id)
}

func (s *cacheProbeStore) VaultPrefix(vault string) [8]byte {
	return s.store.VaultPrefix(vault)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestDeliveryRouterPreservesImmutableSubscriptionPrincipal(t *testing.T) {
	registry := newRegistry()
	workspace := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	key := &auth.APIKey{ID: "principal", Vault: "observe-vault", Mode: auth.ModeObserve}
	requestCtx := context.WithValue(context.Background(), auth.ContextVault, "observe-vault")
	requestCtx = context.WithValue(requestCtx, auth.ContextMode, auth.ModeObserve)
	requestCtx = context.WithValue(requestCtx, auth.ContextAPIKey, key)
	delivered := make(chan context.Context, 1)
	sub := &Subscription{
		ID:             "principal-context",
		Workspace:      workspace,
		RequestContext: context.WithoutCancel(requestCtx),
		PassiveReads:   true,
		Deliver: func(ctx context.Context, _ *ActivationPush) error {
			delivered <- ctx
			return nil
		},
	}
	registry.Add(sub)
	(&DeliveryRouter{registry: registry}).Send(sub, &ActivationPush{})

	select {
	case ctx := <-delivered:
		if got, _ := ctx.Value(auth.ContextVault).(string); got != "observe-vault" {
			t.Fatalf("delivery vault=%q", got)
		}
		if got, _ := ctx.Value(auth.ContextMode).(string); got != auth.ModeObserve {
			t.Fatalf("delivery mode=%q", got)
		}
		if got, _ := ctx.Value(auth.ContextAPIKey).(*auth.APIKey); got != key {
			t.Fatalf("delivery principal=%p, want %p", got, key)
		}
	case <-time.After(time.Second):
		t.Fatal("delivery context was not received")
	}
}

func TestTriggerWorkerObserveReadsDoNotTrainL1AndFullModeStillDoes(t *testing.T) {
	db, err := storage.OpenPebble(t.TempDir(), storage.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	store := storage.NewPebbleStore(db, storage.PebbleStoreConfig{CacheSize: 100})
	defer store.Close()
	workspace := [8]byte{9, 8, 7, 6, 5, 4, 3, 2}
	engram := &storage.Engram{Concept: "cache probe", Content: "passive reads must not train recency"}
	if _, err := store.WriteEngram(context.Background(), workspace, engram); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetEngram(context.Background(), workspace, engram.ID); err != nil {
		t.Fatal(err)
	}
	before := store.EngramLastAccessNs(workspace, engram.ID)
	if before == 0 {
		t.Fatal("write did not warm the L1 cache")
	}
	time.Sleep(2 * time.Millisecond)

	probe := &cacheProbeStore{store: store, probeID: engram.ID}
	registry := newRegistry()
	newSub := func(id, mode string, passive bool) *Subscription {
		ctx := context.WithValue(context.Background(), auth.ContextVault, "cache-probe")
		ctx = context.WithValue(ctx, auth.ContextMode, mode)
		if passive {
			ctx = storage.ContextWithPassiveReads(ctx)
		}
		return &Subscription{
			ID:             id,
			Workspace:      workspace,
			RequestContext: context.WithoutCancel(ctx),
			PassiveReads:   passive,
			pushedScores:   make(map[storage.ULID]float64),
			rateLimiter:    newTokenBucket(10),
		}
	}
	registry.Add(newSub("full", auth.ModeFull, false))
	registry.Add(newSub("observe", auth.ModeObserve, true))
	worker := &TriggerWorker{registry: registry, store: probe, deliver: &DeliveryRouter{registry: registry}}
	worker.handleContradiction(context.Background(), ContradictEvent{Workspace: workspace, EngramA: engram.ID, EngramB: storage.NewULID()})

	probe.mu.Lock()
	records := append([]cacheAccessRecord(nil), probe.records...)
	probe.mu.Unlock()
	if len(records) != 2 {
		t.Fatalf("storage reads=%v, want full then observe", records)
	}
	if records[0].mode != auth.ModeFull || records[0].workspace != workspace || records[0].lastAccess <= before {
		t.Fatalf("full read record=%+v, before=%d", records[0], before)
	}
	if records[1].mode != auth.ModeObserve || records[1].workspace != workspace {
		t.Fatalf("observe read record=%+v", records[1])
	}
	if records[1].lastAccess != records[0].lastAccess {
		t.Fatalf("observe read advanced L1 timestamp: full=%d observe=%d", records[0].lastAccess, records[1].lastAccess)
	}
}

func TestTriggerWorkerObserveOnlyReadLeavesL1TimestampUnchanged(t *testing.T) {
	db, err := storage.OpenPebble(t.TempDir(), storage.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	store := storage.NewPebbleStore(db, storage.PebbleStoreConfig{CacheSize: 100})
	defer store.Close()
	workspace := [8]byte{7, 7, 7, 7, 1, 2, 3, 4}
	engram := &storage.Engram{Concept: "observe only", Content: "no cache mutation"}
	if _, err := store.WriteEngram(context.Background(), workspace, engram); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetEngram(context.Background(), workspace, engram.ID); err != nil {
		t.Fatal(err)
	}
	before := store.EngramLastAccessNs(workspace, engram.ID)
	time.Sleep(2 * time.Millisecond)

	probe := &cacheProbeStore{store: store, probeID: engram.ID}
	registry := newRegistry()
	observeCtx := context.WithValue(context.Background(), auth.ContextMode, auth.ModeObserve)
	registry.Add(&Subscription{
		ID:             "observe-only",
		Workspace:      workspace,
		RequestContext: context.WithoutCancel(storage.ContextWithPassiveReads(observeCtx)),
		PassiveReads:   true,
		pushedScores:   make(map[storage.ULID]float64),
		rateLimiter:    newTokenBucket(10),
	})
	worker := &TriggerWorker{registry: registry, store: probe, deliver: &DeliveryRouter{registry: registry}}
	worker.handleContradiction(context.Background(), ContradictEvent{Workspace: workspace, EngramA: engram.ID, EngramB: storage.NewULID()})
	if after := store.EngramLastAccessNs(workspace, engram.ID); after != before {
		t.Fatalf("observe-only worker advanced L1 timestamp: before=%d after=%d", before, after)
	}
}

func TestTriggerWorkerCognitiveUsesVaultScopedMetadataForSameULID(t *testing.T) {
	db, err := storage.OpenPebble(t.TempDir(), storage.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	store := storage.NewPebbleStore(db, storage.PebbleStoreConfig{CacheSize: 100})
	defer store.Close()
	workspaceA := store.VaultPrefix("same-id-a")
	workspaceB := store.VaultPrefix("same-id-b")
	id := storage.NewULID()
	engramA := &storage.Engram{ID: id, Concept: "vault A", Content: "below threshold", Confidence: 0.1, Relevance: 0.1}
	engramB := &storage.Engram{ID: id, Concept: "vault B", Content: "above threshold", Confidence: 0.9, Relevance: 0.8}
	if _, err := store.WriteEngram(context.Background(), workspaceA, engramA); err != nil {
		t.Fatalf("WriteEngram(workspaceA): %v", err)
	}
	if _, err := store.WriteEngram(context.Background(), workspaceB, engramB); err != nil {
		t.Fatalf("WriteEngram(workspaceB): %v", err)
	}
	// Warm workspace A first. An ID-only metadata cache would now poison the
	// cognitive read for workspace B below.
	if _, err := store.GetMetadata(context.Background(), workspaceA, []storage.ULID{id}); err != nil {
		t.Fatalf("GetMetadata(workspaceA): %v", err)
	}

	registry := newRegistry()
	delivered := make(chan *ActivationPush, 1)
	sub := &Subscription{
		ID:           "same-id-b",
		Workspace:    workspaceB,
		Threshold:    0.1,
		Deliver:      func(_ context.Context, push *ActivationPush) error { delivered <- push; return nil },
		pushedScores: make(map[storage.ULID]float64),
		rateLimiter:  newTokenBucket(10),
	}
	if err := registry.Add(sub); err != nil {
		t.Fatalf("registry.Add: %v", err)
	}
	worker := &TriggerWorker{registry: registry, store: store, deliver: &DeliveryRouter{registry: registry}}
	worker.handleCognitive(context.Background(), CognitiveEvent{Workspace: workspaceB, EngramID: id, Delta: 1})

	select {
	case push := <-delivered:
		if push.Score < sub.Threshold {
			t.Fatalf("workspace B score=%v, threshold=%v", push.Score, sub.Threshold)
		}
	case <-time.After(time.Second):
		t.Fatal("workspace B cognitive event was scored with workspace A metadata")
	}
}

func TestTriggerWorker_HandleWrite_NewEngram(t *testing.T) {
	registry := newRegistry()
	deliver := &DeliveryRouter{registry: registry}

	var pushCount atomic.Int32
	sub := &Subscription{
		ID:             "test-sub-1",
		Workspace:      testWorkspace(1),
		Context:        []string{"test context"},
		Threshold:      0.0,
		DeltaThreshold: 0.0,
		PushOnWrite:    true,
		expiresAt:      time.Now().Add(1 * time.Hour),
		Deliver: func(ctx context.Context, push *ActivationPush) error {
			pushCount.Add(1)
			return nil
		},
		pushedScores: make(map[storage.ULID]float64),
		rateLimiter:  newTokenBucket(10),
	}
	registry.Add(sub)

	writeCh := make(chan *EngramEvent, 10)
	cogCh := make(chan CognitiveEvent, 10)
	contraCh := make(chan ContradictEvent, 10)

	worker := &TriggerWorker{
		registry:     registry,
		embedCache:   newEmbedCache(),
		deliver:      deliver,
		writeEvents:  writeCh,
		cogEvents:    cogCh,
		contraEvents: contraCh,
	}

	engID := storage.NewULID()
	writeCh <- &EngramEvent{
		Workspace: testWorkspace(1),
		IsNew:     true,
		Engram: &storage.Engram{
			ID:         engID,
			Concept:    "test concept",
			Content:    "test content",
			Confidence: 0.9,
			Relevance:  0.8,
			Stability:  30,
			CreatedAt:  time.Now(),
			LastAccess: time.Now(),
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		worker.Run(ctx)
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	if pushCount.Load() < 1 {
		t.Errorf("expected at least 1 push for new write, got %d", pushCount.Load())
	}
}

func TestTriggerWorker_HandleWrite_SkipsUpdates(t *testing.T) {
	registry := newRegistry()
	deliver := &DeliveryRouter{registry: registry}

	var pushCount atomic.Int32
	sub := &Subscription{
		ID:          "test-sub-2",
		Workspace:   testWorkspace(1),
		Context:     []string{"test"},
		Threshold:   0.0,
		PushOnWrite: true,
		expiresAt:   time.Now().Add(1 * time.Hour),
		Deliver: func(ctx context.Context, push *ActivationPush) error {
			pushCount.Add(1)
			return nil
		},
		pushedScores: make(map[storage.ULID]float64),
		rateLimiter:  newTokenBucket(10),
	}
	registry.Add(sub)

	writeCh := make(chan *EngramEvent, 10)
	cogCh := make(chan CognitiveEvent, 10)
	contraCh := make(chan ContradictEvent, 10)

	worker := &TriggerWorker{
		registry:     registry,
		embedCache:   newEmbedCache(),
		deliver:      deliver,
		writeEvents:  writeCh,
		cogEvents:    cogCh,
		contraEvents: contraCh,
	}

	writeCh <- &EngramEvent{
		Workspace: testWorkspace(1),
		IsNew:     false,
		Engram: &storage.Engram{
			ID:         storage.NewULID(),
			Concept:    "updated",
			Content:    "updated content",
			Confidence: 0.9,
			Relevance:  0.8,
			Stability:  30,
			CreatedAt:  time.Now(),
			LastAccess: time.Now(),
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		worker.Run(ctx)
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	if pushCount.Load() != 0 {
		t.Errorf("expected 0 pushes for update (not new), got %d", pushCount.Load())
	}
}

func TestTriggerWorker_HandleContradiction(t *testing.T) {
	registry := newRegistry()
	deliver := &DeliveryRouter{registry: registry}
	tStore := newMockTriggerStore()

	engA := storage.NewULID()
	engB := storage.NewULID()
	tStore.engrams[engA] = &storage.Engram{ID: engA, Concept: "claim 1", Content: "x", State: storage.StateActive}
	tStore.engrams[engB] = &storage.Engram{ID: engB, Concept: "claim 2", Content: "y", State: storage.StateActive}

	var pushCount atomic.Int32
	sub := &Subscription{
		ID:        "contra-sub",
		Workspace: testWorkspace(1),
		Context:   []string{"test"},
		Threshold: 0.0,
		expiresAt: time.Now().Add(1 * time.Hour),
		Deliver: func(ctx context.Context, push *ActivationPush) error {
			pushCount.Add(1)
			return nil
		},
		pushedScores: map[storage.ULID]float64{engA: 0.8},
		rateLimiter:  newTokenBucket(10),
	}
	registry.Add(sub)

	writeCh := make(chan *EngramEvent, 10)
	cogCh := make(chan CognitiveEvent, 10)
	contraCh := make(chan ContradictEvent, 10)

	worker := &TriggerWorker{
		registry:     registry,
		embedCache:   newEmbedCache(),
		store:        tStore,
		deliver:      deliver,
		writeEvents:  writeCh,
		cogEvents:    cogCh,
		contraEvents: contraCh,
	}

	contraCh <- ContradictEvent{
		Workspace: testWorkspace(1),
		EngramA:   engA,
		EngramB:   engB,
		Severity:  0.8,
		Type:      "semantic",
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		worker.Run(ctx)
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	if pushCount.Load() < 1 {
		t.Errorf("expected at least 1 contradiction push, got %d", pushCount.Load())
	}
}

func TestTriggerWorker_ContextCancellation(t *testing.T) {
	registry := newRegistry()
	deliver := &DeliveryRouter{registry: registry}

	writeCh := make(chan *EngramEvent, 10)
	cogCh := make(chan CognitiveEvent, 10)
	contraCh := make(chan ContradictEvent, 10)

	worker := &TriggerWorker{
		registry:     registry,
		embedCache:   newEmbedCache(),
		deliver:      deliver,
		writeEvents:  writeCh,
		cogEvents:    cogCh,
		contraEvents: contraCh,
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		worker.Run(ctx)
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("TriggerWorker.Run did not exit after context cancellation")
	}
}

func TestTriggerWorker_ChannelClose(t *testing.T) {
	registry := newRegistry()
	deliver := &DeliveryRouter{registry: registry}

	writeCh := make(chan *EngramEvent, 10)
	cogCh := make(chan CognitiveEvent, 10)
	contraCh := make(chan ContradictEvent, 10)

	worker := &TriggerWorker{
		registry:     registry,
		embedCache:   newEmbedCache(),
		deliver:      deliver,
		writeEvents:  writeCh,
		cogEvents:    cogCh,
		contraEvents: contraCh,
	}

	ctx := context.Background()
	done := make(chan struct{})
	go func() {
		worker.Run(ctx)
		close(done)
	}()

	close(contraCh)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("TriggerWorker.Run did not exit after channel close")
	}
}

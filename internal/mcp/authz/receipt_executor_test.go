package authz

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/scrypster/muninndb/internal/auth"
)

var (
	errFakeReceiptRead        = errors.New("fake receipt read failed")
	errFakePrePublish         = errors.New("fake pre-publish failure")
	errFakeCommitAckLost      = errors.New("fake commit acknowledgment lost")
	errFakePreSettlementWrite = errors.New("fake pre-settlement write failure")
	errFakeSettlementAckLost  = errors.New("fake settlement acknowledgment lost")
)

type receiptIdentity struct {
	vaultIdentity   string
	vaultGeneration uint64
	operation       string
	opID            string
}

func identityFromClaim(claim ReceiptClaim) receiptIdentity {
	return receiptIdentity{
		vaultIdentity:   claim.vaultIdentity,
		vaultGeneration: claim.vaultGeneration,
		operation:       claim.operation.value,
		opID:            claim.opID,
	}
}

type authorizedReceiptRequest struct {
	operation      AuthorizedOperation
	principalStore PrincipalStore
	scopeSource    StableVaultScopeSource
	claim          ReceiptClaim
}

func (r authorizedReceiptRequest) validate() error {
	if r.operation.validate() != nil || r.principalStore == nil || r.scopeSource == nil {
		return ErrInvalidAuthorizedOperation
	}
	return r.claim.validate()
}

type fakeAtomicReceiptStore struct {
	mu      sync.Mutex
	records map[receiptIdentity]ReceiptRecord
	effects map[receiptIdentity]int
	locks   map[receiptIdentity]*sync.Mutex

	reads       atomic.Int64
	settlements atomic.Int64

	readErr                error
	prePublishFailureOnce  atomic.Bool
	commitAckLostOnce      atomic.Bool
	preSettlementWriteOnce atomic.Bool
	settleAckLostOnce      atomic.Bool
	afterCommit            func()
}

func newFakeAtomicReceiptStore() *fakeAtomicReceiptStore {
	return &fakeAtomicReceiptStore{
		records: make(map[receiptIdentity]ReceiptRecord),
		effects: make(map[receiptIdentity]int),
		locks:   make(map[receiptIdentity]*sync.Mutex),
	}
}

func (s *fakeAtomicReceiptStore) keyLock(key receiptIdentity) *sync.Mutex {
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, ok := s.locks[key]
	if !ok {
		lock = &sync.Mutex{}
		s.locks[key] = lock
	}
	return lock
}

func (s *fakeAtomicReceiptStore) load(key receiptIdentity) (ReceiptRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[key]
	return record.clone(), ok
}

func (s *fakeAtomicReceiptStore) putRecord(key receiptIdentity, record ReceiptRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[key] = record.clone()
}

func (s *fakeAtomicReceiptStore) jointSnapshot(
	key receiptIdentity,
) (ReceiptRecord, bool, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[key]
	return record.clone(), ok, s.effects[key]
}

func (s *fakeAtomicReceiptStore) totalEffects() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	total := 0
	for _, count := range s.effects {
		total += count
	}
	return total
}

func (s *fakeAtomicReceiptStore) executeAuthorized(
	ctx context.Context,
	principalStore PrincipalStore,
	scopeSource StableVaultScopeSource,
	session SessionPin,
	requestedVault string,
	tool string,
	opID string,
	canonical []byte,
	stage func(context.Context) (ReceiptCompletion, error),
) (ReceiptOutcome, error) {
	authorizedContext, operation, err := AuthorizeOperation(
		ctx,
		principalStore,
		session,
		requestedVault,
		tool,
	)
	if err != nil {
		return ReceiptOutcome{}, err
	}
	scope, err := ResolveStableVaultScope(authorizedContext, scopeSource, operation)
	if err != nil {
		return ReceiptOutcome{}, err
	}
	claim, err := NewReceiptClaim(operation, scope, opID, canonical)
	if err != nil {
		return ReceiptOutcome{}, err
	}
	return s.execute(ctx, authorizedReceiptRequest{
		operation:      operation,
		principalStore: principalStore,
		scopeSource:    scopeSource,
		claim:          claim,
	}, stage)
}

func (s *fakeAtomicReceiptStore) revalidateRequest(
	ctx context.Context,
	request authorizedReceiptRequest,
) (context.Context, error) {
	authorizedContext, refreshed, err := request.operation.Revalidate(ctx, request.principalStore)
	if err != nil {
		return nil, err
	}
	scope, err := ResolveStableVaultScope(authorizedContext, request.scopeSource, refreshed)
	if err != nil {
		return nil, err
	}
	if err := request.claim.authorizedBy(refreshed, scope); err != nil {
		return nil, err
	}
	return authorizedContext, nil
}

func (s *fakeAtomicReceiptStore) execute(
	ctx context.Context,
	request authorizedReceiptRequest,
	stage func(context.Context) (ReceiptCompletion, error),
) (ReceiptOutcome, error) {
	if err := request.validate(); err != nil {
		return ReceiptOutcome{}, err
	}
	key := identityFromClaim(request.claim)
	lock := s.keyLock(key)
	lock.Lock()
	defer lock.Unlock()

	// The authorization tick occurs after waiting for the exact-key lock and
	// before any receipt read, replay, or canonical staging work.
	authorizedContext, err := s.revalidateRequest(ctx, request)
	if err != nil {
		return ReceiptOutcome{}, err
	}

	s.reads.Add(1)
	if s.readErr != nil {
		return ReceiptOutcome{}, s.readErr
	}
	record, found := s.load(key)
	var existing *ReceiptRecord
	if found {
		existing = &record
	}
	evaluation, err := EvaluateReceipt(request.claim, existing)
	if err != nil {
		return ReceiptOutcome{}, err
	}
	switch evaluation {
	case ReceiptAbsent:
		completion, err := stage(authorizedContext)
		if err != nil {
			return ReceiptOutcome{}, err
		}
		committed, err := NewCommittedReceipt(request.claim, completion)
		if err != nil {
			return ReceiptOutcome{}, err
		}
		if s.prePublishFailureOnce.CompareAndSwap(true, false) {
			return ReceiptOutcome{}, errFakePrePublish
		}
		// Revalidate again immediately before the fake atomic publish point.
		if _, err := s.revalidateRequest(ctx, request); err != nil {
			return ReceiptOutcome{}, err
		}
		// The effect and Committed record are published under one mutex and
		// can only be observed together through jointSnapshot.
		s.mu.Lock()
		s.effects[key]++
		s.records[key] = committed.clone()
		s.mu.Unlock()
		if s.afterCommit != nil {
			s.afterCommit()
		}
		if err := ctx.Err(); err != nil {
			return ReceiptOutcome{}, err
		}
		if s.commitAckLostOnce.CompareAndSwap(true, false) {
			return ReceiptOutcome{}, errFakeCommitAckLost
		}
		record = committed
	case ReceiptResumeCommitted:
		record = record.clone()
	case ReceiptReplaySettled:
		return NewReplayedReceiptOutcome(record)
	case ReceiptEvaluationConflict:
		return NewConflictReceiptOutcome(), nil
	default:
		return ReceiptOutcome{}, ErrReceiptCorrupt
	}

	envelope := append([]byte("receipt-envelope:"), record.completion.resultSeed...)
	settled, _, err := SettleReceipt(record, request.claim, envelope)
	if err != nil {
		return ReceiptOutcome{}, err
	}
	if s.preSettlementWriteOnce.CompareAndSwap(true, false) {
		return ReceiptOutcome{}, errFakePreSettlementWrite
	}
	s.putRecord(key, settled)
	s.settlements.Add(1)
	if s.settleAckLostOnce.CompareAndSwap(true, false) {
		return ReceiptOutcome{}, errFakeSettlementAckLost
	}
	if evaluation == ReceiptAbsent {
		return NewExecutedReceiptOutcome(settled)
	}
	return NewReplayedReceiptOutcome(settled)
}

func sessionForReceiptTest(
	t *testing.T,
	vault string,
	mode string,
) (SessionPin, *fakePrincipalStore) {
	t.Helper()
	principal, err := NewPrincipal(PrincipalClaims{
		Kind:          auth.PrincipalAPIKey,
		Vault:         vault,
		Mode:          mode,
		CredentialRef: "sha256:" + vault + ":" + mode,
		KeyID:         "key-" + vault + "-" + mode,
	})
	if err != nil {
		t.Fatal(err)
	}
	store := &fakePrincipalStore{
		principals: map[string]Principal{principal.CredentialRef(): principal},
		errs:       make(map[string]error),
	}
	current, err := RevalidatePinned(context.Background(), store, principal)
	if err != nil {
		t.Fatal(err)
	}
	session, err := NewSessionPin(current)
	if err != nil {
		t.Fatal(err)
	}
	return session, store
}

func scopeSourceFor(vault, identity string, generation uint64) StableVaultScopeSource {
	return staticStableVaultScopeSource{claims: StableVaultScopeClaims{
		CanonicalVault: vault,
		Identity:       identity,
		Generation:     generation,
	}}
}

func receiptRequestForTest(
	t *testing.T,
	vault string,
	tool string,
	opID string,
	canonical string,
) (authorizedReceiptRequest, *fakePrincipalStore) {
	t.Helper()
	session, principalStore := sessionForReceiptTest(t, vault, auth.ModeFull)
	_, operation, err := AuthorizeOperation(
		context.Background(), principalStore, session, vault, tool,
	)
	if err != nil {
		t.Fatal(err)
	}
	source := scopeSourceFor(vault, "stable:"+vault, 1)
	scope, err := ResolveStableVaultScope(context.Background(), source, operation)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := NewReceiptClaim(operation, scope, opID, []byte(canonical))
	if err != nil {
		t.Fatal(err)
	}
	return authorizedReceiptRequest{
		operation:      operation,
		principalStore: principalStore,
		scopeSource:    source,
		claim:          claim,
	}, principalStore
}

func completionBuilder(
	target string,
	seed string,
	calls *atomic.Int64,
) func(context.Context) (ReceiptCompletion, error) {
	return func(ctx context.Context) (ReceiptCompletion, error) {
		if _, ok := PrincipalFromContext(ctx); !ok {
			return ReceiptCompletion{}, ErrMissingPrincipal
		}
		if calls != nil {
			calls.Add(1)
		}
		return NewReceiptCompletion(target, []byte(seed))
	}
}

func TestReceiptCoordinatorAuthorizationDenialsNeverReadReceiptStore(t *testing.T) {
	tests := []struct {
		name           string
		makeSession    func(*testing.T) (SessionPin, PrincipalStore)
		requestedVault string
		tool           string
		ctx            func() context.Context
		wantErr        error
	}{
		{
			name: "zero session", makeSession: func(*testing.T) (SessionPin, PrincipalStore) {
				return SessionPin{}, &fakePrincipalStore{principals: map[string]Principal{}, errs: map[string]error{}}
			}, tool: "muninn_forget", ctx: context.Background, wantErr: ErrInvalidPrincipal,
		},
		{
			name: "observe mutation", makeSession: func(t *testing.T) (SessionPin, PrincipalStore) {
				session, store := sessionForReceiptTest(t, "client-a", auth.ModeObserve)
				return session, store
			}, tool: "muninn_forget", ctx: context.Background, wantErr: ErrToolForbidden,
		},
		{
			name: "cross vault", makeSession: func(t *testing.T) (SessionPin, PrincipalStore) {
				session, store := sessionForReceiptTest(t, "client-a", auth.ModeFull)
				return session, store
			}, requestedVault: "client-b", tool: "muninn_forget", ctx: context.Background, wantErr: ErrVaultMismatch,
		},
		{
			name: "unknown tool", makeSession: func(t *testing.T) (SessionPin, PrincipalStore) {
				session, store := sessionForReceiptTest(t, "client-a", auth.ModeFull)
				return session, store
			}, tool: "muninn_future_tool", ctx: context.Background, wantErr: ErrUnknownTool,
		},
		{
			name: "entity blocked remember", makeSession: func(t *testing.T) (SessionPin, PrincipalStore) {
				session, store := sessionForReceiptTest(t, "client-a", auth.ModeFull)
				return session, store
			}, tool: "muninn_remember", ctx: context.Background, wantErr: ErrEntityPolicyDisabled,
		},
		{
			name: "revoked", makeSession: func(t *testing.T) (SessionPin, PrincipalStore) {
				session, store := sessionForReceiptTest(t, "client-a", auth.ModeFull)
				store.errs[session.principal.CredentialRef()] = errNotAuthorized
				return session, store
			}, tool: "muninn_forget", ctx: context.Background, wantErr: errNotAuthorized,
		},
		{
			name: "expired", makeSession: func(t *testing.T) (SessionPin, PrincipalStore) {
				principal := Principal{
					valid: true, kind: auth.PrincipalAPIKey, vault: "client-a", mode: auth.ModeFull,
					credentialRef: "sha256:expired", keyID: "expired", hasExpiry: true,
					expiresAt: time.Now().Add(-time.Hour),
				}
				store := &fakePrincipalStore{
					principals: map[string]Principal{principal.CredentialRef(): principal},
					errs:       make(map[string]error),
				}
				return SessionPin{principal: principal}, store
			}, tool: "muninn_forget", ctx: context.Background, wantErr: ErrPrincipalExpired,
		},
		{
			name: "canceled", makeSession: func(t *testing.T) (SessionPin, PrincipalStore) {
				session, store := sessionForReceiptTest(t, "client-a", auth.ModeFull)
				store.errs[session.principal.CredentialRef()] = context.Canceled
				return session, store
			}, tool: "muninn_forget", ctx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			}, wantErr: context.Canceled,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			receipts := newFakeAtomicReceiptStore()
			session, principalStore := tc.makeSession(t)
			_, err := receipts.executeAuthorized(
				tc.ctx(), principalStore,
				scopeSourceFor("client-a", "stable:client-a", 1),
				session, tc.requestedVault, tc.tool, "op-1", []byte("{}"),
				completionBuilder("target", "seed", nil),
			)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
			if got := receipts.reads.Load(); got != 0 {
				t.Fatalf("receipt reads = %d, want zero", got)
			}
			if got := receipts.totalEffects(); got != 0 {
				t.Fatalf("canonical effects = %d, want zero", got)
			}
		})
	}
}

func TestFakeAtomicReceiptRevalidatesAfterKeyWaitBeforeRead(t *testing.T) {
	request, principalStore := receiptRequestForTest(
		t, "client-a", "muninn_forget", "op-1", `{"id":"01"}`,
	)
	receipts := newFakeAtomicReceiptStore()
	key := identityFromClaim(request.claim)
	lock := receipts.keyLock(key)
	lock.Lock()

	started := make(chan struct{})
	result := make(chan error, 1)
	var stages atomic.Int64
	go func() {
		close(started)
		_, err := receipts.execute(
			context.Background(), request,
			completionBuilder("engram:01", "seed", &stages),
		)
		result <- err
	}()
	<-started
	principalStore.errs[request.operation.session.principal.CredentialRef()] = errNotAuthorized
	lock.Unlock()

	if err := <-result; !errors.Is(err, errNotAuthorized) {
		t.Fatalf("queued revocation error = %v, want denial", err)
	}
	if receipts.reads.Load() != 0 || receipts.totalEffects() != 0 || stages.Load() != 0 {
		t.Fatalf("denied queued request touched state: reads=%d effects=%d stages=%d",
			receipts.reads.Load(), receipts.totalEffects(), stages.Load())
	}
}

func TestFakeAtomicReceiptFirstExecutionReplayAndConflict(t *testing.T) {
	request, _ := receiptRequestForTest(
		t, "client-a", "muninn_forget", "op-1", `{"id":"01"}`,
	)
	receipts := newFakeAtomicReceiptStore()
	var stages atomic.Int64
	stage := completionBuilder("engram:01", "seed-01", &stages)

	executed, err := receipts.execute(context.Background(), request, stage)
	if err != nil || executed.Disposition() != ReceiptExecuted {
		t.Fatalf("first outcome = %#v, %v", executed, err)
	}
	replayed, err := receipts.execute(context.Background(), request, stage)
	if err != nil || replayed.Disposition() != ReceiptReplayed ||
		string(replayed.Envelope()) != string(executed.Envelope()) {
		t.Fatalf("replay outcome = %#v, %v", replayed, err)
	}
	changed := request
	changed.claim, err = NewReceiptClaim(
		request.operation,
		stableScopeForOperation(t, request.operation, request.claim.vaultIdentity, request.claim.vaultGeneration),
		request.claim.opID,
		[]byte(`{"id":"02"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	conflict, err := receipts.execute(context.Background(), changed, stage)
	if err != nil || conflict.Disposition() != ReceiptInvocationConflict || conflict.Envelope() != nil {
		t.Fatalf("conflict outcome = %#v, %v", conflict, err)
	}
	if stages.Load() != 1 || receipts.totalEffects() != 1 {
		t.Fatalf("stages=%d effects=%d, want one each", stages.Load(), receipts.totalEffects())
	}
}

func TestFakeAtomicReceiptScopesSameOpIDByExactStableTuple(t *testing.T) {
	receipts := newFakeAtomicReceiptStore()
	var stages atomic.Int64
	for _, tc := range []struct {
		vault string
		tool  string
	}{
		{vault: "client-a", tool: "muninn_forget"},
		{vault: "client-b", tool: "muninn_forget"},
		{vault: "client-a", tool: "muninn_feedback"},
	} {
		request, _ := receiptRequestForTest(t, tc.vault, tc.tool, "same|op:id", `{"value":"x"}`)
		outcome, err := receipts.execute(
			context.Background(), request,
			completionBuilder(tc.vault+":"+tc.tool, tc.tool, &stages),
		)
		if err != nil || outcome.Disposition() != ReceiptExecuted {
			t.Fatalf("%s/%s outcome = %#v, %v", tc.vault, tc.tool, outcome, err)
		}
	}
	if stages.Load() != 3 || receipts.totalEffects() != 3 {
		t.Fatalf("scope accounting stages=%d effects=%d", stages.Load(), receipts.totalEffects())
	}
}

func TestFakeAtomicReceiptFailsClosedOnReadErrorCollisionAndCorruption(t *testing.T) {
	request, _ := receiptRequestForTest(
		t, "client-a", "muninn_forget", "op-1", `{"id":"01"}`,
	)
	receipts := newFakeAtomicReceiptStore()
	receipts.readErr = errFakeReceiptRead
	if _, err := receipts.execute(
		context.Background(), request, completionBuilder("target", "seed", nil),
	); !errors.Is(err, errFakeReceiptRead) {
		t.Fatalf("read error = %v", err)
	}
	if receipts.totalEffects() != 0 {
		t.Fatal("read error executed canonical effect")
	}

	receipts.readErr = nil
	otherRequest, _ := receiptRequestForTest(
		t, "client-b", "muninn_forget", "op-1", `{"id":"01"}`,
	)
	otherRecord, err := NewCommittedReceipt(otherRequest.claim, testReceiptCompletion(t))
	if err != nil {
		t.Fatal(err)
	}
	key := identityFromClaim(request.claim)
	receipts.putRecord(key, otherRecord)
	if _, err := receipts.execute(
		context.Background(), request, completionBuilder("target", "seed", nil),
	); !errors.Is(err, ErrReceiptCollision) {
		t.Fatalf("forced collision error = %v", err)
	}

	corrupt := otherRecord
	corrupt.version = 99
	receipts.putRecord(key, corrupt)
	if _, err := receipts.execute(
		context.Background(), request, completionBuilder("target", "seed", nil),
	); !errors.Is(err, ErrReceiptCorrupt) {
		t.Fatalf("corruption error = %v", err)
	}
	if receipts.totalEffects() != 0 {
		t.Fatal("collision/corruption executed canonical effect")
	}
}

func TestFakeAtomicReceiptSuccessfulStageThenPrePublishFailureIsInvisible(t *testing.T) {
	request, _ := receiptRequestForTest(
		t, "client-a", "muninn_forget", "op-1", `{"id":"01"}`,
	)
	receipts := newFakeAtomicReceiptStore()
	receipts.prePublishFailureOnce.Store(true)
	var stages atomic.Int64
	stage := completionBuilder("engram:01", "seed", &stages)
	if _, err := receipts.execute(context.Background(), request, stage); !errors.Is(err, errFakePrePublish) {
		t.Fatalf("pre-publish error = %v", err)
	}
	record, found, effects := receipts.jointSnapshot(identityFromClaim(request.claim))
	if found || effects != 0 || record.valid {
		t.Fatalf("partial publish visible: record=%#v found=%v effects=%d", record, found, effects)
	}
	if stages.Load() != 1 {
		t.Fatalf("successful staging calls = %d, want 1", stages.Load())
	}
	outcome, err := receipts.execute(context.Background(), request, stage)
	if err != nil || outcome.Disposition() != ReceiptExecuted || receipts.totalEffects() != 1 {
		t.Fatalf("retry outcome = %#v, %v effects=%d", outcome, err, receipts.totalEffects())
	}
}

func TestFakeAtomicReceiptCrashCutsRecoverWithoutReexecution(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*fakeAtomicReceiptStore, context.CancelFunc)
		wantErr   error
		wantState ReceiptState
	}{
		{
			name: "commit ack lost", configure: func(s *fakeAtomicReceiptStore, _ context.CancelFunc) {
				s.commitAckLostOnce.Store(true)
			}, wantErr: errFakeCommitAckLost, wantState: ReceiptCommitted,
		},
		{
			name: "pre-settlement write failure", configure: func(s *fakeAtomicReceiptStore, _ context.CancelFunc) {
				s.preSettlementWriteOnce.Store(true)
			}, wantErr: errFakePreSettlementWrite, wantState: ReceiptCommitted,
		},
		{
			name: "settlement ack lost", configure: func(s *fakeAtomicReceiptStore, _ context.CancelFunc) {
				s.settleAckLostOnce.Store(true)
			}, wantErr: errFakeSettlementAckLost, wantState: ReceiptSettled,
		},
		{
			name: "canceled after commit", configure: func(s *fakeAtomicReceiptStore, cancel context.CancelFunc) {
				s.afterCommit = cancel
			}, wantErr: context.Canceled, wantState: ReceiptCommitted,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			request, _ := receiptRequestForTest(
				t, "client-a", "muninn_forget", "op-1", `{"id":"01"}`,
			)
			receipts := newFakeAtomicReceiptStore()
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			tc.configure(receipts, cancel)
			var stages atomic.Int64
			stage := completionBuilder("engram:01", "seed-01", &stages)
			if _, err := receipts.execute(ctx, request, stage); !errors.Is(err, tc.wantErr) {
				t.Fatalf("first error = %v, want %v", err, tc.wantErr)
			}
			record, found, effects := receipts.jointSnapshot(identityFromClaim(request.claim))
			if !found || record.State() != tc.wantState || effects != 1 {
				t.Fatalf("joint state record=%#v found=%v effects=%d; want %v/1", record, found, effects, tc.wantState)
			}
			receipts.afterCommit = nil
			replayed, err := receipts.execute(context.Background(), request, stage)
			if err != nil || replayed.Disposition() != ReceiptReplayed {
				t.Fatalf("retry outcome = %#v, %v", replayed, err)
			}
			if stages.Load() != 1 || receipts.totalEffects() != 1 {
				t.Fatalf("retry duplicated work: stages=%d effects=%d", stages.Load(), receipts.totalEffects())
			}
		})
	}
}

func TestFakeAtomicReceiptStageFailureLeavesNothing(t *testing.T) {
	request, _ := receiptRequestForTest(
		t, "client-a", "muninn_forget", "op-1", `{"id":"01"}`,
	)
	receipts := newFakeAtomicReceiptStore()
	errStage := errors.New("canonical staging failed")
	if _, err := receipts.execute(context.Background(), request, func(context.Context) (ReceiptCompletion, error) {
		return ReceiptCompletion{}, errStage
	}); !errors.Is(err, errStage) {
		t.Fatalf("stage error = %v", err)
	}
	if _, found, effects := receipts.jointSnapshot(identityFromClaim(request.claim)); found || effects != 0 {
		t.Fatalf("failed stage published record/effect: found=%v effects=%d", found, effects)
	}
}

func TestFakeAtomicReceiptConcurrentIdenticalRequestExecutesOnce(t *testing.T) {
	request, _ := receiptRequestForTest(
		t, "client-a", "muninn_forget", "op-1", `{"id":"01"}`,
	)
	receipts := newFakeAtomicReceiptStore()
	const workers = 128
	start := make(chan struct{})
	results := make(chan ReceiptOutcome, workers)
	errs := make(chan error, workers)
	var stages atomic.Int64
	var group sync.WaitGroup
	group.Add(workers)
	for range workers {
		go func() {
			defer group.Done()
			<-start
			outcome, err := receipts.execute(
				context.Background(), request,
				completionBuilder("engram:01", "seed", &stages),
			)
			results <- outcome
			errs <- err
		}()
	}
	close(start)
	group.Wait()
	close(results)
	close(errs)

	counts := map[ReceiptDisposition]int{}
	for outcome := range results {
		counts[outcome.Disposition()]++
	}
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent error: %v", err)
		}
	}
	if counts[ReceiptExecuted] != 1 || counts[ReceiptReplayed] != workers-1 ||
		stages.Load() != 1 || receipts.totalEffects() != 1 {
		t.Fatalf("outcomes=%v stages=%d effects=%d", counts, stages.Load(), receipts.totalEffects())
	}
}

func TestFakeAtomicReceiptConcurrentDigestGroupsHaveOneWinner(t *testing.T) {
	requestA, _ := receiptRequestForTest(
		t, "client-a", "muninn_forget", "op-1", `{"id":"A"}`,
	)
	requestB := requestA
	scope := stableScopeForOperation(
		t,
		requestA.operation,
		requestA.claim.vaultIdentity,
		requestA.claim.vaultGeneration,
	)
	var err error
	requestB.claim, err = NewReceiptClaim(
		requestA.operation, scope, requestA.claim.opID, []byte(`{"id":"B"}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	receipts := newFakeAtomicReceiptStore()
	const perGroup = 64
	start := make(chan struct{})
	results := make(chan ReceiptOutcome, perGroup*2)
	errs := make(chan error, perGroup*2)
	var stages atomic.Int64
	var group sync.WaitGroup
	for _, request := range []authorizedReceiptRequest{requestA, requestB} {
		for range perGroup {
			group.Add(1)
			go func(request authorizedReceiptRequest) {
				defer group.Done()
				<-start
				outcome, err := receipts.execute(
					context.Background(), request,
					completionBuilder("engram:winner", "seed", &stages),
				)
				results <- outcome
				errs <- err
			}(request)
		}
	}
	close(start)
	group.Wait()
	close(results)
	close(errs)

	counts := map[ReceiptDisposition]int{}
	for outcome := range results {
		counts[outcome.Disposition()]++
	}
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent digest error: %v", err)
		}
	}
	if counts[ReceiptExecuted] != 1 || counts[ReceiptReplayed] != perGroup-1 ||
		counts[ReceiptInvocationConflict] != perGroup || stages.Load() != 1 ||
		receipts.totalEffects() != 1 {
		t.Fatalf("outcomes=%v stages=%d effects=%d", counts, stages.Load(), receipts.totalEffects())
	}
}

func TestFakeAtomicReceiptDifferentKeysProgressIndependently(t *testing.T) {
	requestA, _ := receiptRequestForTest(
		t, "client-a", "muninn_forget", "op-a", `{"id":"A"}`,
	)
	requestB, _ := receiptRequestForTest(
		t, "client-a", "muninn_forget", "op-b", `{"id":"B"}`,
	)
	receipts := newFakeAtomicReceiptStore()
	enteredA := make(chan struct{})
	releaseA := make(chan struct{})
	doneA := make(chan error, 1)
	go func() {
		_, err := receipts.execute(context.Background(), requestA, func(ctx context.Context) (ReceiptCompletion, error) {
			if _, ok := PrincipalFromContext(ctx); !ok {
				return ReceiptCompletion{}, ErrMissingPrincipal
			}
			close(enteredA)
			<-releaseA
			return NewReceiptCompletion("engram:A", []byte("seed-A"))
		})
		doneA <- err
	}()
	<-enteredA
	doneB := make(chan error, 1)
	go func() {
		_, err := receipts.execute(
			context.Background(), requestB,
			completionBuilder("engram:B", "seed-B", nil),
		)
		doneB <- err
	}()
	select {
	case err := <-doneB:
		if err != nil {
			t.Fatalf("independent key failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("independent key was globally serialized")
	}
	close(releaseA)
	if err := <-doneA; err != nil {
		t.Fatalf("blocked key failed: %v", err)
	}
	if receipts.totalEffects() != 2 {
		t.Fatalf("canonical effects = %d, want 2", receipts.totalEffects())
	}
}

package engine

import (
	"context"
	"testing"
	"time"

	"github.com/scrypster/muninndb/internal/auth"
	"github.com/scrypster/muninndb/internal/scoring"
	"github.com/scrypster/muninndb/internal/storage"
	"github.com/scrypster/muninndb/internal/transport/mbp"
)

func TestRead_ObserveModeDoesNotPersistFeedbackWeights(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()

	writeResp, err := eng.Write(context.Background(), &mbp.WriteRequest{
		Vault:   "observe-read",
		Concept: "observe read feedback",
		Content: "an observe-mode read must not train scoring weights",
	})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	id, err := storage.ParseULID(writeResp.ID)
	if err != nil {
		t.Fatalf("ParseULID: %v", err)
	}
	ws := eng.store.ResolveVaultPrefix("observe-read")
	lastAccessBefore := eng.store.EngramLastAccessNs(ws, id)

	observeCtx := context.WithValue(context.Background(), auth.ContextMode, auth.ModeObserve)
	if _, err := eng.Read(observeCtx, &mbp.ReadRequest{Vault: "observe-read", ID: writeResp.ID}); err != nil {
		t.Fatalf("observe Read: %v", err)
	}
	eng.fireAndForgetWG.Wait()
	if got := eng.store.EngramLastAccessNs(ws, id); got != lastAccessBefore {
		t.Fatalf("observe read changed cognitive last-access: got %d want %d", got, lastAccessBefore)
	}

	eng.scoring.InvalidateCache()
	afterObserve, err := eng.scoring.Get(context.Background(), ws)
	if err != nil {
		t.Fatalf("Get weights after observe read: %v", err)
	}
	if afterObserve.UpdateCount != 0 {
		t.Fatalf("observe read changed UpdateCount: got %d want 0", afterObserve.UpdateCount)
	}
	if afterObserve.Weights != scoring.DefaultWeights() {
		t.Fatalf("observe read changed learned weights: got %v want %v", afterObserve.Weights, scoring.DefaultWeights())
	}

	fullCtx := context.WithValue(context.Background(), auth.ContextMode, auth.ModeFull)
	if _, err := eng.Read(fullCtx, &mbp.ReadRequest{Vault: "observe-read", ID: writeResp.ID}); err != nil {
		t.Fatalf("full Read: %v", err)
	}
	eng.fireAndForgetWG.Wait()
	if got := eng.store.EngramLastAccessNs(ws, id); got <= lastAccessBefore {
		t.Fatalf("full read did not advance cognitive last-access: got %d want > %d", got, lastAccessBefore)
	}

	eng.scoring.InvalidateCache()
	afterFull, err := eng.scoring.Get(context.Background(), ws)
	if err != nil {
		t.Fatalf("Get weights after full read: %v", err)
	}
	if afterFull.UpdateCount != 1 {
		t.Fatalf("full read UpdateCount: got %d want 1", afterFull.UpdateCount)
	}
}

func TestActivate_ObserveModeDoesNotForwardCognitiveEffects(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()

	forwarder := &mockForwarder{}
	eng.SetCoordinator(forwarder, "observe-lobe")

	writeResp, err := eng.Write(context.Background(), &mbp.WriteRequest{
		Vault:   "observe-activation",
		Concept: "observe forwarding",
		Content: "observe activation must not forward cognitive mutations",
	})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	awaitFTS(t, eng)
	id, err := storage.ParseULID(writeResp.ID)
	if err != nil {
		t.Fatalf("ParseULID: %v", err)
	}
	ws := eng.store.ResolveVaultPrefix("observe-activation")
	lastAccessBefore := eng.store.EngramLastAccessNs(ws, id)
	eng.activity.Evict(ws)

	req := &mbp.ActivateRequest{
		Vault:      "observe-activation",
		Context:    []string{"observe forwarding"},
		MaxResults: 10,
		Threshold:  0.01,
	}
	observeCtx := context.WithValue(context.Background(), auth.ContextMode, auth.ModeObserve)
	observeResp, err := eng.Activate(observeCtx, req)
	if err != nil {
		t.Fatalf("observe Activate: %v", err)
	}
	if len(observeResp.Activations) == 0 {
		t.Fatal("observe Activate returned no results; forwarding assertion would be inconclusive")
	}
	if got := len(forwarder.received()); got != 0 {
		t.Fatalf("observe Activate forwarded %d cognitive effects, want 0", got)
	}
	if got := eng.store.EngramLastAccessNs(ws, id); got != lastAccessBefore {
		t.Fatalf("observe Activate changed cognitive last-access: got %d want %d", got, lastAccessBefore)
	}
	if idle := eng.activity.IdleSince(ws); idle < 29*24*time.Hour {
		t.Fatalf("observe Activate marked vault active: idle=%s want unknown-vault idle", idle)
	}

	fullCtx := context.WithValue(context.Background(), auth.ContextMode, auth.ModeFull)
	fullResp, err := eng.Activate(fullCtx, req)
	if err != nil {
		t.Fatalf("full Activate: %v", err)
	}
	if len(fullResp.Activations) == 0 {
		t.Fatal("full Activate returned no results; forwarding assertion would be inconclusive")
	}
	if got := len(forwarder.received()); got == 0 {
		t.Fatal("full Activate forwarded no cognitive effects; full-mode behavior regressed")
	}
	if got := eng.store.EngramLastAccessNs(ws, id); got <= lastAccessBefore {
		t.Fatalf("full Activate did not advance cognitive last-access: got %d want > %d", got, lastAccessBefore)
	}
	if idle := eng.activity.IdleSince(ws); idle > time.Minute {
		t.Fatalf("full Activate did not mark vault active: idle=%s", idle)
	}
}

func TestTraverse_ObserveModeDoesNotAdvanceLastAccess(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()

	writeResp, err := eng.Write(context.Background(), &mbp.WriteRequest{
		Vault:   "observe-traverse",
		Concept: "observe traversal",
		Content: "observe graph traversal must not train recency",
	})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	id, err := storage.ParseULID(writeResp.ID)
	if err != nil {
		t.Fatalf("ParseULID: %v", err)
	}
	ws := eng.store.ResolveVaultPrefix("observe-traverse")
	lastAccessBefore := eng.store.EngramLastAccessNs(ws, id)

	observeCtx := context.WithValue(context.Background(), auth.ContextMode, auth.ModeObserve)
	nodes, _, err := eng.Traverse(observeCtx, "observe-traverse", writeResp.ID, 0, 10, false)
	if err != nil {
		t.Fatalf("observe Traverse: %v", err)
	}
	if len(nodes) == 0 {
		t.Fatal("observe Traverse returned no nodes; last-access assertion would be inconclusive")
	}
	if got := eng.store.EngramLastAccessNs(ws, id); got != lastAccessBefore {
		t.Fatalf("observe Traverse changed cognitive last-access: got %d want %d", got, lastAccessBefore)
	}

	fullCtx := context.WithValue(context.Background(), auth.ContextMode, auth.ModeFull)
	nodes, _, err = eng.Traverse(fullCtx, "observe-traverse", writeResp.ID, 0, 10, false)
	if err != nil {
		t.Fatalf("full Traverse: %v", err)
	}
	if len(nodes) == 0 {
		t.Fatal("full Traverse returned no nodes; last-access assertion would be inconclusive")
	}
	if got := eng.store.EngramLastAccessNs(ws, id); got <= lastAccessBefore {
		t.Fatalf("full Traverse did not advance cognitive last-access: got %d want > %d", got, lastAccessBefore)
	}
}

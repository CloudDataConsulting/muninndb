package engine

import (
	"context"
	"testing"

	"github.com/scrypster/muninndb/internal/auth"
	"github.com/scrypster/muninndb/internal/transport/mbp"
)

// TestWorkerStats_ReturnsWithoutPanic verifies that WorkerStats() returns without
// panicking. In the test environment, all cognitive workers are nil, so all
// WorkerStats fields should be zero-valued.
func TestWorkerStats_ReturnsWithoutPanic(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()

	// testEnv wires nil hebbianWorker, contradictWorker, and confidenceWorker,
	// so WorkerStats should return zero-value EngineWorkerStats.
	stats := eng.WorkerStats()

	// In test env workers are nil — all fields must be the zero value.
	if stats.Hebbian.Processed != 0 {
		t.Errorf("Hebbian.Processed = %d, want 0 (nil worker in test env)", stats.Hebbian.Processed)
	}
	if stats.Contradict.Processed != 0 {
		t.Errorf("Contradict.Processed = %d, want 0 (nil worker in test env)", stats.Contradict.Processed)
	}
	if stats.Confidence.Processed != 0 {
		t.Errorf("Confidence.Processed = %d, want 0 (nil worker in test env)", stats.Confidence.Processed)
	}
	if stats.Hebbian.Errors != 0 {
		t.Errorf("Hebbian.Errors = %d, want 0", stats.Hebbian.Errors)
	}
}

// TestUnsubscribe_InvalidID verifies that calling Unsubscribe with a non-existent
// subscription ID does not panic and returns nil.
// Engine.Unsubscribe delegates to trigger.TriggerSystem.Unsubscribe which calls
// sync.Map.Delete — a no-op for missing keys — so the result is always nil.
func TestUnsubscribe_InvalidID(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()

	err := eng.Unsubscribe(ctx, "nonexistent-subscription-id")
	if err != nil {
		t.Errorf("Unsubscribe(nonexistent): expected nil error, got %v", err)
	}
}

func TestSubscribeObservePreservesWorkspacePrincipalAndPassiveMode(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()

	key := &auth.APIKey{ID: "observe-sub", Vault: "subscribe-observe", Mode: auth.ModeObserve}
	ctx := context.WithValue(context.Background(), auth.ContextVault, key.Vault)
	ctx = context.WithValue(ctx, auth.ContextMode, key.Mode)
	ctx = context.WithValue(ctx, auth.ContextAPIKey, key)
	if _, err := eng.SubscribeWithDeliver(ctx, &mbp.SubscribeRequest{Vault: key.Vault}, nil); err != nil {
		t.Fatalf("SubscribeWithDeliver: %v", err)
	}

	workspace := eng.store.ResolveVaultPrefix(key.Vault)
	subs := eng.triggers.ForVault(workspace)
	if len(subs) != 1 {
		t.Fatalf("subscriptions=%d, want 1", len(subs))
	}
	sub := subs[0]
	if sub.Workspace != workspace || !sub.PassiveReads {
		t.Fatalf("subscription workspace/passive=%v/%v, want %v/true", sub.Workspace, sub.PassiveReads, workspace)
	}
	if got, _ := sub.RequestContext.Value(auth.ContextMode).(string); got != auth.ModeObserve {
		t.Fatalf("subscription mode=%q", got)
	}
	if got, _ := sub.RequestContext.Value(auth.ContextAPIKey).(*auth.APIKey); got != key {
		t.Fatalf("subscription principal=%p, want %p", got, key)
	}
}

func TestSubscribeRejectsRequestedVaultOutsideAuthenticatedContext(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()

	ctx := context.WithValue(context.Background(), auth.ContextVault, "vault-a")
	ctx = context.WithValue(ctx, auth.ContextMode, auth.ModeObserve)
	if _, err := eng.SubscribeWithDeliver(ctx, &mbp.SubscribeRequest{Vault: "vault-b"}, nil); err == nil {
		t.Fatal("SubscribeWithDeliver accepted vault-b under vault-a authentication")
	}
	if got := len(eng.triggers.ForVault(eng.store.ResolveVaultPrefix("vault-a"))); got != 0 {
		t.Fatalf("vault-a subscriptions=%d, want 0", got)
	}
	if got := len(eng.triggers.ForVault(eng.store.ResolveVaultPrefix("vault-b"))); got != 0 {
		t.Fatalf("vault-b subscriptions=%d, want 0", got)
	}
}

func TestSubscribeDerivesEmptyRequestVaultFromAuthenticatedContext(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()

	ctx := context.WithValue(context.Background(), auth.ContextVault, "vault-a")
	ctx = context.WithValue(ctx, auth.ContextMode, auth.ModeObserve)
	subID, err := eng.SubscribeWithDeliver(ctx, &mbp.SubscribeRequest{}, nil)
	if err != nil {
		t.Fatalf("SubscribeWithDeliver: %v", err)
	}
	defer eng.Unsubscribe(ctx, subID)
	if got := len(eng.triggers.ForVault(eng.store.ResolveVaultPrefix("vault-a"))); got != 1 {
		t.Fatalf("vault-a subscriptions=%d, want 1", got)
	}
}

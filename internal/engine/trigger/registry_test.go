package trigger

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// TestSubscriptionRegistryAddAndGet — Add a subscription, Get returns it
// ---------------------------------------------------------------------------

func TestSubscriptionRegistryAddAndGet(t *testing.T) {
	reg := newRegistry()

	sub := newMinimalSub("get-test-1", 10, 0)
	reg.Add(sub)

	got, ok := reg.Get("get-test-1")
	if !ok {
		t.Fatal("Get returned false for a subscription that was just Added")
	}
	if got == nil {
		t.Fatal("Get returned nil subscription")
	}
	if got.ID != "get-test-1" {
		t.Errorf("Get returned subscription with ID %q, want %q", got.ID, "get-test-1")
	}
	if got.Workspace != testWorkspace(10) {
		t.Errorf("Get returned subscription with Workspace %v, want %v", got.Workspace, testWorkspace(10))
	}
}

// ---------------------------------------------------------------------------
// TestSubscriptionRegistryRemove — Remove deletes the subscription
// ---------------------------------------------------------------------------

func TestSubscriptionRegistryRemove(t *testing.T) {
	reg := newRegistry()

	sub := newMinimalSub("remove-test-1", 20, 0)
	reg.Add(sub)

	// Confirm it exists first.
	if _, ok := reg.Get("remove-test-1"); !ok {
		t.Fatal("subscription not found before Remove — test setup error")
	}

	reg.Remove("remove-test-1")

	// After Remove, Get must return false.
	if _, ok := reg.Get("remove-test-1"); ok {
		t.Error("Get returned true after Remove — subscription was not deleted")
	}

	// ForVault must also return an empty slice.
	subs := reg.ForVault(testWorkspace(20))
	for _, s := range subs {
		if s.ID == "remove-test-1" {
			t.Error("removed subscription still present in ForVault result")
		}
	}

	// Counts must be back to zero.
	if reg.CountForVault(testWorkspace(20)) != 0 {
		t.Errorf("CountForVault after Remove = %d, want 0", reg.CountForVault(testWorkspace(20)))
	}
	if reg.CountTotal() != 0 {
		t.Errorf("CountTotal after Remove = %d, want 0", reg.CountTotal())
	}
}

func TestSubscriptionRegistryRejectsDuplicateIDWithoutOrphaning(t *testing.T) {
	reg := newRegistry()
	first := newMinimalSub("shared-id", 20, 0)
	second := newMinimalSub("shared-id", 21, 0)
	if err := reg.Add(first); err != nil {
		t.Fatalf("Add(first): %v", err)
	}
	if err := reg.Add(second); !errors.Is(err, ErrDuplicateSubscriptionID) {
		t.Fatalf("Add(duplicate) error=%v, want %v", err, ErrDuplicateSubscriptionID)
	}
	if got, ok := reg.Get(first.ID); !ok || got != first {
		t.Fatalf("Get(shared-id)=(%p,%v), want original %p", got, ok, first)
	}
	if got := len(reg.ForVault(first.Workspace)); got != 1 {
		t.Fatalf("original workspace subscriptions=%d, want 1", got)
	}
	if got := len(reg.ForVault(second.Workspace)); got != 0 {
		t.Fatalf("duplicate workspace subscriptions=%d, want 0", got)
	}
	if got := reg.CountTotal(); got != 1 {
		t.Fatalf("total subscriptions=%d, want 1", got)
	}

	reg.Remove(first.ID)
	if _, ok := reg.Get(first.ID); ok || reg.CountTotal() != 0 || len(reg.ForVault(first.Workspace)) != 0 {
		t.Fatal("original subscription remained active after Remove")
	}
}

func TestSubscriptionRegistryConcurrentAdmissionHonorsLimits(t *testing.T) {
	const attempts = 64

	t.Run("per-vault", func(t *testing.T) {
		reg := newRegistry()
		workspace := testWorkspace(40)
		start := make(chan struct{})
		var wg sync.WaitGroup
		var admitted atomic.Int32
		for i := 0; i < attempts; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				err := reg.Add(&Subscription{ID: fmt.Sprintf("vault-%d", i), Workspace: workspace}, 1, attempts)
				if err == nil {
					admitted.Add(1)
				} else if !errors.Is(err, ErrVaultSubscriptionLimitReached) {
					t.Errorf("Add error=%v", err)
				}
			}(i)
		}
		close(start)
		wg.Wait()
		if admitted.Load() != 1 || reg.CountForVault(workspace) != 1 || reg.CountTotal() != 1 {
			t.Fatalf("admitted=%d vault=%d total=%d, want 1/1/1", admitted.Load(), reg.CountForVault(workspace), reg.CountTotal())
		}
	})

	t.Run("global", func(t *testing.T) {
		reg := newRegistry()
		start := make(chan struct{})
		var wg sync.WaitGroup
		var admitted atomic.Int32
		for i := 0; i < attempts; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				err := reg.Add(&Subscription{ID: fmt.Sprintf("global-%d", i), Workspace: testWorkspace(uint32(i + 100))}, attempts, 3)
				if err == nil {
					admitted.Add(1)
				} else if !errors.Is(err, ErrGlobalSubscriptionLimitReached) {
					t.Errorf("Add error=%v", err)
				}
			}(i)
		}
		close(start)
		wg.Wait()
		if admitted.Load() != 3 || reg.CountTotal() != 3 {
			t.Fatalf("admitted=%d total=%d, want 3/3", admitted.Load(), reg.CountTotal())
		}
	})
}

// ---------------------------------------------------------------------------
// TestSubscriptionRegistryForVault — ForVault returns only the matching vault's subs
// ---------------------------------------------------------------------------

func TestSubscriptionRegistryForVault(t *testing.T) {
	reg := newRegistry()

	// Add two subscriptions to vault 100 and one to vault 200.
	a := newMinimalSub("vault-a1", 100, 0)
	b := newMinimalSub("vault-a2", 100, 0)
	c := newMinimalSub("vault-b1", 200, 0)

	reg.Add(a)
	reg.Add(b)
	reg.Add(c)

	// ForVault(100) must return exactly the two vault-100 subs.
	subs100 := reg.ForVault(testWorkspace(100))
	if len(subs100) != 2 {
		t.Fatalf("ForVault(100) returned %d subs, want 2", len(subs100))
	}
	ids100 := map[string]bool{}
	for _, s := range subs100 {
		ids100[s.ID] = true
	}
	if !ids100["vault-a1"] {
		t.Error("vault-a1 missing from ForVault(100)")
	}
	if !ids100["vault-a2"] {
		t.Error("vault-a2 missing from ForVault(100)")
	}
	if ids100["vault-b1"] {
		t.Error("vault-b1 from vault 200 incorrectly appeared in ForVault(100)")
	}

	// ForVault(200) must return exactly the one vault-200 sub.
	subs200 := reg.ForVault(testWorkspace(200))
	if len(subs200) != 1 {
		t.Fatalf("ForVault(200) returned %d subs, want 1", len(subs200))
	}
	if subs200[0].ID != "vault-b1" {
		t.Errorf("ForVault(200) returned sub with ID %q, want 'vault-b1'", subs200[0].ID)
	}

	// ForVault on an unknown vault must return nil/empty.
	subs999 := reg.ForVault(testWorkspace(999))
	if len(subs999) != 0 {
		t.Errorf("ForVault(999) returned %d subs for unknown vault, want 0", len(subs999))
	}
}

// ---------------------------------------------------------------------------
// TestSubscriptionRegistryPruneExpiredDetailed — expired subs are removed;
// non-expired and TTL=0 subs survive; counts are accurate after pruning.
// (trigger_test.go covers the basic case; this test adds count assertions
// and a third long-lived subscription to prove selective pruning.)
// ---------------------------------------------------------------------------

func TestSubscriptionRegistryPruneExpiredDetailed(t *testing.T) {
	reg := newRegistry()

	// 1ms TTL — expires almost immediately.
	shortLived := newMinimalSub("prune-short", 30, 1*time.Millisecond)
	// No TTL — should survive forever.
	immortal := newMinimalSub("prune-immortal", 30, 0)
	// Longer TTL — should still be alive when we prune.
	longLived := newMinimalSub("prune-long", 30, 10*time.Second)

	reg.Add(shortLived)
	reg.Add(immortal)
	reg.Add(longLived)

	// Wait for the short TTL to elapse.
	time.Sleep(10 * time.Millisecond)

	pruned := reg.PruneExpired()
	if pruned != 1 {
		t.Errorf("PruneExpired removed %d subscriptions, want 1", pruned)
	}

	// The short-lived sub must be gone.
	if _, ok := reg.Get("prune-short"); ok {
		t.Error("expired subscription 'prune-short' still present after PruneExpired")
	}

	// The immortal sub must still be present.
	if _, ok := reg.Get("prune-immortal"); !ok {
		t.Error("TTL=0 subscription 'prune-immortal' was incorrectly pruned")
	}

	// The long-lived sub must still be present.
	if _, ok := reg.Get("prune-long"); !ok {
		t.Error("long-lived subscription 'prune-long' was incorrectly pruned")
	}

	// Counts must reflect the two remaining subs.
	if reg.CountForVault(testWorkspace(30)) != 2 {
		t.Errorf("CountForVault(30) after prune = %d, want 2", reg.CountForVault(testWorkspace(30)))
	}
	if reg.CountTotal() != 2 {
		t.Errorf("CountTotal after prune = %d, want 2", reg.CountTotal())
	}
}

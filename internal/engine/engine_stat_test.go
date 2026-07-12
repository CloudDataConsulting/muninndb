package engine

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/cockroachdb/pebble"
	"github.com/scrypster/muninndb/internal/auth"
	"github.com/scrypster/muninndb/internal/storage"
	"github.com/scrypster/muninndb/internal/storage/keys"
	"github.com/scrypster/muninndb/internal/transport/mbp"
)

func TestStatObserveModeDoesNotInitializeVaultCounter(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()

	vault := "stat-observe-passive"
	ws := eng.store.ResolveVaultPrefix(vault)
	id := storage.NewULID()
	if err := eng.store.GetDB().Set(
		keys.EngramKey(ws, [16]byte(id)),
		[]byte("canonical count fixture"),
		pebble.Sync,
	); err != nil {
		t.Fatalf("seed canonical engram: %v", err)
	}
	counterKey := keys.VaultCountKey(ws)
	if value, err := storage.Get(eng.store.GetDB(), counterKey); err != nil || value != nil {
		t.Fatalf("counter before observe Stat = %x err=%v, want absent", value, err)
	}

	observeCtx := context.WithValue(context.Background(), auth.ContextMode, auth.ModeObserve)
	stat, err := eng.Stat(observeCtx, &mbp.StatRequest{Vault: vault})
	if err != nil {
		t.Fatalf("observe Stat: %v", err)
	}
	if stat.EngramCount != 1 || stat.StatsScope != "vault" {
		t.Fatalf("observe Stat = %#v, want exact one-row vault response", stat)
	}
	if value, err := storage.Get(eng.store.GetDB(), counterKey); err != nil || value != nil {
		t.Fatalf("counter after observe Stat = %x err=%v, want absent", value, err)
	}

	stat, err = eng.Stat(context.Background(), &mbp.StatRequest{Vault: vault})
	if err != nil {
		t.Fatalf("normal Stat: %v", err)
	}
	if stat.EngramCount != 1 {
		t.Fatalf("normal Stat count = %d, want 1", stat.EngramCount)
	}
	value, err := storage.Get(eng.store.GetDB(), counterKey)
	if err != nil {
		t.Fatalf("read normal Stat counter: %v", err)
	}
	if len(value) != 8 || binary.BigEndian.Uint64(value) != 1 {
		t.Fatalf("normal Stat counter = %x, want persisted value 1", value)
	}
}

func TestStat_CanceledFirstReconciliationDoesNotPoisonRetry(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := eng.Stat(canceled, &mbp.StatRequest{Vault: "stat-canceled-first"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Stat error = %v, want context.Canceled", err)
	}

	stat, err := eng.Stat(context.Background(), &mbp.StatRequest{Vault: "stat-canceled-first"})
	if err != nil {
		t.Fatalf("healthy Stat retry: %v", err)
	}
	if stat.EngramCount != 0 || stat.StatsScope != "vault" {
		t.Fatalf("healthy Stat retry = %#v, want empty vault-scoped response", stat)
	}
}

// TestStat_AfterWrites writes 3 engrams and verifies a named-vault Stat request
// returns only truthful vault-scoped values.
func TestStat_AfterWrites(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()

	writes := []struct {
		concept string
		content string
	}{
		{"stat test concept one", "content about first stat engram"},
		{"stat test concept two", "content about second stat engram"},
		{"stat test concept three", "content about third stat engram"},
	}

	for _, w := range writes {
		_, err := eng.Write(ctx, &mbp.WriteRequest{
			Vault:   "stat-vault",
			Concept: w.concept,
			Content: w.content,
		})
		if err != nil {
			t.Fatalf("Write(%q): %v", w.concept, err)
		}
	}

	stat, err := eng.Stat(ctx, &mbp.StatRequest{Vault: "stat-vault"})
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}

	if stat.EngramCount != 3 {
		t.Errorf("EngramCount = %d, want 3", stat.EngramCount)
	}
	if stat.VaultCount != 1 {
		t.Errorf("VaultCount = %d, want 1", stat.VaultCount)
	}
	if stat.StorageBytes != 0 {
		t.Errorf("StorageBytes = %d, want 0 for a scoped request", stat.StorageBytes)
	}
	if stat.StatsScope != "vault" || stat.StorageBytesAvailable || stat.IndexSizeAvailable {
		t.Errorf("scoped availability = %#v, want vault scope with unavailable sizes", stat)
	}
}

// TestStat_EmptyVaultField verifies that Stat() with an empty Vault field
// preserves the global internal/admin behavior.
func TestStat_EmptyVaultField(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()

	// Write one engram so we have something to count.
	_, err := eng.Write(ctx, &mbp.WriteRequest{
		Vault:   "any-vault",
		Concept: "empty vault field test",
		Content: "content for empty vault field stat test",
	})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Stat with empty Vault field — must return global stats without error.
	stat, err := eng.Stat(ctx, &mbp.StatRequest{Vault: ""})
	if err != nil {
		t.Fatalf("Stat(Vault=\"\"): %v", err)
	}

	if stat == nil {
		t.Fatal("Stat returned nil response")
	}

	// VaultCount must be >= 1 (the vault we wrote to).
	if stat.VaultCount < 1 {
		t.Errorf("VaultCount = %d, want >= 1", stat.VaultCount)
	}

	// EngramCount must reflect the written engram.
	if stat.EngramCount <= 0 {
		t.Errorf("EngramCount = %d, want > 0", stat.EngramCount)
	}

	// StorageBytes may be 0 if Pebble hasn't flushed yet; assert >= 0.
	if stat.StorageBytes < 0 {
		t.Errorf("StorageBytes = %d, want >= 0", stat.StorageBytes)
	}
}

func TestStat_NamedVaultDoesNotLeakOtherVaults(t *testing.T) {
	eng, cleanup := testEnv(t)
	defer cleanup()
	ctx := context.Background()

	write := func(vault, concept string) {
		t.Helper()
		if _, err := eng.Write(ctx, &mbp.WriteRequest{
			Vault:   vault,
			Concept: concept,
			Content: "scoped statistics regression fixture",
		}); err != nil {
			t.Fatalf("Write(%q): %v", vault, err)
		}
	}

	write("scoped-alpha", "alpha one")
	write("scoped-beta", "beta one")
	write("scoped-beta", "beta two")

	scoped, err := eng.Stat(ctx, &mbp.StatRequest{Vault: "scoped-alpha"})
	if err != nil {
		t.Fatalf("Stat(scoped-alpha): %v", err)
	}
	if scoped.EngramCount != 1 {
		t.Errorf("scoped EngramCount = %d, want 1", scoped.EngramCount)
	}
	if scoped.VaultCount != 1 {
		t.Errorf("scoped VaultCount = %d, want 1", scoped.VaultCount)
	}
	if scoped.StorageBytes != 0 {
		t.Errorf("scoped StorageBytes = %d, want 0", scoped.StorageBytes)
	}
	if scoped.CoherenceScores != nil {
		t.Fatalf("scoped coherence = %#v, want unavailable until registry/cardinality reconciliation", scoped.CoherenceScores)
	}

	global, err := eng.Stat(ctx, &mbp.StatRequest{})
	if err != nil {
		t.Fatalf("Stat(global): %v", err)
	}
	if global.EngramCount != 3 {
		t.Errorf("global EngramCount = %d, want 3", global.EngramCount)
	}
	if global.VaultCount != 2 {
		t.Errorf("global VaultCount = %d, want 2", global.VaultCount)
	}
	if global.StatsScope != "global" || !global.StorageBytesAvailable || global.IndexSizeAvailable {
		t.Errorf("global availability = %#v, want global scope with disk-only availability", global)
	}
	for _, vault := range []string{"scoped-alpha", "scoped-beta"} {
		if _, ok := global.CoherenceScores[vault]; !ok {
			t.Errorf("global coherence missing %q: %#v", vault, global.CoherenceScores)
		}
	}
}

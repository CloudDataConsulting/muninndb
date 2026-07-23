package storage

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/cockroachdb/pebble"
)

func TestStorageKeyspaceRegistry_CurrentVaultCoverageAndReservations(t *testing.T) {
	requiredVaultPrefixes := map[byte]keyspaceClearAction{
		0x01: clearRangeDelete, 0x02: clearRangeDelete, 0x03: clearRangeDelete,
		0x04: clearRangeDelete, 0x05: clearRangeDelete, 0x06: clearRangeDelete,
		0x07: clearRangeDelete, 0x08: clearRangeDelete, 0x09: clearRangeDelete,
		0x0A: clearRangeDelete, 0x0B: clearRangeDelete, 0x0C: clearRangeDelete,
		0x0D: clearRangeDelete, 0x10: clearRangeDelete,
		0x12: clearExactPointDelete, 0x13: clearExactPointDelete,
		0x14: clearValueAwarePointDelete,
		0x15: clearRangeDelete, 0x16: clearRangeDelete, 0x17: clearRangeDelete,
		0x18: clearRangeDelete, 0x1A: clearRangeDelete, 0x1B: clearRangeDelete,
		0x1C: clearRangeDelete, 0x1D: clearRangeDelete, 0x1E: clearRangeDelete,
		0x20: clearRangeDelete, 0x21: clearRangeDelete, 0x22: clearRangeDelete,
		0x24: clearRangeDelete, 0x25: clearRangeDelete, 0x26: clearRangeDelete,
	}

	descriptors := storageKeyspaceRegistry()
	ids := make(map[string]struct{}, len(descriptors))
	coveredVaultPrefixes := make(map[byte]keyspaceClearAction)
	authReservations := make(map[byte]bool)
	var global19, reservedFF int
	var cross23 bool
	for _, descriptor := range descriptors {
		if _, duplicate := ids[descriptor.id]; duplicate {
			t.Errorf("duplicate keyspace descriptor ID %q", descriptor.id)
		}
		ids[descriptor.id] = struct{}{}
		if descriptor.owner == "storage" && descriptor.scope == keyspaceVaultFirst {
			if descriptor.workspaceOffset != 1 {
				t.Errorf("vault-first descriptor %q has workspace offset %d", descriptor.id, descriptor.workspaceOffset)
			}
			if prior, exists := coveredVaultPrefixes[descriptor.prefix]; exists && prior != descriptor.clear {
				t.Errorf("prefix 0x%02X has conflicting clear actions %d and %d", descriptor.prefix, prior, descriptor.clear)
			}
			coveredVaultPrefixes[descriptor.prefix] = descriptor.clear
		}
		if descriptor.owner == "auth" && descriptor.prefix >= 0x11 && descriptor.prefix <= 0x14 {
			authReservations[descriptor.prefix] = true
		}
		if descriptor.prefix == 0x19 {
			global19++
		}
		if descriptor.prefix == 0xFF {
			reservedFF++
		}
		if descriptor.prefix == 0x23 && descriptor.scope == keyspaceCrossVault && descriptor.workspaceOffset == 9 && descriptor.keyLength == 33 && descriptor.clear == clearFilteredPointDelete {
			cross23 = true
		}
	}

	for prefix, action := range requiredVaultPrefixes {
		if got, ok := coveredVaultPrefixes[prefix]; !ok || got != action {
			t.Errorf("vault prefix 0x%02X registry action = %d, present=%v; want %d", prefix, got, ok, action)
		}
	}
	if len(coveredVaultPrefixes) != len(requiredVaultPrefixes) {
		t.Errorf("registry has %d unique vault-first prefixes, want %d", len(coveredVaultPrefixes), len(requiredVaultPrefixes))
	}
	for prefix := byte(0x11); prefix <= 0x14; prefix++ {
		if !authReservations[prefix] {
			t.Errorf("missing auth reservation at shared prefix 0x%02X", prefix)
		}
	}
	if global19 < 6 {
		t.Errorf("0x19 has %d classified owners/layouts, want at least 6", global19)
	}
	if reservedFF != 2 {
		t.Errorf("0xFF has %d classified reservations, want 2", reservedFF)
	}
	if !cross23 {
		t.Error("missing exact 0x23 cross-vault filtered-delete descriptor")
	}
}

func TestVaultClearPlan_NeverRangeDeletesSharedAuthPrefixes(t *testing.T) {
	want := map[byte]keyspaceClearAction{
		0x12: clearExactPointDelete,
		0x13: clearExactPointDelete,
		0x14: clearValueAwarePointDelete,
		0x23: clearFilteredPointDelete,
	}
	for _, step := range vaultClearPlan() {
		if expected, ok := want[step.prefix]; ok {
			if step.action != expected {
				t.Errorf("clear plan prefix 0x%02X action = %d, want %d", step.prefix, step.action, expected)
			}
			delete(want, step.prefix)
		}
		if step.prefix == 0x11 || step.prefix == 0x19 || step.prefix == 0x1F || step.prefix == 0xFF {
			t.Errorf("global/reserved prefix 0x%02X entered the vault clear plan", step.prefix)
		}
	}
	for prefix, action := range want {
		t.Errorf("clear plan missing prefix 0x%02X action %d", prefix, action)
	}
}

func TestClearVault_PreservesAdversarialSharedAuthRecords(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	ws := store.VaultPrefix("shared-prefix-target")
	wsPlus, err := incrementWS(ws)
	if err != nil {
		t.Fatal(err)
	}

	authRecords := [][]byte{
		append(append([]byte{0x12}, ws[:]...), make([]byte, 8)...),
		append(append([]byte{0x13}, ws[:]...), []byte("auth-index-tail")...),
		append(append([]byte{0x14}, ws[:]...), make([]byte, 32)...),
	}
	authValues := [][]byte{
		[]byte(`{"id":"auth-record"}`),
		make([]byte, 16),
		[]byte(`{"name":"forty-byte-auth-config-record","public":false}`),
	}
	for i, key := range authRecords {
		if err := store.db.Set(key, authValues[i], pebble.Sync); err != nil {
			t.Fatalf("seed shared auth record %d: %v", i, err)
		}
		lo, hi := vaultFirstBounds(key[0], ws, wsPlus)
		if bytes.Compare(key, lo) < 0 || bytes.Compare(key, hi) >= 0 {
			t.Fatalf("adversarial key %d is not in the target workspace range", i)
		}
	}

	if _, err := store.ClearVault(ctx, ws); err != nil {
		t.Fatalf("ClearVault: %v", err)
	}
	for i, key := range authRecords {
		exists, err := pebbleKeyExists(store.db, key)
		if err != nil {
			t.Fatalf("read shared auth record %d: %v", i, err)
		}
		if !exists {
			t.Errorf("ClearVault deleted shared auth record %d at prefix 0x%02X", i, key[0])
		}
	}
}

func TestClearVault_MalformedCrossVaultKeyAbortsBeforeCommit(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	ws := store.VaultPrefix("malformed-cross-vault")
	id, err := store.WriteEngram(ctx, ws, &Engram{Concept: "preserve", Content: "batch must not commit", Confidence: 1, Stability: 30})
	if err != nil {
		t.Fatalf("write engram: %v", err)
	}
	malformed := make([]byte, 32)
	malformed[0] = 0x23
	if err := store.db.Set(malformed, nil, pebble.Sync); err != nil {
		t.Fatalf("seed malformed 0x23 key: %v", err)
	}

	if _, err := store.ClearVault(ctx, ws); err == nil {
		t.Fatal("ClearVault succeeded with malformed owned 0x23 layout")
	}
	if _, err := store.GetEngram(ctx, ws, id); err != nil {
		t.Fatalf("ClearVault committed staged deletes before malformed-layout failure: %v", err)
	}
	exists, err := pebbleKeyExists(store.db, malformed)
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Error("malformed 0x23 key disappeared despite aborted batch")
	}
}

func TestKeyspaceSchemaDocumentsRegistryRiskBoundaries(t *testing.T) {
	doc, err := readKeyspaceSchemaForTest()
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"internal/storage/keyspace_registry.go",
		"0x22", "0x25", "0x26",
		"Auth overlap", "0x11–0x14",
		"replication", "Hebbian", "0xFF",
	} {
		if !bytes.Contains(doc, []byte(required)) {
			t.Errorf("key-space schema is missing %q", required)
		}
	}
}

func readKeyspaceSchemaForTest() ([]byte, error) {
	doc, err := os.ReadFile("../../docs/key-space-schema.md")
	if err != nil {
		return nil, fmt.Errorf("read key-space schema: %w", err)
	}
	return doc, nil
}

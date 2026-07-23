package storage

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"

	"github.com/cockroachdb/pebble"
)

type vaultNamespaceProbe struct {
	prefix    byte
	suffixLen int
}

type namedProbeKey struct {
	label string
	key   []byte
}

// These lengths mirror the current concrete key layouts after prefix(1)|ws(8).
// Vault metadata (0x0E) is intentionally absent because ClearVault preserves the
// vault registration. Global namespaces 0x0F, 0x11, 0x19, and 0x1F are also absent.
var currentVaultNamespaceProbes = []vaultNamespaceProbe{
	{0x01, 16}, {0x02, 16}, {0x03, 36}, {0x04, 36},
	{0x05, 18}, {0x06, 19}, {0x07, 17}, {0x08, 5},
	{0x09, 1}, {0x0A, 22}, {0x0B, 17}, {0x0C, 20},
	{0x0D, 20}, {0x10, 17}, {0x12, 0}, {0x13, 0},
	{0x14, 32}, {0x15, 0}, {0x16, 28}, {0x17, 0},
	{0x18, 16}, {0x1A, 16}, {0x1B, 0}, {0x1C, 32},
	{0x1D, 0}, {0x1E, 32}, {0x20, 24}, {0x21, 33},
	{0x22, 24}, {0x24, 16}, {0x25, 32}, {0x26, 24},
}

func TestVaultLifecycleCharacterization_ClearRemovesEveryCurrentVaultNamespace(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	target := store.VaultPrefix("namespace-clear-target")
	other := store.VaultPrefix("namespace-clear-other")

	if err := store.WriteVaultName(target, "namespace-clear-target"); err != nil {
		t.Fatalf("write target vault name: %v", err)
	}
	if err := store.WriteVaultName(other, "namespace-clear-other"); err != nil {
		t.Fatalf("write other vault name: %v", err)
	}

	targetKeys := make([]namedProbeKey, 0, len(currentVaultNamespaceProbes)+1)
	otherKeys := make([]namedProbeKey, 0, len(currentVaultNamespaceProbes)+1)
	batch := store.db.NewBatch()
	defer batch.Close()

	for _, probe := range currentVaultNamespaceProbes {
		label := fmt.Sprintf("0x%02X", probe.prefix)
		targetKey := scopedNamespaceProbeKey(probe.prefix, target, probe.suffixLen)
		otherKey := scopedNamespaceProbeKey(probe.prefix, other, probe.suffixLen)
		targetKeys = append(targetKeys, namedProbeKey{label: label, key: targetKey})
		otherKeys = append(otherKeys, namedProbeKey{label: label, key: otherKey})

		value := []byte("vault-namespace-probe")
		if probe.prefix == 0x15 {
			value = make([]byte, 8)
			binary.BigEndian.PutUint64(value, 1)
		}
		if probe.prefix == 0x14 {
			// Current association-weight index values are float32 bits. The
			// exact value length distinguishes them from shared 0x14 auth config.
			value = []byte{0x3F, 0x80, 0x00, 0x00}
		}
		if err := batch.Set(targetKey, value, nil); err != nil {
			t.Fatalf("stage target %s probe: %v", label, err)
		}
		if err := batch.Set(otherKey, value, nil); err != nil {
			t.Fatalf("stage other %s probe: %v", label, err)
		}
	}

	// 0x23 is cross-vault: entityHash precedes the embedded workspace slice.
	targetReverse := crossVaultReverseProbeKey(target)
	otherReverse := crossVaultReverseProbeKey(other)
	targetKeys = append(targetKeys, namedProbeKey{label: "0x23-vault-slice", key: targetReverse})
	otherKeys = append(otherKeys, namedProbeKey{label: "0x23-vault-slice", key: otherReverse})
	if err := batch.Set(targetReverse, nil, nil); err != nil {
		t.Fatalf("stage target 0x23 probe: %v", err)
	}
	if err := batch.Set(otherReverse, nil, nil); err != nil {
		t.Fatalf("stage other 0x23 probe: %v", err)
	}
	if err := batch.Commit(pebble.Sync); err != nil {
		t.Fatalf("commit namespace probes: %v", err)
	}

	if _, err := store.ClearVault(ctx, target); err != nil {
		t.Fatalf("clear target vault: %v", err)
	}

	for _, probe := range targetKeys {
		exists, err := pebbleKeyExists(store.db, probe.key)
		if err != nil {
			t.Errorf("read target %s probe: %v", probe.label, err)
			continue
		}
		if exists {
			t.Errorf("ClearVault left target %s probe behind", probe.label)
		}
	}
	for _, probe := range otherKeys {
		exists, err := pebbleKeyExists(store.db, probe.key)
		if err != nil {
			t.Errorf("read other %s probe: %v", probe.label, err)
			continue
		}
		if !exists {
			t.Errorf("ClearVault removed other vault's %s probe", probe.label)
		}
	}
}

func scopedNamespaceProbeKey(prefix byte, ws [8]byte, suffixLen int) []byte {
	key := make([]byte, 1+len(ws)+suffixLen)
	key[0] = prefix
	copy(key[1:9], ws[:])
	for i := 9; i < len(key); i++ {
		key[i] = 0xA5
	}
	return key
}

func crossVaultReverseProbeKey(ws [8]byte) []byte {
	key := make([]byte, 1+8+8+16)
	key[0] = 0x23
	for i := 1; i < 9; i++ {
		key[i] = 0xB6
	}
	copy(key[9:17], ws[:])
	for i := 17; i < len(key); i++ {
		key[i] = 0xC7
	}
	return key
}

func pebbleKeyExists(db *pebble.DB, key []byte) (bool, error) {
	_, closer, err := db.Get(key)
	if err == nil {
		closer.Close()
		return true, nil
	}
	if errors.Is(err, pebble.ErrNotFound) {
		return false, nil
	}
	return false, err
}

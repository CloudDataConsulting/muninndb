package rest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/vfs"
	"github.com/scrypster/muninndb/internal/storage"
	"github.com/scrypster/muninndb/internal/storage/keys"
)

// consolidationMockEngine implements both EngineAPI (via embedding MockEngine) and
// consolidation.EngineInterface so the type assertion in handleConsolidate succeeds.
type consolidationMockEngine struct {
	MockEngine
	store *storage.PebbleStore
}

// Store implements consolidation.EngineInterface.
func (m *consolidationMockEngine) Store() *storage.PebbleStore {
	return m.store
}

// ListVaults implements consolidation.EngineInterface (overrides MockEngine.ListVaults).
func (m *consolidationMockEngine) ListVaults(ctx context.Context) ([]string, error) {
	names, err := m.store.ListVaultNames()
	if err != nil {
		return nil, err
	}
	return names, nil
}

// UpdateLifecycleState implements consolidation.EngineInterface.
func (m *consolidationMockEngine) UpdateLifecycleState(ctx context.Context, vault, id, state string) error {
	ulid, err := storage.ParseULID(id)
	if err != nil {
		return err
	}
	wsPrefix := m.store.ResolveVaultPrefix(vault)
	eng, err := m.store.GetEngram(ctx, wsPrefix, ulid)
	if err != nil {
		return err
	}
	newState, err := storage.ParseLifecycleState(state)
	if err != nil {
		return err
	}
	meta := &storage.EngramMeta{
		State:       newState,
		Confidence:  eng.Confidence,
		Relevance:   eng.Relevance,
		Stability:   eng.Stability,
		AccessCount: eng.AccessCount,
		UpdatedAt:   time.Now(),
		LastAccess:  eng.LastAccess,
	}
	return m.store.UpdateMetadata(ctx, wsPrefix, ulid, meta)
}

// newConsolidationTestEngine creates a consolidationMockEngine backed by an in-memory pebble DB.
func newConsolidationTestEngine(t *testing.T) *consolidationMockEngine {
	t.Helper()
	db, err := pebble.Open("", &pebble.Options{FS: vfs.NewMem()})
	if err != nil {
		t.Fatalf("open pebble: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	store := storage.NewPebbleStore(db, storage.PebbleStoreConfig{CacheSize: 64})
	return &consolidationMockEngine{store: store}
}

// TestHandleConsolidate_Success posts a valid consolidation request and expects HTTP 200.
func TestHandleConsolidate_Success(t *testing.T) {
	eng := newConsolidationTestEngine(t)
	wsPrefix := eng.store.ResolveVaultPrefix("default")
	if err := eng.store.WriteVaultName(wsPrefix, "default"); err != nil {
		t.Fatalf("register default vault: %v", err)
	}
	srv := NewServer("localhost:0", eng, nil, nil, nil, EmbedInfo{}, EnrichInfo{}, nil, "", nil)

	handler := srv.handleConsolidate()

	req := httptest.NewRequest("POST", "/v1/vaults/default/consolidate", strings.NewReader(`{}`))
	req.SetPathValue("vault", "default")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestHandleConsolidate_MissingVault expects HTTP 400 when the vault path value is empty.
func TestHandleConsolidate_MissingVault(t *testing.T) {
	eng := newConsolidationTestEngine(t)
	srv := NewServer("localhost:0", eng, nil, nil, nil, EmbedInfo{}, EnrichInfo{}, nil, "", nil)

	handler := srv.handleConsolidate()

	// No vault path value set — PathValue("vault") returns "".
	req := httptest.NewRequest("POST", "/v1/vaults//consolidate", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing vault, got %d: %s", w.Code, w.Body.String())
	}
}

// TestHandleConsolidate_UnknownVault verifies an unknown vault fails closed with 404.
func TestHandleConsolidate_UnknownVault(t *testing.T) {
	eng := newConsolidationTestEngine(t)
	srv := NewServer("localhost:0", eng, nil, nil, nil, EmbedInfo{}, EnrichInfo{}, nil, "", nil)

	handler := srv.handleConsolidate()

	req := httptest.NewRequest("POST", "/v1/vaults/nonexistent/consolidate", strings.NewReader(`{}`))
	req.SetPathValue("vault", "nonexistent")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown vault, got %d: %s", w.Code, w.Body.String())
	}
	var response ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if response.Error.Code != ErrVaultNotFound {
		t.Errorf("error code = %v, want %v", response.Error.Code, ErrVaultNotFound)
	}
}

// TestHandleConsolidate_CorruptListedVault verifies a one-sided/corrupt
// persisted mapping is a storage failure, not a not-found response.
func TestHandleConsolidate_CorruptListedVault(t *testing.T) {
	eng := newConsolidationTestEngine(t)
	const vault = "corrupt-vault"
	wsPrefix := eng.store.ResolveVaultPrefix(vault)
	if err := eng.store.WriteVaultName(wsPrefix, vault); err != nil {
		t.Fatalf("register vault: %v", err)
	}
	if err := eng.store.GetDB().Set(keys.VaultNameIndexKey(vault), []byte{0x01}, nil); err != nil {
		t.Fatalf("corrupt vault name index: %v", err)
	}
	srv := NewServer("localhost:0", eng, nil, nil, nil, EmbedInfo{}, EnrichInfo{}, nil, "", nil)

	handler := srv.handleConsolidate()
	req := httptest.NewRequest("POST", "/v1/vaults/"+vault+"/consolidate", strings.NewReader(`{}`))
	req.SetPathValue("vault", vault)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 for corrupt listed vault, got %d: %s", w.Code, w.Body.String())
	}
	var response ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if response.Error.Code != ErrStorageError {
		t.Errorf("error code = %v, want %v", response.Error.Code, ErrStorageError)
	}
}

// TestHandleConsolidate_InvalidJSON expects HTTP 400 when the request body is not valid JSON.
func TestHandleConsolidate_InvalidJSON(t *testing.T) {
	eng := newConsolidationTestEngine(t)
	srv := NewServer("localhost:0", eng, nil, nil, nil, EmbedInfo{}, EnrichInfo{}, nil, "", nil)

	handler := srv.handleConsolidate()

	req := httptest.NewRequest("POST", "/v1/vaults/default/consolidate", strings.NewReader("invalid-json"))
	req.SetPathValue("vault", "default")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON body, got %d: %s", w.Code, w.Body.String())
	}
}

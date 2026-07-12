package rest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/scrypster/muninndb/internal/auth"
	mbp "github.com/scrypster/muninndb/internal/transport/mbp"
)

type modeGuardCall struct {
	operation string
	mode      string
}

type modeGuardTrackingEngine struct {
	MockEngine
	calls []modeGuardCall
}

func (e *modeGuardTrackingEngine) record(ctx context.Context, operation string) {
	mode, _ := ctx.Value(auth.ContextMode).(string)
	e.calls = append(e.calls, modeGuardCall{operation: operation, mode: mode})
}

func (e *modeGuardTrackingEngine) Write(ctx context.Context, req *WriteRequest) (*WriteResponse, error) {
	e.record(ctx, "write")
	return e.MockEngine.Write(ctx, req)
}

func (e *modeGuardTrackingEngine) WriteBatch(ctx context.Context, reqs []*WriteRequest) ([]*WriteResponse, []error) {
	e.record(ctx, "batch-write")
	return e.MockEngine.WriteBatch(ctx, reqs)
}

func (e *modeGuardTrackingEngine) Forget(ctx context.Context, req *ForgetRequest) (*ForgetResponse, error) {
	e.record(ctx, "forget")
	return e.MockEngine.Forget(ctx, req)
}

func (e *modeGuardTrackingEngine) Link(ctx context.Context, req *mbp.LinkRequest) (*LinkResponse, error) {
	e.record(ctx, "link")
	return e.MockEngine.Link(ctx, req)
}

func (e *modeGuardTrackingEngine) Evolve(ctx context.Context, vault, engramID, newContent, reason string) (*EvolveResponse, error) {
	e.record(ctx, "evolve")
	return e.MockEngine.Evolve(ctx, vault, engramID, newContent, reason)
}

func (e *modeGuardTrackingEngine) Consolidate(ctx context.Context, vault string, ids []string, mergedContent string) (*ConsolidateResponse, error) {
	e.record(ctx, "consolidate")
	return e.MockEngine.Consolidate(ctx, vault, ids, mergedContent)
}

func (e *modeGuardTrackingEngine) Decide(ctx context.Context, vault, decision, rationale string, alternatives, evidenceIDs []string) (*DecideResponse, error) {
	e.record(ctx, "decide")
	return e.MockEngine.Decide(ctx, vault, decision, rationale, alternatives, evidenceIDs)
}

func (e *modeGuardTrackingEngine) Restore(ctx context.Context, vault, engramID string) (*RestoreResponse, error) {
	e.record(ctx, "restore")
	return e.MockEngine.Restore(ctx, vault, engramID)
}

func (e *modeGuardTrackingEngine) UpdateState(ctx context.Context, vault, engramID, state, reason string) error {
	e.record(ctx, "update-state")
	return e.MockEngine.UpdateState(ctx, vault, engramID, state, reason)
}

func (e *modeGuardTrackingEngine) UpdateTags(ctx context.Context, vault, engramID string, tags []string) error {
	e.record(ctx, "update-tags")
	return e.MockEngine.UpdateTags(ctx, vault, engramID, tags)
}

func (e *modeGuardTrackingEngine) RetryEnrich(ctx context.Context, vault, engramID string) (*RetryEnrichResponse, error) {
	e.record(ctx, "retry-enrich")
	return e.MockEngine.RetryEnrich(ctx, vault, engramID)
}

type modeGuardRoute struct {
	name       string
	operation  string
	method     string
	path       string
	body       string
	wantStatus int
}

var mutatingModeGuardRoutes = []modeGuardRoute{
	{name: "create engram", operation: "write", method: http.MethodPost, path: "/api/engrams?vault=default", body: `{"concept":"test","content":"hello"}`, wantStatus: http.StatusCreated},
	{name: "batch create", operation: "batch-write", method: http.MethodPost, path: "/api/engrams/batch?vault=default", body: `{"engrams":[{"concept":"test","content":"hello"}]}`, wantStatus: http.StatusCreated},
	{name: "delete engram", operation: "forget", method: http.MethodDelete, path: "/api/engrams/test-id?vault=default", wantStatus: http.StatusOK},
	{name: "link engrams", operation: "link", method: http.MethodPost, path: "/api/link?vault=default", body: `{"source_id":"id1","target_id":"id2","rel_type":1}`, wantStatus: http.StatusOK},
	{name: "set state", operation: "update-state", method: http.MethodPut, path: "/api/engrams/test-id/state?vault=default", body: `{"state":"active"}`, wantStatus: http.StatusOK},
	{name: "update tags", operation: "update-tags", method: http.MethodPut, path: "/api/engrams/test-id/tags?vault=default", body: `{"tags":["test"]}`, wantStatus: http.StatusOK},
	{name: "evolve", operation: "evolve", method: http.MethodPost, path: "/api/engrams/test-id/evolve?vault=default", body: `{"new_content":"updated","reason":"correction"}`, wantStatus: http.StatusOK},
	{name: "consolidate", operation: "consolidate", method: http.MethodPost, path: "/api/consolidate?vault=default", body: `{"ids":["id1","id2"],"merged_content":"merged"}`, wantStatus: http.StatusOK},
	{name: "decide", operation: "decide", method: http.MethodPost, path: "/api/decide?vault=default", body: `{"decision":"ship","rationale":"validated"}`, wantStatus: http.StatusCreated},
	{name: "restore", operation: "restore", method: http.MethodPost, path: "/api/engrams/test-id/restore?vault=default", wantStatus: http.StatusOK},
	{name: "retry enrich", operation: "retry-enrich", method: http.MethodPost, path: "/api/engrams/test-id/retry-enrich?vault=default", wantStatus: http.StatusOK},
}

func newModeGuardRouteServer(t *testing.T, public bool) (*Server, *modeGuardTrackingEngine, *auth.Store) {
	t.Helper()
	store := newTestAuthStore(t)
	if err := store.SetVaultConfig(auth.VaultConfig{Name: "default", Public: public}); err != nil {
		t.Fatalf("SetVaultConfig: %v", err)
	}
	eng := &modeGuardTrackingEngine{}
	srv := NewServer("localhost:0", eng, store, nil, nil, EmbedInfo{}, EnrichInfo{}, nil, "", nil)
	t.Cleanup(func() { close(srv.shutdown) })
	return srv, eng, store
}

func generateModeKey(t *testing.T, store *auth.Store, mode string) string {
	t.Helper()
	token, _, err := store.GenerateAPIKey("default", mode+"-test", mode, nil)
	if err != nil {
		t.Fatalf("GenerateAPIKey(%s): %v", mode, err)
	}
	return token
}

func serveModeGuardRoute(srv *Server, route modeGuardRoute, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(route.method, route.path, strings.NewReader(route.body))
	if route.body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	return w
}

func assertSingleModeGuardCall(t *testing.T, eng *modeGuardTrackingEngine, operation, mode string) {
	t.Helper()
	if len(eng.calls) != 1 {
		t.Fatalf("engine calls=%v, want one %s call", eng.calls, operation)
	}
	if got := eng.calls[0]; got.operation != operation || got.mode != mode {
		t.Fatalf("engine call=%+v, want operation=%q mode=%q", got, operation, mode)
	}
}

func TestObserveMode_MutatingRoutesDeniedBeforeEngine(t *testing.T) {
	srv, eng, store := newModeGuardRouteServer(t, false)
	token := generateModeKey(t, store, auth.ModeObserve)

	for _, route := range mutatingModeGuardRoutes {
		t.Run(route.name, func(t *testing.T) {
			eng.calls = nil
			w := serveModeGuardRoute(srv, route, token)
			if w.Code != http.StatusForbidden {
				t.Fatalf("status=%d body=%s, want 403", w.Code, w.Body.String())
			}
			if len(eng.calls) != 0 {
				t.Fatalf("engine was invoked before denial: %+v", eng.calls)
			}
		})
	}
}

func TestPublicVault_MutatingRoutesRunInFullMode(t *testing.T) {
	srv, eng, _ := newModeGuardRouteServer(t, true)

	for _, route := range mutatingModeGuardRoutes {
		t.Run(route.name, func(t *testing.T) {
			eng.calls = nil
			w := serveModeGuardRoute(srv, route, "")
			if w.Code != route.wantStatus {
				t.Fatalf("status=%d body=%s, want %d", w.Code, w.Body.String(), route.wantStatus)
			}
			assertSingleModeGuardCall(t, eng, route.operation, auth.ModeFull)
		})
	}
}

func TestPublicVault_ExplicitObserveKeyRemainsReadOnly(t *testing.T) {
	srv, eng, store := newModeGuardRouteServer(t, true)
	token := generateModeKey(t, store, auth.ModeObserve)

	w := serveModeGuardRoute(srv, mutatingModeGuardRoutes[0], token)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s, want 403", w.Code, w.Body.String())
	}
	if len(eng.calls) != 0 {
		t.Fatalf("engine was invoked before denial: %+v", eng.calls)
	}
}

func TestFullMode_MutatingRoutesRemainAllowed(t *testing.T) {
	srv, eng, store := newModeGuardRouteServer(t, false)
	token := generateModeKey(t, store, auth.ModeFull)

	for _, route := range mutatingModeGuardRoutes {
		t.Run(route.name, func(t *testing.T) {
			eng.calls = nil
			w := serveModeGuardRoute(srv, route, token)
			if w.Code != route.wantStatus {
				t.Fatalf("status=%d body=%s, want %d", w.Code, w.Body.String(), route.wantStatus)
			}
			assertSingleModeGuardCall(t, eng, route.operation, auth.ModeFull)
		})
	}
}

func TestWriteMode_PureMutationRoutesRemainAllowed(t *testing.T) {
	srv, eng, store := newModeGuardRouteServer(t, false)
	token := generateModeKey(t, store, auth.ModeWrite)

	for _, route := range mutatingModeGuardRoutes[:6] {
		t.Run(route.name, func(t *testing.T) {
			eng.calls = nil
			w := serveModeGuardRoute(srv, route, token)
			if w.Code != route.wantStatus {
				t.Fatalf("status=%d body=%s, want %d", w.Code, w.Body.String(), route.wantStatus)
			}
			assertSingleModeGuardCall(t, eng, route.operation, auth.ModeWrite)
		})
	}
}

func TestWriteMode_DataReturningMutationsRemainDenied(t *testing.T) {
	srv, eng, store := newModeGuardRouteServer(t, false)
	token := generateModeKey(t, store, auth.ModeWrite)

	for _, route := range mutatingModeGuardRoutes[6:] {
		t.Run(route.name, func(t *testing.T) {
			eng.calls = nil
			w := serveModeGuardRoute(srv, route, token)
			if w.Code != http.StatusForbidden {
				t.Fatalf("status=%d body=%s, want 403", w.Code, w.Body.String())
			}
			if len(eng.calls) != 0 {
				t.Fatalf("engine was invoked before denial: %+v", eng.calls)
			}
		})
	}
}

func TestObserveMode_ReadLikePostRoutesRemainAllowed(t *testing.T) {
	srv, _, store := newModeGuardRouteServer(t, false)
	token := generateModeKey(t, store, auth.ModeObserve)
	routes := []modeGuardRoute{
		{name: "activate", method: http.MethodPost, path: "/api/activate?vault=default", body: `{"context":["test"]}`},
		{name: "batch links", method: http.MethodPost, path: "/api/engrams/links/batch?vault=default", body: `{"ids":["test-id"]}`},
		{name: "traverse", method: http.MethodPost, path: "/api/traverse?vault=default", body: `{"start_id":"test-id"}`},
		{name: "explain", method: http.MethodPost, path: "/api/explain?vault=default", body: `{"engram_id":"test-id"}`},
	}

	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			w := serveModeGuardRoute(srv, route, token)
			if w.Code == http.StatusUnauthorized || w.Code == http.StatusForbidden {
				t.Fatalf("observe semantic-read status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
}

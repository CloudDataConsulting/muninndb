package rest

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/scrypster/muninndb/internal/auth"
	"github.com/scrypster/muninndb/internal/engine"
)

type externalIdentityRESTEngine struct {
	MockEngine
	lastWrite *WriteRequest
	lastBatch []*WriteRequest
	writeErr  error
}

func (e *externalIdentityRESTEngine) Write(ctx context.Context, req *WriteRequest) (*WriteResponse, error) {
	e.lastWrite = req
	if e.writeErr != nil {
		return nil, e.writeErr
	}
	return e.MockEngine.Write(ctx, req)
}

func (e *externalIdentityRESTEngine) WriteBatch(ctx context.Context, reqs []*WriteRequest) ([]*WriteResponse, []error) {
	e.lastBatch = reqs
	return e.MockEngine.WriteBatch(ctx, reqs)
}

func TestRESTCreateForwardsIdempotentID(t *testing.T) {
	eng := &externalIdentityRESTEngine{}
	srv := &Server{engine: eng}
	req := httptest.NewRequest(http.MethodPost, "/api/engrams", strings.NewReader(`{"vault":"client","content":"hello","idempotent_id":"source:event:1"}`))
	req = req.WithContext(context.WithValue(req.Context(), auth.ContextVault, "client"))
	w := httptest.NewRecorder()
	srv.handleCreateEngram(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	if eng.lastWrite == nil || eng.lastWrite.IdempotentID != "source:event:1" || eng.lastWrite.Vault != "client" {
		t.Fatalf("forwarded request = %+v", eng.lastWrite)
	}
}

func TestRESTCreateExternalIdentityConflictReturns409(t *testing.T) {
	eng := &externalIdentityRESTEngine{writeErr: fmt.Errorf("write engram: %w", engine.ErrExternalIdentityConflict)}
	srv := &Server{engine: eng}
	req := httptest.NewRequest(http.MethodPost, "/api/engrams?vault=client", strings.NewReader(`{"content":"changed","idempotent_id":"source:event:1"}`))
	w := httptest.NewRecorder()
	srv.handleCreateEngram(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", w.Code, w.Body.String())
	}
}

func TestRESTCreateExternalIdentitySafetyErrorsAreTyped(t *testing.T) {
	for name, tc := range map[string]struct {
		err    error
		status int
	}{
		"post-commit payload": {err: engine.ErrExternalIdentityUnsupportedPayload, status: http.StatusUnprocessableEntity},
		"cluster mode":        {err: engine.ErrExternalIdentityClusterUnsupported, status: http.StatusServiceUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			eng := &externalIdentityRESTEngine{writeErr: tc.err}
			srv := &Server{engine: eng}
			req := httptest.NewRequest(http.MethodPost, "/api/engrams", strings.NewReader(`{"content":"x","idempotent_id":"event"}`))
			w := httptest.NewRecorder()
			srv.handleCreateEngram(w, req)
			if w.Code != tc.status {
				t.Fatalf("status = %d, want %d; body=%s", w.Code, tc.status, w.Body.String())
			}
		})
	}
}

func TestRESTBatchForwardsPerItemIdempotentIDs(t *testing.T) {
	eng := &externalIdentityRESTEngine{}
	srv := &Server{engine: eng}
	body := `{"engrams":[{"vault":"client","content":"a","idempotent_id":"event-a"},{"vault":"client","content":"b","idempotent_id":"event-b"}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/engrams/batch", strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), auth.ContextVault, "client"))
	w := httptest.NewRecorder()
	srv.handleBatchCreate(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	if len(eng.lastBatch) != 2 || eng.lastBatch[0].IdempotentID != "event-a" || eng.lastBatch[1].IdempotentID != "event-b" {
		t.Fatalf("forwarded batch = %+v", eng.lastBatch)
	}
	if eng.lastBatch[0].Vault != "client" || eng.lastBatch[1].Vault != "client" {
		t.Fatalf("batch vaults = %q/%q", eng.lastBatch[0].Vault, eng.lastBatch[1].Vault)
	}
}

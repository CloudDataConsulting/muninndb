package rest

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/scrypster/muninndb/internal/auth"
	"github.com/scrypster/muninndb/internal/engine/trigger"
	"github.com/scrypster/muninndb/internal/storage"
	"github.com/scrypster/muninndb/internal/transport/mbp"
)

var sseSessionSecret = []byte("sse-security-session-secret")

type sseSecurityEngine struct {
	MockEngine
	mu           sync.Mutex
	deliver      trigger.DeliverFunc
	subscribeCtx context.Context
	subscribeReq *mbp.SubscribeRequest
	ready        chan struct{}
	readyOnce    sync.Once
}

func newSSESecurityEngine() *sseSecurityEngine {
	return &sseSecurityEngine{ready: make(chan struct{})}
}

func (e *sseSecurityEngine) SubscribeWithDeliver(ctx context.Context, req *mbp.SubscribeRequest, deliver trigger.DeliverFunc) (string, error) {
	e.mu.Lock()
	e.deliver = deliver
	e.subscribeCtx = context.WithoutCancel(ctx)
	copyReq := *req
	e.subscribeReq = &copyReq
	e.mu.Unlock()
	e.readyOnce.Do(func() { close(e.ready) })
	return "security-sub", nil
}

func (e *sseSecurityEngine) push(push *trigger.ActivationPush) error {
	e.mu.Lock()
	deliver := e.deliver
	e.mu.Unlock()
	if deliver == nil {
		return errors.New("subscription delivery is not ready")
	}
	return deliver(context.Background(), push)
}

type testSSEStream struct {
	lines  <-chan string
	done   <-chan error
	cancel context.CancelFunc
	body   *http.Response
}

func openTestSSEStream(t *testing.T, serverURL, path, token string, cookie *http.Cookie) *testSSEStream {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, serverURL+path, nil)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		t.Fatalf("open SSE stream: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		cancel()
		t.Fatalf("open SSE status=%d", resp.StatusCode)
	}

	lines := make(chan string, 32)
	done := make(chan error, 1)
	go func() {
		defer close(lines)
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			lines <- scanner.Text()
		}
		done <- scanner.Err()
	}()

	stream := &testSSEStream{lines: lines, done: done, cancel: cancel, body: resp}
	t.Cleanup(func() {
		cancel()
		resp.Body.Close()
	})
	return stream
}

func waitForSSELine(t *testing.T, stream *testSSEStream, substring string) {
	t.Helper()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for {
		select {
		case line, ok := <-stream.lines:
			if !ok {
				t.Fatalf("SSE stream closed before line containing %q", substring)
			}
			if strings.Contains(line, substring) {
				return
			}
		case err := <-stream.done:
			t.Fatalf("SSE stream ended before line containing %q: %v", substring, err)
		case <-timer.C:
			t.Fatalf("timed out waiting for SSE line containing %q", substring)
		}
	}
}

func waitForSSEClose(t *testing.T, stream *testSSEStream) {
	t.Helper()
	select {
	case err := <-stream.done:
		if err != nil {
			t.Fatalf("SSE stream closed with read error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for unauthorized SSE stream to close")
	}
}

func newSSEAuthTestServer(t *testing.T, engine *sseSecurityEngine, store *auth.Store) (*Server, *httptest.Server) {
	t.Helper()
	server := NewServer("localhost:0", engine, store, sseSessionSecret, nil, EmbedInfo{}, EnrichInfo{}, nil, "", nil)
	server.subscriptionAuthorizationInterval = 5 * time.Millisecond
	httpServer := httptest.NewServer(server.Handler())
	t.Cleanup(func() {
		httpServer.Close()
		select {
		case <-server.shutdown:
		default:
			close(server.shutdown)
		}
	})
	return server, httpServer
}

func shortLivedAdminCookie(expiry time.Time) *http.Cookie {
	payload := "admin|" + strconv.FormatInt(expiry.Unix(), 10)
	encoded := base64.RawURLEncoding.EncodeToString([]byte(payload))
	mac := hmac.New(sha256.New, sseSessionSecret)
	mac.Write([]byte(encoded))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return &http.Cookie{Name: "muninn_session", Value: encoded + "." + signature}
}

func TestSSERevokedKeyStopsDeliveryAndClosesStream(t *testing.T) {
	store := newTestAuthStore(t)
	if err := store.SetVaultConfig(auth.VaultConfig{Name: "private", Public: false}); err != nil {
		t.Fatal(err)
	}
	token, key, err := store.GenerateAPIKey("private", "stream", auth.ModeFull, nil)
	if err != nil {
		t.Fatal(err)
	}
	engine := newSSESecurityEngine()
	_, httpServer := newSSEAuthTestServer(t, engine, store)
	stream := openTestSSEStream(t, httpServer.URL, "/api/subscribe?vault=private&on_write=true", token, nil)
	waitForSSELine(t, stream, "event: subscribed")

	if err := engine.push(&trigger.ActivationPush{SubscriptionID: "security-sub", Trigger: trigger.TriggerNewWrite, Engram: &storage.Engram{Concept: "allowed"}}); err != nil {
		t.Fatalf("valid delivery: %v", err)
	}
	waitForSSELine(t, stream, "event: push")

	if err := store.RevokeAPIKey("private", key.ID); err != nil {
		t.Fatal(err)
	}
	if err := engine.push(&trigger.ActivationPush{SubscriptionID: "security-sub", Trigger: trigger.TriggerNewWrite, Engram: &storage.Engram{Concept: "must-not-leak"}}); err == nil {
		t.Fatal("delivery with revoked key succeeded")
	}
	waitForSSEClose(t, stream)
}

func TestSSEExpiredKeyClosesIdleStream(t *testing.T) {
	store := newTestAuthStore(t)
	if err := store.SetVaultConfig(auth.VaultConfig{Name: "expiring", Public: false}); err != nil {
		t.Fatal(err)
	}
	expiresAt := time.Now().Add(300 * time.Millisecond)
	token, _, err := store.GenerateAPIKey("expiring", "stream", auth.ModeObserve, &expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	engine := newSSESecurityEngine()
	_, httpServer := newSSEAuthTestServer(t, engine, store)
	stream := openTestSSEStream(t, httpServer.URL, "/api/subscribe?vault=expiring", token, nil)
	waitForSSELine(t, stream, "event: subscribed")
	waitForSSEClose(t, stream)
}

func TestSSEPublicVaultLockClosesIdleStream(t *testing.T) {
	store := newTestAuthStore(t)
	if err := store.SetVaultConfig(auth.VaultConfig{Name: "public-stream", Public: true}); err != nil {
		t.Fatal(err)
	}
	engine := newSSESecurityEngine()
	_, httpServer := newSSEAuthTestServer(t, engine, store)
	stream := openTestSSEStream(t, httpServer.URL, "/api/subscribe?vault=public-stream", "", nil)
	waitForSSELine(t, stream, "event: subscribed")
	if err := store.SetVaultConfig(auth.VaultConfig{Name: "public-stream", Public: false}); err != nil {
		t.Fatal(err)
	}
	waitForSSEClose(t, stream)
}

func TestSSEExpiredAdminSessionClosesWithoutPublicDowngrade(t *testing.T) {
	store := newTestAuthStore(t)
	if err := store.SetVaultConfig(auth.VaultConfig{Name: "admin-public", Public: true}); err != nil {
		t.Fatal(err)
	}
	engine := newSSESecurityEngine()
	_, httpServer := newSSEAuthTestServer(t, engine, store)
	stream := openTestSSEStream(
		t,
		httpServer.URL,
		"/api/subscribe?vault=admin-public",
		"",
		shortLivedAdminCookie(time.Now().Add(1200*time.Millisecond)),
	)
	waitForSSELine(t, stream, "event: subscribed")
	engine.mu.Lock()
	subscribeCtx := engine.subscribeCtx
	engine.mu.Unlock()
	if got := auth.PrincipalFromContext(subscribeCtx); got != auth.PrincipalAdmin {
		t.Fatalf("subscription principal=%q, want admin", got)
	}
	waitForSSEClose(t, stream)
	if cfg, err := store.GetVaultConfig("admin-public"); err != nil || !cfg.Public {
		t.Fatalf("public policy changed during test: cfg=%+v err=%v", cfg, err)
	}
}

func TestSSECredentialCrossVaultAndWriteModeDenied(t *testing.T) {
	store := newTestAuthStore(t)
	for _, vault := range []string{"vault-a", "vault-b"} {
		if err := store.SetVaultConfig(auth.VaultConfig{Name: vault, Public: false}); err != nil {
			t.Fatal(err)
		}
	}
	fullToken, _, err := store.GenerateAPIKey("vault-a", "full", auth.ModeFull, nil)
	if err != nil {
		t.Fatal(err)
	}
	writeToken, _, err := store.GenerateAPIKey("vault-a", "write", auth.ModeWrite, nil)
	if err != nil {
		t.Fatal(err)
	}
	engine := newSSESecurityEngine()
	server, _ := newSSEAuthTestServer(t, engine, store)

	tests := []struct {
		name  string
		path  string
		token string
		code  int
	}{
		{name: "cross-vault", path: "/api/subscribe?vault=vault-b", token: fullToken, code: http.StatusUnauthorized},
		{name: "write-mode", path: "/api/subscribe?vault=vault-a", token: writeToken, code: http.StatusForbidden},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, test.path, nil)
			req.Header.Set("Authorization", "Bearer "+test.token)
			writer := httptest.NewRecorder()
			server.mux.ServeHTTP(writer, req)
			if writer.Code != test.code {
				t.Fatalf("status=%d body=%s, want %d", writer.Code, writer.Body.String(), test.code)
			}
		})
	}
}

func TestSubscribeAcceptsOriginalAndSDKPushOnWriteParameters(t *testing.T) {
	tests := []struct {
		query string
		want  bool
	}{
		{query: "on_write=true", want: true},
		{query: "on_write=1", want: true},
		{query: "push_on_write=true", want: true},
		{query: "push_on_write=1", want: true},
		{query: "push_on_write=false", want: false},
	}
	for _, test := range tests {
		t.Run(test.query, func(t *testing.T) {
			engine := newSSESecurityEngine()
			server := NewServer("localhost:0", engine, nil, nil, nil, EmbedInfo{}, EnrichInfo{}, nil, "", nil)
			t.Cleanup(func() { close(server.shutdown) })
			ctx, cancel := context.WithCancel(context.Background())
			req := httptest.NewRequest(http.MethodGet, "/api/subscribe?"+test.query, nil).WithContext(ctx)
			writer := httptest.NewRecorder()
			done := make(chan struct{})
			go func() {
				server.handleSubscribe(writer, req)
				close(done)
			}()
			<-engine.ready
			cancel()
			<-done
			engine.mu.Lock()
			got := engine.subscribeReq.PushOnWrite
			engine.mu.Unlock()
			if got != test.want {
				t.Fatalf("PushOnWrite=%v, want %v", got, test.want)
			}
		})
	}
}

func TestStatusRecorderPreservesStreamingCapabilities(t *testing.T) {
	inner := httptest.NewRecorder()
	recorder := &statusRecorder{ResponseWriter: inner}
	if _, ok := any(recorder).(http.Flusher); !ok {
		t.Fatal("statusRecorder does not implement http.Flusher")
	}
	if got := recorder.Unwrap(); got != inner {
		t.Fatalf("Unwrap()=%T, want underlying recorder", got)
	}
}

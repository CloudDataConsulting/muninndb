package mbp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/vfs"
	"github.com/scrypster/muninndb/internal/auth"
)

type wireCall struct {
	op    string
	vault string
	mode  string
}

type wireAuthEngine struct {
	stubEngine

	mu           sync.Mutex
	calls        []wireCall
	unsubscribed []string

	writeStarted chan struct{}
	releaseWrite chan struct{}
	writeOnce    sync.Once
}

func (e *wireAuthEngine) record(ctx context.Context, op, vault string) {
	mode, _ := ctx.Value(auth.ContextMode).(string)
	e.mu.Lock()
	e.calls = append(e.calls, wireCall{op: op, vault: vault, mode: mode})
	e.mu.Unlock()
}

func (e *wireAuthEngine) Hello(ctx context.Context, req *HelloRequest) (*HelloResponse, error) {
	e.record(ctx, "hello", req.Vault)
	return BuildHelloResponse("session", req.Vault, req.Capabilities), nil
}

func (e *wireAuthEngine) Write(ctx context.Context, req *WriteRequest) (*WriteResponse, error) {
	e.record(ctx, "write", req.Vault)
	if e.writeStarted != nil {
		e.writeOnce.Do(func() { close(e.writeStarted) })
	}
	if e.releaseWrite != nil {
		select {
		case <-e.releaseWrite:
		case <-ctx.Done():
		}
	}
	return e.stubEngine.Write(ctx, req)
}

func (e *wireAuthEngine) Read(ctx context.Context, req *ReadRequest) (*ReadResponse, error) {
	e.record(ctx, "read", req.Vault)
	return e.stubEngine.Read(ctx, req)
}

func (e *wireAuthEngine) Activate(ctx context.Context, req *ActivateRequest) (*ActivateResponse, error) {
	e.record(ctx, "activate", req.Vault)
	return e.stubEngine.Activate(ctx, req)
}

func (e *wireAuthEngine) Subscribe(ctx context.Context, req *SubscribeRequest) (*SubscribeResponse, error) {
	e.record(ctx, "subscribe", req.Vault)
	return &SubscribeResponse{SubID: req.SubscriptionID, Status: "active"}, nil
}

func (e *wireAuthEngine) Unsubscribe(_ context.Context, subID string) error {
	e.mu.Lock()
	e.unsubscribed = append(e.unsubscribed, subID)
	e.mu.Unlock()
	return nil
}

func (e *wireAuthEngine) Link(ctx context.Context, req *LinkRequest) (*LinkResponse, error) {
	e.record(ctx, "link", req.Vault)
	return e.stubEngine.Link(ctx, req)
}

func (e *wireAuthEngine) Forget(ctx context.Context, req *ForgetRequest) (*ForgetResponse, error) {
	e.record(ctx, "forget", req.Vault)
	return e.stubEngine.Forget(ctx, req)
}

func (e *wireAuthEngine) Stat(ctx context.Context, req *StatRequest) (*StatResponse, error) {
	e.record(ctx, "stat", req.Vault)
	return e.stubEngine.Stat(ctx, req)
}

func (e *wireAuthEngine) nonHelloCalls() []wireCall {
	e.mu.Lock()
	defer e.mu.Unlock()
	var calls []wireCall
	for _, call := range e.calls {
		if call.op != "hello" {
			calls = append(calls, call)
		}
	}
	return calls
}

func (e *wireAuthEngine) helloCall() wireCall {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, call := range e.calls {
		if call.op == "hello" {
			return call
		}
	}
	return wireCall{}
}

func (e *wireAuthEngine) unsubscribeCalls() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.unsubscribed...)
}

func newWireAuthStore(t *testing.T) *auth.Store {
	t.Helper()
	db, err := pebble.Open("", &pebble.Options{FS: vfs.NewMem()})
	if err != nil {
		t.Fatalf("open auth db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := auth.NewStore(db)
	for _, cfg := range []auth.VaultConfig{
		{Name: "default", Public: true},
		{Name: "public", Public: true},
		{Name: "private", Public: false},
	} {
		if err := store.SetVaultConfig(cfg); err != nil {
			t.Fatalf("set vault config %q: %v", cfg.Name, err)
		}
	}
	return store
}

func newWireServer(engine EngineAPI, store vaultAuthStore) *Server {
	return &Server{engine: engine, authStore: store, shutdown: make(chan struct{})}
}

func handshake(t *testing.T, conn net.Conn, req HelloRequest) *Frame {
	t.Helper()
	payload, err := EncodeMsgpack(&req)
	if err != nil {
		t.Fatalf("encode HELLO: %v", err)
	}
	if err := WriteFrame(conn, &Frame{Version: 1, Type: TypeHello, CorrelationID: 1, Payload: payload}); err != nil {
		t.Fatalf("write HELLO: %v", err)
	}
	frame, err := ReadFrame(conn)
	if err != nil {
		t.Fatalf("read HELLO response: %v", err)
	}
	return frame
}

func assertWireError(t *testing.T, frame *Frame, wantCode ErrorCode) ErrorPayload {
	t.Helper()
	if frame.Type != TypeError {
		t.Fatalf("expected error frame, got type 0x%02x", frame.Type)
	}
	var payload ErrorPayload
	if err := DecodeMsgpack(frame.Payload, &payload); err != nil {
		t.Fatalf("decode error payload: %v", err)
	}
	if payload.Code != wantCode {
		t.Fatalf("error code = %d (%s), want %d; message=%q", payload.Code, ErrorCodeMessage(payload.Code), wantCode, payload.Message)
	}
	return payload
}

func openTokenConnection(t *testing.T, server *Server, token, vault string) (net.Conn, func()) {
	t.Helper()
	conn, wait := startTestConn(t, server)
	frame := handshake(t, conn, HelloRequest{Version: "1", AuthMethod: "token", Token: token, Vault: vault})
	if frame.Type != TypeHelloOK {
		assertWireError(t, frame, authorizationErrorCode(newAuthorizationError(ErrAuthFailed, "handshake failed")))
		t.Fatalf("token HELLO failed")
	}
	return conn, wait
}

func TestMBPHelloBindsVaultAndMode(t *testing.T) {
	t.Run("anonymous explicitly public vault uses full mode", func(t *testing.T) {
		engine := &wireAuthEngine{}
		server := newWireServer(engine, newWireAuthStore(t))
		conn, wait := startTestConn(t, server)
		defer wait()

		frame := handshake(t, conn, HelloRequest{Version: "1", AuthMethod: "none", Vault: "public"})
		if frame.Type != TypeHelloOK {
			assertWireError(t, frame, ErrAuthFailed)
		}
		var response HelloResponse
		if err := DecodeMsgpack(frame.Payload, &response); err != nil {
			t.Fatalf("decode HELLO_OK: %v", err)
		}
		if response.VaultID != "public" {
			t.Fatalf("HELLO_OK vault = %q, want public", response.VaultID)
		}
		if got := engine.helloCall(); got.vault != "public" || got.mode != auth.ModeFull {
			t.Fatalf("engine HELLO call = %+v, want public/full", got)
		}
	})

	t.Run("anonymous private vault fails", func(t *testing.T) {
		server := newWireServer(&wireAuthEngine{}, newWireAuthStore(t))
		conn, wait := startTestConn(t, server)
		defer wait()
		assertWireError(t, handshake(t, conn, HelloRequest{Version: "1", AuthMethod: "none", Vault: "private"}), ErrAuthFailed)
	})

	t.Run("nil auth store fails closed", func(t *testing.T) {
		server := newWireServer(&wireAuthEngine{}, nil)
		conn, wait := startTestConn(t, server)
		defer wait()
		assertWireError(t, handshake(t, conn, HelloRequest{Version: "1", AuthMethod: "none"}), ErrAuthFailed)
	})

	t.Run("token auth also fails with nil auth store", func(t *testing.T) {
		server := newWireServer(&wireAuthEngine{}, nil)
		conn, wait := startTestConn(t, server)
		defer wait()
		assertWireError(t, handshake(t, conn, HelloRequest{Version: "1", AuthMethod: "token", Token: "mk_not-used"}), ErrAuthFailed)
	})

	t.Run("key vault is canonical when HELLO omits vault", func(t *testing.T) {
		store := newWireAuthStore(t)
		token, _, err := store.GenerateAPIKey("private", "test", auth.ModeObserve, nil)
		if err != nil {
			t.Fatal(err)
		}
		engine := &wireAuthEngine{}
		server := newWireServer(engine, store)
		conn, wait := startTestConn(t, server)
		defer wait()
		frame := handshake(t, conn, HelloRequest{Version: "1", AuthMethod: "token", Token: token})
		if frame.Type != TypeHelloOK {
			assertWireError(t, frame, ErrAuthFailed)
		}
		if got := engine.helloCall(); got.vault != "private" || got.mode != auth.ModeObserve {
			t.Fatalf("engine HELLO call = %+v, want private/observe", got)
		}
	})

	t.Run("key cannot select another vault", func(t *testing.T) {
		store := newWireAuthStore(t)
		token, _, err := store.GenerateAPIKey("private", "test", auth.ModeFull, nil)
		if err != nil {
			t.Fatal(err)
		}
		server := newWireServer(&wireAuthEngine{}, store)
		conn, wait := startTestConn(t, server)
		defer wait()
		assertWireError(t, handshake(t, conn, HelloRequest{Version: "1", AuthMethod: "token", Token: token, Vault: "public"}), ErrVaultForbidden)
	})
}

func TestMBPHelloRejectsInvalidKeyClaims(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  auth.APIKey
	}{
		{"empty key id", auth.APIKey{Vault: "private", Mode: auth.ModeFull}},
		{"empty vault", auth.APIKey{ID: "key-1", Mode: auth.ModeFull}},
		{"unknown mode", auth.APIKey{ID: "key-1", Vault: "private", Mode: "admin"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &mutableVaultAuthStore{key: tc.key, configs: map[string]auth.VaultConfig{}}
			server := newWireServer(&wireAuthEngine{}, store)
			conn, wait := startTestConn(t, server)
			defer wait()
			assertWireError(t, handshake(t, conn, HelloRequest{Version: "1", AuthMethod: "token", Token: "test-token"}), ErrAuthFailed)
		})
	}
}

func TestMBPRejectsNoncanonicalVaultsBeforeStoreOrEngine(t *testing.T) {
	t.Run("anonymous HELLO does not query invalid names", func(t *testing.T) {
		for _, vault := range []string{"Upper", " leading", "trailing ", "slash/name", "ümlaut", string(make([]byte, 65))} {
			t.Run(fmt.Sprintf("%x", []byte(vault)), func(t *testing.T) {
				store := &mutableVaultAuthStore{configs: map[string]auth.VaultConfig{}}
				server := newWireServer(&wireAuthEngine{}, store)
				conn, wait := startTestConn(t, server)
				defer wait()
				assertWireError(t, handshake(t, conn, HelloRequest{Version: "1", AuthMethod: "none", Vault: vault}), ErrAuthFailed)
				_, configReads := store.callCounts()
				if configReads != 0 {
					t.Fatalf("invalid vault reached GetVaultConfig %d times", configReads)
				}
			})
		}
	})

	t.Run("noncanonical key claim is rejected rather than rebound", func(t *testing.T) {
		store := &mutableVaultAuthStore{
			key:     auth.APIKey{ID: "key-1", Vault: " private ", Mode: auth.ModeFull},
			configs: map[string]auth.VaultConfig{},
		}
		engine := &wireAuthEngine{}
		server := newWireServer(engine, store)
		conn, wait := startTestConn(t, server)
		defer wait()
		assertWireError(t, handshake(t, conn, HelloRequest{Version: "1", AuthMethod: "token", Token: "test-token"}), ErrAuthFailed)
		if got := engine.helloCall(); got.op != "" {
			t.Fatalf("invalid key claim reached engine: %+v", got)
		}
	})

	t.Run("per-frame vault is not whitespace-normalized", func(t *testing.T) {
		store := newWireAuthStore(t)
		token, _, err := store.GenerateAPIKey("private", "test", auth.ModeFull, nil)
		if err != nil {
			t.Fatal(err)
		}
		engine := &wireAuthEngine{}
		conn, wait := openTokenConnection(t, newWireServer(engine, store), token, "")
		defer wait()
		assertWireError(t, sendAndReceive(t, conn, TypeRead, 18, &ReadRequest{ID: "id", Vault: " private "}), ErrVaultForbidden)
		if calls := engine.nonHelloCalls(); len(calls) != 0 {
			t.Fatalf("invalid per-frame vault reached engine: %+v", calls)
		}
	})
}

func TestMBPCrossVaultRejectedForEveryRequestType(t *testing.T) {
	store := newWireAuthStore(t)
	token, _, err := store.GenerateAPIKey("private", "test", auth.ModeFull, nil)
	if err != nil {
		t.Fatal(err)
	}
	engine := &wireAuthEngine{}
	server := newWireServer(engine, store)
	conn, wait := openTokenConnection(t, server, token, "")
	defer wait()

	tests := []struct {
		name  string
		type_ uint8
		req   any
	}{
		{"write", TypeWrite, &WriteRequest{Concept: "c", Vault: "public"}},
		{"read", TypeRead, &ReadRequest{ID: "id", Vault: "public"}},
		{"activate", TypeActivate, &ActivateRequest{Context: []string{"q"}, Vault: "public"}},
		{"subscribe", TypeSubscribe, &SubscribeRequest{Context: []string{"q"}, Vault: "public"}},
		{"link", TypeLink, &LinkRequest{SourceID: "a", TargetID: "b", Vault: "public"}},
		{"forget", TypeForget, &ForgetRequest{ID: "id", Vault: "public"}},
		{"stat", TypeStat, &StatRequest{Vault: "public"}},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frame := sendAndReceive(t, conn, tt.type_, uint64(i+10), tt.req)
			assertWireError(t, frame, ErrVaultForbidden)
		})
	}
	if calls := engine.nonHelloCalls(); len(calls) != 0 {
		t.Fatalf("cross-vault requests reached engine: %+v", calls)
	}
}

func TestMBPAnonymousSessionCannotSwitchPublicVaults(t *testing.T) {
	store := newWireAuthStore(t)
	engine := &wireAuthEngine{}
	server := newWireServer(engine, store)
	conn, wait := startTestConn(t, server)
	defer wait()
	if frame := handshake(t, conn, HelloRequest{Version: "1", AuthMethod: "none", Vault: "public"}); frame.Type != TypeHelloOK {
		t.Fatalf("HELLO response = 0x%02x", frame.Type)
	}
	assertWireError(t, sendAndReceive(t, conn, TypeRead, 19, &ReadRequest{ID: "id", Vault: "default"}), ErrVaultForbidden)
	if calls := engine.nonHelloCalls(); len(calls) != 0 {
		t.Fatalf("anonymous cross-vault request reached engine: %+v", calls)
	}
}

func TestMBPLegacyVaultFlagCannotOverrideSessionVault(t *testing.T) {
	store := newWireAuthStore(t)
	token, _, err := store.GenerateAPIKey("private", "test", auth.ModeFull, nil)
	if err != nil {
		t.Fatal(err)
	}
	engine := &wireAuthEngine{}
	conn, wait := openTokenConnection(t, newWireServer(engine, store), token, "")
	defer wait()
	payload, err := EncodeMsgpack(&ReadRequest{ID: "id", Vault: "public"})
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteFrame(conn, &Frame{Version: 1, Type: TypeRead, Flags: FlagVault, CorrelationID: 19, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	frame, err := ReadFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	assertWireError(t, frame, ErrVaultForbidden)
	if calls := engine.nonHelloCalls(); len(calls) != 0 {
		t.Fatalf("legacy vault flag overrode session scope: %+v", calls)
	}
}

func TestMBPEmptyVaultPinnedForEveryRequestType(t *testing.T) {
	store := newWireAuthStore(t)
	token, _, err := store.GenerateAPIKey("private", "test", auth.ModeFull, nil)
	if err != nil {
		t.Fatal(err)
	}
	engine := &wireAuthEngine{}
	server := newWireServer(engine, store)
	conn, wait := openTokenConnection(t, server, token, "")
	defer wait()

	tests := []struct {
		name     string
		type_    uint8
		wantType uint8
		req      any
	}{
		{"write", TypeWrite, TypeWriteOK, &WriteRequest{Concept: "c"}},
		{"read", TypeRead, TypeReadResp, &ReadRequest{ID: "id"}},
		{"activate", TypeActivate, TypeActivateResp, &ActivateRequest{Context: []string{"q"}}},
		{"subscribe", TypeSubscribe, TypeSubOK, &SubscribeRequest{Context: []string{"q"}}},
		{"link", TypeLink, TypeLinkOK, &LinkRequest{SourceID: "a", TargetID: "b"}},
		{"forget", TypeForget, TypeForgetOK, &ForgetRequest{ID: "id"}},
		{"stat", TypeStat, TypeStatResp, &StatRequest{}},
	}
	for i, tt := range tests {
		frame := sendAndReceive(t, conn, tt.type_, uint64(i+20), tt.req)
		if frame.Type != tt.wantType {
			t.Fatalf("%s response type = 0x%02x, want 0x%02x", tt.name, frame.Type, tt.wantType)
		}
	}
	for _, call := range engine.nonHelloCalls() {
		if call.vault != "private" || call.mode != auth.ModeFull {
			t.Fatalf("engine call not pinned to private/full: %+v", call)
		}
	}
}

func TestMBPModeEnforcement(t *testing.T) {
	t.Run("observe denies mutations and permits reads", func(t *testing.T) {
		store := newWireAuthStore(t)
		token, _, err := store.GenerateAPIKey("private", "observe", auth.ModeObserve, nil)
		if err != nil {
			t.Fatal(err)
		}
		engine := &wireAuthEngine{}
		conn, wait := openTokenConnection(t, newWireServer(engine, store), token, "")
		defer wait()

		denied := []struct {
			type_ uint8
			req   any
		}{
			{TypeWrite, &WriteRequest{Concept: "c"}},
			{TypeLink, &LinkRequest{SourceID: "a", TargetID: "b"}},
			{TypeForget, &ForgetRequest{ID: "id"}},
		}
		for i, tt := range denied {
			assertWireError(t, sendAndReceive(t, conn, tt.type_, uint64(i+30), tt.req), ErrVaultForbidden)
		}
		if frame := sendAndReceive(t, conn, TypeRead, 40, &ReadRequest{ID: "id"}); frame.Type != TypeReadResp {
			t.Fatalf("observe read response = 0x%02x", frame.Type)
		}
		if frame := sendAndReceive(t, conn, TypePing, 41, &PingRequest{Data: "ok"}); frame.Type != TypePong {
			t.Fatalf("observe ping response = 0x%02x", frame.Type)
		}
		calls := engine.nonHelloCalls()
		if len(calls) != 1 || calls[0].op != "read" || calls[0].mode != auth.ModeObserve {
			t.Fatalf("unexpected observe engine calls: %+v", calls)
		}
	})

	t.Run("write-only denies reads and permits mutations", func(t *testing.T) {
		store := newWireAuthStore(t)
		token, _, err := store.GenerateAPIKey("private", "ingest", auth.ModeWrite, nil)
		if err != nil {
			t.Fatal(err)
		}
		engine := &wireAuthEngine{}
		conn, wait := openTokenConnection(t, newWireServer(engine, store), token, "")
		defer wait()

		denied := []struct {
			type_ uint8
			req   any
		}{
			{TypeRead, &ReadRequest{ID: "id"}},
			{TypeActivate, &ActivateRequest{Context: []string{"q"}}},
			{TypeSubscribe, &SubscribeRequest{Context: []string{"q"}}},
			{TypeStat, &StatRequest{}},
		}
		for i, tt := range denied {
			assertWireError(t, sendAndReceive(t, conn, tt.type_, uint64(i+50), tt.req), ErrVaultForbidden)
		}
		if frame := sendAndReceive(t, conn, TypeWrite, 60, &WriteRequest{Concept: "c"}); frame.Type != TypeWriteOK {
			t.Fatalf("write-only write response = 0x%02x", frame.Type)
		}
		if frame := sendAndReceive(t, conn, TypePing, 61, &PingRequest{Data: "ok"}); frame.Type != TypePong {
			t.Fatalf("write-only ping response = 0x%02x", frame.Type)
		}
		calls := engine.nonHelloCalls()
		if len(calls) != 1 || calls[0].op != "write" || calls[0].mode != auth.ModeWrite {
			t.Fatalf("unexpected write-only engine calls: %+v", calls)
		}
	})
}

type overadvertisingHelloEngine struct {
	wireAuthEngine
}

func (e *overadvertisingHelloEngine) Hello(ctx context.Context, req *HelloRequest) (*HelloResponse, error) {
	e.record(ctx, "hello", req.Vault)
	return &HelloResponse{
		ServerVersion: "test",
		SessionID:     "session",
		VaultID:       "wrong-vault",
		Capabilities:  []string{"compression", "not-a-server-capability"},
		Limits:        Limits{MaxResults: 999, MaxHopDepth: 999, MaxRate: 999, MaxPayloadMB: 64},
	}, nil
}

func TestMBPTransportOwnsHelloCapabilitiesAndLimits(t *testing.T) {
	server := newWireServer(&overadvertisingHelloEngine{}, newWireAuthStore(t))
	conn, wait := startTestConn(t, server)
	defer wait()
	frame := handshake(t, conn, HelloRequest{Version: "1", AuthMethod: "none"})
	if frame.Type != TypeHelloOK {
		t.Fatalf("HELLO response = 0x%02x", frame.Type)
	}
	var response HelloResponse
	if err := DecodeMsgpack(frame.Payload, &response); err != nil {
		t.Fatal(err)
	}
	if len(response.Capabilities) != 0 {
		t.Fatalf("engine over-advertisement escaped transport negotiation: %v", response.Capabilities)
	}
	if response.Limits != ServerLimits || response.Limits.MaxPayloadMB != MaxPayloadSize/(1024*1024) {
		t.Fatalf("HELLO limits = %+v, want transport limits %+v", response.Limits, ServerLimits)
	}
	if response.VaultID != "default" {
		t.Fatalf("HELLO vault = %q, want default", response.VaultID)
	}

	payload, err := EncodeMsgpack(&PingRequest{Data: strings.Repeat("x", 4096)})
	if err != nil {
		t.Fatal(err)
	}
	compressed, ok, err := CompressPayload(payload)
	if err != nil || !ok {
		t.Fatalf("compress test payload: compressed=%v err=%v", ok, err)
	}
	if err := WriteFrame(conn, &Frame{Version: 1, Type: TypePing, Flags: FlagCompressed, CorrelationID: 61, Payload: compressed}); err != nil {
		t.Fatal(err)
	}
	compressedResponse, err := ReadFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	assertWireError(t, compressedResponse, ErrInvalidEngram)
}

func TestMBPCompressedFramesAreAuthorizedNegotiatedAndBounded(t *testing.T) {
	compressedPing := func(t *testing.T) []byte {
		t.Helper()
		payload, err := EncodeMsgpack(&PingRequest{Data: strings.Repeat("x", 4096)})
		if err != nil {
			t.Fatal(err)
		}
		compressed, ok, err := CompressPayload(payload)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Fatal("test payload did not compress")
		}
		return compressed
	}

	t.Run("compression must be negotiated", func(t *testing.T) {
		server := newWireServer(&wireAuthEngine{}, newWireAuthStore(t))
		conn, wait := startTestConn(t, server)
		defer wait()
		if frame := handshake(t, conn, HelloRequest{Version: "1", AuthMethod: "none"}); frame.Type != TypeHelloOK {
			t.Fatalf("HELLO response = 0x%02x", frame.Type)
		}
		if err := WriteFrame(conn, &Frame{Version: 1, Type: TypePing, Flags: FlagCompressed, CorrelationID: 62, Payload: compressedPing(t)}); err != nil {
			t.Fatal(err)
		}
		frame, err := ReadFrame(conn)
		if err != nil {
			t.Fatal(err)
		}
		assertWireError(t, frame, ErrInvalidEngram)
	})

	t.Run("negotiated compressed frame succeeds", func(t *testing.T) {
		server := newWireServer(&wireAuthEngine{}, newWireAuthStore(t))
		conn, wait := startTestConn(t, server)
		defer wait()
		if frame := handshake(t, conn, HelloRequest{Version: "1", AuthMethod: "none", Capabilities: []string{"compression"}}); frame.Type != TypeHelloOK {
			t.Fatalf("HELLO response = 0x%02x", frame.Type)
		}
		if err := WriteFrame(conn, &Frame{Version: 1, Type: TypePing, Flags: FlagCompressed, CorrelationID: 63, Payload: compressedPing(t)}); err != nil {
			t.Fatal(err)
		}
		frame, err := ReadFrame(conn)
		if err != nil {
			t.Fatal(err)
		}
		if frame.Type != TypePong {
			t.Fatalf("compressed ping response = 0x%02x", frame.Type)
		}
	})

	t.Run("authorization precedes decompression", func(t *testing.T) {
		store := newWireAuthStore(t)
		token, key, err := store.GenerateAPIKey("private", "test", auth.ModeFull, nil)
		if err != nil {
			t.Fatal(err)
		}
		server := newWireServer(&wireAuthEngine{}, store)
		server.authRecheckInterval = time.Hour
		conn, wait := openTokenConnection(t, server, token, "")
		defer wait()
		if err := store.RevokeAPIKey("private", key.ID); err != nil {
			t.Fatal(err)
		}
		if err := WriteFrame(conn, &Frame{Version: 1, Type: TypePing, Flags: FlagCompressed, CorrelationID: 64, Payload: []byte("not-zstd")}); err != nil {
			t.Fatal(err)
		}
		frame, err := ReadFrame(conn)
		if err != nil {
			t.Fatal(err)
		}
		assertWireError(t, frame, ErrAuthFailed)
	})

	t.Run("decoder rejects output beyond frame limit", func(t *testing.T) {
		payload := bytes.Repeat([]byte{'x'}, maxDecompressedPayloadSize+1)
		compressed, ok, err := CompressPayload(payload)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Fatal("oversized test payload did not compress")
		}
		if _, err := DecompressPayload(compressed); err == nil {
			t.Fatal("expected bounded decoder to reject oversized output")
		}
	})
}

func TestMBPRevalidatesAuthorizationEveryFrame(t *testing.T) {
	t.Run("revoked key", func(t *testing.T) {
		store := newWireAuthStore(t)
		token, key, err := store.GenerateAPIKey("private", "test", auth.ModeFull, nil)
		if err != nil {
			t.Fatal(err)
		}
		engine := &wireAuthEngine{}
		server := newWireServer(engine, store)
		server.authRecheckInterval = time.Hour // exercise the per-frame terminal path
		conn, wait := openTokenConnection(t, server, token, "")
		subFrame := sendAndReceive(t, conn, TypeSubscribe, 69, &SubscribeRequest{Context: []string{"q"}})
		if subFrame.Type != TypeSubOK {
			t.Fatalf("subscribe response = 0x%02x", subFrame.Type)
		}
		var sub SubscribeResponse
		if err := DecodeMsgpack(subFrame.Payload, &sub); err != nil {
			t.Fatal(err)
		}
		if err := store.RevokeAPIKey("private", key.ID); err != nil {
			t.Fatal(err)
		}
		assertWireError(t, sendAndReceive(t, conn, TypeRead, 70, &ReadRequest{ID: "id"}), ErrAuthFailed)
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := ReadFrame(conn); err == nil {
			t.Fatal("connection remained open after terminal auth failure")
		}
		wait()
		calls := engine.nonHelloCalls()
		if len(calls) != 1 || calls[0].op != "subscribe" {
			t.Fatalf("revoked read reached engine: %+v", calls)
		}
		if unsubscribed := engine.unsubscribeCalls(); len(unsubscribed) != 1 || unsubscribed[0] != sub.SubID {
			t.Fatalf("terminal auth failure did not clean subscription %q: %v", sub.SubID, unsubscribed)
		}
	})

	t.Run("expired key", func(t *testing.T) {
		store := newWireAuthStore(t)
		expires := time.Now().Add(150 * time.Millisecond)
		token, _, err := store.GenerateAPIKey("private", "test", auth.ModeFull, &expires)
		if err != nil {
			t.Fatal(err)
		}
		engine := &wireAuthEngine{}
		conn, wait := openTokenConnection(t, newWireServer(engine, store), token, "")
		defer wait()
		deadline := time.Now().Add(2 * time.Second)
		for {
			if _, err := store.ValidateAPIKey(token); err != nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("key did not expire")
			}
			time.Sleep(5 * time.Millisecond)
		}
		payload, err := EncodeMsgpack(&PingRequest{})
		if err != nil {
			t.Fatal(err)
		}
		// The idle monitor expires the connection at the credential deadline, so
		// either the write or the read must observe the terminal close.
		if err := WriteFrame(conn, &Frame{Version: 1, Type: TypePing, CorrelationID: 71, Payload: payload}); err == nil {
			frame, readErr := ReadFrame(conn)
			if readErr == nil {
				assertWireError(t, frame, ErrAuthFailed)
			}
		}
	})

	t.Run("public vault locked after HELLO", func(t *testing.T) {
		store := newWireAuthStore(t)
		engine := &wireAuthEngine{}
		server := newWireServer(engine, store)
		conn, wait := startTestConn(t, server)
		defer wait()
		if frame := handshake(t, conn, HelloRequest{Version: "1", AuthMethod: "none", Vault: "public"}); frame.Type != TypeHelloOK {
			t.Fatalf("HELLO response = 0x%02x", frame.Type)
		}
		if err := store.SetVaultConfig(auth.VaultConfig{Name: "public", Public: false}); err != nil {
			t.Fatal(err)
		}
		assertWireError(t, sendAndReceive(t, conn, TypePing, 72, &PingRequest{}), ErrAuthFailed)
	})
}

func TestMBPIdleAuthorizationLifecycleClosesAndCleansSubscriptions(t *testing.T) {
	t.Run("revoked key", func(t *testing.T) {
		store := newWireAuthStore(t)
		token, key, err := store.GenerateAPIKey("private", "test", auth.ModeFull, nil)
		if err != nil {
			t.Fatal(err)
		}
		engine := &wireAuthEngine{}
		server := newWireServer(engine, store)
		server.authRecheckInterval = 10 * time.Millisecond
		conn, wait := openTokenConnection(t, server, token, "")
		subID := subscribeForLifecycleTest(t, conn)
		if err := store.RevokeAPIKey("private", key.ID); err != nil {
			t.Fatal(err)
		}
		assertIdleConnectionClosedAndCleaned(t, conn, wait, engine, subID)
	})

	t.Run("expired key", func(t *testing.T) {
		store := newWireAuthStore(t)
		expires := time.Now().Add(150 * time.Millisecond)
		token, _, err := store.GenerateAPIKey("private", "test", auth.ModeFull, &expires)
		if err != nil {
			t.Fatal(err)
		}
		engine := &wireAuthEngine{}
		server := newWireServer(engine, store)
		server.authRecheckInterval = time.Hour // expiry itself schedules the wakeup
		conn, wait := openTokenConnection(t, server, token, "")
		subID := subscribeForLifecycleTest(t, conn)
		assertIdleConnectionClosedAndCleaned(t, conn, wait, engine, subID)
	})

	t.Run("public vault locked", func(t *testing.T) {
		store := newWireAuthStore(t)
		engine := &wireAuthEngine{}
		server := newWireServer(engine, store)
		server.authRecheckInterval = 10 * time.Millisecond
		conn, wait := startTestConn(t, server)
		if frame := handshake(t, conn, HelloRequest{Version: "1", AuthMethod: "none", Vault: "public"}); frame.Type != TypeHelloOK {
			t.Fatalf("HELLO response = 0x%02x", frame.Type)
		}
		subID := subscribeForLifecycleTest(t, conn)
		if err := store.SetVaultConfig(auth.VaultConfig{Name: "public", Public: false}); err != nil {
			t.Fatal(err)
		}
		assertIdleConnectionClosedAndCleaned(t, conn, wait, engine, subID)
	})
}

func subscribeForLifecycleTest(t *testing.T, conn net.Conn) string {
	t.Helper()
	frame := sendAndReceive(t, conn, TypeSubscribe, 75, &SubscribeRequest{Context: []string{"lifecycle"}})
	if frame.Type != TypeSubOK {
		t.Fatalf("subscribe response = 0x%02x", frame.Type)
	}
	var response SubscribeResponse
	if err := DecodeMsgpack(frame.Payload, &response); err != nil {
		t.Fatal(err)
	}
	return response.SubID
}

func assertIdleConnectionClosedAndCleaned(t *testing.T, conn net.Conn, wait func(), engine *wireAuthEngine, subID string) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := ReadFrame(conn); err == nil {
		t.Fatal("idle connection remained open after authorization ended")
	}
	wait()
	for _, got := range engine.unsubscribeCalls() {
		if got == subID {
			return
		}
	}
	t.Fatalf("subscription %q was not cleaned up: %v", subID, engine.unsubscribeCalls())
}

type mutableVaultAuthStore struct {
	mu          sync.Mutex
	key         auth.APIKey
	keyErr      error
	configs     map[string]auth.VaultConfig
	validates   int
	configReads int
}

func (s *mutableVaultAuthStore) ValidateAPIKey(string) (auth.APIKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.validates++
	return s.key, s.keyErr
}

func (s *mutableVaultAuthStore) GetVaultConfig(vault string) (auth.VaultConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.configReads++
	cfg, ok := s.configs[vault]
	if !ok {
		return auth.VaultConfig{Name: vault}, nil
	}
	return cfg, nil
}

func (s *mutableVaultAuthStore) callCounts() (validates, configReads int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.validates, s.configReads
}

func (s *mutableVaultAuthStore) changeKey(mutator func(*auth.APIKey)) {
	s.mu.Lock()
	mutator(&s.key)
	s.mu.Unlock()
}

func TestMBPRejectsKeyClaimChangesAfterHello(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*auth.APIKey)
	}{
		{"vault", func(key *auth.APIKey) { key.Vault = "other" }},
		{"mode", func(key *auth.APIKey) { key.Mode = auth.ModeObserve }},
		{"expiry", func(key *auth.APIKey) { expiry := time.Now().Add(time.Hour); key.ExpiresAt = &expiry }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &mutableVaultAuthStore{
				key:     auth.APIKey{ID: "key-1", Vault: "private", Mode: auth.ModeFull},
				configs: map[string]auth.VaultConfig{},
			}
			engine := &wireAuthEngine{}
			conn, wait := openTokenConnection(t, newWireServer(engine, store), "test-token", "")
			defer wait()
			store.changeKey(tc.change)
			assertWireError(t, sendAndReceive(t, conn, TypePing, 80, &PingRequest{}), ErrAuthFailed)
		})
	}
}

func TestMBPSubscriptionOwnershipAndDisconnectCleanup(t *testing.T) {
	store := newWireAuthStore(t)
	token, _, err := store.GenerateAPIKey("private", "test", auth.ModeFull, nil)
	if err != nil {
		t.Fatal(err)
	}
	engine := &wireAuthEngine{}
	server := newWireServer(engine, store)
	conn1, wait1 := openTokenConnection(t, server, token, "")
	conn2, wait2 := openTokenConnection(t, server, token, "")

	subFrame := sendAndReceive(t, conn1, TypeSubscribe, 90, &SubscribeRequest{Context: []string{"q"}})
	if subFrame.Type != TypeSubOK {
		t.Fatalf("subscribe response = 0x%02x", subFrame.Type)
	}
	var sub SubscribeResponse
	if err := DecodeMsgpack(subFrame.Payload, &sub); err != nil {
		t.Fatal(err)
	}

	assertWireError(t, sendAndReceive(t, conn2, TypeUnsub, 91, &UnsubscribeRequest{SubID: sub.SubID}), ErrSubscriptionNotFound)
	if calls := engine.unsubscribeCalls(); len(calls) != 0 {
		t.Fatalf("foreign unsubscribe reached engine: %v", calls)
	}
	if frame := sendAndReceive(t, conn1, TypeUnsub, 92, &UnsubscribeRequest{SubID: sub.SubID}); frame.Type != TypeUnsubOK {
		t.Fatalf("owner unsubscribe response = 0x%02x", frame.Type)
	}

	// A client cannot choose a victim's global ID when subscribing.
	assertWireError(t, sendAndReceive(t, conn2, TypeSubscribe, 93, &SubscribeRequest{SubscriptionID: sub.SubID, Context: []string{"q"}}), ErrInvalidEngram)

	cleanupFrame := sendAndReceive(t, conn2, TypeSubscribe, 94, &SubscribeRequest{Context: []string{"cleanup"}})
	if cleanupFrame.Type != TypeSubOK {
		t.Fatalf("cleanup subscribe response = 0x%02x", cleanupFrame.Type)
	}
	var cleanupSub SubscribeResponse
	if err := DecodeMsgpack(cleanupFrame.Payload, &cleanupSub); err != nil {
		t.Fatal(err)
	}

	conn2.Close()
	wait2()
	conn1.Close()
	wait1()

	calls := engine.unsubscribeCalls()
	want := map[string]bool{sub.SubID: false, cleanupSub.SubID: false}
	for _, id := range calls {
		if _, ok := want[id]; ok {
			want[id] = true
		}
	}
	for id, seen := range want {
		if !seen {
			t.Fatalf("subscription %q was not cleaned up; calls=%v", id, calls)
		}
	}
}

type invalidSubscribeEngine struct {
	wireAuthEngine
	response *SubscribeResponse
	err      error
	assigned string
}

func (e *invalidSubscribeEngine) Subscribe(ctx context.Context, req *SubscribeRequest) (*SubscribeResponse, error) {
	e.record(ctx, "subscribe", req.Vault)
	e.mu.Lock()
	e.assigned = req.SubscriptionID
	e.mu.Unlock()
	return e.response, e.err
}

func (e *invalidSubscribeEngine) assignedID() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.assigned
}

func TestMBPInvalidSubscribeResponsesAreRolledBack(t *testing.T) {
	tests := []struct {
		name         string
		response     *SubscribeResponse
		err          error
		wantCode     ErrorCode
		alsoRollback string
	}{
		{"nil response", nil, nil, ErrInternal, ""},
		{"empty id", &SubscribeResponse{Status: "active"}, nil, ErrInternal, ""},
		{"mismatched id", &SubscribeResponse{SubID: "adapter-selected", Status: "active"}, nil, ErrInternal, "adapter-selected"},
		{"error after partial registration", nil, errors.New("adapter failed"), ErrSubscriptionNotFound, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newWireAuthStore(t)
			token, _, err := store.GenerateAPIKey("private", "test", auth.ModeFull, nil)
			if err != nil {
				t.Fatal(err)
			}
			engine := &invalidSubscribeEngine{response: tt.response, err: tt.err}
			conn, wait := openTokenConnection(t, newWireServer(engine, store), token, "")
			defer wait()
			frame := sendAndReceive(t, conn, TypeSubscribe, 95, &SubscribeRequest{Context: []string{"q"}})
			assertWireError(t, frame, tt.wantCode)

			assigned := engine.assignedID()
			if assigned == "" {
				t.Fatal("transport did not assign a subscription id before the engine call")
			}
			seen := make(map[string]bool)
			for _, id := range engine.unsubscribeCalls() {
				seen[id] = true
			}
			if !seen[assigned] {
				t.Fatalf("assigned subscription %q was not rolled back: %v", assigned, engine.unsubscribeCalls())
			}
			if tt.alsoRollback != "" && !seen[tt.alsoRollback] {
				t.Fatalf("adapter response subscription %q was not rolled back: %v", tt.alsoRollback, engine.unsubscribeCalls())
			}
		})
	}
}

type blockingCleanupEngine struct {
	wireAuthEngine
	block chan struct{}
}

func (e *blockingCleanupEngine) Unsubscribe(context.Context, string) error {
	<-e.block // deliberately ignores context to exercise the transport deadline
	return nil
}

func TestMBPConnectionCleanupHasOneTotalDeadline(t *testing.T) {
	engine := &blockingCleanupEngine{block: make(chan struct{})}
	server := newWireServer(engine, newWireAuthStore(t))
	server.subscriptionCleanupTimeout = 25 * time.Millisecond
	session := &connectionSession{subscriptions: make(map[string]struct{})}
	for i := 0; i < 100; i++ {
		session.addSubscription(fmt.Sprintf("sub-%d", i))
	}
	started := time.Now()
	server.cleanupSubscriptions(session)
	elapsed := time.Since(started)
	close(engine.block)
	if elapsed > 250*time.Millisecond {
		t.Fatalf("connection cleanup took %s; expected one bounded deadline", elapsed)
	}
}

func TestMBPMalformedHelloFailsClosedOnWire(t *testing.T) {
	requests := []HelloRequest{
		{Version: "2", AuthMethod: "none"},
		{Version: "1", AuthMethod: "bogus"},
		{Version: "1", AuthMethod: "token"},
		{Version: "1", AuthMethod: "none", Token: "must-not-be-ignored"},
		{Version: "1", Token: "must-not-default-to-none"},
	}
	for i, req := range requests {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			server := newWireServer(&wireAuthEngine{}, newWireAuthStore(t))
			conn, wait := startTestConn(t, server)
			defer wait()
			assertWireError(t, handshake(t, conn, req), ErrAuthFailed)
		})
	}
}

func TestMBPConcurrentDisconnectDoesNotCloseWriterBeforeHandlers(t *testing.T) {
	for i := 0; i < 20; i++ {
		store := newWireAuthStore(t)
		token, _, err := store.GenerateAPIKey("private", "test", auth.ModeFull, nil)
		if err != nil {
			t.Fatal(err)
		}
		engine := &wireAuthEngine{
			writeStarted: make(chan struct{}),
			releaseWrite: make(chan struct{}),
		}
		server := newWireServer(engine, store)
		conn, wait := openTokenConnection(t, server, token, "")

		payload, err := EncodeMsgpack(&WriteRequest{Concept: "blocked"})
		if err != nil {
			t.Fatal(err)
		}
		if err := WriteFrame(conn, &Frame{Version: 1, Type: TypeWrite, CorrelationID: 100, Payload: payload}); err != nil {
			t.Fatal(err)
		}
		select {
		case <-engine.writeStarted:
		case <-time.After(time.Second):
			t.Fatal("write handler did not start")
		}

		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		if err := server.Shutdown(shutdownCtx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("shutdown: %v", err)
		}
		cancel()
		close(engine.releaseWrite)
		_ = conn.Close()
		wait()
	}
}

type disconnectCancellationEngine struct {
	stubEngine
	started  chan struct{}
	canceled chan struct{}
}

func (e *disconnectCancellationEngine) Write(ctx context.Context, _ *WriteRequest) (*WriteResponse, error) {
	close(e.started)
	<-ctx.Done()
	close(e.canceled)
	return nil, ctx.Err()
}

func TestMBPPlainClientDisconnectCancelsInflightHandler(t *testing.T) {
	engine := &disconnectCancellationEngine{
		started:  make(chan struct{}),
		canceled: make(chan struct{}),
	}
	server := newWireServer(engine, newWireAuthStore(t))
	client, serverConn := net.Pipe()
	deadline := time.Now().Add(5 * time.Second)
	if err := client.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := serverConn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	connectionCtx, forceCancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		server.handleConnection(connectionCtx, serverConn)
	}()
	t.Cleanup(func() {
		_ = client.Close()
		forceCancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("connection handler did not stop during test cleanup")
		}
	})

	if frame := handshake(t, client, HelloRequest{Version: "1", AuthMethod: "none", Vault: "public"}); frame.Type != TypeHelloOK {
		t.Fatalf("HELLO response = 0x%02x", frame.Type)
	}
	payload, err := EncodeMsgpack(&WriteRequest{Concept: "wait-for-disconnect"})
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteFrame(client, &Frame{Version: 1, Type: TypeWrite, CorrelationID: 101, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-engine.started:
	case <-time.After(time.Second):
		t.Fatal("write handler did not start")
	}

	// A plain client close must cancel the connection context on its own. The
	// test deliberately does not call Server.Shutdown or forceCancel here.
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-engine.canceled:
	case <-time.After(time.Second):
		t.Fatal("client disconnect did not cancel the in-flight engine operation")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("connection handler did not return after client disconnect")
	}
}

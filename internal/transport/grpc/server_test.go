package grpc_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/cockroachdb/pebble/vfs"
	"github.com/scrypster/muninndb/internal/auth"
	"github.com/scrypster/muninndb/internal/engine/trigger"
	"github.com/scrypster/muninndb/internal/storage"
	transportgrpc "github.com/scrypster/muninndb/internal/transport/grpc"
	pb "github.com/scrypster/muninndb/proto/gen/go/muninn/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// mockEngine implements EngineAPI for testing. Every method returns a zero-value
// response and no error unless the test provides specific behaviour via the
// function fields.
type mockEngine struct {
	helloFn                func(ctx context.Context, req *pb.HelloRequest) (*pb.HelloResponse, error)
	writeFn                func(ctx context.Context, req *pb.WriteRequest) (*pb.WriteResponse, error)
	readFn                 func(ctx context.Context, req *pb.ReadRequest) (*pb.ReadResponse, error)
	activateFn             func(ctx context.Context, req *pb.ActivateRequest) (*pb.ActivateResponse, error)
	linkFn                 func(ctx context.Context, req *pb.LinkRequest) (*pb.LinkResponse, error)
	forgetFn               func(ctx context.Context, req *pb.ForgetRequest) (*pb.ForgetResponse, error)
	statFn                 func(ctx context.Context, req *pb.StatRequest) (*pb.StatResponse, error)
	subscribeFn            func(ctx context.Context, req *pb.SubscribeRequest) (*pb.SubscribeResponse, error)
	subscribeWithDeliverFn func(ctx context.Context, req *pb.SubscribeRequest, deliver trigger.DeliverFunc) (string, error)
	unsubscribeFn          func(ctx context.Context, subID string) error
}

func (m *mockEngine) Hello(ctx context.Context, req *pb.HelloRequest) (*pb.HelloResponse, error) {
	if m.helloFn != nil {
		return m.helloFn(ctx, req)
	}
	return &pb.HelloResponse{ServerVersion: "test"}, nil
}

func (m *mockEngine) Write(ctx context.Context, req *pb.WriteRequest) (*pb.WriteResponse, error) {
	if m.writeFn != nil {
		return m.writeFn(ctx, req)
	}
	return &pb.WriteResponse{Id: "00000000000000000000000000"}, nil
}

func (m *mockEngine) BatchWrite(ctx context.Context, req *pb.BatchWriteRequest) (*pb.BatchWriteResponse, error) {
	results := make([]*pb.BatchWriteItemResult, len(req.Requests))
	for i := range req.Requests {
		results[i] = &pb.BatchWriteItemResult{
			Index: int32(i),
			Id:    "00000000000000000000000000",
		}
	}
	return &pb.BatchWriteResponse{Results: results}, nil
}

func (m *mockEngine) Read(ctx context.Context, req *pb.ReadRequest) (*pb.ReadResponse, error) {
	if m.readFn != nil {
		return m.readFn(ctx, req)
	}
	return &pb.ReadResponse{}, nil
}

func (m *mockEngine) Activate(ctx context.Context, req *pb.ActivateRequest) (*pb.ActivateResponse, error) {
	if m.activateFn != nil {
		return m.activateFn(ctx, req)
	}
	return &pb.ActivateResponse{}, nil
}

func (m *mockEngine) Link(ctx context.Context, req *pb.LinkRequest) (*pb.LinkResponse, error) {
	if m.linkFn != nil {
		return m.linkFn(ctx, req)
	}
	return &pb.LinkResponse{Ok: true}, nil
}

func (m *mockEngine) Forget(ctx context.Context, req *pb.ForgetRequest) (*pb.ForgetResponse, error) {
	if m.forgetFn != nil {
		return m.forgetFn(ctx, req)
	}
	return &pb.ForgetResponse{Ok: true}, nil
}

func (m *mockEngine) Stat(ctx context.Context, req *pb.StatRequest) (*pb.StatResponse, error) {
	if m.statFn != nil {
		return m.statFn(ctx, req)
	}
	return &pb.StatResponse{}, nil
}

func (m *mockEngine) Subscribe(ctx context.Context, req *pb.SubscribeRequest) (*pb.SubscribeResponse, error) {
	if m.subscribeFn != nil {
		return m.subscribeFn(ctx, req)
	}
	return &pb.SubscribeResponse{SubId: "sub-1", Status: "ok"}, nil
}

func (m *mockEngine) SubscribeWithDeliver(ctx context.Context, req *pb.SubscribeRequest, deliver trigger.DeliverFunc) (string, error) {
	if m.subscribeWithDeliverFn != nil {
		return m.subscribeWithDeliverFn(ctx, req, deliver)
	}
	return "mock-sub-id", nil
}

func (m *mockEngine) Unsubscribe(ctx context.Context, subID string) error {
	if m.unsubscribeFn != nil {
		return m.unsubscribeFn(ctx, subID)
	}
	return nil
}

// newTestAuthStore opens an in-memory pebble database and returns an auth.Store.
func newTestAuthStore(t *testing.T) *auth.Store {
	t.Helper()
	db, err := pebble.Open("", &pebble.Options{FS: vfs.NewMem()})
	if err != nil {
		t.Fatalf("open test auth db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return auth.NewStore(db)
}

// freePort returns an available TCP port on localhost.
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not find free port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// TestServerStartStop creates a Server, calls Serve in a goroutine, verifies it
// is accepting TCP connections, then cancels the context and verifies clean shutdown.
func TestServerStartStop(t *testing.T) {
	addr := freePort(t)
	engine := &mockEngine{}
	srv := transportgrpc.NewServer(addr, engine, newTestAuthStore(t), nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.Serve(ctx)
	}()

	// Verify the server is accepting TCP connections within a reasonable window.
	var conn net.Conn
	var dialErr error
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, dialErr = net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if dialErr == nil {
			conn.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if dialErr != nil {
		t.Fatalf("could not connect to server at %s: %v", addr, dialErr)
	}

	// Cancel context to trigger graceful shutdown.
	cancel()

	select {
	case err := <-serveErr:
		if err != nil {
			t.Errorf("Serve returned unexpected error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Error("server did not shut down within 3 seconds after context cancellation")
	}
}

// TestGracefulShutdown starts a server, calls Shutdown with a reasonable timeout,
// and verifies it returns nil.
func TestGracefulShutdown(t *testing.T) {
	addr := freePort(t)
	engine := &mockEngine{}
	srv := transportgrpc.NewServer(addr, engine, newTestAuthStore(t), nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.Serve(ctx)
	}()

	// Wait for server to be up.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Call Shutdown with a 2-second timeout.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		t.Errorf("Shutdown returned unexpected error: %v", err)
	}
}

// TestEngineAPIInterface verifies at compile time that mockEngine satisfies the
// EngineAPI interface. This test contains no runtime assertions — if it compiles,
// the interface contract is met.
func TestEngineAPIInterface(t *testing.T) {
	// Verify that NewServer accepts our mock without a cast.
	engine := &mockEngine{}
	_ = transportgrpc.NewServer(":0", engine, newTestAuthStore(t), nil)
}

// TestSubscribeWithDeliverInterface verifies at compile-time and runtime that:
//   - mockEngine satisfies the full EngineAPI interface including SubscribeWithDeliver
//   - The deliver func passed to SubscribeWithDeliver correctly channels pushes
//
// Wire-level default-codec coverage lives in wire_codec_test.go and is enabled by
// the grpcwire build tag after the hosted workflow regenerates canonical stubs.
func TestSubscribeWithDeliverInterface(t *testing.T) {
	// Compile-time check: mockEngine satisfies transportgrpc.EngineAPI.
	var _ transportgrpc.EngineAPI = &mockEngine{}

	// Runtime: verify the SubscribeWithDeliver mock correctly invokes the deliver func.
	received := make(chan *trigger.ActivationPush, 4)
	var capturedDeliver trigger.DeliverFunc

	eng := &mockEngine{
		subscribeWithDeliverFn: func(ctx context.Context, req *pb.SubscribeRequest, deliver trigger.DeliverFunc) (string, error) {
			capturedDeliver = deliver
			return "test-sub-id", nil
		},
	}

	// Call SubscribeWithDeliver — in production this is called by grpc.Server.Subscribe.
	ctx := context.Background()
	req := &pb.SubscribeRequest{Vault: "default", PushOnWrite: true}
	deliver := func(ctx context.Context, push *trigger.ActivationPush) error {
		received <- push
		return nil
	}

	subID, err := eng.SubscribeWithDeliver(ctx, req, deliver)
	if err != nil {
		t.Fatalf("SubscribeWithDeliver: %v", err)
	}
	if subID != "test-sub-id" {
		t.Errorf("subID = %q, want test-sub-id", subID)
	}
	if capturedDeliver == nil {
		t.Fatal("deliver func was not captured")
	}

	// Simulate the trigger system calling the deliver func.
	push := &trigger.ActivationPush{
		SubscriptionID: subID,
		Trigger:        trigger.TriggerNewWrite,
		PushNumber:     1,
		At:             time.Now(),
	}
	if err := capturedDeliver(ctx, push); err != nil {
		t.Fatalf("capturedDeliver: %v", err)
	}

	select {
	case got := <-received:
		if got.SubscriptionID != subID {
			t.Errorf("push.SubscriptionID = %q, want %q", got.SubscriptionID, subID)
		}
		if string(got.Trigger) != string(trigger.TriggerNewWrite) {
			t.Errorf("push.Trigger = %q, want %q", got.Trigger, trigger.TriggerNewWrite)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for push")
	}
}

// ---------------------------------------------------------------------------
// Auth interceptor tests
// ---------------------------------------------------------------------------

// TestAuthUnaryInterceptor_ValidKey generates a real API key, sends it via the
// authorization metadata header, and verifies the handler receives the correct
// vault, mode, and APIKey in its context.
func TestAuthUnaryInterceptor_ValidKey(t *testing.T) {
	store := newTestAuthStore(t)
	token, _, err := store.GenerateAPIKey("testvault", "test-label", "full", nil)
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}

	srv := transportgrpc.NewServer(":0", &mockEngine{}, store, nil)

	var capturedVault, capturedMode string
	var capturedKey *auth.APIKey
	handler := func(ctx context.Context, req any) (any, error) {
		capturedVault, _ = ctx.Value(auth.ContextVault).(string)
		capturedMode, _ = ctx.Value(auth.ContextMode).(string)
		capturedKey, _ = ctx.Value(auth.ContextAPIKey).(*auth.APIKey)
		return "ok", nil
	}

	md := metadata.Pairs("authorization", "Bearer "+token)
	ctx := metadata.NewIncomingContext(context.Background(), md)

	resp, err := srv.TestableAuthUnaryInterceptor(ctx, &pb.WriteRequest{Vault: "testvault"}, nil, handler)
	if err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}
	if resp != "ok" {
		t.Errorf("resp = %v, want \"ok\"", resp)
	}
	if capturedVault != "testvault" {
		t.Errorf("vault = %q, want \"testvault\"", capturedVault)
	}
	if capturedMode != "full" {
		t.Errorf("mode = %q, want \"full\"", capturedMode)
	}
	if capturedKey == nil {
		t.Fatal("context APIKey is nil")
	}
	if capturedKey.Vault != "testvault" {
		t.Errorf("key.Vault = %q, want \"testvault\"", capturedKey.Vault)
	}
}

// TestAuthUnaryInterceptor_InvalidKey sends a malformed token via the x-api-key
// metadata header and verifies the interceptor returns codes.Unauthenticated
// without invoking the handler.
func TestAuthUnaryInterceptor_InvalidKey(t *testing.T) {
	store := newTestAuthStore(t)
	srv := transportgrpc.NewServer(":0", &mockEngine{}, store, nil)

	handler := func(ctx context.Context, req any) (any, error) {
		t.Fatal("handler should not be called with invalid key")
		return nil, nil
	}

	md := metadata.Pairs("x-api-key", "mk_not-a-valid-base64-token!!")
	ctx := metadata.NewIncomingContext(context.Background(), md)

	_, err := srv.TestableAuthUnaryInterceptor(ctx, &pb.HelloRequest{}, nil, handler)
	if err == nil {
		t.Fatal("expected error for invalid key, got nil")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("error is not a gRPC status: %v", err)
	}
	if st.Code() != codes.Unauthenticated {
		t.Errorf("code = %v, want Unauthenticated", st.Code())
	}
}

func TestAuthUnaryInterceptor_ExplicitEmptyCredentialIsRejected(t *testing.T) {
	store := newTestAuthStore(t)
	if err := store.SetVaultConfig(auth.VaultConfig{Name: "default", Public: true}); err != nil {
		t.Fatalf("SetVaultConfig: %v", err)
	}
	srv := transportgrpc.NewServer(":0", &mockEngine{}, store, nil)
	handler := func(context.Context, any) (any, error) {
		t.Fatal("handler should not be called with an empty credential")
		return nil, nil
	}

	for name, md := range map[string]metadata.MD{
		"empty authorization": metadata.Pairs("authorization", ""),
		"empty bearer":        metadata.Pairs("authorization", "Bearer "),
		"empty x-api-key":     metadata.Pairs("x-api-key", ""),
	} {
		t.Run(name, func(t *testing.T) {
			ctx := metadata.NewIncomingContext(context.Background(), md)
			_, err := srv.TestableAuthUnaryInterceptor(ctx, &pb.HelloRequest{}, nil, handler)
			if status.Code(err) != codes.Unauthenticated {
				t.Fatalf("code = %v, want Unauthenticated (err=%v)", status.Code(err), err)
			}
		})
	}
}

// TestAuthUnaryInterceptor_NoKeyPublicVault configures the default vault as
// public, sends a request without any auth metadata, and verifies the handler
// is called with vault "default" and mode "full".
func TestAuthUnaryInterceptor_NoKeyPublicVault(t *testing.T) {
	store := newTestAuthStore(t)
	if err := store.SetVaultConfig(auth.VaultConfig{Name: "default", Public: true}); err != nil {
		t.Fatalf("SetVaultConfig: %v", err)
	}

	srv := transportgrpc.NewServer(":0", &mockEngine{}, store, nil)

	var capturedVault, capturedMode string
	handler := func(ctx context.Context, req any) (any, error) {
		capturedVault, _ = ctx.Value(auth.ContextVault).(string)
		capturedMode, _ = ctx.Value(auth.ContextMode).(string)
		return "ok", nil
	}

	ctx := context.Background()
	resp, err := srv.TestableAuthUnaryInterceptor(ctx, &pb.HelloRequest{}, nil, handler)
	if err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}
	if resp != "ok" {
		t.Errorf("resp = %v, want \"ok\"", resp)
	}
	if capturedVault != "default" {
		t.Errorf("vault = %q, want \"default\"", capturedVault)
	}
	if capturedMode != "full" {
		t.Errorf("mode = %q, want \"full\"", capturedMode)
	}
}

// TestAuthUnaryInterceptor_NoKeyLockedVault explicitly locks the default vault
// and verifies that an unauthenticated request is rejected with
// codes.Unauthenticated.
func TestAuthUnaryInterceptor_NoKeyLockedVault(t *testing.T) {
	store := newTestAuthStore(t)
	if err := store.SetVaultConfig(auth.VaultConfig{Name: "default", Public: false}); err != nil {
		t.Fatalf("SetVaultConfig: %v", err)
	}

	srv := transportgrpc.NewServer(":0", &mockEngine{}, store, nil)

	handler := func(ctx context.Context, req any) (any, error) {
		t.Fatal("handler should not be called for locked vault without auth")
		return nil, nil
	}

	ctx := context.Background()
	_, err := srv.TestableAuthUnaryInterceptor(ctx, &pb.HelloRequest{}, nil, handler)
	if err == nil {
		t.Fatal("expected error for locked vault, got nil")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("error is not a gRPC status: %v", err)
	}
	if st.Code() != codes.Unauthenticated {
		t.Errorf("code = %v, want Unauthenticated", st.Code())
	}
}

// TestAuthUnaryInterceptor_MissingKeyStore uses a fresh auth store with no
// vault configuration at all. The fail-closed default in GetVaultConfig returns
// Public: false for unknown vaults, so an unauthenticated request must be
// rejected with codes.Unauthenticated.
func TestAuthUnaryInterceptor_MissingKeyStore(t *testing.T) {
	store := newTestAuthStore(t)
	srv := transportgrpc.NewServer(":0", &mockEngine{}, store, nil)

	handler := func(ctx context.Context, req any) (any, error) {
		t.Fatal("handler should not be called when vault is unconfigured")
		return nil, nil
	}

	ctx := context.Background()
	_, err := srv.TestableAuthUnaryInterceptor(ctx, &pb.HelloRequest{}, nil, handler)
	if err == nil {
		t.Fatal("expected error for unconfigured vault (fail-closed), got nil")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("error is not a gRPC status: %v", err)
	}
	if st.Code() != codes.Unauthenticated {
		t.Errorf("code = %v, want Unauthenticated", st.Code())
	}
}

func TestAuthUnaryInterceptor_UnsupportedRequestFailsClosed(t *testing.T) {
	store := newTestAuthStore(t)
	if err := store.SetVaultConfig(auth.VaultConfig{Name: "default", Public: true}); err != nil {
		t.Fatalf("SetVaultConfig: %v", err)
	}
	srv := transportgrpc.NewServer(":0", &mockEngine{}, store, nil)
	handler := func(context.Context, any) (any, error) {
		t.Fatal("handler should not be called for an unsupported request type")
		return nil, nil
	}

	_, err := srv.TestableAuthUnaryInterceptor(context.Background(), struct{ Vault string }{Vault: "private"}, nil, handler)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument (err=%v)", status.Code(err), err)
	}
}

// TestAuthUnaryInterceptor_XApiKeyHeader verifies that the x-api-key metadata
// header is accepted as an alternative to the authorization header.
func TestAuthUnaryInterceptor_XApiKeyHeader(t *testing.T) {
	store := newTestAuthStore(t)
	token, _, err := store.GenerateAPIKey("default", "test-label", "full", nil)
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}

	srv := transportgrpc.NewServer(":0", &mockEngine{}, store, nil)

	var capturedMode string
	handler := func(ctx context.Context, req any) (any, error) {
		capturedMode, _ = ctx.Value(auth.ContextMode).(string)
		return "ok", nil
	}

	md := metadata.Pairs("x-api-key", token)
	ctx := metadata.NewIncomingContext(context.Background(), md)

	_, err = srv.TestableAuthUnaryInterceptor(ctx, &pb.HelloRequest{}, nil, handler)
	if err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}
	if capturedMode != "full" {
		t.Errorf("mode = %q, want \"full\"", capturedMode)
	}
}

func TestAuthUnaryInterceptor_RejectsCrossVaultKey(t *testing.T) {
	store := newTestAuthStore(t)
	token, _, err := store.GenerateAPIKey("vault-a", "test-label", "full", nil)
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}

	srv := transportgrpc.NewServer(":0", &mockEngine{}, store, nil)
	handler := func(context.Context, any) (any, error) {
		t.Fatal("handler should not be called for a cross-vault key")
		return nil, nil
	}
	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs("authorization", "Bearer "+token),
	)

	_, err = srv.TestableAuthUnaryInterceptor(ctx, &pb.ReadRequest{Vault: "vault-b"}, nil, handler)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied (err=%v)", status.Code(err), err)
	}
}

func TestAuthUnaryInterceptor_EmptyVaultUsesKeyVault(t *testing.T) {
	store := newTestAuthStore(t)
	token, _, err := store.GenerateAPIKey("vault-a", "test-label", "full", nil)
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	srv := transportgrpc.NewServer(":0", &mockEngine{}, store, nil)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-api-key", token))
	req := &pb.WriteRequest{}
	handler := func(ctx context.Context, _ any) (any, error) {
		if req.Vault != "vault-a" {
			t.Errorf("request vault = %q, want vault-a", req.Vault)
		}
		if vault, _ := ctx.Value(auth.ContextVault).(string); vault != "vault-a" {
			t.Errorf("context vault = %q, want vault-a", vault)
		}
		return "ok", nil
	}

	if _, err := srv.TestableAuthUnaryInterceptor(ctx, req, nil, handler); err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}
}

func TestAuthUnaryInterceptor_RejectsPrivateRequestWhenDefaultIsPublic(t *testing.T) {
	store := newTestAuthStore(t)
	if err := store.SetVaultConfig(auth.VaultConfig{Name: "default", Public: true}); err != nil {
		t.Fatalf("SetVaultConfig(default): %v", err)
	}
	if err := store.SetVaultConfig(auth.VaultConfig{Name: "private", Public: false}); err != nil {
		t.Fatalf("SetVaultConfig(private): %v", err)
	}

	srv := transportgrpc.NewServer(":0", &mockEngine{}, store, nil)
	handler := func(context.Context, any) (any, error) {
		t.Fatal("handler should not be called for a private vault")
		return nil, nil
	}

	_, err := srv.TestableAuthUnaryInterceptor(
		context.Background(),
		&pb.WriteRequest{Vault: "private"},
		nil,
		handler,
	)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want Unauthenticated (err=%v)", status.Code(err), err)
	}
}

func TestAuthUnaryInterceptor_RejectsMixedVaultBatch(t *testing.T) {
	store := newTestAuthStore(t)
	if err := store.SetVaultConfig(auth.VaultConfig{Name: "default", Public: true}); err != nil {
		t.Fatalf("SetVaultConfig: %v", err)
	}
	srv := transportgrpc.NewServer(":0", &mockEngine{}, store, nil)
	handler := func(context.Context, any) (any, error) {
		t.Fatal("handler should not be called for a mixed-vault batch")
		return nil, nil
	}

	_, err := srv.TestableAuthUnaryInterceptor(
		context.Background(),
		&pb.BatchWriteRequest{Requests: []*pb.WriteRequest{
			{Vault: "default"},
			{Vault: "private"},
		}},
		nil,
		handler,
	)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument (err=%v)", status.Code(err), err)
	}
}

func TestAuthUnaryInterceptor_RejectsNilBatchItem(t *testing.T) {
	store := newTestAuthStore(t)
	if err := store.SetVaultConfig(auth.VaultConfig{Name: "default", Public: true}); err != nil {
		t.Fatalf("SetVaultConfig: %v", err)
	}
	srv := transportgrpc.NewServer(":0", &mockEngine{}, store, nil)
	handler := func(context.Context, any) (any, error) {
		t.Fatal("handler should not be called for a nil batch item")
		return nil, nil
	}

	_, err := srv.TestableAuthUnaryInterceptor(
		context.Background(),
		&pb.BatchWriteRequest{Requests: []*pb.WriteRequest{nil}},
		nil,
		handler,
	)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument (err=%v)", status.Code(err), err)
	}
}

func TestAuthUnaryInterceptor_CanonicalizesBatchVault(t *testing.T) {
	store := newTestAuthStore(t)
	if err := store.SetVaultConfig(auth.VaultConfig{Name: "default", Public: true}); err != nil {
		t.Fatalf("SetVaultConfig: %v", err)
	}
	srv := transportgrpc.NewServer(":0", &mockEngine{}, store, nil)
	req := &pb.BatchWriteRequest{Requests: []*pb.WriteRequest{{Vault: ""}, {Vault: " default "}}}
	handler := func(ctx context.Context, got any) (any, error) {
		batch := got.(*pb.BatchWriteRequest)
		for i, item := range batch.Requests {
			if item.Vault != "default" {
				t.Errorf("item %d vault = %q, want default", i, item.Vault)
			}
		}
		if vault, _ := ctx.Value(auth.ContextVault).(string); vault != "default" {
			t.Errorf("context vault = %q, want default", vault)
		}
		return "ok", nil
	}

	if _, err := srv.TestableAuthUnaryInterceptor(context.Background(), req, nil, handler); err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}
}

func TestAuthUnaryInterceptor_WriteOnlyCannotRead(t *testing.T) {
	store := newTestAuthStore(t)
	token, _, err := store.GenerateAPIKey("default", "ingest", auth.ModeWrite, nil)
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	srv := transportgrpc.NewServer(":0", &mockEngine{}, store, nil)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-api-key", token))
	handler := func(context.Context, any) (any, error) {
		t.Fatal("handler should not be called for a write-only read")
		return nil, nil
	}

	_, err = srv.TestableAuthUnaryInterceptor(ctx, &pb.ReadRequest{Vault: "default"}, nil, handler)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied (err=%v)", status.Code(err), err)
	}
}

func TestAuthUnaryInterceptor_WriteOnlyCanWrite(t *testing.T) {
	store := newTestAuthStore(t)
	token, _, err := store.GenerateAPIKey("default", "ingest", auth.ModeWrite, nil)
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	srv := transportgrpc.NewServer(":0", &mockEngine{}, store, nil)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-api-key", token))
	called := false
	handler := func(context.Context, any) (any, error) {
		called = true
		return "ok", nil
	}

	if _, err := srv.TestableAuthUnaryInterceptor(ctx, &pb.WriteRequest{Vault: "default"}, nil, handler); err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}
	if !called {
		t.Fatal("handler was not called")
	}
}

func TestAuthUnaryInterceptor_ObserveCannotMutate(t *testing.T) {
	store := newTestAuthStore(t)
	token, _, err := store.GenerateAPIKey("default", "observer", auth.ModeObserve, nil)
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	srv := transportgrpc.NewServer(":0", &mockEngine{}, store, nil)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-api-key", token))
	handler := func(context.Context, any) (any, error) {
		t.Fatal("handler should not be called for an observe-mode mutation")
		return nil, nil
	}

	requests := []any{
		&pb.WriteRequest{Vault: "default"},
		&pb.BatchWriteRequest{Requests: []*pb.WriteRequest{{Vault: "default"}}},
		&pb.ForgetRequest{Vault: "default"},
		&pb.LinkRequest{Vault: "default"},
	}
	for _, req := range requests {
		_, err := srv.TestableAuthUnaryInterceptor(ctx, req, nil, handler)
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("%T code = %v, want PermissionDenied (err=%v)", req, status.Code(err), err)
		}
	}
}

func TestAuthUnaryInterceptor_ObserveCanRead(t *testing.T) {
	store := newTestAuthStore(t)
	token, _, err := store.GenerateAPIKey("default", "observer", auth.ModeObserve, nil)
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	srv := transportgrpc.NewServer(":0", &mockEngine{}, store, nil)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-api-key", token))
	called := false
	handler := func(context.Context, any) (any, error) {
		called = true
		return "ok", nil
	}

	if _, err := srv.TestableAuthUnaryInterceptor(ctx, &pb.ReadRequest{Vault: "default"}, nil, handler); err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}
	if !called {
		t.Fatal("handler was not called")
	}
}

func TestAuthUnaryInterceptor_PublicVaultCanWrite(t *testing.T) {
	store := newTestAuthStore(t)
	if err := store.SetVaultConfig(auth.VaultConfig{Name: "default", Public: true}); err != nil {
		t.Fatalf("SetVaultConfig: %v", err)
	}
	srv := transportgrpc.NewServer(":0", &mockEngine{}, store, nil)
	called := false
	handler := func(ctx context.Context, _ any) (any, error) {
		called = true
		if mode, _ := ctx.Value(auth.ContextMode).(string); mode != auth.ModeFull {
			t.Errorf("mode = %q, want full", mode)
		}
		return "ok", nil
	}

	if _, err := srv.TestableAuthUnaryInterceptor(
		context.Background(),
		&pb.WriteRequest{Vault: "default"},
		nil,
		handler,
	); err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}
	if !called {
		t.Fatal("handler was not called")
	}
}

func TestRPCHandlers_RejectCrossVaultWithoutInterceptor(t *testing.T) {
	store := newTestAuthStore(t)
	srv := transportgrpc.NewServer(":0", &mockEngine{}, store, nil)
	key := &auth.APIKey{Vault: "vault-a", Mode: auth.ModeFull}
	ctx := context.WithValue(context.Background(), auth.ContextAPIKey, key)
	ctx = context.WithValue(ctx, auth.ContextMode, auth.ModeFull)

	tests := []struct {
		name string
		call func() error
	}{
		{"hello", func() error {
			_, err := srv.Hello(ctx, &pb.HelloRequest{Vault: "vault-b"})
			return err
		}},
		{"write", func() error {
			_, err := srv.Write(ctx, &pb.WriteRequest{Vault: "vault-b"})
			return err
		}},
		{"batch-write", func() error {
			_, err := srv.BatchWrite(ctx, &pb.BatchWriteRequest{Requests: []*pb.WriteRequest{{Vault: "vault-b"}}})
			return err
		}},
		{"read", func() error {
			_, err := srv.Read(ctx, &pb.ReadRequest{Vault: "vault-b"})
			return err
		}},
		{"forget", func() error {
			_, err := srv.Forget(ctx, &pb.ForgetRequest{Vault: "vault-b"})
			return err
		}},
		{"stat", func() error {
			_, err := srv.Stat(ctx, &pb.StatRequest{Vault: "vault-b"})
			return err
		}},
		{"link", func() error {
			_, err := srv.Link(ctx, &pb.LinkRequest{Vault: "vault-b"})
			return err
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); status.Code(err) != codes.PermissionDenied {
				t.Fatalf("code = %v, want PermissionDenied (err=%v)", status.Code(err), err)
			}
		})
	}

	activateStream := &mockActivateStream{ctx: ctx}
	if err := srv.Activate(&pb.ActivateRequest{Vault: "vault-b"}, activateStream); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("activate code = %v, want PermissionDenied (err=%v)", status.Code(err), err)
	}
	subscribeStream := &mockSubscribeStream{ctx: ctx, recvReq: &pb.SubscribeRequest{Vault: "vault-b"}}
	if err := srv.Subscribe(subscribeStream); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("subscribe code = %v, want PermissionDenied (err=%v)", status.Code(err), err)
	}
}

func TestRPCHandlers_NilAuthStoreFailsClosed(t *testing.T) {
	srv := transportgrpc.NewServer(":0", &mockEngine{}, nil, nil)
	_, err := srv.Write(context.Background(), &pb.WriteRequest{Vault: "default"})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want Unauthenticated (err=%v)", status.Code(err), err)
	}
}

// ---------------------------------------------------------------------------
// Auth stream interceptor tests
// ---------------------------------------------------------------------------

// mockServerStream implements grpc.ServerStream for testing stream interceptors.
type mockServerStream struct {
	ctx      context.Context
	sentMsgs []any
	recvMsgs []any
	recvIdx  int
	recvFn   func(any) error
}

func (m *mockServerStream) SetHeader(metadata.MD) error  { return nil }
func (m *mockServerStream) SendHeader(metadata.MD) error { return nil }
func (m *mockServerStream) SetTrailer(metadata.MD)       {}
func (m *mockServerStream) Context() context.Context     { return m.ctx }
func (m *mockServerStream) SendMsg(msg any) error {
	m.sentMsgs = append(m.sentMsgs, msg)
	return nil
}
func (m *mockServerStream) RecvMsg(msg any) error {
	if m.recvFn != nil {
		return m.recvFn(msg)
	}
	return nil
}

func TestAuthStreamInterceptor_ValidKey(t *testing.T) {
	store := newTestAuthStore(t)
	token, _, err := store.GenerateAPIKey("testvault", "test-label", "full", nil)
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}

	srv := transportgrpc.NewServer(":0", &mockEngine{}, store, nil)

	var capturedVault, capturedMode string
	handler := func(srv any, stream grpc.ServerStream) error {
		if err := stream.RecvMsg(&pb.ActivateRequest{Vault: "testvault"}); err != nil {
			return err
		}
		ctx := stream.Context()
		capturedVault, _ = ctx.Value(auth.ContextVault).(string)
		capturedMode, _ = ctx.Value(auth.ContextMode).(string)
		return nil
	}

	md := metadata.Pairs("authorization", "Bearer "+token)
	ctx := metadata.NewIncomingContext(context.Background(), md)
	ss := &mockServerStream{ctx: ctx}

	err = srv.TestableAuthStreamInterceptor(nil, ss, nil, handler)
	if err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}
	if capturedVault != "testvault" {
		t.Errorf("vault = %q, want \"testvault\"", capturedVault)
	}
	if capturedMode != "full" {
		t.Errorf("mode = %q, want \"full\"", capturedMode)
	}
}

func TestAuthStreamInterceptor_InvalidKey(t *testing.T) {
	store := newTestAuthStore(t)
	srv := transportgrpc.NewServer(":0", &mockEngine{}, store, nil)

	handler := func(srv any, stream grpc.ServerStream) error {
		t.Fatal("handler should not be called with invalid key")
		return nil
	}

	md := metadata.Pairs("x-api-key", "mk_invalid-token")
	ctx := metadata.NewIncomingContext(context.Background(), md)
	ss := &mockServerStream{ctx: ctx}

	err := srv.TestableAuthStreamInterceptor(nil, ss, nil, handler)
	if err == nil {
		t.Fatal("expected error for invalid key, got nil")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("error is not a gRPC status: %v", err)
	}
	if st.Code() != codes.Unauthenticated {
		t.Errorf("code = %v, want Unauthenticated", st.Code())
	}
}

func TestAuthStreamInterceptor_NoKeyPublicVault(t *testing.T) {
	store := newTestAuthStore(t)
	if err := store.SetVaultConfig(auth.VaultConfig{Name: "default", Public: true}); err != nil {
		t.Fatalf("SetVaultConfig: %v", err)
	}

	srv := transportgrpc.NewServer(":0", &mockEngine{}, store, nil)

	var capturedVault, capturedMode string
	handler := func(srv any, stream grpc.ServerStream) error {
		if err := stream.RecvMsg(&pb.ActivateRequest{Vault: "default"}); err != nil {
			return err
		}
		ctx := stream.Context()
		capturedVault, _ = ctx.Value(auth.ContextVault).(string)
		capturedMode, _ = ctx.Value(auth.ContextMode).(string)
		return nil
	}

	ctx := context.Background()
	ss := &mockServerStream{ctx: ctx}

	err := srv.TestableAuthStreamInterceptor(nil, ss, nil, handler)
	if err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}
	if capturedVault != "default" {
		t.Errorf("vault = %q, want \"default\"", capturedVault)
	}
	if capturedMode != "full" {
		t.Errorf("mode = %q, want \"full\"", capturedMode)
	}
}

func TestAuthStreamInterceptor_NoKeyLockedVault(t *testing.T) {
	store := newTestAuthStore(t)
	srv := transportgrpc.NewServer(":0", &mockEngine{}, store, nil)

	handler := func(srv any, stream grpc.ServerStream) error {
		return stream.RecvMsg(&pb.ActivateRequest{Vault: "default"})
	}

	ctx := context.Background()
	ss := &mockServerStream{ctx: ctx}

	err := srv.TestableAuthStreamInterceptor(nil, ss, nil, handler)
	if err == nil {
		t.Fatal("expected error for locked vault, got nil")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("error is not a gRPC status: %v", err)
	}
	if st.Code() != codes.Unauthenticated {
		t.Errorf("code = %v, want Unauthenticated", st.Code())
	}
}

func TestAuthStreamInterceptor_XApiKey(t *testing.T) {
	store := newTestAuthStore(t)
	token, _, err := store.GenerateAPIKey("default", "test-label", "observe", nil)
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}

	srv := transportgrpc.NewServer(":0", &mockEngine{}, store, nil)

	var capturedMode string
	handler := func(srv any, stream grpc.ServerStream) error {
		if err := stream.RecvMsg(&pb.ActivateRequest{Vault: "default"}); err != nil {
			return err
		}
		ctx := stream.Context()
		capturedMode, _ = ctx.Value(auth.ContextMode).(string)
		return nil
	}

	md := metadata.Pairs("x-api-key", token)
	ctx := metadata.NewIncomingContext(context.Background(), md)
	ss := &mockServerStream{ctx: ctx}

	err = srv.TestableAuthStreamInterceptor(nil, ss, nil, handler)
	if err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}
	if capturedMode != "observe" {
		t.Errorf("mode = %q, want \"observe\"", capturedMode)
	}
}

func TestAuthStreamInterceptor_RejectsCrossVaultKey(t *testing.T) {
	store := newTestAuthStore(t)
	token, _, err := store.GenerateAPIKey("vault-a", "test-label", "full", nil)
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	srv := transportgrpc.NewServer(":0", &mockEngine{}, store, nil)
	ctx := metadata.NewIncomingContext(
		context.Background(),
		metadata.Pairs("authorization", "Bearer "+token),
	)
	ss := &mockServerStream{ctx: ctx}
	handler := func(_ any, stream grpc.ServerStream) error {
		return stream.RecvMsg(&pb.ActivateRequest{Vault: "vault-b"})
	}

	err = srv.TestableAuthStreamInterceptor(nil, ss, nil, handler)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied (err=%v)", status.Code(err), err)
	}
}

func TestAuthStreamInterceptor_UsesDecodedPublicVault(t *testing.T) {
	store := newTestAuthStore(t)
	if err := store.SetVaultConfig(auth.VaultConfig{Name: "default", Public: false}); err != nil {
		t.Fatalf("SetVaultConfig(default): %v", err)
	}
	if err := store.SetVaultConfig(auth.VaultConfig{Name: "public-b", Public: true}); err != nil {
		t.Fatalf("SetVaultConfig(public-b): %v", err)
	}
	srv := transportgrpc.NewServer(":0", &mockEngine{}, store, nil)
	ss := &mockServerStream{ctx: context.Background()}
	var capturedVault string
	handler := func(_ any, stream grpc.ServerStream) error {
		if err := stream.RecvMsg(&pb.SubscribeRequest{Vault: "public-b"}); err != nil {
			return err
		}
		capturedVault, _ = stream.Context().Value(auth.ContextVault).(string)
		return nil
	}

	if err := srv.TestableAuthStreamInterceptor(nil, ss, nil, handler); err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}
	if capturedVault != "public-b" {
		t.Fatalf("vault = %q, want public-b", capturedVault)
	}
}

func TestAuthStreamInterceptor_WriteOnlyCannotRead(t *testing.T) {
	store := newTestAuthStore(t)
	token, _, err := store.GenerateAPIKey("default", "ingest", auth.ModeWrite, nil)
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	srv := transportgrpc.NewServer(":0", &mockEngine{}, store, nil)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-api-key", token))
	ss := &mockServerStream{ctx: ctx}
	handler := func(_ any, stream grpc.ServerStream) error {
		return stream.RecvMsg(&pb.ActivateRequest{Vault: "default"})
	}

	err = srv.TestableAuthStreamInterceptor(nil, ss, nil, handler)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied (err=%v)", status.Code(err), err)
	}
}

func TestAuthStreamInterceptor_RevokedKeyCancelsStream(t *testing.T) {
	store := newTestAuthStore(t)
	token, key, err := store.GenerateAPIKey("default", "stream", auth.ModeFull, nil)
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	srv := transportgrpc.NewServer(":0", &mockEngine{}, store, nil)
	srv.SetTestStreamAuthRecheckInterval(5 * time.Millisecond)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-api-key", token))
	ss := &mockServerStream{ctx: ctx}
	ready := make(chan struct{})
	handler := func(_ any, stream grpc.ServerStream) error {
		if err := stream.RecvMsg(&pb.SubscribeRequest{Vault: "default"}); err != nil {
			return err
		}
		close(ready)
		<-stream.Context().Done()
		return context.Cause(stream.Context())
	}
	result := make(chan error, 1)
	go func() {
		result <- srv.TestableAuthStreamInterceptor(nil, ss, nil, handler)
	}()

	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("stream was not authorized")
	}
	if err := store.RevokeAPIKey("default", key.ID); err != nil {
		t.Fatalf("RevokeAPIKey: %v", err)
	}
	select {
	case err := <-result:
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("code = %v, want Unauthenticated (err=%v)", status.Code(err), err)
		}
	case <-time.After(time.Second):
		t.Fatal("revoked key did not cancel stream")
	}
}

func TestAuthStreamInterceptor_ExpiredKeyCancelsStream(t *testing.T) {
	store := newTestAuthStore(t)
	expiresAt := time.Now().Add(300 * time.Millisecond)
	token, _, err := store.GenerateAPIKey("default", "stream", auth.ModeFull, &expiresAt)
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}
	srv := transportgrpc.NewServer(":0", &mockEngine{}, store, nil)
	srv.SetTestStreamAuthRecheckInterval(5 * time.Millisecond)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-api-key", token))
	ss := &mockServerStream{ctx: ctx}
	ready := make(chan struct{})
	handler := func(_ any, stream grpc.ServerStream) error {
		if err := stream.RecvMsg(&pb.SubscribeRequest{Vault: "default"}); err != nil {
			return err
		}
		close(ready)
		<-stream.Context().Done()
		return context.Cause(stream.Context())
	}

	result := make(chan error, 1)
	go func() {
		result <- srv.TestableAuthStreamInterceptor(nil, ss, nil, handler)
	}()
	select {
	case <-ready:
	case err := <-result:
		t.Fatalf("stream was not initially authorized: %v", err)
	case <-time.After(time.Second):
		t.Fatal("stream was not initially authorized")
	}
	select {
	case err := <-result:
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("code = %v, want Unauthenticated (err=%v)", status.Code(err), err)
		}
	case <-time.After(time.Second):
		t.Fatal("expired key did not cancel stream")
	}
}

func TestAuthStreamInterceptor_CancellationWhileFirstMessageBlocked(t *testing.T) {
	tests := []struct {
		name   string
		cancel func(*auth.Store, auth.APIKey)
		expiry time.Duration
	}{
		{
			name: "revoked",
			cancel: func(store *auth.Store, key auth.APIKey) {
				if err := store.RevokeAPIKey("default", key.ID); err != nil {
					t.Fatalf("RevokeAPIKey: %v", err)
				}
			},
		},
		{name: "expired", expiry: 300 * time.Millisecond},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := newTestAuthStore(t)
			var expiresAt *time.Time
			if tc.expiry > 0 {
				deadline := time.Now().Add(tc.expiry)
				expiresAt = &deadline
			}
			token, key, err := store.GenerateAPIKey("default", "stream", auth.ModeFull, expiresAt)
			if err != nil {
				t.Fatalf("GenerateAPIKey: %v", err)
			}
			srv := transportgrpc.NewServer(":0", &mockEngine{}, store, nil)
			srv.SetTestStreamAuthRecheckInterval(5 * time.Millisecond)

			enteredRecv := make(chan struct{})
			releaseRecv := make(chan struct{})
			ss := &mockServerStream{
				ctx: metadata.NewIncomingContext(
					context.Background(),
					metadata.Pairs("x-api-key", token),
				),
				recvFn: func(any) error {
					close(enteredRecv)
					<-releaseRecv
					return nil
				},
			}
			streamCtx := make(chan context.Context, 1)
			handlerCalled := make(chan struct{})
			handler := func(_ any, stream grpc.ServerStream) error {
				close(handlerCalled)
				streamCtx <- stream.Context()
				return stream.RecvMsg(&pb.SubscribeRequest{Vault: "default"})
			}
			result := make(chan error, 1)
			go func() {
				result <- srv.TestableAuthStreamInterceptor(nil, ss, nil, handler)
			}()

			select {
			case <-handlerCalled:
			case err := <-result:
				t.Fatalf("stream did not authenticate initially: %v", err)
			case <-time.After(time.Second):
				t.Fatal("stream did not authenticate initially")
			}
			ctx := <-streamCtx
			select {
			case <-enteredRecv:
			case <-time.After(time.Second):
				t.Fatal("first message did not block in RecvMsg")
			}
			if tc.cancel != nil {
				tc.cancel(store, key)
			}
			select {
			case <-ctx.Done():
			case <-time.After(time.Second):
				t.Fatal("stream credentials were not invalidated")
			}
			close(releaseRecv)

			select {
			case err := <-result:
				if status.Code(err) != codes.Unauthenticated {
					t.Fatalf("code = %v, want Unauthenticated (err=%v)", status.Code(err), err)
				}
			case <-time.After(time.Second):
				t.Fatal("blocked first message did not fail after credential invalidation")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// RPC handler tests — Unary RPCs
// ---------------------------------------------------------------------------

// newPublicTestServer creates a Server with a public default vault, suitable
// for testing RPC handlers without auth ceremony.
func newPublicTestServer(t *testing.T, eng *mockEngine) *transportgrpc.Server {
	t.Helper()
	store := newTestAuthStore(t)
	if err := store.SetVaultConfig(auth.VaultConfig{Name: "default", Public: true}); err != nil {
		t.Fatalf("SetVaultConfig: %v", err)
	}
	return transportgrpc.NewServer(":0", eng, store, nil)
}

func TestHello_Success(t *testing.T) {
	eng := &mockEngine{
		helloFn: func(ctx context.Context, req *pb.HelloRequest) (*pb.HelloResponse, error) {
			return &pb.HelloResponse{ServerVersion: "1.0.0", SessionId: "sess-1"}, nil
		},
	}
	srv := newPublicTestServer(t, eng)

	resp, err := srv.Hello(context.Background(), &pb.HelloRequest{Version: "1.0"})
	if err != nil {
		t.Fatalf("Hello: %v", err)
	}
	if resp.ServerVersion != "1.0.0" {
		t.Errorf("ServerVersion = %q, want \"1.0.0\"", resp.ServerVersion)
	}
	if resp.SessionId != "sess-1" {
		t.Errorf("SessionId = %q, want \"sess-1\"", resp.SessionId)
	}
}

func TestHello_Error(t *testing.T) {
	eng := &mockEngine{
		helloFn: func(ctx context.Context, req *pb.HelloRequest) (*pb.HelloResponse, error) {
			return nil, errors.New("engine down")
		},
	}
	srv := newPublicTestServer(t, eng)

	_, err := srv.Hello(context.Background(), &pb.HelloRequest{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestWrite_Success(t *testing.T) {
	eng := &mockEngine{
		writeFn: func(ctx context.Context, req *pb.WriteRequest) (*pb.WriteResponse, error) {
			return &pb.WriteResponse{Id: "engram-123", CreatedAt: 1000}, nil
		},
	}
	srv := newPublicTestServer(t, eng)

	resp, err := srv.Write(context.Background(), &pb.WriteRequest{
		Concept: "test", Content: "hello world",
	})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if resp.Id != "engram-123" {
		t.Errorf("Id = %q, want \"engram-123\"", resp.Id)
	}
}

func TestWrite_Error(t *testing.T) {
	eng := &mockEngine{
		writeFn: func(ctx context.Context, req *pb.WriteRequest) (*pb.WriteResponse, error) {
			return nil, errors.New("disk full")
		},
	}
	srv := newPublicTestServer(t, eng)

	_, err := srv.Write(context.Background(), &pb.WriteRequest{
		Concept: "test", Content: "hello world",
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestBatchWrite_Success(t *testing.T) {
	eng := &mockEngine{}
	srv := newPublicTestServer(t, eng)

	resp, err := srv.BatchWrite(context.Background(), &pb.BatchWriteRequest{
		Requests: []*pb.WriteRequest{
			{Concept: "a", Content: "content a"},
			{Concept: "b", Content: "content b"},
		},
	})
	if err != nil {
		t.Fatalf("BatchWrite: %v", err)
	}
	if len(resp.Results) != 2 {
		t.Fatalf("got %d results, want 2", len(resp.Results))
	}
}

func TestRead_Success(t *testing.T) {
	eng := &mockEngine{
		readFn: func(ctx context.Context, req *pb.ReadRequest) (*pb.ReadResponse, error) {
			return &pb.ReadResponse{
				Id: req.Id, Concept: "test-concept", Content: "test-content",
			}, nil
		},
	}
	srv := newPublicTestServer(t, eng)

	resp, err := srv.Read(context.Background(), &pb.ReadRequest{Id: "engram-1"})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if resp.Concept != "test-concept" {
		t.Errorf("Concept = %q, want \"test-concept\"", resp.Concept)
	}
}

func TestRead_Error(t *testing.T) {
	eng := &mockEngine{
		readFn: func(ctx context.Context, req *pb.ReadRequest) (*pb.ReadResponse, error) {
			return nil, errors.New("not found")
		},
	}
	srv := newPublicTestServer(t, eng)

	_, err := srv.Read(context.Background(), &pb.ReadRequest{Id: "missing"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestForget_Success(t *testing.T) {
	eng := &mockEngine{
		forgetFn: func(ctx context.Context, req *pb.ForgetRequest) (*pb.ForgetResponse, error) {
			return &pb.ForgetResponse{Ok: true}, nil
		},
	}
	srv := newPublicTestServer(t, eng)

	resp, err := srv.Forget(context.Background(), &pb.ForgetRequest{Id: "engram-1"})
	if err != nil {
		t.Fatalf("Forget: %v", err)
	}
	if !resp.Ok {
		t.Error("Ok = false, want true")
	}
}

func TestForget_Error(t *testing.T) {
	eng := &mockEngine{
		forgetFn: func(ctx context.Context, req *pb.ForgetRequest) (*pb.ForgetResponse, error) {
			return nil, errors.New("permission denied")
		},
	}
	srv := newPublicTestServer(t, eng)

	_, err := srv.Forget(context.Background(), &pb.ForgetRequest{Id: "engram-1"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestStat_Success(t *testing.T) {
	eng := &mockEngine{
		statFn: func(ctx context.Context, req *pb.StatRequest) (*pb.StatResponse, error) {
			return &pb.StatResponse{EngramCount: 42, StorageBytes: 1024}, nil
		},
	}
	srv := newPublicTestServer(t, eng)

	resp, err := srv.Stat(context.Background(), &pb.StatRequest{})
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if resp.EngramCount != 42 {
		t.Errorf("EngramCount = %d, want 42", resp.EngramCount)
	}
}

func TestStat_Error(t *testing.T) {
	eng := &mockEngine{
		statFn: func(ctx context.Context, req *pb.StatRequest) (*pb.StatResponse, error) {
			return nil, errors.New("internal error")
		},
	}
	srv := newPublicTestServer(t, eng)

	_, err := srv.Stat(context.Background(), &pb.StatRequest{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestLink_Success(t *testing.T) {
	eng := &mockEngine{
		linkFn: func(ctx context.Context, req *pb.LinkRequest) (*pb.LinkResponse, error) {
			return &pb.LinkResponse{Ok: true}, nil
		},
	}
	srv := newPublicTestServer(t, eng)

	resp, err := srv.Link(context.Background(), &pb.LinkRequest{
		SourceId: "a", TargetId: "b", RelType: 1, Weight: 0.5,
	})
	if err != nil {
		t.Fatalf("Link: %v", err)
	}
	if !resp.Ok {
		t.Error("Ok = false, want true")
	}
}

func TestLink_Error(t *testing.T) {
	eng := &mockEngine{
		linkFn: func(ctx context.Context, req *pb.LinkRequest) (*pb.LinkResponse, error) {
			return nil, errors.New("invalid source")
		},
	}
	srv := newPublicTestServer(t, eng)

	_, err := srv.Link(context.Background(), &pb.LinkRequest{SourceId: "bad"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// Streaming RPC tests
// ---------------------------------------------------------------------------

// mockActivateStream implements pb.MuninnDB_ActivateServer for testing.
type mockActivateStream struct {
	grpc.ServerStream
	ctx  context.Context
	sent []*pb.ActivateResponse
}

func (m *mockActivateStream) Context() context.Context { return m.ctx }
func (m *mockActivateStream) Send(resp *pb.ActivateResponse) error {
	m.sent = append(m.sent, resp)
	return nil
}

func TestActivate_Success(t *testing.T) {
	eng := &mockEngine{
		activateFn: func(ctx context.Context, req *pb.ActivateRequest) (*pb.ActivateResponse, error) {
			return &pb.ActivateResponse{
				QueryId:    "q-1",
				TotalFound: 2,
				Activations: []*pb.ActivationItem{
					{Id: "e1", Concept: "concept1", Score: 0.9},
					{Id: "e2", Concept: "concept2", Score: 0.7},
				},
				LatencyMs: 1.5,
			}, nil
		},
	}
	srv := newPublicTestServer(t, eng)

	stream := &mockActivateStream{ctx: context.Background()}
	err := srv.Activate(&pb.ActivateRequest{Context: []string{"test"}}, stream)
	if err != nil {
		t.Fatalf("Activate: %v", err)
	}
	if len(stream.sent) != 1 {
		t.Fatalf("sent %d responses, want 1", len(stream.sent))
	}
	if stream.sent[0].TotalFound != 2 {
		t.Errorf("TotalFound = %d, want 2", stream.sent[0].TotalFound)
	}
}

func TestActivate_EngineError(t *testing.T) {
	eng := &mockEngine{
		activateFn: func(ctx context.Context, req *pb.ActivateRequest) (*pb.ActivateResponse, error) {
			return nil, errors.New("activation failed")
		},
	}
	srv := newPublicTestServer(t, eng)

	stream := &mockActivateStream{ctx: context.Background()}
	err := srv.Activate(&pb.ActivateRequest{}, stream)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

type errActivateStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (m *errActivateStream) Context() context.Context { return m.ctx }
func (m *errActivateStream) Send(*pb.ActivateResponse) error {
	return errors.New("stream send error")
}

func TestActivate_SendError(t *testing.T) {
	eng := &mockEngine{}
	srv := newPublicTestServer(t, eng)

	stream := &errActivateStream{ctx: context.Background()}
	err := srv.Activate(&pb.ActivateRequest{}, stream)
	if err == nil {
		t.Fatal("expected error from stream send, got nil")
	}
}

// mockSubscribeStream implements pb.MuninnDB_SubscribeServer for testing.
type mockSubscribeStream struct {
	grpc.ServerStream
	ctx     context.Context
	recvReq *pb.SubscribeRequest
	recvErr error
	sent    []*pb.ActivationPush
	sendErr error
}

type cancelOnConfirmSubscribeStream struct {
	grpc.ServerStream
	ctx    context.Context
	cancel context.CancelFunc
	req    *pb.SubscribeRequest
	once   sync.Once
}

func (m *cancelOnConfirmSubscribeStream) Context() context.Context { return m.ctx }
func (m *cancelOnConfirmSubscribeStream) Recv() (*pb.SubscribeRequest, error) {
	return m.req, nil
}
func (m *cancelOnConfirmSubscribeStream) Send(push *pb.ActivationPush) error {
	if push.Trigger == "subscription_created" {
		m.once.Do(m.cancel)
	}
	return nil
}

func TestSubscribe_RejectsConcurrentClientAssignedIDAcrossVaults(t *testing.T) {
	store := newTestAuthStore(t)
	for _, vault := range []string{"vault-a", "vault-b"} {
		if err := store.SetVaultConfig(auth.VaultConfig{Name: vault, Public: true}); err != nil {
			t.Fatalf("SetVaultConfig(%s): %v", vault, err)
		}
	}

	var subscribeCalls atomic.Int64
	var unsubscribeCalls atomic.Int64
	eng := &mockEngine{
		subscribeWithDeliverFn: func(context.Context, *pb.SubscribeRequest, trigger.DeliverFunc) (string, error) {
			subscribeCalls.Add(1)
			return "", errors.New("engine must not receive a client-assigned subscription id")
		},
		unsubscribeFn: func(context.Context, string) error {
			unsubscribeCalls.Add(1)
			return nil
		},
	}
	srv := transportgrpc.NewServer(":0", eng, store, nil)

	const streams = 64
	start := make(chan struct{})
	results := make(chan error, streams)
	var wg sync.WaitGroup
	for i := 0; i < streams; i++ {
		vault := "vault-a"
		if i%2 == 1 {
			vault = "vault-b"
		}
		clientID := "shared-cross-vault-id"
		if i%4 >= 2 {
			clientID = " "
		}
		wg.Add(1)
		go func(vault, clientID string) {
			defer wg.Done()
			<-start
			results <- srv.Subscribe(&mockSubscribeStream{
				ctx: context.Background(),
				recvReq: &pb.SubscribeRequest{
					Vault:          vault,
					SubscriptionId: clientID,
				},
			})
		}(vault, clientID)
	}
	close(start)
	wg.Wait()
	close(results)

	for err := range results {
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("code = %v, want InvalidArgument (err=%v)", status.Code(err), err)
		}
	}
	if got := subscribeCalls.Load(); got != 0 {
		t.Fatalf("engine subscribe calls = %d, want 0", got)
	}
	if got := unsubscribeCalls.Load(); got != 0 {
		t.Fatalf("engine unsubscribe calls = %d, want 0", got)
	}
}

func TestSubscribe_ConcurrentServerAssignedIDsOwnCleanup(t *testing.T) {
	store := newTestAuthStore(t)
	for _, vault := range []string{"vault-a", "vault-b"} {
		if err := store.SetVaultConfig(auth.VaultConfig{Name: vault, Public: true}); err != nil {
			t.Fatalf("SetVaultConfig(%s): %v", vault, err)
		}
	}

	const streams = 64
	var mu sync.Mutex
	active := make(map[string]string, streams)
	assigned := make(map[string]string, streams)
	cleanupCounts := make(map[string]int, streams)
	var callbackIssues []string
	eng := &mockEngine{
		subscribeWithDeliverFn: func(_ context.Context, req *pb.SubscribeRequest, _ trigger.DeliverFunc) (string, error) {
			mu.Lock()
			defer mu.Unlock()
			if req.SubscriptionId == "" {
				return "", errors.New("server did not assign a subscription id")
			}
			if owner, exists := active[req.SubscriptionId]; exists {
				return "", fmt.Errorf("duplicate subscription id already owned by %s", owner)
			}
			active[req.SubscriptionId] = req.Vault
			assigned[req.SubscriptionId] = req.Vault
			return req.SubscriptionId, nil
		},
		unsubscribeFn: func(ctx context.Context, subID string) error {
			mu.Lock()
			defer mu.Unlock()
			if ctx.Err() != nil {
				callbackIssues = append(callbackIssues, fmt.Sprintf("cleanup %s used canceled context: %v", subID, ctx.Err()))
			}
			if _, exists := active[subID]; !exists {
				callbackIssues = append(callbackIssues, fmt.Sprintf("cleanup did not own %s", subID))
				return nil
			}
			delete(active, subID)
			cleanupCounts[subID]++
			return nil
		},
	}
	srv := transportgrpc.NewServer(":0", eng, store, nil)

	start := make(chan struct{})
	results := make(chan error, streams)
	var wg sync.WaitGroup
	for i := 0; i < streams; i++ {
		vault := "vault-a"
		if i%2 == 1 {
			vault = "vault-b"
		}
		wg.Add(1)
		go func(vault string) {
			defer wg.Done()
			<-start
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			results <- srv.Subscribe(&cancelOnConfirmSubscribeStream{
				ctx:    ctx,
				cancel: cancel,
				req:    &pb.SubscribeRequest{Vault: vault},
			})
		}(vault)
	}
	close(start)
	wg.Wait()
	close(results)

	for err := range results {
		if err != nil {
			t.Errorf("Subscribe returned error: %v", err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(callbackIssues) > 0 {
		t.Fatalf("ownership issues: %v", callbackIssues)
	}
	if len(assigned) != streams {
		t.Fatalf("unique assigned IDs = %d, want %d", len(assigned), streams)
	}
	if len(active) != 0 {
		t.Fatalf("active subscriptions after teardown = %v, want none", active)
	}
	for subID, vault := range assigned {
		if cleanupCounts[subID] != 1 {
			t.Errorf("cleanup count for %s (%s) = %d, want 1", subID, vault, cleanupCounts[subID])
		}
	}
}

func TestSubscribe_EngineIDMismatchCleansOnlyAssignedID(t *testing.T) {
	const otherOwnerID = "other-connection-subscription"
	var assignedSubID string
	var cleaned []string
	var cleanupContextErr error
	eng := &mockEngine{
		subscribeWithDeliverFn: func(_ context.Context, req *pb.SubscribeRequest, _ trigger.DeliverFunc) (string, error) {
			assignedSubID = req.SubscriptionId
			return otherOwnerID, nil
		},
		unsubscribeFn: func(ctx context.Context, subID string) error {
			cleanupContextErr = ctx.Err()
			cleaned = append(cleaned, subID)
			return nil
		},
	}
	srv := newPublicTestServer(t, eng)
	err := srv.Subscribe(&mockSubscribeStream{
		ctx:     context.Background(),
		recvReq: &pb.SubscribeRequest{Vault: "default"},
	})

	if status.Code(err) != codes.Internal {
		t.Fatalf("code = %v, want Internal (err=%v)", status.Code(err), err)
	}
	if assignedSubID == "" {
		t.Fatal("server did not assign a subscription ID")
	}
	if cleanupContextErr != nil {
		t.Fatalf("cleanup context error = %v, want nil", cleanupContextErr)
	}
	if len(cleaned) != 1 || cleaned[0] != assignedSubID {
		t.Fatalf("cleaned IDs = %v, want only assigned %q", cleaned, assignedSubID)
	}
	if cleaned[0] == otherOwnerID {
		t.Fatalf("cleanup canceled another owner's subscription %q", otherOwnerID)
	}
}

func (m *mockSubscribeStream) Context() context.Context { return m.ctx }
func (m *mockSubscribeStream) Send(push *pb.ActivationPush) error {
	if m.sendErr != nil {
		return m.sendErr
	}
	m.sent = append(m.sent, push)
	return nil
}
func (m *mockSubscribeStream) Recv() (*pb.SubscribeRequest, error) {
	if m.recvErr != nil {
		return nil, m.recvErr
	}
	return m.recvReq, nil
}

func TestSubscribe_Success(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var assignedSubID string

	eng := &mockEngine{
		subscribeWithDeliverFn: func(ctx context.Context, req *pb.SubscribeRequest, deliver trigger.DeliverFunc) (string, error) {
			assignedSubID = req.SubscriptionId
			go func(subID string) {
				push := &trigger.ActivationPush{
					SubscriptionID: subID,
					Trigger:        trigger.TriggerNewWrite,
					PushNumber:     1,
					At:             time.Now(),
					Engram: &storage.Engram{
						Concept: "test-concept",
						Content: "test-content",
					},
					Score: 0.85,
					Why:   "semantic match",
				}
				_ = deliver(ctx, push)
				time.Sleep(20 * time.Millisecond)
				cancel()
			}(assignedSubID)
			return assignedSubID, nil
		},
	}
	srv := newPublicTestServer(t, eng)

	stream := &mockSubscribeStream{
		ctx:     ctx,
		recvReq: &pb.SubscribeRequest{Vault: "default", PushOnWrite: true},
	}

	err := srv.Subscribe(stream)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	if len(stream.sent) < 1 {
		t.Fatal("expected at least 1 sent message (subscription confirmation)")
	}
	if stream.sent[0].Trigger != "subscription_created" {
		t.Errorf("first push trigger = %q, want \"subscription_created\"", stream.sent[0].Trigger)
	}
	if assignedSubID == "" {
		t.Fatal("server did not assign a subscription ID")
	}
	if stream.sent[0].SubscriptionId != assignedSubID {
		t.Errorf("SubscriptionId = %q, want %q", stream.sent[0].SubscriptionId, assignedSubID)
	}

	// The second message should be the actual push with engram data.
	if len(stream.sent) >= 2 {
		push := stream.sent[1]
		if push.Activation == nil {
			t.Fatal("expected Activation in push, got nil")
		}
		if push.Activation.Concept != "test-concept" {
			t.Errorf("Activation.Concept = %q, want \"test-concept\"", push.Activation.Concept)
		}
		if push.Activation.Score != 0.85 {
			t.Errorf("Activation.Score = %f, want 0.85", push.Activation.Score)
		}
	}
}

func TestSubscribe_RecvError(t *testing.T) {
	eng := &mockEngine{}
	srv := newPublicTestServer(t, eng)

	stream := &mockSubscribeStream{
		ctx:     context.Background(),
		recvErr: errors.New("client disconnected"),
	}

	err := srv.Subscribe(stream)
	if err == nil {
		t.Fatal("expected error from Recv, got nil")
	}
}

func TestSubscribe_EngineError(t *testing.T) {
	var unsubscribeCalls atomic.Int64
	eng := &mockEngine{
		subscribeWithDeliverFn: func(ctx context.Context, req *pb.SubscribeRequest, deliver trigger.DeliverFunc) (string, error) {
			return "", errors.New("subscribe limit reached")
		},
		unsubscribeFn: func(context.Context, string) error {
			unsubscribeCalls.Add(1)
			return nil
		},
	}
	srv := newPublicTestServer(t, eng)

	stream := &mockSubscribeStream{
		ctx:     context.Background(),
		recvReq: &pb.SubscribeRequest{Vault: "default"},
	}

	err := srv.Subscribe(stream)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if got := unsubscribeCalls.Load(); got != 0 {
		t.Fatalf("unsubscribe calls after failed registration = %d, want 0", got)
	}
}

func TestSubscribe_SendConfirmError(t *testing.T) {
	eng := &mockEngine{
		subscribeWithDeliverFn: func(ctx context.Context, req *pb.SubscribeRequest, deliver trigger.DeliverFunc) (string, error) {
			return req.SubscriptionId, nil
		},
	}
	srv := newPublicTestServer(t, eng)

	stream := &mockSubscribeStream{
		ctx:     context.Background(),
		recvReq: &pb.SubscribeRequest{Vault: "default"},
		sendErr: errors.New("broken pipe"),
	}

	err := srv.Subscribe(stream)
	if err == nil {
		t.Fatal("expected error from send, got nil")
	}
}

func TestSubscribe_NilEngram(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	eng := &mockEngine{
		subscribeWithDeliverFn: func(ctx context.Context, req *pb.SubscribeRequest, deliver trigger.DeliverFunc) (string, error) {
			go func(subID string) {
				push := &trigger.ActivationPush{
					SubscriptionID: subID,
					Trigger:        trigger.TriggerNewWrite,
					PushNumber:     1,
					At:             time.Now(),
				}
				_ = deliver(ctx, push)
				time.Sleep(20 * time.Millisecond)
				cancel()
			}(req.SubscriptionId)
			return req.SubscriptionId, nil
		},
	}
	srv := newPublicTestServer(t, eng)

	stream := &mockSubscribeStream{
		ctx:     ctx,
		recvReq: &pb.SubscribeRequest{Vault: "default"},
	}

	err := srv.Subscribe(stream)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	// Should have confirmation + push without activation.
	for _, msg := range stream.sent {
		if msg.Trigger == string(trigger.TriggerNewWrite) && msg.Activation != nil {
			t.Error("expected nil Activation for push with nil Engram")
		}
	}
}

func TestSubscribe_AuthCancellationReturnsCause(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	authErr := status.Error(codes.Unauthenticated, "api key expired or revoked")
	cancel(authErr)

	eng := &mockEngine{
		subscribeWithDeliverFn: func(_ context.Context, req *pb.SubscribeRequest, _ trigger.DeliverFunc) (string, error) {
			return req.SubscriptionId, nil
		},
	}
	srv := newPublicTestServer(t, eng)
	stream := &mockSubscribeStream{
		ctx:     ctx,
		recvReq: &pb.SubscribeRequest{Vault: "default"},
	}

	err := srv.Subscribe(stream)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want Unauthenticated (err=%v)", status.Code(err), err)
	}
}

func TestSubscribe_AuthCancellationBeforeConfirmationDoesNotSend(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	authErr := status.Error(codes.Unauthenticated, "api key expired or revoked")
	unsubscribed := false
	var assignedSubID string
	eng := &mockEngine{
		subscribeWithDeliverFn: func(_ context.Context, req *pb.SubscribeRequest, _ trigger.DeliverFunc) (string, error) {
			assignedSubID = req.SubscriptionId
			cancel(authErr)
			return assignedSubID, nil
		},
		unsubscribeFn: func(ctx context.Context, subID string) error {
			if ctx.Err() != nil {
				t.Errorf("cleanup context is canceled: %v", ctx.Err())
			}
			if subID != assignedSubID {
				t.Errorf("cleanup subscription ID = %q, want owned %q", subID, assignedSubID)
			}
			unsubscribed = true
			return nil
		},
	}
	srv := newPublicTestServer(t, eng)
	stream := &mockSubscribeStream{
		ctx:     ctx,
		recvReq: &pb.SubscribeRequest{Vault: "default"},
	}

	err := srv.Subscribe(stream)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("code = %v, want Unauthenticated (err=%v)", status.Code(err), err)
	}
	if len(stream.sent) != 0 {
		t.Fatalf("sent %d messages after auth cancellation, want 0", len(stream.sent))
	}
	if !unsubscribed {
		t.Fatal("subscription was not cleaned up after auth cancellation")
	}
}

// ---------------------------------------------------------------------------
// Shutdown tests
// ---------------------------------------------------------------------------

func TestShutdown_ContextTimeout(t *testing.T) {
	addr := freePort(t)
	eng := &mockEngine{}
	srv := transportgrpc.NewServer(addr, eng, newTestAuthStore(t), nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.Serve(ctx)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Use an already-expired context so Shutdown must force-stop.
	expiredCtx, expiredCancel := context.WithTimeout(context.Background(), 0)
	defer expiredCancel()
	time.Sleep(5 * time.Millisecond) // let the context expire

	err := srv.Shutdown(expiredCtx)
	if err == nil {
		// GracefulStop may finish before the deadline in a lightly loaded test.
		// Both outcomes (nil or context.DeadlineExceeded) are acceptable.
		return
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Shutdown error = %v, want context.DeadlineExceeded", err)
	}
}

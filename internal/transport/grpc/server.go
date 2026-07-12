package grpc

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/scrypster/muninndb/internal/auth"
	"github.com/scrypster/muninndb/internal/engine/trigger"
	pb "github.com/scrypster/muninndb/proto/gen/go/muninn/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// EngineAPI is the interface the gRPC server requires from the engine.
type EngineAPI interface {
	Hello(ctx context.Context, req *pb.HelloRequest) (*pb.HelloResponse, error)
	Write(ctx context.Context, req *pb.WriteRequest) (*pb.WriteResponse, error)
	BatchWrite(ctx context.Context, req *pb.BatchWriteRequest) (*pb.BatchWriteResponse, error)
	Read(ctx context.Context, req *pb.ReadRequest) (*pb.ReadResponse, error)
	Activate(ctx context.Context, req *pb.ActivateRequest) (*pb.ActivateResponse, error)
	Link(ctx context.Context, req *pb.LinkRequest) (*pb.LinkResponse, error)
	Forget(ctx context.Context, req *pb.ForgetRequest) (*pb.ForgetResponse, error)
	Stat(ctx context.Context, req *pb.StatRequest) (*pb.StatResponse, error)
	Subscribe(ctx context.Context, req *pb.SubscribeRequest) (*pb.SubscribeResponse, error)
	SubscribeWithDeliver(ctx context.Context, req *pb.SubscribeRequest, deliver trigger.DeliverFunc) (string, error)
	Unsubscribe(ctx context.Context, subID string) error
}

// vaultAuthStore is the narrow auth surface required by gRPC. NewServer keeps
// accepting *auth.Store so the production construction boundary is unchanged;
// the interface makes stream authorization lifecycle tests deterministic.
type vaultAuthStore interface {
	ValidateAPIKey(token string) (auth.APIKey, error)
	GetVaultConfig(vault string) (auth.VaultConfig, error)
}

// Server implements the MuninnDB gRPC service.
type Server struct {
	pb.UnimplementedMuninnDBServer
	addr                      string
	engine                    EngineAPI
	authStore                 vaultAuthStore
	gs                        *grpc.Server
	tlsConfig                 *tls.Config // nil = plain TCP
	streamAuthRecheckInterval time.Duration
}

const defaultStreamAuthRecheckInterval = 30 * time.Second

const subscriptionCleanupTimeout = 5 * time.Second

// NewServer creates a new gRPC server.
// authStore is required and used to validate API keys on every inbound RPC.
// tlsConfig, if non-nil, enables TLS using gRPC transport credentials.
func NewServer(addr string, engine EngineAPI, authStore *auth.Store, tlsConfig *tls.Config) *Server {
	kasp := keepalive.ServerParameters{
		Time:                  10 * time.Second, // seconds, ping interval
		Timeout:               5 * time.Second,  // seconds, ping timeout
		MaxConnectionIdle:     5 * time.Minute,  // 5 minutes
		MaxConnectionAge:      30 * time.Minute, // 30 minutes
		MaxConnectionAgeGrace: time.Minute,      // bound active streams after GOAWAY
	}

	var store vaultAuthStore
	if authStore != nil {
		store = authStore
	}

	server := &Server{
		addr:                      addr,
		engine:                    engine,
		authStore:                 store,
		tlsConfig:                 tlsConfig,
		streamAuthRecheckInterval: defaultStreamAuthRecheckInterval,
	}

	opts := []grpc.ServerOption{
		grpc.MaxConcurrentStreams(500),
		grpc.KeepaliveParams(kasp),
		grpc.UnaryInterceptor(server.authUnaryInterceptor),
		grpc.StreamInterceptor(server.authStreamInterceptor),
	}
	if tlsConfig != nil {
		opts = append(opts, grpc.Creds(credentials.NewTLS(tlsConfig)))
		slog.Info("grpc: TLS enabled", "addr", addr)
	}

	gs := grpc.NewServer(opts...)
	server.gs = gs

	pb.RegisterMuninnDBServer(gs, server)
	return server
}

// authUnaryInterceptor is a gRPC unary server interceptor that enforces API key
// authentication and vault authorization. It mirrors the logic of
// auth.VaultAuthMiddleware:
//
//   - If an "authorization" or "x-api-key" metadata value is present, the token is
//     validated via the auth store. An invalid token always results in
//     codes.Unauthenticated regardless of vault visibility.
//   - If no token is provided, the vault config is consulted. Non-public vaults
//     (including unconfigured vaults, which default to fail-closed) require a key.
//     Public vaults run in full mode so their documented open-write behavior is
//     preserved; observe mode requires an explicit observe key.
//
// The vault name is resolved explicitly for every RPC request type. This must not
// rely on generated GetVault methods: MuninnDB's hand-written protobuf structs do
// not consistently provide them, and BatchWrite needs every item validated.
func (s *Server) authUnaryInterceptor(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	ctx, err := s.authenticateContext(ctx)
	if err != nil {
		return nil, err
	}

	vault, err := s.authorizeRequest(ctx, req)
	if err != nil {
		return nil, err
	}

	ctx = context.WithValue(ctx, auth.ContextVault, vault)
	return handler(ctx, req)
}

// wrappedStream wraps a grpc.ServerStream and overrides its context so that
// auth values injected by authStreamInterceptor are visible to handlers.
type wrappedStream struct {
	grpc.ServerStream
	server      *Server
	cancel      context.CancelCauseFunc
	monitorWG   *sync.WaitGroup
	monitorOnce sync.Once
	mu          sync.RWMutex
	ctx         context.Context
}

func (w *wrappedStream) Context() context.Context {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.ctx
}

// RecvMsg authorizes the vault only after gRPC has decoded the request. Stream
// interceptors run before that decode, so checking "default" in the interceptor
// would authorize the wrong vault for Activate and Subscribe.
func (w *wrappedStream) RecvMsg(msg any) error {
	if err := w.ServerStream.RecvMsg(msg); err != nil {
		return err
	}

	ctx := w.Context()
	vault, err := w.server.authorizeRequest(ctx, msg)
	if err != nil {
		return err
	}

	ctx = context.WithValue(ctx, auth.ContextVault, vault)
	w.mu.Lock()
	w.ctx = ctx
	w.mu.Unlock()

	if key, ok := ctx.Value(auth.ContextAPIKey).(*auth.APIKey); !ok || key == nil {
		w.monitorOnce.Do(func() {
			w.monitorWG.Add(1)
			go func() {
				defer w.monitorWG.Done()
				w.server.monitorStreamPublicVault(ctx, w.cancel, vault)
			}()
		})
	}
	return nil
}

// authStreamInterceptor is a gRPC stream server interceptor that enforces API key
// authentication for streaming RPCs (Activate, Subscribe). Vault authorization
// is deferred to wrappedStream.RecvMsg, after the target vault is decoded.
func (s *Server) authStreamInterceptor(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	ctx, err := s.authenticateContext(ss.Context())
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancelCause(ctx)
	var monitorWG sync.WaitGroup
	if key, ok := ctx.Value(auth.ContextAPIKey).(*auth.APIKey); ok && key != nil {
		token, present, parseErr := apiKeyFromMetadata(ss.Context())
		if parseErr != nil || !present {
			cancel(nil)
			return status.Error(codes.Unauthenticated, "invalid api key")
		}
		monitorWG.Add(1)
		go func() {
			defer monitorWG.Done()
			s.monitorStreamAPIKey(ctx, cancel, token, *key)
		}()
	}

	err = handler(srv, &wrappedStream{
		ServerStream: ss,
		server:       s,
		cancel:       cancel,
		monitorWG:    &monitorWG,
		ctx:          ctx,
	})
	cancel(nil)
	monitorWG.Wait()
	return err
}

// authenticateContext validates an optional API key and records its immutable
// vault/mode claims. The requested vault is authorized separately after it has
// been decoded from the RPC request.
func (s *Server) authenticateContext(ctx context.Context) (context.Context, error) {
	token, present, parseErr := apiKeyFromMetadata(ctx)
	if parseErr != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid api key")
	}
	if !present {
		// Public vaults are intentionally open for both reads and writes. Observe
		// semantics require an explicit observe-mode API key.
		return context.WithValue(ctx, auth.ContextMode, auth.ModeFull), nil
	}
	if s.authStore == nil {
		return nil, status.Error(codes.Unauthenticated, "authentication unavailable")
	}

	key, err := s.authStore.ValidateAPIKey(token)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid api key")
	}
	if strings.TrimSpace(key.Vault) == "" {
		return nil, status.Error(codes.Unauthenticated, "invalid api key scope")
	}
	switch key.Mode {
	case auth.ModeFull, auth.ModeObserve, auth.ModeWrite:
	default:
		return nil, status.Error(codes.Unauthenticated, "invalid api key mode")
	}
	ctx = context.WithValue(ctx, auth.ContextMode, key.Mode)
	ctx = context.WithValue(ctx, auth.ContextAPIKey, &key)
	ctx = context.WithValue(ctx, auth.ContextVault, key.Vault)
	return ctx, nil
}

func apiKeyFromMetadata(ctx context.Context) (token string, present bool, err error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", false, nil
	}
	if vals := md.Get("authorization"); len(vals) > 0 {
		value := strings.TrimSpace(vals[0])
		if value == "" {
			return "", true, fmt.Errorf("authorization metadata is empty")
		}
		if bearerToken, ok := strings.CutPrefix(value, "Bearer "); ok {
			bearerToken = strings.TrimSpace(bearerToken)
			if bearerToken == "" {
				return "", true, fmt.Errorf("bearer token is empty")
			}
			return bearerToken, true, nil
		}
		return value, true, nil
	}
	if vals := md.Get("x-api-key"); len(vals) > 0 {
		value := strings.TrimSpace(vals[0])
		if value == "" {
			return "", true, fmt.Errorf("x-api-key metadata is empty")
		}
		return value, true, nil
	}
	return "", false, nil
}

func (s *Server) monitorStreamAPIKey(ctx context.Context, cancel context.CancelCauseFunc, token string, expected auth.APIKey) {
	interval := s.streamAuthRecheckInterval
	if interval <= 0 {
		interval = defaultStreamAuthRecheckInterval
	}

	for {
		wait := interval
		if expected.ExpiresAt != nil {
			untilExpiry := time.Until(*expected.ExpiresAt)
			if untilExpiry <= 0 {
				cancel(status.Error(codes.Unauthenticated, "api key expired or revoked"))
				return
			}
			if untilExpiry < wait {
				wait = untilExpiry
			}
		}

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-timer.C:
		}

		current, err := s.authStore.ValidateAPIKey(token)
		if err != nil || current.ID != expected.ID || current.Vault != expected.Vault || current.Mode != expected.Mode {
			cancel(status.Error(codes.Unauthenticated, "api key expired or revoked"))
			return
		}
		expected = current
	}
}

// monitorStreamPublicVault makes a public-vault policy change effective for an
// already-authorized anonymous stream. The vault is known only after RecvMsg
// decodes the first request, so wrappedStream starts this monitor at that point.
func (s *Server) monitorStreamPublicVault(ctx context.Context, cancel context.CancelCauseFunc, vault string) {
	interval := s.streamAuthRecheckInterval
	if interval <= 0 {
		interval = defaultStreamAuthRecheckInterval
	}

	for {
		if ctx.Err() != nil {
			return
		}
		cfg, err := s.authStore.GetVaultConfig(vault)
		if err != nil || !cfg.Public {
			cancel(status.Errorf(codes.Unauthenticated, "vault %q is no longer public", vault))
			return
		}

		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return
		case <-timer.C:
		}
	}
}

// authorizeVault enforces exact vault scoping for authenticated keys and checks
// public visibility for anonymous requests. A valid key for one vault never
// grants access to another vault, even if the target vault is public.
func (s *Server) authorizeVault(ctx context.Context, vault string) error {
	if s.authStore == nil {
		return status.Error(codes.Unauthenticated, "authentication unavailable")
	}
	if key, ok := ctx.Value(auth.ContextAPIKey).(*auth.APIKey); ok && key != nil {
		if key.Vault != vault {
			return status.Errorf(codes.PermissionDenied, "api key is not authorized for vault %q", vault)
		}
		return nil
	}

	cfg, err := s.authStore.GetVaultConfig(vault)
	if err != nil || !cfg.Public {
		return status.Errorf(codes.Unauthenticated, "vault %q requires an API key", vault)
	}
	return nil
}

func (s *Server) authorizeRequest(ctx context.Context, req any) (string, error) {
	if err := requestContextError(ctx); err != nil {
		return "", err
	}

	defaultVault := "default"
	if key, ok := ctx.Value(auth.ContextAPIKey).(*auth.APIKey); ok && key != nil {
		defaultVault = key.Vault
	}
	vault, err := resolveRequestVault(req, defaultVault)
	if err != nil {
		return "", status.Error(codes.InvalidArgument, err.Error())
	}
	if err := s.authorizeVault(ctx, vault); err != nil {
		return "", err
	}
	if isMutationRequest(req) && auth.ObserveFromContext(ctx) {
		return "", status.Error(codes.PermissionDenied, "read-only api key cannot write")
	}
	if isReadRequest(req) && auth.WriteOnlyFromContext(ctx) {
		return "", status.Error(codes.PermissionDenied, "write-only api key cannot read")
	}
	if err := requestContextError(ctx); err != nil {
		return "", err
	}
	return vault, nil
}

func requestContextError(ctx context.Context) error {
	if ctx.Err() == nil {
		return nil
	}
	if cause := streamTerminationError(ctx); cause != nil {
		return cause
	}
	return status.FromContextError(ctx.Err()).Err()
}

// resolveRequestVault returns one canonical target vault and writes that value
// back to known request structs so the engine cannot resolve a different vault.
// Batch writes must be single-vault, matching the REST API contract.
func resolveRequestVault(req any, defaultVault string) (string, error) {
	canonical := func(vault string) string {
		vault = strings.TrimSpace(vault)
		if vault == "" {
			return defaultVault
		}
		return vault
	}

	switch r := req.(type) {
	case *pb.BatchWriteRequest:
		if r == nil {
			return "", fmt.Errorf("batch write request is required")
		}
		vault := defaultVault
		for i, item := range r.Requests {
			if item == nil {
				return "", fmt.Errorf("batch write item %d is required", i)
			}
			itemVault := canonical(item.Vault)
			if i == 0 {
				vault = itemVault
			} else if itemVault != vault {
				return "", fmt.Errorf("batch write requests must target one vault")
			}
			item.Vault = itemVault
		}
		return vault, nil
	case *pb.HelloRequest:
		if r == nil {
			return "", fmt.Errorf("hello request is required")
		}
		r.Vault = canonical(r.Vault)
		return r.Vault, nil
	case *pb.WriteRequest:
		if r == nil {
			return "", fmt.Errorf("write request is required")
		}
		r.Vault = canonical(r.Vault)
		return r.Vault, nil
	case *pb.ReadRequest:
		if r == nil {
			return "", fmt.Errorf("read request is required")
		}
		r.Vault = canonical(r.Vault)
		return r.Vault, nil
	case *pb.ForgetRequest:
		if r == nil {
			return "", fmt.Errorf("forget request is required")
		}
		r.Vault = canonical(r.Vault)
		return r.Vault, nil
	case *pb.StatRequest:
		if r == nil {
			return "", fmt.Errorf("stat request is required")
		}
		r.Vault = canonical(r.Vault)
		return r.Vault, nil
	case *pb.LinkRequest:
		if r == nil {
			return "", fmt.Errorf("link request is required")
		}
		r.Vault = canonical(r.Vault)
		return r.Vault, nil
	case *pb.ActivateRequest:
		if r == nil {
			return "", fmt.Errorf("activate request is required")
		}
		r.Vault = canonical(r.Vault)
		return r.Vault, nil
	case *pb.SubscribeRequest:
		if r == nil {
			return "", fmt.Errorf("subscribe request is required")
		}
		r.Vault = canonical(r.Vault)
		return r.Vault, nil
	default:
		return "", fmt.Errorf("unsupported grpc request type %T", req)
	}
}

func isReadRequest(req any) bool {
	switch req.(type) {
	case *pb.ReadRequest, *pb.StatRequest, *pb.ActivateRequest, *pb.SubscribeRequest:
		return true
	default:
		return false
	}
}

func isMutationRequest(req any) bool {
	switch req.(type) {
	case *pb.WriteRequest, *pb.BatchWriteRequest, *pb.ForgetRequest, *pb.LinkRequest:
		return true
	default:
		return false
	}
}

func streamTerminationError(ctx context.Context) error {
	cause := context.Cause(ctx)
	if cause != nil && !errors.Is(cause, context.Canceled) && !errors.Is(cause, context.DeadlineExceeded) {
		return cause
	}
	return nil
}

// Serve starts listening and blocks until context is cancelled or Shutdown is called.
func (s *Server) Serve(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.addr, err)
	}
	slog.Info("grpc: listening", "addr", listener.Addr().String())
	defer listener.Close()

	go s.gs.Serve(listener)

	<-ctx.Done()
	s.gs.GracefulStop()
	return nil
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		s.gs.GracefulStop()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		s.gs.Stop()
		return ctx.Err()
	}
}

// RPC Handlers

// Hello implements the Hello RPC.
func (s *Server) Hello(ctx context.Context, req *pb.HelloRequest) (*pb.HelloResponse, error) {
	if _, err := s.authorizeRequest(ctx, req); err != nil {
		return nil, err
	}
	resp, err := s.engine.Hello(ctx, req)
	if err != nil {
		slog.Error("hello failed", "error", err)
		return nil, err
	}
	return resp, nil
}

// Write implements the Write RPC.
func (s *Server) Write(ctx context.Context, req *pb.WriteRequest) (*pb.WriteResponse, error) {
	if _, err := s.authorizeRequest(ctx, req); err != nil {
		return nil, err
	}
	resp, err := s.engine.Write(ctx, req)
	if err != nil {
		slog.Error("write failed", "error", err)
		return nil, err
	}
	return resp, nil
}

// BatchWrite implements the BatchWrite RPC.
func (s *Server) BatchWrite(ctx context.Context, req *pb.BatchWriteRequest) (*pb.BatchWriteResponse, error) {
	if _, err := s.authorizeRequest(ctx, req); err != nil {
		return nil, err
	}
	resp, err := s.engine.BatchWrite(ctx, req)
	if err != nil {
		slog.Error("batch write failed", "error", err)
		return nil, err
	}
	return resp, nil
}

// Read implements the Read RPC.
func (s *Server) Read(ctx context.Context, req *pb.ReadRequest) (*pb.ReadResponse, error) {
	if _, err := s.authorizeRequest(ctx, req); err != nil {
		return nil, err
	}
	resp, err := s.engine.Read(ctx, req)
	if err != nil {
		slog.Error("read failed", "error", err)
		return nil, err
	}
	return resp, nil
}

// Forget implements the Forget RPC.
func (s *Server) Forget(ctx context.Context, req *pb.ForgetRequest) (*pb.ForgetResponse, error) {
	if _, err := s.authorizeRequest(ctx, req); err != nil {
		return nil, err
	}
	resp, err := s.engine.Forget(ctx, req)
	if err != nil {
		slog.Error("forget failed", "error", err)
		return nil, err
	}
	return resp, nil
}

// Stat implements the Stat RPC.
func (s *Server) Stat(ctx context.Context, req *pb.StatRequest) (*pb.StatResponse, error) {
	if _, err := s.authorizeRequest(ctx, req); err != nil {
		return nil, err
	}
	resp, err := s.engine.Stat(ctx, req)
	if err != nil {
		slog.Error("stat failed", "error", err)
		return nil, err
	}
	return resp, nil
}

// Link implements the Link RPC.
func (s *Server) Link(ctx context.Context, req *pb.LinkRequest) (*pb.LinkResponse, error) {
	if _, err := s.authorizeRequest(ctx, req); err != nil {
		return nil, err
	}
	resp, err := s.engine.Link(ctx, req)
	if err != nil {
		slog.Error("link failed", "error", err)
		return nil, err
	}
	return resp, nil
}

// Activate implements the Activate RPC (server-streaming).
func (s *Server) Activate(req *pb.ActivateRequest, stream pb.MuninnDB_ActivateServer) error {
	ctx := stream.Context()
	vault, err := s.authorizeRequest(ctx, req)
	if err != nil {
		return err
	}
	ctx = context.WithValue(ctx, auth.ContextVault, vault)
	resp, err := s.engine.Activate(ctx, req)
	if err != nil {
		slog.Error("activate failed", "error", err)
		return err
	}
	if ctx.Err() != nil {
		return streamTerminationError(ctx)
	}

	// Send response to client
	if err := stream.Send(resp); err != nil {
		slog.Error("send activate response failed", "error", err)
		return err
	}

	return nil
}

// Subscribe implements the Subscribe RPC (bidirectional streaming).
// The client sends one SubscribeRequest; the server streams ActivationPush
// messages until the client disconnects or the subscription TTL expires.
func (s *Server) Subscribe(stream pb.MuninnDB_SubscribeServer) error {
	ctx := stream.Context()

	req, err := stream.Recv()
	if err != nil {
		return err
	}
	vault, err := s.authorizeRequest(ctx, req)
	if err != nil {
		return err
	}
	// Subscription identifiers are server-assigned. Accepting a caller-selected
	// global ID would let one stream replace and later remove another stream's
	// subscription in the engine registry.
	if req.SubscriptionID != "" {
		return status.Error(codes.InvalidArgument, "subscription_id must be empty; the server assigns it")
	}
	ctx = context.WithValue(ctx, auth.ContextVault, vault)
	assignedSubID := uuid.NewString()
	req.SubscriptionID = assignedSubID

	// Buffered push channel. The deliver func is non-blocking: it drops the push
	// if the channel is full so the trigger worker goroutine is never blocked.
	// When the stream context is cancelled the deliver func returns an error,
	// which causes DeliveryRouter to remove the subscription automatically.
	pushCh := make(chan *trigger.ActivationPush, 32)

	deliver := func(ctx context.Context, push *trigger.ActivationPush) error {
		select {
		case pushCh <- push:
			return nil
		case <-ctx.Done():
			// Stream closed — signal DeliveryRouter to remove this subscription.
			return ctx.Err()
		default:
			// Client too slow — drop this push, keep subscription alive.
			return nil
		}
	}

	subID, err := s.engine.SubscribeWithDeliver(ctx, req, deliver)
	if err != nil {
		slog.Error("subscribe failed", "error", err)
		return err
	}
	if subID != assignedSubID {
		s.cleanupSubscription(assignedSubID)
		return status.Error(codes.Internal, "subscription returned an invalid id")
	}
	defer s.cleanupSubscription(assignedSubID)
	if ctx.Err() != nil {
		return streamTerminationError(ctx)
	}

	// Confirm subscription to the client.
	if err := stream.Send(&pb.ActivationPush{
		SubscriptionID: assignedSubID,
		Trigger:        "subscription_created",
		At:             time.Now().UnixNano(),
	}); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return streamTerminationError(ctx)
		case push, ok := <-pushCh:
			if !ok {
				return nil
			}
			if ctx.Err() != nil {
				return streamTerminationError(ctx)
			}
			pbPush := &pb.ActivationPush{
				SubscriptionID: assignedSubID,
				Trigger:        string(push.Trigger),
				PushNumber:     int32(push.PushNumber),
				At:             push.At.UnixNano(),
			}
			if push.Engram != nil {
				pbPush.Activation = &pb.ActivationItem{
					ID:      push.Engram.ID.String(),
					Concept: push.Engram.Concept,
					Content: push.Engram.Content,
					Score:   float32(push.Score),
					Why:     push.Why,
				}
			}
			if err := stream.Send(pbPush); err != nil {
				slog.Error("grpc send push failed", "error", err)
				return err
			}
		}
	}
}

// cleanupSubscription removes only the identifier assigned to this gRPC
// stream. A fresh bounded context keeps auth expiry or client disconnect from
// suppressing teardown while preventing cleanup from running indefinitely.
func (s *Server) cleanupSubscription(subID string) {
	ctx, cancel := context.WithTimeout(context.Background(), subscriptionCleanupTimeout)
	defer cancel()
	if err := s.engine.Unsubscribe(ctx, subID); err != nil {
		slog.Warn("grpc subscription cleanup failed", "subscription_id", subID, "error", err)
	}
}

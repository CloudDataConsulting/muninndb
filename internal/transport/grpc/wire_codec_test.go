//go:build grpcwire

package grpc_test

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/scrypster/muninndb/internal/auth"
	"github.com/scrypster/muninndb/internal/engine/trigger"
	transportgrpc "github.com/scrypster/muninndb/internal/transport/grpc"
	pb "github.com/scrypster/muninndb/proto/gen/go/muninn/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

func TestCanonicalMessages_DefaultProtoCodecRoundTrip(t *testing.T) {
	messages := pb.File_muninn_v1_service_proto.Messages()
	if got, want := messages.Len(), 26; got != want {
		t.Fatalf("generated message count = %d, want %d", got, want)
	}

	seen := make(map[protoreflect.FullName]struct{}, messages.Len())
	for i := 0; i < messages.Len(); i++ {
		descriptor := messages.Get(i)
		t.Run(string(descriptor.Name()), func(t *testing.T) {
			messageType, err := protoregistry.GlobalTypes.FindMessageByName(descriptor.FullName())
			if err != nil {
				t.Fatalf("resolve generated type %s: %v", descriptor.FullName(), err)
			}
			input := messageType.New().Interface()
			populateWireMessage(t, input.ProtoReflect(), 0)
			assertWireMessagePopulated(t, input.ProtoReflect(), 0)

			encoded, err := proto.Marshal(input)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			output := input.ProtoReflect().Type().New().Interface()
			if err := proto.Unmarshal(encoded, output); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if !proto.Equal(input, output) {
				t.Fatalf("round trip mismatch:\n in: %s\nout: %s", input, output)
			}
		})
		seen[descriptor.FullName()] = struct{}{}
	}
	if got, want := len(seen), messages.Len(); got != want {
		t.Fatalf("unique generated message types exercised = %d, want %d", got, want)
	}
}

func populateWireMessage(t *testing.T, message protoreflect.Message, depth int) {
	t.Helper()
	if depth > 8 {
		t.Fatalf("message graph exceeded bounded depth at %s", message.Descriptor().FullName())
	}

	fields := message.Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		field := fields.Get(i)
		if field.IsMap() {
			t.Fatalf("map field %s needs an explicit test fixture", field.FullName())
		}
		if field.IsList() {
			list := message.Mutable(field).List()
			if field.Kind() == protoreflect.MessageKind || field.Kind() == protoreflect.GroupKind {
				value := list.NewElement()
				populateWireMessage(t, value.Message(), depth+1)
				list.Append(value)
			} else {
				list.Append(nonzeroWireScalar(t, field))
			}
			continue
		}
		if field.Kind() == protoreflect.MessageKind || field.Kind() == protoreflect.GroupKind {
			populateWireMessage(t, message.Mutable(field).Message(), depth+1)
			continue
		}
		message.Set(field, nonzeroWireScalar(t, field))
	}
}

func nonzeroWireScalar(t *testing.T, field protoreflect.FieldDescriptor) protoreflect.Value {
	t.Helper()
	switch field.Kind() {
	case protoreflect.BoolKind:
		return protoreflect.ValueOfBool(true)
	case protoreflect.EnumKind:
		values := field.Enum().Values()
		if values.Len() < 2 {
			t.Fatalf("enum field %s has no nonzero value", field.FullName())
		}
		return protoreflect.ValueOfEnum(values.Get(1).Number())
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		return protoreflect.ValueOfInt32(17)
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		return protoreflect.ValueOfInt64(1701)
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return protoreflect.ValueOfUint32(23)
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return protoreflect.ValueOfUint64(2301)
	case protoreflect.FloatKind:
		return protoreflect.ValueOfFloat32(0.75)
	case protoreflect.DoubleKind:
		return protoreflect.ValueOfFloat64(0.875)
	case protoreflect.StringKind:
		return protoreflect.ValueOfString("wire-" + string(field.Name()))
	case protoreflect.BytesKind:
		return protoreflect.ValueOfBytes([]byte{0x01, byte(field.Number()), 0x7f})
	default:
		t.Fatalf("unsupported scalar kind %s for %s", field.Kind(), field.FullName())
		return protoreflect.Value{}
	}
}

func assertWireMessagePopulated(t *testing.T, message protoreflect.Message, depth int) {
	t.Helper()
	if depth > 8 {
		t.Fatalf("message graph exceeded bounded depth at %s", message.Descriptor().FullName())
	}
	fields := message.Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		field := fields.Get(i)
		if field.IsList() {
			list := message.Get(field).List()
			if list.Len() == 0 {
				t.Fatalf("repeated field %s is empty", field.FullName())
			}
			if field.Kind() == protoreflect.MessageKind || field.Kind() == protoreflect.GroupKind {
				assertWireMessagePopulated(t, list.Get(0).Message(), depth+1)
			}
			continue
		}
		if !message.Has(field) {
			t.Fatalf("field %s was not populated", field.FullName())
		}
		if field.Kind() == protoreflect.MessageKind || field.Kind() == protoreflect.GroupKind {
			assertWireMessagePopulated(t, message.Get(field).Message(), depth+1)
		}
	}
}

func TestDefaultProtoCodec_RPCShapesOverTCP(t *testing.T) {
	addr := freePort(t)
	store := newTestAuthStore(t)
	if err := store.SetVaultConfig(auth.VaultConfig{Name: "default", Public: true}); err != nil {
		t.Fatalf("SetVaultConfig: %v", err)
	}

	unsubscribed := make(chan string, 1)
	eng := &mockEngine{
		helloFn: func(_ context.Context, req *pb.HelloRequest) (*pb.HelloResponse, error) {
			return &pb.HelloResponse{
				ServerVersion: "wire-test", SessionId: req.Client,
				Limits: &pb.Limits{MaxResults: 50},
			}, nil
		},
		activateFn: func(_ context.Context, req *pb.ActivateRequest) (*pb.ActivateResponse, error) {
			return &pb.ActivateResponse{
				QueryId: "wire-query", TotalFound: 1,
				Activations: []*pb.ActivationItem{{
					Id: "01JTESTRESULT", Concept: req.Context[0], Score: 0.9,
				}},
			}, nil
		},
		subscribeWithDeliverFn: func(ctx context.Context, req *pb.SubscribeRequest, deliver trigger.DeliverFunc) (string, error) {
			if err := deliver(ctx, &trigger.ActivationPush{
				SubscriptionID: req.SubscriptionId,
				Trigger:        trigger.TriggerNewWrite, PushNumber: 1, At: time.Unix(123, 0),
			}); err != nil {
				return "", err
			}
			return req.SubscriptionId, nil
		},
		unsubscribeFn: func(_ context.Context, subID string) error {
			unsubscribed <- subID
			return nil
		},
	}
	srv := transportgrpc.NewServer(addr, eng, store, nil)
	serveCtx, stop := context.WithCancel(context.Background())
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(serveCtx) }()
	t.Cleanup(func() {
		stop()
		select {
		case err := <-serveErr:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("server did not stop")
		}
	})

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	waitForWireConnection(t, conn)
	client := pb.NewMuninnDBClient(conn)

	unaryCtx, cancelUnary := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelUnary()
	resp, err := client.Hello(unaryCtx, &pb.HelloRequest{
		Version: "1", Vault: "default", Client: "wire-client",
	})
	if err != nil {
		t.Fatalf("Hello over default protobuf codec: %v", err)
	}
	want := &pb.HelloResponse{
		ServerVersion: "wire-test", SessionId: "wire-client",
		Limits: &pb.Limits{MaxResults: 50},
	}
	if !proto.Equal(resp, want) {
		t.Fatalf("response = %v, want %v", resp, want)
	}

	activateCtx, cancelActivate := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelActivate()
	activateStream, err := client.Activate(activateCtx, &pb.ActivateRequest{
		Context: []string{"wire-stream"}, Vault: "default",
	})
	if err != nil {
		t.Fatalf("Activate over default protobuf codec: %v", err)
	}
	activateResp, err := activateStream.Recv()
	if err != nil {
		t.Fatalf("Activate Recv: %v", err)
	}
	if len(activateResp.Activations) != 1 || activateResp.Activations[0].Concept != "wire-stream" {
		t.Fatalf("Activate response = %v", activateResp)
	}
	if _, err := activateStream.Recv(); err != io.EOF {
		t.Fatalf("Activate second Recv = %v, want EOF", err)
	}

	subscribeCtx, cancelSubscribe := context.WithCancel(context.Background())
	subscribeStream, err := client.Subscribe(subscribeCtx)
	if err != nil {
		cancelSubscribe()
		t.Fatalf("Subscribe over default protobuf codec: %v", err)
	}
	if err := subscribeStream.Send(&pb.SubscribeRequest{Vault: "default"}); err != nil {
		cancelSubscribe()
		t.Fatalf("Subscribe Send: %v", err)
	}
	created, err := subscribeStream.Recv()
	if err != nil {
		cancelSubscribe()
		t.Fatalf("Subscribe creation Recv: %v", err)
	}
	if created.SubscriptionId == "" || created.Trigger != "subscription_created" {
		cancelSubscribe()
		t.Fatalf("Subscribe creation = %v", created)
	}
	push, err := subscribeStream.Recv()
	if err != nil {
		cancelSubscribe()
		t.Fatalf("Subscribe push Recv: %v", err)
	}
	if push.SubscriptionId != created.SubscriptionId || push.Trigger != string(trigger.TriggerNewWrite) {
		cancelSubscribe()
		t.Fatalf("Subscribe push = %v, creation = %v", push, created)
	}
	cancelSubscribe()
	select {
	case cleanedID := <-unsubscribed:
		if cleanedID != created.SubscriptionId {
			t.Fatalf("cleaned subscription = %q, want %q", cleanedID, created.SubscriptionId)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("subscription was not cleaned up after client cancellation")
	}
}

func TestDefaultProtoCodec_WireAuthorization(t *testing.T) {
	addr := freePort(t)
	store := newTestAuthStore(t)
	if err := store.SetVaultConfig(auth.VaultConfig{Name: "private", Public: false}); err != nil {
		t.Fatalf("SetVaultConfig: %v", err)
	}
	if err := store.SetVaultConfig(auth.VaultConfig{Name: "public-transition", Public: true}); err != nil {
		t.Fatalf("SetVaultConfig(public-transition): %v", err)
	}
	fullToken, fullKey, err := store.GenerateAPIKey("private", "wire-full", auth.ModeFull, nil)
	if err != nil {
		t.Fatalf("GenerateAPIKey(full): %v", err)
	}
	observeToken, _, err := store.GenerateAPIKey("private", "wire-observe", auth.ModeObserve, nil)
	if err != nil {
		t.Fatalf("GenerateAPIKey(observe): %v", err)
	}
	writeToken, _, err := store.GenerateAPIKey("private", "wire-write", auth.ModeWrite, nil)
	if err != nil {
		t.Fatalf("GenerateAPIKey(write): %v", err)
	}
	expiredAt := time.Now().Add(-time.Minute)
	expiredToken, _, err := store.GenerateAPIKey("private", "wire-expired", auth.ModeFull, &expiredAt)
	if err != nil {
		t.Fatalf("GenerateAPIKey(expired): %v", err)
	}

	eng := &mockEngine{
		helloFn: func(ctx context.Context, _ *pb.HelloRequest) (*pb.HelloResponse, error) {
			vault, _ := ctx.Value(auth.ContextVault).(string)
			mode, _ := ctx.Value(auth.ContextMode).(string)
			return &pb.HelloResponse{VaultId: vault, SessionId: mode}, nil
		},
		readFn: func(ctx context.Context, req *pb.ReadRequest) (*pb.ReadResponse, error) {
			vault, _ := ctx.Value(auth.ContextVault).(string)
			mode, _ := ctx.Value(auth.ContextMode).(string)
			return &pb.ReadResponse{Id: req.Id, Content: vault, Concept: mode}, nil
		},
	}
	srv := transportgrpc.NewServer(addr, eng, store, nil)
	serveCtx, stop := context.WithCancel(context.Background())
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(serveCtx) }()
	t.Cleanup(func() {
		stop()
		select {
		case err := <-serveErr:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("server did not stop")
		}
	})

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	waitForWireConnection(t, conn)
	client := pb.NewMuninnDBClient(conn)

	callCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := client.Hello(callCtx, &pb.HelloRequest{Vault: "private"}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("anonymous private-vault code = %v, want Unauthenticated (err=%v)", status.Code(err), err)
	}

	fullCtx := metadata.NewOutgoingContext(callCtx, metadata.Pairs("authorization", "Bearer "+fullToken))
	resp, err := client.Hello(fullCtx, &pb.HelloRequest{Vault: "private"})
	if err != nil {
		t.Fatalf("full-key Hello: %v", err)
	}
	if resp.VaultId != "private" || resp.SessionId != auth.ModeFull {
		t.Fatalf("full-key principal response = %v", resp)
	}
	if _, err := client.Hello(fullCtx, &pb.HelloRequest{Vault: "other"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("cross-vault code = %v, want PermissionDenied (err=%v)", status.Code(err), err)
	}

	observeCtx := metadata.NewOutgoingContext(callCtx, metadata.Pairs("x-api-key", observeToken))
	observeResp, err := client.Read(observeCtx, &pb.ReadRequest{Vault: "private", Id: "01JOBSERVE"})
	if err != nil {
		t.Fatalf("observe Read: %v", err)
	}
	if observeResp.Id != "01JOBSERVE" || observeResp.Content != "private" || observeResp.Concept != auth.ModeObserve {
		t.Fatalf("observe Read principal response = %v", observeResp)
	}
	if _, err := client.Write(observeCtx, &pb.WriteRequest{Vault: "private", Concept: "denied"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("observe-write code = %v, want PermissionDenied (err=%v)", status.Code(err), err)
	}

	writeCtx := metadata.NewOutgoingContext(callCtx, metadata.Pairs("authorization", "Bearer "+writeToken))
	if _, err := client.Write(writeCtx, &pb.WriteRequest{Vault: "private", Concept: "allowed"}); err != nil {
		t.Fatalf("write-only Write: %v", err)
	}
	if _, err := client.Read(writeCtx, &pb.ReadRequest{Vault: "private", Id: "01JTEST"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("write-only Read code = %v, want PermissionDenied (err=%v)", status.Code(err), err)
	}

	expiredCtx := metadata.NewOutgoingContext(callCtx, metadata.Pairs("authorization", "Bearer "+expiredToken))
	if _, err := client.Hello(expiredCtx, &pb.HelloRequest{Vault: "private"}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expired-key code = %v, want Unauthenticated (err=%v)", status.Code(err), err)
	}

	if _, err := client.Hello(callCtx, &pb.HelloRequest{Vault: "public-transition"}); err != nil {
		t.Fatalf("anonymous public-vault Hello: %v", err)
	}
	if err := store.SetVaultConfig(auth.VaultConfig{Name: "public-transition", Public: false}); err != nil {
		t.Fatalf("lock public-transition: %v", err)
	}
	if _, err := client.Hello(callCtx, &pb.HelloRequest{Vault: "public-transition"}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("public-to-locked code = %v, want Unauthenticated (err=%v)", status.Code(err), err)
	}

	if err := store.RevokeAPIKey("private", fullKey.ID); err != nil {
		t.Fatalf("RevokeAPIKey: %v", err)
	}
	if _, err := client.Hello(fullCtx, &pb.HelloRequest{Vault: "private"}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("revoked-key code = %v, want Unauthenticated (err=%v)", status.Code(err), err)
	}
}

func TestDefaultProtoCodec_PrivateSubscribeRevocationOverTCP(t *testing.T) {
	store := newTestAuthStore(t)
	if err := store.SetVaultConfig(auth.VaultConfig{Name: "private", Public: false}); err != nil {
		t.Fatalf("SetVaultConfig: %v", err)
	}
	token, key, err := store.GenerateAPIKey("private", "wire-private-subscribe", auth.ModeFull, nil)
	if err != nil {
		t.Fatalf("GenerateAPIKey: %v", err)
	}

	unsubscribed := make(chan string, 1)
	eng := &mockEngine{
		subscribeWithDeliverFn: func(ctx context.Context, req *pb.SubscribeRequest, deliver trigger.DeliverFunc) (string, error) {
			if err := deliver(ctx, &trigger.ActivationPush{
				SubscriptionID: req.SubscriptionId,
				Trigger:        trigger.TriggerNewWrite,
				PushNumber:     1,
				At:             time.Unix(456, 0),
			}); err != nil {
				return "", err
			}
			return req.SubscriptionId, nil
		},
		unsubscribeFn: func(_ context.Context, subID string) error {
			unsubscribed <- subID
			return nil
		},
	}
	client := startConfiguredWireClient(t, store, eng, func(server *transportgrpc.Server) {
		server.SetTestStreamAuthRecheckInterval(5 * time.Millisecond)
	})

	streamCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	streamCtx = metadata.NewOutgoingContext(streamCtx, metadata.Pairs("authorization", "Bearer "+token))
	stream, err := client.Subscribe(streamCtx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	if err := stream.Send(&pb.SubscribeRequest{Vault: "private"}); err != nil {
		t.Fatalf("Subscribe Send: %v", err)
	}
	created, err := stream.Recv()
	if err != nil {
		t.Fatalf("subscription creation Recv: %v", err)
	}
	if created.SubscriptionId == "" || created.Trigger != "subscription_created" {
		t.Fatalf("subscription creation = %v", created)
	}
	push, err := stream.Recv()
	if err != nil {
		t.Fatalf("subscription push Recv: %v", err)
	}
	if push.SubscriptionId != created.SubscriptionId || push.Trigger != string(trigger.TriggerNewWrite) {
		t.Fatalf("subscription push = %v, creation = %v", push, created)
	}

	if err := store.RevokeAPIKey("private", key.ID); err != nil {
		t.Fatalf("RevokeAPIKey: %v", err)
	}
	if _, err := stream.Recv(); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("revoked private Subscribe code = %v, want Unauthenticated (err=%v)", status.Code(err), err)
	}
	select {
	case cleanedID := <-unsubscribed:
		if cleanedID != created.SubscriptionId {
			t.Fatalf("cleaned subscription = %q, want %q", cleanedID, created.SubscriptionId)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("revoked private subscription was not cleaned up")
	}
}

func startConfiguredWireClient(
	t *testing.T,
	store *auth.Store,
	eng *mockEngine,
	configure func(*transportgrpc.Server),
) pb.MuninnDBClient {
	t.Helper()
	addr := freePort(t)
	server := transportgrpc.NewServer(addr, eng, store, nil)
	if configure != nil {
		configure(server)
	}
	serveCtx, stop := context.WithCancel(context.Background())
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(serveCtx) }()
	t.Cleanup(func() {
		stop()
		select {
		case err := <-serveErr:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("server did not stop")
		}
	})

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	waitForWireConnection(t, conn)
	return pb.NewMuninnDBClient(conn)
}

func waitForWireConnection(t *testing.T, conn *grpc.ClientConn) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn.Connect()
	for {
		state := conn.GetState()
		switch state {
		case connectivity.Ready:
			return
		case connectivity.Shutdown:
			t.Fatal("gRPC connection shut down before becoming ready")
		}
		if !conn.WaitForStateChange(ctx, state) {
			t.Fatalf("gRPC connection did not become ready: state=%s err=%v", conn.GetState(), ctx.Err())
		}
	}
}

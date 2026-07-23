package grpc_test

import (
	"context"
	"io"
	"reflect"
	"testing"
	"time"

	"github.com/scrypster/muninndb/internal/auth"
	"github.com/scrypster/muninndb/internal/engine/trigger"
	transportgrpc "github.com/scrypster/muninndb/internal/transport/grpc"
	pb "github.com/scrypster/muninndb/proto/gen/go/muninn/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/protoadapt"
)

func TestHandwrittenMessages_DefaultProtoCodecRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		in   protoadapt.MessageV1
		out  protoadapt.MessageV1
	}{
		{
			name: "write with associations",
			in: &pb.WriteRequest{
				Concept: "codec",
				Content: "round trip",
				Vault:   "default",
				Associations: []*pb.Association{{
					TargetID: "01JTESTTARGET",
					RelType:  3,
					Weight:   0.75,
				}},
			},
			out: &pb.WriteRequest{},
		},
		{
			name: "activate with nested filters and weights",
			in: &pb.ActivateRequest{
				Context: []string{"codec", "wire"},
				Vault:   "default",
				Weights: &pb.Weights{SemanticSimilarity: 0.8},
				Filters: []*pb.Filter{{Field: "source", Op: "eq", Value: []byte("gmail")}},
			},
			out: &pb.ActivateRequest{},
		},
		{
			name: "activation response with nested items",
			in: &pb.ActivateResponse{
				QueryID: "query-1",
				Activations: []*pb.ActivationItem{{
					ID:      "01JTESTRESULT",
					Concept: "result",
					Score:   0.9,
					ScoreComponents: &pb.ScoreComponents{
						Raw:   0.8,
						Final: 0.9,
					},
				}},
			},
			out: &pb.ActivateResponse{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := proto.Marshal(protoadapt.MessageV2Of(tt.in))
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if err := proto.Unmarshal(encoded, protoadapt.MessageV2Of(tt.out)); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if !proto.Equal(protoadapt.MessageV2Of(tt.in), protoadapt.MessageV2Of(tt.out)) {
				t.Fatalf("round trip mismatch:\n in: %s\nout: %s", tt.in, tt.out)
			}
		})
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
				ServerVersion: "wire-test",
				SessionID:     req.Client,
				Limits:        &pb.Limits{MaxResults: 50},
			}, nil
		},
		activateFn: func(_ context.Context, req *pb.ActivateRequest) (*pb.ActivateResponse, error) {
			return &pb.ActivateResponse{
				QueryID:    "wire-query",
				TotalFound: 1,
				Activations: []*pb.ActivationItem{{
					ID:      "01JTESTRESULT",
					Concept: req.Context[0],
					Score:   0.9,
				}},
			}, nil
		},
		subscribeWithDeliverFn: func(ctx context.Context, req *pb.SubscribeRequest, deliver trigger.DeliverFunc) (string, error) {
			if err := deliver(ctx, &trigger.ActivationPush{
				SubscriptionID: req.SubscriptionID,
				Trigger:        trigger.TriggerNewWrite,
				PushNumber:     1,
				At:             time.Unix(123, 0),
			}); err != nil {
				return "", err
			}
			return req.SubscriptionID, nil
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
	t.Cleanup(func() { conn.Close() })

	client := pb.NewMuninnDBClient(conn)

	unaryCtx, cancelUnary := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelUnary()
	resp, err := client.Hello(unaryCtx, &pb.HelloRequest{
		Version: "1",
		Vault:   "default",
		Client:  "wire-client",
	})
	if err != nil {
		t.Fatalf("Hello over default protobuf codec: %v", err)
	}
	want := &pb.HelloResponse{
		ServerVersion: "wire-test",
		SessionID:     "wire-client",
		Limits:        &pb.Limits{MaxResults: 50},
	}
	if !reflect.DeepEqual(resp, want) {
		t.Fatalf("response = %#v, want %#v", resp, want)
	}

	activateCtx, cancelActivate := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelActivate()
	activateStream, err := client.Activate(activateCtx, &pb.ActivateRequest{
		Context: []string{"wire-stream"},
		Vault:   "default",
	})
	if err != nil {
		t.Fatalf("Activate over default protobuf codec: %v", err)
	}
	activateResp, err := activateStream.Recv()
	if err != nil {
		t.Fatalf("Activate Recv: %v", err)
	}
	if len(activateResp.Activations) != 1 || activateResp.Activations[0].Concept != "wire-stream" {
		t.Fatalf("Activate response = %#v", activateResp)
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
	if created.SubscriptionID == "" || created.Trigger != "subscription_created" {
		cancelSubscribe()
		t.Fatalf("Subscribe creation = %#v", created)
	}
	push, err := subscribeStream.Recv()
	if err != nil {
		cancelSubscribe()
		t.Fatalf("Subscribe push Recv: %v", err)
	}
	if push.SubscriptionID != created.SubscriptionID || push.Trigger != string(trigger.TriggerNewWrite) {
		cancelSubscribe()
		t.Fatalf("Subscribe push = %#v, creation = %#v", push, created)
	}
	cancelSubscribe()
	select {
	case cleanedID := <-unsubscribed:
		if cleanedID != created.SubscriptionID {
			t.Fatalf("cleaned subscription = %q, want %q", cleanedID, created.SubscriptionID)
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
	fullToken, fullKey, err := store.GenerateAPIKey("private", "wire-full", auth.ModeFull, nil)
	if err != nil {
		t.Fatalf("GenerateAPIKey(full): %v", err)
	}
	observeToken, _, err := store.GenerateAPIKey("private", "wire-observe", auth.ModeObserve, nil)
	if err != nil {
		t.Fatalf("GenerateAPIKey(observe): %v", err)
	}

	eng := &mockEngine{
		helloFn: func(ctx context.Context, _ *pb.HelloRequest) (*pb.HelloResponse, error) {
			vault, _ := ctx.Value(auth.ContextVault).(string)
			mode, _ := ctx.Value(auth.ContextMode).(string)
			return &pb.HelloResponse{VaultID: vault, SessionID: mode}, nil
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
	t.Cleanup(func() { conn.Close() })
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
	if resp.VaultID != "private" || resp.SessionID != auth.ModeFull {
		t.Fatalf("full-key principal response = %#v", resp)
	}
	if _, err := client.Hello(fullCtx, &pb.HelloRequest{Vault: "other"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("cross-vault code = %v, want PermissionDenied (err=%v)", status.Code(err), err)
	}

	observeCtx := metadata.NewOutgoingContext(callCtx, metadata.Pairs("x-api-key", observeToken))
	if _, err := client.Write(observeCtx, &pb.WriteRequest{Vault: "private", Concept: "denied"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("observe-write code = %v, want PermissionDenied (err=%v)", status.Code(err), err)
	}

	if err := store.RevokeAPIKey("private", fullKey.ID); err != nil {
		t.Fatalf("RevokeAPIKey: %v", err)
	}
	if _, err := client.Hello(fullCtx, &pb.HelloRequest{Vault: "private"}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("revoked-key code = %v, want Unauthenticated (err=%v)", status.Code(err), err)
	}
}

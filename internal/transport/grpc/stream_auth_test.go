package grpc

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/scrypster/muninndb/internal/auth"
	pb "github.com/scrypster/muninndb/proto/gen/go/muninn/v1"
	googlegrpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type fakeStreamAuthStore struct {
	mu          sync.RWMutex
	configs     map[string]auth.VaultConfig
	configReads chan string
}

func newFakeStreamAuthStore(vault string, public bool) *fakeStreamAuthStore {
	return &fakeStreamAuthStore{
		configs: map[string]auth.VaultConfig{
			vault: {Name: vault, Public: public},
		},
		configReads: make(chan string, 16),
	}
}

func (s *fakeStreamAuthStore) ValidateAPIKey(string) (auth.APIKey, error) {
	return auth.APIKey{}, errors.New("no api keys configured")
}

func (s *fakeStreamAuthStore) GetVaultConfig(vault string) (auth.VaultConfig, error) {
	s.mu.RLock()
	cfg, ok := s.configs[vault]
	s.mu.RUnlock()

	select {
	case s.configReads <- vault:
	default:
	}
	if !ok {
		return auth.VaultConfig{Name: vault, Public: false}, nil
	}
	return cfg, nil
}

func (s *fakeStreamAuthStore) setPublic(vault string, public bool) {
	s.mu.Lock()
	s.configs[vault] = auth.VaultConfig{Name: vault, Public: public}
	s.mu.Unlock()
}

type fakeAuthServerStream struct {
	ctx context.Context
}

func (s *fakeAuthServerStream) SetHeader(metadata.MD) error  { return nil }
func (s *fakeAuthServerStream) SendHeader(metadata.MD) error { return nil }
func (s *fakeAuthServerStream) SetTrailer(metadata.MD)       {}
func (s *fakeAuthServerStream) Context() context.Context     { return s.ctx }
func (s *fakeAuthServerStream) SendMsg(any) error            { return nil }
func (s *fakeAuthServerStream) RecvMsg(any) error            { return nil }

func TestAuthStreamInterceptor_AnonymousPublicVaultLockCancelsStream(t *testing.T) {
	const vault = "public-vault"
	store := newFakeStreamAuthStore(vault, true)
	srv := &Server{
		authStore:                 store,
		streamAuthRecheckInterval: 5 * time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := &fakeAuthServerStream{ctx: ctx}
	ready := make(chan struct{})

	handler := func(_ any, stream googlegrpc.ServerStream) error {
		if err := stream.RecvMsg(&pb.SubscribeRequest{Vault: vault}); err != nil {
			return err
		}
		close(ready)
		<-stream.Context().Done()
		return context.Cause(stream.Context())
	}

	result := make(chan error, 1)
	go func() {
		result <- srv.authStreamInterceptor(nil, stream, nil, handler)
	}()

	select {
	case <-ready:
	case err := <-result:
		t.Fatalf("anonymous stream was not initially authorized: %v", err)
	case <-time.After(time.Second):
		t.Fatal("anonymous stream was not initially authorized")
	}

	// The first read authorizes RecvMsg; the second proves the idle monitor is
	// running. Lock only after both so this exercises a periodic revalidation.
	for reads := 0; reads < 2; reads++ {
		select {
		case gotVault := <-store.configReads:
			if gotVault != vault {
				t.Fatalf("config read vault = %q, want %q", gotVault, vault)
			}
		case <-time.After(time.Second):
			t.Fatal("public-vault monitor did not revalidate authorization")
		}
	}
	store.setPublic(vault, false)

	select {
	case err := <-result:
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("code = %v, want Unauthenticated (err=%v)", status.Code(err), err)
		}
		if !strings.Contains(status.Convert(err).Message(), "no longer public") {
			t.Fatalf("error = %q, want fail-closed public-policy cause", err)
		}
	case <-time.After(time.Second):
		t.Fatal("locked public vault did not cancel anonymous stream")
	}
}

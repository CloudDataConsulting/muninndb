package grpc

import (
	"context"
	"time"

	googlegrpc "google.golang.org/grpc"
)

// TestableAuthUnaryInterceptor exposes the unexported authUnaryInterceptor
// for use by external tests in package grpc_test.
func (s *Server) TestableAuthUnaryInterceptor(ctx context.Context, req any, info *googlegrpc.UnaryServerInfo, handler googlegrpc.UnaryHandler) (any, error) {
	return s.authUnaryInterceptor(ctx, req, info, handler)
}

// SetTestStreamAuthRecheckInterval shortens stream key revalidation for tests.
func (s *Server) SetTestStreamAuthRecheckInterval(interval time.Duration) {
	s.streamAuthRecheckInterval = interval
}

// TestableAuthStreamInterceptor exposes the unexported authStreamInterceptor
// for use by external tests in package grpc_test.
func (s *Server) TestableAuthStreamInterceptor(srv any, ss googlegrpc.ServerStream, info *googlegrpc.StreamServerInfo, handler googlegrpc.StreamHandler) error {
	return s.authStreamInterceptor(srv, ss, info, handler)
}

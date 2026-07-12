package mbp

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/scrypster/muninndb/internal/auth"
)

// EngineAPI is the interface the MBP server requires from the engine.
// Defined here (consumer-side), implemented by internal/engine or a mock.
type EngineAPI interface {
	Hello(ctx context.Context, req *HelloRequest) (*HelloResponse, error)
	Write(ctx context.Context, req *WriteRequest) (*WriteResponse, error)
	Read(ctx context.Context, req *ReadRequest) (*ReadResponse, error)
	Activate(ctx context.Context, req *ActivateRequest) (*ActivateResponse, error)
	Subscribe(ctx context.Context, req *SubscribeRequest) (*SubscribeResponse, error)
	Unsubscribe(ctx context.Context, subID string) error
	Link(ctx context.Context, req *LinkRequest) (*LinkResponse, error)
	Forget(ctx context.Context, req *ForgetRequest) (*ForgetResponse, error)
	Stat(ctx context.Context, req *StatRequest) (*StatResponse, error)
}

// Server listens on a TCP port and handles MBP connections.
type Server struct {
	addr      string
	engine    EngineAPI
	authStore vaultAuthStore
	listener  net.Listener
	shutdown  chan struct{}
	wg        sync.WaitGroup
	shutdownM sync.Mutex
	tlsConfig *tls.Config // nil = plain TCP

	authRecheckInterval        time.Duration
	subscriptionCleanupTimeout time.Duration
}

// NewServer creates a new MBP server.
// tlsConfig, if non-nil, wraps the TCP listener with TLS.
func NewServer(addr string, engine EngineAPI, authStore *auth.Store, tlsConfig *tls.Config) *Server {
	return &Server{
		addr:                       addr,
		engine:                     engine,
		authStore:                  authStore,
		shutdown:                   make(chan struct{}),
		tlsConfig:                  tlsConfig,
		authRecheckInterval:        defaultSessionAuthRecheckInterval,
		subscriptionCleanupTimeout: defaultSubscriptionCleanupTimeout,
	}
}

// Serve starts listening and blocks until context is cancelled or Shutdown is called.
func (s *Server) Serve(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.addr, err)
	}
	if s.tlsConfig != nil {
		ln = tls.NewListener(ln, s.tlsConfig)
		slog.Info("mbp: TLS enabled", "addr", ln.Addr().String())
	}
	slog.Info("mbp: listening", "addr", ln.Addr().String())
	s.listener = ln

	// Accept connections in a goroutine
	s.wg.Add(1)
	go s.acceptLoop(ctx)

	// Wait for shutdown signal
	<-s.shutdown
	ln.Close()
	s.wg.Wait()

	return nil
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.shutdownM.Lock()
	defer s.shutdownM.Unlock()

	select {
	case <-s.shutdown:
		return nil // Already shut down
	default:
	}

	close(s.shutdown)

	// Wait for goroutines to finish with timeout
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// acceptLoop accepts incoming connections.
func (s *Server) acceptLoop(ctx context.Context) {
	defer s.wg.Done()

	for {
		select {
		case <-s.shutdown:
			return
		default:
		}

		// Set accept deadline to allow checking shutdown.
		// Use a defensive type assertion: a TLS listener wraps the TCP listener
		// and does not implement *net.TCPListener directly, so we skip the
		// deadline if the underlying type is not accessible.
		if deadline, ok := ctx.Deadline(); ok {
			if tc, ok := s.listener.(*net.TCPListener); ok {
				tc.SetDeadline(deadline)
			}
		}

		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.shutdown:
				return
			default:
			}
			// Log but continue
			continue
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConnection(ctx, conn)
		}()
	}
}

// handleConnection handles a single client connection.
func (s *Server) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	// Closing the connection is what unblocks ReadFrame. Watch both the serving
	// context and explicit Shutdown so authenticated and pre-HELLO connections
	// cannot hold server shutdown open indefinitely.
	baseConnCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	watchStop := make(chan struct{})
	defer close(watchStop)
	go func() {
		select {
		case <-baseConnCtx.Done():
		case <-s.shutdown:
			cancel()
		case <-watchStop:
			return
		}
		_ = conn.Close()
	}()

	// Read the HELLO frame first
	helloFrame, err := ReadFrame(conn)
	if err != nil {
		s.writeErrorFrame(conn, 0, ErrAuthFailed, "failed to read HELLO")
		return
	}

	if helloFrame.Type != TypeHello {
		s.writeErrorFrame(conn, helloFrame.CorrelationID, ErrAuthFailed, "expected HELLO as first message")
		return
	}

	// Decode HELLO request
	var helloReq HelloRequest
	if err := DecodeMsgpack(helloFrame.Payload, &helloReq); err != nil {
		s.writeErrorFrame(conn, helloFrame.CorrelationID, ErrAuthFailed, "invalid HELLO payload")
		return
	}

	// Validate HELLO
	if err := ValidateHelloRequest(&helloReq); err != nil {
		s.writeErrorFrame(conn, helloFrame.CorrelationID, ErrAuthFailed, err.Error())
		return
	}

	// Authenticate once, bind immutable claims to the connection, and pin HELLO
	// to the authorized vault before the engine sees it.
	session, err := s.authenticateHello(&helloReq)
	if err != nil {
		s.writeErrorFrame(conn, helloFrame.CorrelationID, authorizationErrorCode(err), err.Error())
		return
	}
	session.terminate = cancel
	helloReq.Vault = session.vault
	negotiatedCapabilities := NegotiateCapabilities(append([]string(nil), helloReq.Capabilities...))
	connCtx := withConnectionSession(baseConnCtx, session)
	go s.monitorSessionAuthorization(baseConnCtx, session)

	// Call engine's Hello handler
	helloResp, err := s.engine.Hello(connCtx, &helloReq)
	if err != nil {
		s.writeErrorFrame(conn, helloFrame.CorrelationID, ErrAuthFailed, err.Error())
		return
	}
	if helloResp == nil {
		s.writeErrorFrame(conn, helloFrame.CorrelationID, ErrInternal, "empty HELLO response")
		return
	}
	// Do not trust an engine adapter to advertise a vault other than the one
	// authorized at HELLO, capabilities the client did not offer, or limits that
	// contradict the MBP frame codec. Wire policy belongs to the transport.
	helloResp.VaultID = session.vault
	helloResp.Capabilities = negotiatedCapabilities
	helloResp.Limits = ServerLimits

	// Write HELLO_OK
	helloOKFrame := &Frame{
		Version:       0x01,
		Type:          TypeHelloOK,
		Flags:         0,
		CorrelationID: helloFrame.CorrelationID,
	}

	payload, err := EncodeMsgpack(helloResp)
	if err != nil {
		s.writeErrorFrame(conn, helloFrame.CorrelationID, ErrInternal, "failed to encode HELLO_OK")
		return
	}
	helloOKFrame.Payload = payload
	helloOKFrame.PayloadLength = uint32(len(payload))

	if err := WriteFrame(conn, helloOKFrame); err != nil {
		return
	}

	// Start writer goroutine
	writeCh := make(responseQueue, 256)
	writerDone := make(chan error, 1)
	go func() {
		err := s.writerLoop(conn, writeCh)
		// A failed writer can no longer return errors to the client. Cancel and
		// close the connection so the reader and in-flight handlers wind down.
		if err != nil {
			cancel()
			_ = conn.Close()
		}
		writerDone <- err
	}()

	// Start the reader loop. Handler lifetime is tracked here so a read error can
	// cancel the connection before we wait for in-flight engine operations. The
	// response queue remains open until every handler has returned.
	var handlers sync.WaitGroup
	s.readerLoop(connCtx, conn, writeCh, helloResp.Capabilities, &handlers)

	// A plain client disconnect stops reads but does not otherwise cancel the
	// connection context. Cancel immediately so handlers blocked in an engine
	// operation can exit, then wait before closing the response queue.
	cancel()
	_ = conn.Close()
	handlers.Wait()
	s.cleanupSubscriptions(session)
	close(writeCh)

	// Wait for writer goroutine
	<-writerDone
}

// maxConcurrentFrames caps the number of goroutines processing frames
// concurrently for a single connection. This prevents goroutine exhaustion
// from a client sending rapid-fire frames (Slowloris-style attack).
const maxConcurrentFrames = 64

const terminalErrorFlushTimeout = time.Second

type outboundFrame struct {
	frame   *Frame
	written chan error
}

type responseQueue chan *outboundFrame

func hasCapability(capabilities []string, want string) bool {
	for _, capability := range capabilities {
		if capability == want {
			return true
		}
	}
	return false
}

// readerLoop reads frames and dispatches them to handlers.
// A semaphore limits per-connection goroutine concurrency to maxConcurrentFrames.
func (s *Server) readerLoop(
	ctx context.Context,
	conn net.Conn,
	writeCh responseQueue,
	negotiatedCapabilities []string,
	handlers *sync.WaitGroup,
) {
	sem := make(chan struct{}, maxConcurrentFrames)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		frame, err := ReadFrame(conn)
		if err != nil {
			return // Connection closed or read error
		}

		// Acquire semaphore slot before spawning; blocks if maxConcurrentFrames
		// goroutines are already active for this connection.
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return
		}

		// Launch handler goroutine
		handlers.Add(1)
		go func(f *Frame) {
			defer handlers.Done()
			defer func() { <-sem }()
			s.dispatchFrame(ctx, f, writeCh, negotiatedCapabilities)
		}(frame)
	}
}

// writerLoop serializes frames to the connection.
func (s *Server) writerLoop(conn net.Conn, writeCh responseQueue) error {
	bw := bufio.NewWriter(conn)

	for outbound := range writeCh {
		err := WriteFrame(bw, outbound.frame)
		if err == nil {
			err = bw.Flush()
		}
		if outbound.written != nil {
			outbound.written <- err
			close(outbound.written)
		}
		if err != nil {
			return err
		}
	}

	return nil
}

// dispatchFrame routes a frame to the appropriate handler.
func (s *Server) dispatchFrame(ctx context.Context, frame *Frame, writeCh responseQueue, negotiatedCapabilities []string) {
	// Authorization precedes any decompression or decoding so expired, revoked,
	// or mode-forbidden sessions cannot spend decoder resources.
	if _, err := s.authorizeFrame(ctx, frame.Type); err != nil {
		code := authorizationErrorCode(err)
		if code == ErrAuthFailed {
			s.queueTerminalAuthorizationError(ctx, writeCh, frame.CorrelationID, err.Error())
		} else {
			s.queueErrorFrame(writeCh, frame.CorrelationID, code, err.Error())
		}
		return
	}

	// Compressed input is accepted only when compression was negotiated during
	// HELLO. DecompressPayload itself applies a hard output/window memory bound.
	var payload []byte = frame.Payload
	if (frame.Flags & FlagCompressed) != 0 {
		if !hasCapability(negotiatedCapabilities, "compression") {
			s.queueErrorFrame(writeCh, frame.CorrelationID, ErrInvalidEngram, "compression was not negotiated")
			return
		}
		decompressed, err := DecompressPayload(frame.Payload)
		if err != nil {
			s.queueErrorFrame(writeCh, frame.CorrelationID, ErrInternal, "decompression failed")
			return
		}
		payload = decompressed
	}

	// Dispatch by type
	switch frame.Type {
	case TypeWrite:
		s.handleWrite(ctx, frame.CorrelationID, payload, writeCh, negotiatedCapabilities)
	case TypeRead:
		s.handleRead(ctx, frame.CorrelationID, payload, writeCh, negotiatedCapabilities)
	case TypeActivate:
		s.handleActivate(ctx, frame.CorrelationID, payload, writeCh, negotiatedCapabilities)
	case TypeSubscribe:
		s.handleSubscribe(ctx, frame.CorrelationID, payload, writeCh, negotiatedCapabilities)
	case TypeUnsub:
		s.handleUnsub(ctx, frame.CorrelationID, payload, writeCh, negotiatedCapabilities)
	case TypeLink:
		s.handleLink(ctx, frame.CorrelationID, payload, writeCh, negotiatedCapabilities)
	case TypeForget:
		s.handleForget(ctx, frame.CorrelationID, payload, writeCh, negotiatedCapabilities)
	case TypeStat:
		s.handleStat(ctx, frame.CorrelationID, payload, writeCh, negotiatedCapabilities)
	case TypePing:
		s.handlePing(ctx, frame.CorrelationID, payload, writeCh, negotiatedCapabilities)
	default:
		s.queueErrorFrame(writeCh, frame.CorrelationID, ErrInternal, fmt.Sprintf("unknown message type: 0x%02X", frame.Type))
	}
}

// Handler methods

func (s *Server) handleWrite(ctx context.Context, corrID uint64, payload []byte, writeCh responseQueue, caps []string) {
	var req WriteRequest
	if err := DecodeMsgpack(payload, &req); err != nil {
		s.queueErrorFrame(writeCh, corrID, ErrInvalidEngram, "invalid write request")
		return
	}
	if err := s.pinContextVault(ctx, &req.Vault); err != nil {
		s.queueErrorFrame(writeCh, corrID, authorizationErrorCode(err), err.Error())
		return
	}

	resp, err := s.engine.Write(ctx, &req)
	if err != nil {
		s.queueErrorFrame(writeCh, corrID, ErrStorageError, err.Error())
		return
	}

	s.queueFrame(writeCh, TypeWriteOK, corrID, resp, caps)
}

func (s *Server) handleRead(ctx context.Context, corrID uint64, payload []byte, writeCh responseQueue, caps []string) {
	var req ReadRequest
	if err := DecodeMsgpack(payload, &req); err != nil {
		s.queueErrorFrame(writeCh, corrID, ErrInvalidEngram, "invalid read request")
		return
	}
	if err := s.pinContextVault(ctx, &req.Vault); err != nil {
		s.queueErrorFrame(writeCh, corrID, authorizationErrorCode(err), err.Error())
		return
	}

	resp, err := s.engine.Read(ctx, &req)
	if err != nil {
		s.queueErrorFrame(writeCh, corrID, ErrEngramNotFound, err.Error())
		return
	}

	s.queueFrame(writeCh, TypeReadResp, corrID, resp, caps)
}

func (s *Server) handleActivate(ctx context.Context, corrID uint64, payload []byte, writeCh responseQueue, caps []string) {
	var req ActivateRequest
	if err := DecodeMsgpack(payload, &req); err != nil {
		s.queueErrorFrame(writeCh, corrID, ErrInvalidEngram, "invalid activate request")
		return
	}
	if err := s.pinContextVault(ctx, &req.Vault); err != nil {
		s.queueErrorFrame(writeCh, corrID, authorizationErrorCode(err), err.Error())
		return
	}

	resp, err := s.engine.Activate(ctx, &req)
	if err != nil {
		s.queueErrorFrame(writeCh, corrID, ErrIndexError, err.Error())
		return
	}

	s.queueActivateResponse(writeCh, corrID, resp, caps)
}

func (s *Server) handleSubscribe(ctx context.Context, corrID uint64, payload []byte, writeCh responseQueue, caps []string) {
	var req SubscribeRequest
	if err := DecodeMsgpack(payload, &req); err != nil {
		s.queueErrorFrame(writeCh, corrID, ErrInvalidEngram, "invalid subscribe request")
		return
	}
	// Subscription identifiers are server-assigned. Allowing a client to choose
	// an existing global ID would let it replace and later remove another
	// connection's subscription in the engine registry.
	if strings.TrimSpace(req.SubscriptionID) != "" {
		s.queueErrorFrame(writeCh, corrID, ErrInvalidEngram, "subscription_id must be empty; the server assigns it")
		return
	}
	session, err := connectionSessionFromContext(ctx)
	if err != nil {
		s.queueErrorFrame(writeCh, corrID, authorizationErrorCode(err), err.Error())
		return
	}
	if err := pinRequestVault(session, &req.Vault); err != nil {
		s.queueErrorFrame(writeCh, corrID, authorizationErrorCode(err), err.Error())
		return
	}
	assignedSubID := uuid.NewString()
	req.SubscriptionID = assignedSubID

	resp, err := s.engine.Subscribe(ctx, &req)
	if err != nil {
		s.rollbackSubscriptions(assignedSubID)
		s.queueErrorFrame(writeCh, corrID, ErrSubscriptionNotFound, err.Error())
		return
	}
	if resp == nil || resp.SubID != assignedSubID || !session.addSubscription(assignedSubID) {
		rollbackIDs := []string{assignedSubID}
		if resp != nil && resp.SubID != "" && resp.SubID != assignedSubID {
			rollbackIDs = append(rollbackIDs, resp.SubID)
		}
		s.rollbackSubscriptions(rollbackIDs...)
		s.queueErrorFrame(writeCh, corrID, ErrInternal, "subscription returned an invalid id")
		return
	}

	s.queueFrame(writeCh, TypeSubOK, corrID, resp, caps)
}

func (s *Server) handleUnsub(ctx context.Context, corrID uint64, payload []byte, writeCh responseQueue, caps []string) {
	var req UnsubscribeRequest
	if err := DecodeMsgpack(payload, &req); err != nil {
		s.queueErrorFrame(writeCh, corrID, ErrInvalidEngram, "invalid unsub request")
		return
	}
	session, err := connectionSessionFromContext(ctx)
	if err != nil {
		s.queueErrorFrame(writeCh, corrID, authorizationErrorCode(err), err.Error())
		return
	}
	if !session.takeSubscription(req.SubID) {
		s.queueErrorFrame(writeCh, corrID, ErrSubscriptionNotFound, "subscription is not owned by this connection")
		return
	}

	err = s.engine.Unsubscribe(ctx, req.SubID)
	if err != nil {
		session.restoreSubscription(req.SubID)
		s.queueErrorFrame(writeCh, corrID, ErrSubscriptionNotFound, err.Error())
		return
	}

	s.queueFrame(writeCh, TypeUnsubOK, corrID, &UnsubscribeResponse{OK: true}, caps)
}

func (s *Server) handleLink(ctx context.Context, corrID uint64, payload []byte, writeCh responseQueue, caps []string) {
	var req LinkRequest
	if err := DecodeMsgpack(payload, &req); err != nil {
		s.queueErrorFrame(writeCh, corrID, ErrInvalidAssociation, "invalid link request")
		return
	}
	if err := s.pinContextVault(ctx, &req.Vault); err != nil {
		s.queueErrorFrame(writeCh, corrID, authorizationErrorCode(err), err.Error())
		return
	}

	resp, err := s.engine.Link(ctx, &req)
	if err != nil {
		s.queueErrorFrame(writeCh, corrID, ErrInvalidAssociation, err.Error())
		return
	}

	s.queueFrame(writeCh, TypeLinkOK, corrID, resp, caps)
}

func (s *Server) handleForget(ctx context.Context, corrID uint64, payload []byte, writeCh responseQueue, caps []string) {
	var req ForgetRequest
	if err := DecodeMsgpack(payload, &req); err != nil {
		s.queueErrorFrame(writeCh, corrID, ErrInvalidEngram, "invalid forget request")
		return
	}
	if err := s.pinContextVault(ctx, &req.Vault); err != nil {
		s.queueErrorFrame(writeCh, corrID, authorizationErrorCode(err), err.Error())
		return
	}

	resp, err := s.engine.Forget(ctx, &req)
	if err != nil {
		s.queueErrorFrame(writeCh, corrID, ErrStorageError, err.Error())
		return
	}

	s.queueFrame(writeCh, TypeForgetOK, corrID, resp, caps)
}

func (s *Server) handleStat(ctx context.Context, corrID uint64, payload []byte, writeCh responseQueue, caps []string) {
	var req StatRequest
	if err := DecodeMsgpack(payload, &req); err != nil {
		s.queueErrorFrame(writeCh, corrID, ErrInvalidEngram, "invalid stat request")
		return
	}
	if err := s.pinContextVault(ctx, &req.Vault); err != nil {
		s.queueErrorFrame(writeCh, corrID, authorizationErrorCode(err), err.Error())
		return
	}

	resp, err := s.engine.Stat(ctx, &req)
	if err != nil {
		s.queueErrorFrame(writeCh, corrID, ErrStorageError, err.Error())
		return
	}

	s.queueFrame(writeCh, TypeStatResp, corrID, resp, caps)
}

func (s *Server) handlePing(ctx context.Context, corrID uint64, payload []byte, writeCh responseQueue, caps []string) {
	var req PingRequest
	if err := DecodeMsgpack(payload, &req); err != nil {
		s.queueErrorFrame(writeCh, corrID, ErrInternal, "invalid ping request")
		return
	}

	s.queueFrame(writeCh, TypePong, corrID, &PongResponse{Data: req.Data}, caps)
}

// Utility methods

func (s *Server) queueFrame(writeCh responseQueue, frameType uint8, corrID uint64, payload interface{}, caps []string) {
	data, err := EncodeMsgpack(payload)
	if err != nil {
		s.queueErrorFrame(writeCh, corrID, ErrInternal, "failed to encode response")
		return
	}

	// Check if compression is negotiated and payload is large
	compressed := false
	if len(data) > CompressionThreshold {
		for _, cap := range caps {
			if cap == "compression" {
				if compData, isCompressed, err := CompressPayload(data); err == nil {
					data = compData
					compressed = isCompressed
				}
				break
			}
		}
	}

	flags := uint16(0)
	if compressed {
		flags |= FlagCompressed
	}

	frame := &Frame{
		Version:       0x01,
		Type:          frameType,
		Flags:         flags,
		PayloadLength: uint32(len(data)),
		CorrelationID: corrID,
		Payload:       data,
	}

	select {
	case writeCh <- &outboundFrame{frame: frame}:
	default:
		// Channel full, drop frame (should not happen with buffered channel)
	}
}

func (s *Server) queueActivateResponse(writeCh responseQueue, corrID uint64, resp *ActivateResponse, caps []string) {
	// For now, send as a single frame
	// TODO: implement multi-frame streaming for large result sets
	s.queueFrame(writeCh, TypeActivateResp, corrID, resp, caps)
}

func (s *Server) queueErrorFrame(writeCh responseQueue, corrID uint64, code ErrorCode, message string) {
	frame := buildErrorFrame(corrID, code, message)
	if frame == nil {
		return
	}

	select {
	case writeCh <- &outboundFrame{frame: frame}:
	default:
	}
}

func (s *Server) queueTerminalAuthorizationError(ctx context.Context, writeCh responseQueue, corrID uint64, message string) {
	session, _ := connectionSessionFromContext(ctx)
	if session != nil {
		defer session.terminateConnection()
	}
	frame := buildErrorFrame(corrID, ErrAuthFailed, message)
	if frame == nil {
		return
	}
	receipt := make(chan error, 1)
	flushCtx, cancel := context.WithTimeout(context.Background(), terminalErrorFlushTimeout)
	defer cancel()
	select {
	case writeCh <- &outboundFrame{frame: frame, written: receipt}:
	case <-flushCtx.Done():
		return
	case <-ctx.Done():
		return
	}
	select {
	case <-receipt:
	case <-flushCtx.Done():
	case <-ctx.Done():
	}
}

func buildErrorFrame(corrID uint64, code ErrorCode, message string) *Frame {
	errPayload := &ErrorPayload{
		Code:      code,
		Message:   message,
		RequestID: uuid.New().String()[:8],
	}

	data, err := EncodeMsgpack(errPayload)
	if err != nil {
		// Can't even encode the error, give up
		return nil
	}

	frame := &Frame{
		Version:       0x01,
		Type:          TypeError,
		Flags:         0,
		PayloadLength: uint32(len(data)),
		CorrelationID: corrID,
		Payload:       data,
	}

	return frame
}

func (s *Server) writeErrorFrame(conn net.Conn, corrID uint64, code ErrorCode, message string) {
	errPayload := &ErrorPayload{
		Code:      code,
		Message:   message,
		RequestID: uuid.New().String()[:8],
	}

	data, err := EncodeMsgpack(errPayload)
	if err != nil {
		return
	}

	frame := &Frame{
		Version:       0x01,
		Type:          TypeError,
		Flags:         0,
		PayloadLength: uint32(len(data)),
		CorrelationID: corrID,
		Payload:       data,
	}

	WriteFrame(conn, frame)
}

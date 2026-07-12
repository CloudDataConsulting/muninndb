package authz

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

const deliveryIDAttempts = 8

var (
	ErrDeliveryInvalidConfig   = errors.New("mcp authz delivery: invalid configuration")
	ErrDeliveryInvalidID       = errors.New("mcp authz delivery: invalid session ID")
	ErrDeliveryIDGeneration    = errors.New("mcp authz delivery: session ID generation failed")
	ErrDeliveryIDCollision     = errors.New("mcp authz delivery: session ID collision limit reached")
	ErrDeliverySessionLimit    = errors.New("mcp authz delivery: active session limit reached")
	ErrDeliverySessionNotFound = errors.New("mcp authz delivery: session not found")
	ErrDeliverySessionClosed   = errors.New("mcp authz delivery: session closed")
	ErrDeliverySessionMismatch = errors.New("mcp authz delivery: session pin mismatch")
	ErrDeliveryBackpressure    = errors.New("mcp authz delivery: session buffer full")
	ErrDeliveryAuthorization   = errors.New("mcp authz delivery: authorization failed")
)

// DeliveryOutcome classifies every exact-session delivery attempt. Successful
// delivery is the only outcome with a nil error; callers can branch on the
// outcome without parsing an error while errors.Is still works for failures.
type DeliveryOutcome uint8

const (
	DeliveryDelivered DeliveryOutcome = iota + 1
	DeliveryBackpressured
	DeliverySessionClosed
	DeliverySessionNotFound
	DeliveryAuthorizationFailed
	DeliverySessionMismatched
)

// ExactSession is the capability returned when a session is opened. ID is a
// registry-generated 256-bit transport address, not an authentication token.
// Events is receive-only so callers cannot close or inject into the queue.
type ExactSession struct {
	ID     string
	Events <-chan []byte
}

// ExactSessionDelivery is a policy-neutral, in-memory delivery boundary. It
// deliberately has no broadcast, by-vault, or by-token API. Session IDs are
// the only routing keys, while an existing immutable SessionPin proves that a
// caller is addressing the session it established.
//
// Both active sessions and closed-ID tombstones are bounded by maxSessions.
// Tombstones remove all pin/queue state while preventing immediate resurrection
// and retaining a useful closed outcome for the most recent session IDs.
type ExactSessionDelivery struct {
	mu          sync.RWMutex
	randomMu    sync.Mutex
	store       PrincipalStore
	capacity    int
	maxSessions int
	now         func() time.Time
	random      io.Reader
	sessions    map[string]*deliverySession
	closed      map[string]struct{}
	closedOrder []string
}

type deliverySession struct {
	mu     sync.Mutex
	pin    SessionPin
	queue  chan []byte
	closed bool
}

// NewExactSessionDelivery creates an unwired exact-session registry.
// bufferCapacity is the deterministic per-session queue bound; maxSessions
// bounds active sessions and, separately, recent closed-ID tombstones.
func NewExactSessionDelivery(
	store PrincipalStore,
	bufferCapacity int,
	maxSessions int,
) (*ExactSessionDelivery, error) {
	return newExactSessionDeliveryAt(
		store,
		bufferCapacity,
		maxSessions,
		time.Now,
		rand.Reader,
	)
}

func newExactSessionDeliveryAt(
	store PrincipalStore,
	bufferCapacity int,
	maxSessions int,
	now func() time.Time,
	random io.Reader,
) (*ExactSessionDelivery, error) {
	if store == nil {
		return nil, fmt.Errorf("%w: principal store is required", ErrDeliveryInvalidConfig)
	}
	if bufferCapacity <= 0 {
		return nil, fmt.Errorf("%w: buffer capacity must be positive", ErrDeliveryInvalidConfig)
	}
	if maxSessions <= 0 {
		return nil, fmt.Errorf("%w: max sessions must be positive", ErrDeliveryInvalidConfig)
	}
	if now == nil {
		return nil, fmt.Errorf("%w: clock is required", ErrDeliveryInvalidConfig)
	}
	if random == nil {
		return nil, fmt.Errorf("%w: random source is required", ErrDeliveryInvalidConfig)
	}
	return &ExactSessionDelivery{
		store:       store,
		capacity:    bufferCapacity,
		maxSessions: maxSessions,
		now:         now,
		random:      random,
		sessions:    make(map[string]*deliverySession),
		closed:      make(map[string]struct{}),
		closedOrder: make([]string, 0, maxSessions),
	}, nil
}

// Open binds one generated exact session ID to an existing SessionPin. It
// accepts no caller-provided ID, bearer token, or other raw credential.
func (d *ExactSessionDelivery) Open(pin SessionPin) (ExactSession, error) {
	if !pin.principal.valid {
		return ExactSession{}, ErrInvalidPrincipal
	}

	for range deliveryIDAttempts {
		sessionID, err := d.newSessionID()
		if err != nil {
			return ExactSession{}, err
		}

		d.mu.Lock()
		if len(d.sessions) >= d.maxSessions {
			d.mu.Unlock()
			return ExactSession{}, ErrDeliverySessionLimit
		}
		if _, exists := d.sessions[sessionID]; exists {
			d.mu.Unlock()
			continue
		}
		if _, closed := d.closed[sessionID]; closed {
			d.mu.Unlock()
			continue
		}

		queue := make(chan []byte, d.capacity)
		d.sessions[sessionID] = &deliverySession{pin: pin, queue: queue}
		d.mu.Unlock()
		return ExactSession{ID: sessionID, Events: queue}, nil
	}
	return ExactSession{}, ErrDeliveryIDCollision
}

// Deliver first verifies that expected is the pin bound to the exact session
// ID. Only then does it revalidate current PrincipalStore claims and perform
// one non-blocking send. This order prevents a mismatched caller (including a
// cancelled one) from terminating another session. Authorization failures for
// a matching session terminate and remove that session.
//
// payload is copied before enqueue. The caller may safely reuse or mutate its
// byte slice after Deliver returns.
func (d *ExactSessionDelivery) Deliver(
	ctx context.Context,
	sessionID string,
	expected SessionPin,
	payload []byte,
) (DeliveryOutcome, error) {
	session, outcome, err := d.lookup(sessionID)
	if err != nil {
		return outcome, err
	}
	if !session.pin.principal.claimsEqual(expected.principal) {
		return DeliverySessionMismatched, ErrDeliverySessionMismatch
	}

	_, err = revalidatePinnedAt(ctx, d.store, session.pin.principal, d.now())
	if err == nil && ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		d.terminate(sessionID, session)
		return DeliveryAuthorizationFailed, fmt.Errorf(
			"%w: %w",
			ErrDeliveryAuthorization,
			err,
		)
	}
	payloadCopy := bytes.Clone(payload)

	session.mu.Lock()
	if session.closed {
		session.mu.Unlock()
		return DeliverySessionClosed, ErrDeliverySessionClosed
	}
	if err := ctx.Err(); err != nil {
		session.mu.Unlock()
		d.terminate(sessionID, session)
		return DeliveryAuthorizationFailed, fmt.Errorf(
			"%w: %w",
			ErrDeliveryAuthorization,
			err,
		)
	}
	select {
	case session.queue <- payloadCopy:
		session.mu.Unlock()
		return DeliveryDelivered, nil
	default:
		session.mu.Unlock()
		return DeliveryBackpressured, ErrDeliveryBackpressure
	}
}

// Close terminates one session and closes its receive queue. Recent closed IDs
// have a typed closed outcome; older evicted tombstones become not found.
func (d *ExactSessionDelivery) Close(sessionID string) error {
	if sessionID == "" {
		return ErrDeliveryInvalidID
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.closed[sessionID]; ok {
		return ErrDeliverySessionClosed
	}
	session, ok := d.sessions[sessionID]
	if !ok {
		return ErrDeliverySessionNotFound
	}

	session.mu.Lock()
	defer session.mu.Unlock()
	delete(d.sessions, sessionID)
	d.addClosedLocked(sessionID)
	if !session.closed {
		session.closed = true
		close(session.queue)
	}
	return nil
}

func (d *ExactSessionDelivery) lookup(
	sessionID string,
) (*deliverySession, DeliveryOutcome, error) {
	if sessionID == "" {
		return nil, DeliverySessionNotFound, ErrDeliveryInvalidID
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if _, ok := d.closed[sessionID]; ok {
		return nil, DeliverySessionClosed, ErrDeliverySessionClosed
	}
	session, ok := d.sessions[sessionID]
	if !ok {
		return nil, DeliverySessionNotFound, ErrDeliverySessionNotFound
	}
	return session, 0, nil
}

// terminate removes only the exact session pointer originally looked up. The
// pointer check ensures a delayed authorization failure can never close a
// different session.
func (d *ExactSessionDelivery) terminate(
	sessionID string,
	session *deliverySession,
) {
	d.mu.Lock()
	defer d.mu.Unlock()
	current, ok := d.sessions[sessionID]
	if !ok || current != session {
		return
	}

	session.mu.Lock()
	defer session.mu.Unlock()
	delete(d.sessions, sessionID)
	d.addClosedLocked(sessionID)
	if !session.closed {
		session.closed = true
		close(session.queue)
	}
}

func (d *ExactSessionDelivery) addClosedLocked(sessionID string) {
	if _, exists := d.closed[sessionID]; exists {
		return
	}
	d.closed[sessionID] = struct{}{}
	d.closedOrder = append(d.closedOrder, sessionID)
	if len(d.closedOrder) <= d.maxSessions {
		return
	}
	oldest := d.closedOrder[0]
	d.closedOrder = d.closedOrder[1:]
	delete(d.closed, oldest)
}

func (d *ExactSessionDelivery) newSessionID() (string, error) {
	var raw [32]byte
	d.randomMu.Lock()
	_, err := io.ReadFull(d.random, raw[:])
	d.randomMu.Unlock()
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrDeliveryIDGeneration, err)
	}
	return hex.EncodeToString(raw[:]), nil
}

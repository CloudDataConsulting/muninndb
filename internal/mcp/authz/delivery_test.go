package authz

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/scrypster/muninndb/internal/auth"
)

var errDeliveryRevoked = errors.New("delivery credential revoked")

type deliveryPrincipalStore struct {
	mu         sync.RWMutex
	principals map[string]Principal
	errs       map[string]error
	calls      map[string]int
	ignoreCtx  bool
}

func newDeliveryPrincipalStore(principals ...Principal) *deliveryPrincipalStore {
	store := &deliveryPrincipalStore{
		principals: make(map[string]Principal),
		errs:       make(map[string]error),
		calls:      make(map[string]int),
	}
	for _, principal := range principals {
		store.principals[principal.CredentialRef()] = principal
	}
	return store
}

func (s *deliveryPrincipalStore) Revalidate(ctx context.Context, ref string) (Principal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls[ref]++
	if !s.ignoreCtx {
		select {
		case <-ctx.Done():
			return Principal{}, ctx.Err()
		default:
		}
	}
	if err := s.errs[ref]; err != nil {
		return Principal{}, err
	}
	principal, ok := s.principals[ref]
	if !ok {
		return Principal{}, errDeliveryRevoked
	}
	return principal, nil
}

func (s *deliveryPrincipalStore) setPrincipal(principal Principal) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.principals[principal.CredentialRef()] = principal
}

func (s *deliveryPrincipalStore) setError(ref string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.errs[ref] = err
}

func (s *deliveryPrincipalStore) callCount(ref string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.calls[ref]
}

func deliveryPrincipal(t *testing.T, vault, ref, keyID, mode string) Principal {
	t.Helper()
	principal, err := NewPrincipal(PrincipalClaims{
		Kind:          auth.PrincipalAPIKey,
		Vault:         vault,
		Mode:          mode,
		CredentialRef: ref,
		KeyID:         keyID,
	})
	if err != nil {
		t.Fatalf("NewPrincipal: %v", err)
	}
	return principal
}

func deliveryPublicPrincipal(t *testing.T) Principal {
	t.Helper()
	principal, err := NewPrincipal(PrincipalClaims{
		Kind:          auth.PrincipalPublic,
		Vault:         "default",
		Mode:          auth.ModeFull,
		CredentialRef: "vault-config:default",
	})
	if err != nil {
		t.Fatalf("NewPrincipal: %v", err)
	}
	return principal
}

func deliveryPin(t *testing.T, store PrincipalStore, principal Principal) SessionPin {
	t.Helper()
	current, err := RevalidatePinned(context.Background(), store, principal)
	if err != nil {
		t.Fatalf("RevalidatePinned: %v", err)
	}
	pin, err := NewSessionPin(current)
	if err != nil {
		t.Fatalf("NewSessionPin: %v", err)
	}
	return pin
}

func TestExactSessionDeliveryValidatesConstructionAndBoundsActiveSessions(t *testing.T) {
	if _, err := NewExactSessionDelivery(nil, 1, 1); !errors.Is(err, ErrDeliveryInvalidConfig) {
		t.Fatalf("nil store error = %v, want ErrDeliveryInvalidConfig", err)
	}
	principal := deliveryPrincipal(t, "client-a", "sha256:key-a", "key-a", auth.ModeFull)
	store := newDeliveryPrincipalStore(principal)
	for _, config := range []struct {
		buffer int
		max    int
	}{{0, 1}, {1, 0}} {
		if _, err := NewExactSessionDelivery(store, config.buffer, config.max); !errors.Is(err, ErrDeliveryInvalidConfig) {
			t.Fatalf("config %+v error = %v, want ErrDeliveryInvalidConfig", config, err)
		}
	}
	delivery, err := NewExactSessionDelivery(store, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := delivery.Open(SessionPin{}); !errors.Is(err, ErrInvalidPrincipal) {
		t.Fatalf("zero pin error = %v, want ErrInvalidPrincipal", err)
	}
	pin := deliveryPin(t, store, principal)
	session, err := delivery.Open(pin)
	if err != nil {
		t.Fatal(err)
	}
	if len(session.ID) != 64 {
		t.Fatalf("session ID length = %d, want 64 hex characters", len(session.ID))
	}
	if _, err := hex.DecodeString(session.ID); err != nil {
		t.Fatalf("session ID is not hex: %v", err)
	}
	if _, err := delivery.Open(pin); !errors.Is(err, ErrDeliverySessionLimit) {
		t.Fatalf("second open error = %v, want ErrDeliverySessionLimit", err)
	}
}

func TestExactSessionDeliveryRetriesGeneratedIDCollisions(t *testing.T) {
	principal := deliveryPrincipal(t, "client-a", "sha256:key-a", "key-a", auth.ModeFull)
	store := newDeliveryPrincipalStore(principal)
	pin := deliveryPin(t, store, principal)
	firstBytes := bytes.Repeat([]byte{0x11}, 32)
	secondBytes := bytes.Repeat([]byte{0x22}, 32)
	random := bytes.NewReader(bytes.Join([][]byte{firstBytes, firstBytes, secondBytes}, nil))
	delivery, err := newExactSessionDeliveryAt(store, 1, 2, time.Now, random)
	if err != nil {
		t.Fatal(err)
	}
	first, err := delivery.Open(pin)
	if err != nil {
		t.Fatal(err)
	}
	second, err := delivery.Open(pin)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != hex.EncodeToString(firstBytes) || second.ID != hex.EncodeToString(secondBytes) {
		t.Fatalf("generated IDs = %q, %q", first.ID, second.ID)
	}

	failing, err := newExactSessionDeliveryAt(store, 1, 2, time.Now, bytes.NewReader(nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := failing.Open(pin); !errors.Is(err, ErrDeliveryIDGeneration) {
		t.Fatalf("random-source error = %v, want ErrDeliveryIDGeneration", err)
	}

	repeated := bytes.NewReader(bytes.Repeat(firstBytes, deliveryIDAttempts+1))
	colliding, err := newExactSessionDeliveryAt(store, 1, 2, time.Now, repeated)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := colliding.Open(pin); err != nil {
		t.Fatal(err)
	}
	if _, err := colliding.Open(pin); !errors.Is(err, ErrDeliveryIDCollision) {
		t.Fatalf("collision error = %v, want ErrDeliveryIDCollision", err)
	}
}

func TestExactSessionDeliveryIsolatesIdenticalPublicSessionsAndCopiesPayload(t *testing.T) {
	principal := deliveryPublicPrincipal(t)
	store := newDeliveryPrincipalStore(principal)
	pin := deliveryPin(t, store, principal)
	delivery, err := NewExactSessionDelivery(store, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	first, err := delivery.Open(pin)
	if err != nil {
		t.Fatal(err)
	}
	second, err := delivery.Open(pin)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("only-first")
	outcome, err := delivery.Deliver(context.Background(), first.ID, pin, payload)
	if err != nil || outcome != DeliveryDelivered {
		t.Fatalf("Deliver = %v, %v; want delivered", outcome, err)
	}
	copy(payload, []byte("XXXXXXXXXX"))
	if got := string(<-first.Events); got != "only-first" {
		t.Fatalf("first received %q", got)
	}
	select {
	case got := <-second.Events:
		t.Fatalf("identical-principal session leaked payload %q", got)
	default:
	}
	if got := store.callCount(principal.CredentialRef()); got != 2 {
		// One call creates the pin and one call authorizes delivery.
		t.Fatalf("revalidation calls = %d, want 2", got)
	}
}

func TestExactSessionDeliveryRejectsMismatchBeforeCancellationOrRevalidation(t *testing.T) {
	principalA := deliveryPrincipal(t, "client-a", "sha256:key-a", "key-a", auth.ModeFull)
	principalB := deliveryPrincipal(t, "client-b", "sha256:key-b", "key-b", auth.ModeObserve)
	store := newDeliveryPrincipalStore(principalA, principalB)
	pinA := deliveryPin(t, store, principalA)
	pinB := deliveryPin(t, store, principalB)
	delivery, err := NewExactSessionDelivery(store, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	sessionB, err := delivery.Open(pinB)
	if err != nil {
		t.Fatal(err)
	}
	before := store.callCount(principalB.CredentialRef())
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	outcome, err := delivery.Deliver(cancelled, sessionB.ID, pinA, []byte("cross-id"))
	if outcome != DeliverySessionMismatched || !errors.Is(err, ErrDeliverySessionMismatch) {
		t.Fatalf("mismatched delivery = %v, %v; want mismatch", outcome, err)
	}
	if got := store.callCount(principalB.CredentialRef()); got != before {
		t.Fatalf("mismatched caller triggered %d revalidations, want none", got-before)
	}
	select {
	case got := <-sessionB.Events:
		t.Fatalf("session B unexpectedly received %q", got)
	default:
	}
	if outcome, err := delivery.Deliver(context.Background(), sessionB.ID, pinB, []byte("correct")); err != nil || outcome != DeliveryDelivered {
		t.Fatalf("correct delivery after mismatch = %v, %v", outcome, err)
	}
	if got := string(<-sessionB.Events); got != "correct" {
		t.Fatalf("session B received %q", got)
	}
}

func TestExactSessionDeliveryAppliesDeterministicBackpressure(t *testing.T) {
	principal := deliveryPrincipal(t, "client-a", "sha256:key-a", "key-a", auth.ModeFull)
	store := newDeliveryPrincipalStore(principal)
	pin := deliveryPin(t, store, principal)
	delivery, err := NewExactSessionDelivery(store, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	session, err := delivery.Open(pin)
	if err != nil {
		t.Fatal(err)
	}

	if outcome, err := delivery.Deliver(context.Background(), session.ID, pin, []byte("one")); err != nil || outcome != DeliveryDelivered {
		t.Fatalf("first delivery = %v, %v", outcome, err)
	}
	if outcome, err := delivery.Deliver(context.Background(), session.ID, pin, []byte("two")); outcome != DeliveryBackpressured || !errors.Is(err, ErrDeliveryBackpressure) {
		t.Fatalf("full delivery = %v, %v; want backpressure", outcome, err)
	}
	if got := string(<-session.Events); got != "one" {
		t.Fatalf("first queued value = %q", got)
	}
	if outcome, err := delivery.Deliver(context.Background(), session.ID, pin, []byte("three")); err != nil || outcome != DeliveryDelivered {
		t.Fatalf("post-drain delivery = %v, %v", outcome, err)
	}
	if got := string(<-session.Events); got != "three" {
		t.Fatalf("post-drain value = %q", got)
	}
	if got := store.callCount(principal.CredentialRef()); got != 4 {
		// One call creates the pin and all three attempts revalidate.
		t.Fatalf("revalidation calls = %d, want 4", got)
	}
}

func TestExactSessionDeliveryRevocationTerminatesSession(t *testing.T) {
	principal := deliveryPrincipal(t, "client-a", "sha256:key-a", "key-a", auth.ModeFull)
	store := newDeliveryPrincipalStore(principal)
	pin := deliveryPin(t, store, principal)
	delivery, err := NewExactSessionDelivery(store, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	session, err := delivery.Open(pin)
	if err != nil {
		t.Fatal(err)
	}
	store.setError(principal.CredentialRef(), errDeliveryRevoked)

	outcome, err := delivery.Deliver(context.Background(), session.ID, pin, []byte("blocked"))
	if outcome != DeliveryAuthorizationFailed || !errors.Is(err, ErrDeliveryAuthorization) || !errors.Is(err, errDeliveryRevoked) {
		t.Fatalf("revoked delivery = %v, %v; want wrapped authorization failure", outcome, err)
	}
	if _, ok := <-session.Events; ok {
		t.Fatal("authorization-failed queue remained open")
	}
	if outcome, err := delivery.Deliver(context.Background(), session.ID, pin, []byte("resurrect")); outcome != DeliverySessionClosed || !errors.Is(err, ErrDeliverySessionClosed) {
		t.Fatalf("post-revocation delivery = %v, %v; want closed", outcome, err)
	}
}

func TestExactSessionDeliveryClaimDriftTerminatesSession(t *testing.T) {
	principal := deliveryPrincipal(t, "client-a", "sha256:key-a", "key-a", auth.ModeFull)
	store := newDeliveryPrincipalStore(principal)
	pin := deliveryPin(t, store, principal)
	delivery, err := NewExactSessionDelivery(store, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	session, err := delivery.Open(pin)
	if err != nil {
		t.Fatal(err)
	}
	store.setPrincipal(deliveryPrincipal(t, "client-a", "sha256:key-a", "key-a", auth.ModeObserve))

	outcome, err := delivery.Deliver(context.Background(), session.ID, pin, []byte("blocked"))
	if outcome != DeliveryAuthorizationFailed || !errors.Is(err, ErrDeliveryAuthorization) || !errors.Is(err, ErrClaimsChanged) {
		t.Fatalf("claim-drift delivery = %v, %v; want wrapped ErrClaimsChanged", outcome, err)
	}
	if _, ok := <-session.Events; ok {
		t.Fatal("claim-drift queue remained open")
	}
}

func TestExactSessionDeliveryRejectsExpiredPinAtInjectedTime(t *testing.T) {
	baseTime := time.Now().UTC().Round(0)
	expires := baseTime.Add(time.Hour)
	principal, err := NewPrincipal(PrincipalClaims{
		Kind:          auth.PrincipalAPIKey,
		Vault:         "client-a",
		Mode:          auth.ModeFull,
		CredentialRef: "sha256:expiring",
		KeyID:         "expiring",
		ExpiresAt:     &expires,
	})
	if err != nil {
		t.Fatal(err)
	}
	store := newDeliveryPrincipalStore(principal)
	pin := deliveryPin(t, store, principal)
	delivery, err := newExactSessionDeliveryAt(
		store,
		1,
		1,
		func() time.Time { return baseTime.Add(2 * time.Hour) },
		strings.NewReader(strings.Repeat("x", 32)),
	)
	if err != nil {
		t.Fatal(err)
	}
	session, err := delivery.Open(pin)
	if err != nil {
		t.Fatal(err)
	}

	outcome, err := delivery.Deliver(context.Background(), session.ID, pin, []byte("blocked"))
	if outcome != DeliveryAuthorizationFailed || !errors.Is(err, ErrDeliveryAuthorization) || !errors.Is(err, ErrPrincipalExpired) {
		t.Fatalf("expired delivery = %v, %v; want wrapped ErrPrincipalExpired", outcome, err)
	}
	if _, ok := <-session.Events; ok {
		t.Fatal("expired queue remained open")
	}
}

func TestExactSessionDeliveryUnknownClosedAndBoundedTombstones(t *testing.T) {
	principal := deliveryPrincipal(t, "client-a", "sha256:key-a", "key-a", auth.ModeFull)
	store := newDeliveryPrincipalStore(principal)
	pin := deliveryPin(t, store, principal)
	delivery, err := NewExactSessionDelivery(store, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if outcome, err := delivery.Deliver(context.Background(), "unknown", pin, nil); outcome != DeliverySessionNotFound || !errors.Is(err, ErrDeliverySessionNotFound) {
		t.Fatalf("unknown delivery = %v, %v", outcome, err)
	}

	sessions := make([]ExactSession, 0, 3)
	for range 3 {
		session, err := delivery.Open(pin)
		if err != nil {
			t.Fatal(err)
		}
		sessions = append(sessions, session)
		if err := delivery.Close(session.ID); err != nil {
			t.Fatal(err)
		}
		if _, ok := <-session.Events; ok {
			t.Fatal("closed queue remained open")
		}
	}
	if outcome, err := delivery.Deliver(context.Background(), sessions[0].ID, pin, nil); outcome != DeliverySessionNotFound || !errors.Is(err, ErrDeliverySessionNotFound) {
		t.Fatalf("evicted tombstone delivery = %v, %v; want not found", outcome, err)
	}
	for _, session := range sessions[1:] {
		if outcome, err := delivery.Deliver(context.Background(), session.ID, pin, nil); outcome != DeliverySessionClosed || !errors.Is(err, ErrDeliverySessionClosed) {
			t.Fatalf("recent closed delivery = %v, %v", outcome, err)
		}
	}
	if err := delivery.Close(sessions[2].ID); !errors.Is(err, ErrDeliverySessionClosed) {
		t.Fatalf("second close error = %v, want ErrDeliverySessionClosed", err)
	}
	if err := delivery.Close("unknown"); !errors.Is(err, ErrDeliverySessionNotFound) {
		t.Fatalf("unknown close error = %v, want ErrDeliverySessionNotFound", err)
	}
}

func TestExactSessionDeliveryCancellationFailsClosed(t *testing.T) {
	principal := deliveryPrincipal(t, "client-a", "sha256:key-a", "key-a", auth.ModeFull)
	store := newDeliveryPrincipalStore(principal)
	store.ignoreCtx = true // Exercise the delivery boundary's own cancellation check.
	pin := deliveryPin(t, store, principal)
	delivery, err := NewExactSessionDelivery(store, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	session, err := delivery.Open(pin)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	outcome, err := delivery.Deliver(ctx, session.ID, pin, []byte("blocked"))
	if outcome != DeliveryAuthorizationFailed || !errors.Is(err, ErrDeliveryAuthorization) || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled delivery = %v, %v; want wrapped context.Canceled", outcome, err)
	}
	if _, ok := <-session.Events; ok {
		t.Fatal("cancelled delivery did not terminate session")
	}
}

func TestExactSessionDeliveryConcurrentCloseAndDeliver(t *testing.T) {
	principal := deliveryPrincipal(t, "client-a", "sha256:key-a", "key-a", auth.ModeFull)
	store := newDeliveryPrincipalStore(principal)
	pin := deliveryPin(t, store, principal)
	const attempts = 256
	delivery, err := NewExactSessionDelivery(store, attempts, 1)
	if err != nil {
		t.Fatal(err)
	}
	session, err := delivery.Open(pin)
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	results := make(chan DeliveryOutcome, attempts)
	errs := make(chan error, attempts)
	var workers sync.WaitGroup
	workers.Add(attempts)
	for i := range attempts {
		go func(value int) {
			defer workers.Done()
			<-start
			outcome, err := delivery.Deliver(
				context.Background(),
				session.ID,
				pin,
				[]byte{byte(value)},
			)
			results <- outcome
			errs <- err
		}(i)
	}
	closeDone := make(chan error, 1)
	go func() {
		<-start
		closeDone <- delivery.Close(session.ID)
	}()
	close(start)
	workers.Wait()
	if err := <-closeDone; err != nil {
		t.Fatalf("concurrent close: %v", err)
	}
	close(results)
	close(errs)

	for outcome := range results {
		if outcome != DeliveryDelivered && outcome != DeliverySessionClosed {
			t.Errorf("concurrent outcome = %v; want delivered or closed", outcome)
		}
	}
	for err := range errs {
		if err != nil && !errors.Is(err, ErrDeliverySessionClosed) {
			t.Errorf("concurrent error = %v", err)
		}
	}
	received := 0
	for range session.Events {
		received++
	}
	if received > attempts {
		t.Fatalf("received %d values from %d attempts", received, attempts)
	}
}

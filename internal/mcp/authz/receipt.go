package authz

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"
)

const (
	receiptRecordVersion       = uint8(1)
	requestDigestDomain        = "muninndb:mcp-receipt-request:v1"
	MaxReceiptOperationIDBytes = 256
)

var (
	ErrInvalidReceiptClaim           = errors.New("mcp authz receipt: invalid claim")
	ErrInvalidReceiptCompletion      = errors.New("mcp authz receipt: invalid completion")
	ErrReceiptCorrupt                = errors.New("mcp authz receipt: corrupt record")
	ErrReceiptConflict               = errors.New("mcp authz receipt: request digest conflict")
	ErrReceiptCollision              = errors.New("mcp authz receipt: lookup identity collision")
	ErrReceiptInconsistentSettlement = errors.New("mcp authz receipt: inconsistent settlement")
)

// RequestDigest is an operation-bound, domain-separated SHA-256 digest of an
// already validated canonical request. Canonicalization remains deliberately
// operation-specific and is not supplied by this storage-free contract.
type RequestDigest struct {
	valid bool
	sum   [sha256.Size]byte
}

func digestCanonicalRequest(operation OperationID, canonical []byte) (RequestDigest, error) {
	if !operation.valid || operation.value == "" || canonical == nil {
		return RequestDigest{}, ErrInvalidReceiptClaim
	}
	h := sha256.New()
	writeDigestFrame(h, []byte(requestDigestDomain))
	writeDigestFrame(h, []byte(operation.value))
	writeDigestFrame(h, canonical)
	var sum [sha256.Size]byte
	copy(sum[:], h.Sum(nil))
	return RequestDigest{valid: true, sum: sum}, nil
}

type digestWriter interface {
	Write([]byte) (int, error)
}

func writeDigestFrame(dst digestWriter, value []byte) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = dst.Write(length[:])
	_, _ = dst.Write(value)
}

// ReceiptClaim binds one opaque client operation ID and request digest to the
// exact vault and versioned mutation operation that authorization produced.
// The digest is not part of lookup identity, so changed payloads with the same
// operation ID are detected as conflicts rather than executed independently.
type ReceiptClaim struct {
	valid           bool
	canonicalVault  string
	vaultIdentity   string
	vaultGeneration uint64
	operation       OperationID
	opID            string
	digest          RequestDigest
}

func NewReceiptClaim(
	authorized AuthorizedOperation,
	scope StableVaultScope,
	opID string,
	canonicalRequest []byte,
) (ReceiptClaim, error) {
	if authorized.validate() != nil || scope.validate() != nil ||
		!scope.matchesAuthorized(authorized) || !validReceiptOperationID(opID) {
		return ReceiptClaim{}, ErrInvalidReceiptClaim
	}
	digest, err := digestCanonicalRequest(authorized.operation, canonicalRequest)
	if err != nil {
		return ReceiptClaim{}, err
	}
	return ReceiptClaim{
		valid:           true,
		canonicalVault:  scope.canonicalVault,
		vaultIdentity:   scope.identity,
		vaultGeneration: scope.generation,
		operation:       authorized.operation,
		opID:            opID,
		digest:          digest,
	}, nil
}

func validReceiptOperationID(opID string) bool {
	return len(opID) >= 1 && len(opID) <= MaxReceiptOperationIDBytes && utf8.ValidString(opID)
}

func (c ReceiptClaim) Vault() string           { return c.canonicalVault }
func (c ReceiptClaim) VaultIdentity() string   { return c.vaultIdentity }
func (c ReceiptClaim) VaultGeneration() uint64 { return c.vaultGeneration }
func (c ReceiptClaim) Operation() OperationID  { return c.operation }
func (c ReceiptClaim) OpID() string            { return c.opID }
func (c ReceiptClaim) RequestDigest() [32]byte { return c.digest.sum }

func (c ReceiptClaim) validate() error {
	if !c.valid || c.canonicalVault == "" || len(c.vaultIdentity) == 0 ||
		len(c.vaultIdentity) > MaxStableVaultIdentityBytes || c.vaultGeneration == 0 ||
		!c.operation.valid || c.operation.value == "" || !validReceiptOperationID(c.opID) || !c.digest.valid {
		return ErrInvalidReceiptClaim
	}
	return nil
}

func (c ReceiptClaim) sameIdentity(other ReceiptClaim) bool {
	return c.valid && other.valid && c.vaultIdentity == other.vaultIdentity &&
		c.vaultGeneration == other.vaultGeneration &&
		c.operation == other.operation && c.opID == other.opID
}

func (c ReceiptClaim) sameDigest(other ReceiptClaim) bool {
	return c.digest.valid && other.digest.valid && c.digest.sum == other.digest.sum
}

// authorizedBy verifies that a freshly revalidated operation and freshly
// resolved stable scope still authorize this original claim. Canonical vault
// names are metadata and may change across a rename; lifecycle identity,
// generation, operation, and opaque operation ID remain binding.
func (c ReceiptClaim) authorizedBy(
	authorized AuthorizedOperation,
	scope StableVaultScope,
) error {
	if err := c.validate(); err != nil {
		return err
	}
	if authorized.validate() != nil || scope.validate() != nil || !scope.matchesAuthorized(authorized) {
		return ErrInvalidReceiptClaim
	}
	if c.operation != authorized.operation {
		return ErrClaimsChanged
	}
	if c.vaultIdentity != scope.identity || c.vaultGeneration != scope.generation {
		return ErrStableVaultScopeChanged
	}
	return nil
}

// ReceiptCompletion is the minimal opaque result seed that a future storage
// transaction must atomically commit with the canonical mutation. It does not
// define target lifecycle, outbox, or response-schema policy.
type ReceiptCompletion struct {
	valid      bool
	targetRef  string
	resultSeed []byte
}

func NewReceiptCompletion(targetRef string, resultSeed []byte) (ReceiptCompletion, error) {
	if targetRef == "" || len(resultSeed) == 0 {
		return ReceiptCompletion{}, ErrInvalidReceiptCompletion
	}
	return ReceiptCompletion{
		valid:      true,
		targetRef:  targetRef,
		resultSeed: bytes.Clone(resultSeed),
	}, nil
}

func (c ReceiptCompletion) TargetRef() string  { return c.targetRef }
func (c ReceiptCompletion) ResultSeed() []byte { return bytes.Clone(c.resultSeed) }

func (c ReceiptCompletion) validate() error {
	if !c.valid || c.targetRef == "" || len(c.resultSeed) == 0 {
		return ErrInvalidReceiptCompletion
	}
	return nil
}

func (c ReceiptCompletion) clone() ReceiptCompletion {
	c.resultSeed = bytes.Clone(c.resultSeed)
	return c
}

type ReceiptState uint8

const (
	ReceiptCommitted ReceiptState = iota + 1
	ReceiptSettled
)

// ReceiptRecord deliberately has no Claimed/Pending state. Without a durable
// lease, fencing token, and takeover protocol, persisting a generic pending
// marker cannot prove whether the canonical mutation committed before a crash.
type ReceiptRecord struct {
	valid      bool
	version    uint8
	claim      ReceiptClaim
	state      ReceiptState
	completion ReceiptCompletion
	envelope   []byte
}

func NewCommittedReceipt(
	claim ReceiptClaim,
	completion ReceiptCompletion,
) (ReceiptRecord, error) {
	if err := claim.validate(); err != nil {
		return ReceiptRecord{}, err
	}
	if err := completion.validate(); err != nil {
		return ReceiptRecord{}, err
	}
	return ReceiptRecord{
		valid:      true,
		version:    receiptRecordVersion,
		claim:      claim,
		state:      ReceiptCommitted,
		completion: completion.clone(),
	}, nil
}

func (r ReceiptRecord) State() ReceiptState           { return r.state }
func (r ReceiptRecord) Claim() ReceiptClaim           { return r.claim }
func (r ReceiptRecord) Completion() ReceiptCompletion { return r.completion.clone() }
func (r ReceiptRecord) Envelope() []byte              { return bytes.Clone(r.envelope) }

func (r ReceiptRecord) clone() ReceiptRecord {
	r.completion = r.completion.clone()
	r.envelope = bytes.Clone(r.envelope)
	return r
}

func (r ReceiptRecord) validate() error {
	if !r.valid || r.version != receiptRecordVersion {
		return ErrReceiptCorrupt
	}
	if err := r.claim.validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrReceiptCorrupt, err)
	}
	if err := r.completion.validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrReceiptCorrupt, err)
	}
	switch r.state {
	case ReceiptCommitted:
		if r.envelope != nil {
			return fmt.Errorf("%w: committed record has replay envelope", ErrReceiptCorrupt)
		}
	case ReceiptSettled:
		if len(r.envelope) == 0 {
			return fmt.Errorf("%w: settled record lacks replay envelope", ErrReceiptCorrupt)
		}
	default:
		return fmt.Errorf("%w: unknown state %d", ErrReceiptCorrupt, r.state)
	}
	return nil
}

type ReceiptEvaluation uint8

const (
	// ReceiptAbsent is informational only. It is never permission to execute;
	// only a future durable atomic acquire/fencing operation may grant that.
	ReceiptAbsent ReceiptEvaluation = iota + 1
	ReceiptResumeCommitted
	ReceiptReplaySettled
	ReceiptEvaluationConflict
	ReceiptEvaluationCollision
)

// EvaluateReceipt is a pure classifier for a record returned from one future
// lookup slot. Corruption is never converted into a cache miss.
func EvaluateReceipt(
	claim ReceiptClaim,
	existing *ReceiptRecord,
) (ReceiptEvaluation, error) {
	if err := claim.validate(); err != nil {
		return 0, err
	}
	if existing == nil {
		return ReceiptAbsent, nil
	}
	if err := existing.validate(); err != nil {
		return 0, err
	}
	if !claim.sameIdentity(existing.claim) {
		return ReceiptEvaluationCollision, ErrReceiptCollision
	}
	if !claim.sameDigest(existing.claim) {
		return ReceiptEvaluationConflict, nil
	}
	switch existing.state {
	case ReceiptCommitted:
		return ReceiptResumeCommitted, nil
	case ReceiptSettled:
		return ReceiptReplaySettled, nil
	default:
		return 0, ErrReceiptCorrupt
	}
}

type ReceiptTransition uint8

const (
	ReceiptTransitionApplied ReceiptTransition = iota + 1
	ReceiptTransitionIdempotent
)

// SettleReceipt applies the only pure forward transition in this slice. A
// future durable implementation must CAS the committed record before storing
// this exact envelope.
func SettleReceipt(
	record ReceiptRecord,
	claim ReceiptClaim,
	envelope []byte,
) (ReceiptRecord, ReceiptTransition, error) {
	if err := record.validate(); err != nil {
		return ReceiptRecord{}, 0, err
	}
	if err := claim.validate(); err != nil {
		return ReceiptRecord{}, 0, err
	}
	if !claim.sameIdentity(record.claim) {
		return ReceiptRecord{}, 0, ErrReceiptCollision
	}
	if !claim.sameDigest(record.claim) {
		return ReceiptRecord{}, 0, ErrReceiptConflict
	}
	if len(envelope) == 0 {
		return ReceiptRecord{}, 0, ErrReceiptInconsistentSettlement
	}
	if record.state == ReceiptSettled {
		if !bytes.Equal(record.envelope, envelope) {
			return ReceiptRecord{}, 0, ErrReceiptInconsistentSettlement
		}
		return record.clone(), ReceiptTransitionIdempotent, nil
	}
	if record.state != ReceiptCommitted {
		return ReceiptRecord{}, 0, ErrReceiptCorrupt
	}
	settled := record.clone()
	settled.state = ReceiptSettled
	settled.envelope = bytes.Clone(envelope)
	return settled, ReceiptTransitionApplied, nil
}

type ReceiptDisposition uint8

const (
	ReceiptExecuted ReceiptDisposition = iota + 1
	ReceiptReplayed
	ReceiptInvocationConflict
)

// ReceiptOutcome is the caller-facing typed result. Conflict intentionally
// carries no target, digest, completion, or prior result data.
type ReceiptOutcome struct {
	valid       bool
	disposition ReceiptDisposition
	envelope    []byte
}

func NewExecutedReceiptOutcome(record ReceiptRecord) (ReceiptOutcome, error) {
	return newSettledReceiptOutcome(ReceiptExecuted, record)
}

func NewReplayedReceiptOutcome(record ReceiptRecord) (ReceiptOutcome, error) {
	return newSettledReceiptOutcome(ReceiptReplayed, record)
}

func newSettledReceiptOutcome(
	disposition ReceiptDisposition,
	record ReceiptRecord,
) (ReceiptOutcome, error) {
	if err := record.validate(); err != nil || record.state != ReceiptSettled {
		if err != nil {
			return ReceiptOutcome{}, err
		}
		return ReceiptOutcome{}, ErrReceiptCorrupt
	}
	return ReceiptOutcome{
		valid:       true,
		disposition: disposition,
		envelope:    bytes.Clone(record.envelope),
	}, nil
}

func NewConflictReceiptOutcome() ReceiptOutcome {
	return ReceiptOutcome{valid: true, disposition: ReceiptInvocationConflict}
}

func (o ReceiptOutcome) Disposition() ReceiptDisposition { return o.disposition }
func (o ReceiptOutcome) Envelope() []byte                { return bytes.Clone(o.envelope) }

func (o ReceiptOutcome) validate() error {
	if !o.valid {
		return ErrReceiptCorrupt
	}
	switch o.disposition {
	case ReceiptExecuted, ReceiptReplayed:
		if len(o.envelope) == 0 {
			return ErrReceiptCorrupt
		}
	case ReceiptInvocationConflict:
		if o.envelope != nil {
			return ErrReceiptCorrupt
		}
	default:
		return ErrReceiptCorrupt
	}
	return nil
}

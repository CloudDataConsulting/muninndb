package authz

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/scrypster/muninndb/internal/auth"
)

func authorizedReceiptOperation(t *testing.T, vault, tool string) AuthorizedOperation {
	t.Helper()
	principal, err := NewPrincipal(PrincipalClaims{
		Kind:          auth.PrincipalAPIKey,
		Vault:         vault,
		Mode:          auth.ModeFull,
		CredentialRef: "sha256:" + vault,
		KeyID:         "key-" + vault,
	})
	if err != nil {
		t.Fatal(err)
	}
	store := &fakePrincipalStore{
		principals: map[string]Principal{principal.CredentialRef(): principal},
		errs:       make(map[string]error),
	}
	current, err := RevalidatePinned(context.Background(), store, principal)
	if err != nil {
		t.Fatal(err)
	}
	session, err := NewSessionPin(current)
	if err != nil {
		t.Fatal(err)
	}
	_, operation, err := AuthorizeOperation(context.Background(), store, session, vault, tool)
	if err != nil {
		t.Fatal(err)
	}
	return operation
}

type staticStableVaultScopeSource struct {
	claims StableVaultScopeClaims
	err    error
}

func (s staticStableVaultScopeSource) ResolveStableVaultScope(
	_ context.Context,
	_ string,
) (StableVaultScopeClaims, error) {
	return s.claims, s.err
}

func stableScopeForOperation(
	t *testing.T,
	operation AuthorizedOperation,
	identity string,
	generation uint64,
) StableVaultScope {
	t.Helper()
	scope, err := ResolveStableVaultScope(
		context.Background(),
		staticStableVaultScopeSource{claims: StableVaultScopeClaims{
			CanonicalVault: operation.Vault(),
			Identity:       identity,
			Generation:     generation,
		}},
		operation,
	)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func testReceiptClaim(t *testing.T, vault, tool, opID, canonical string) ReceiptClaim {
	t.Helper()
	operation := authorizedReceiptOperation(t, vault, tool)
	claim, err := NewReceiptClaim(
		operation,
		stableScopeForOperation(t, operation, "stable:"+vault, 1),
		opID,
		[]byte(canonical),
	)
	if err != nil {
		t.Fatal(err)
	}
	return claim
}

func testReceiptCompletion(t *testing.T) ReceiptCompletion {
	t.Helper()
	completion, err := NewReceiptCompletion("engram:01TEST", []byte("result-seed"))
	if err != nil {
		t.Fatal(err)
	}
	return completion
}

func TestNewReceiptClaimBindsAuthorizedScopeAndCanonicalRequest(t *testing.T) {
	operation := authorizedReceiptOperation(t, "client-a", "muninn_forget")
	scope := stableScopeForOperation(t, operation, "vault-id:01", 7)
	canonical := []byte(`{"id":"01TEST"}`)
	claim, err := NewReceiptClaim(operation, scope, "Op.ID:one/二", canonical)
	if err != nil {
		t.Fatal(err)
	}
	if claim.Vault() != "client-a" || claim.VaultIdentity() != "vault-id:01" ||
		claim.VaultGeneration() != 7 || claim.Operation() != operation.Operation() || claim.OpID() != "Op.ID:one/二" {
		t.Fatalf("claim scope = %#v", claim)
	}
	same, err := NewReceiptClaim(operation, scope, claim.OpID(), canonical)
	if err != nil {
		t.Fatal(err)
	}
	if claim.RequestDigest() != same.RequestDigest() {
		t.Fatal("identical canonical requests produced different digests")
	}
	changed, err := NewReceiptClaim(operation, scope, claim.OpID(), []byte(`{"id":"02OTHER"}`))
	if err != nil {
		t.Fatal(err)
	}
	if claim.RequestDigest() == changed.RequestDigest() {
		t.Fatal("changed canonical request produced identical digest")
	}
	otherOperation := authorizedReceiptOperation(t, "client-a", "muninn_feedback")
	otherScope := stableScopeForOperation(t, otherOperation, "vault-id:01", 7)
	other, err := NewReceiptClaim(otherOperation, otherScope, claim.OpID(), canonical)
	if err != nil {
		t.Fatal(err)
	}
	if claim.RequestDigest() == other.RequestDigest() {
		t.Fatal("operation domain was not bound into request digest")
	}
}

func TestNewReceiptClaimRejectsUnsealedOrMissingInputs(t *testing.T) {
	operation := authorizedReceiptOperation(t, "client-a", "muninn_forget")
	scope := stableScopeForOperation(t, operation, "vault-id:01", 1)
	for name, tc := range map[string]struct {
		authorized AuthorizedOperation
		scope      StableVaultScope
		opID       string
		canonical  []byte
	}{
		"zero capability": {authorized: AuthorizedOperation{}, scope: scope, opID: "op", canonical: []byte("{}")},
		"zero scope":      {authorized: operation, scope: StableVaultScope{}, opID: "op", canonical: []byte("{}")},
		"empty op id":     {authorized: operation, scope: scope, opID: "", canonical: []byte("{}")},
		"absent digest":   {authorized: operation, scope: scope, opID: "op", canonical: nil},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewReceiptClaim(tc.authorized, tc.scope, tc.opID, tc.canonical); !errors.Is(err, ErrInvalidReceiptClaim) {
				t.Fatalf("error = %v, want ErrInvalidReceiptClaim", err)
			}
		})
	}
}

func TestReceiptOperationIDPreservesOpaqueUTF8WithinBound(t *testing.T) {
	operation := authorizedReceiptOperation(t, "client-a", "muninn_forget")
	scope := stableScopeForOperation(t, operation, "vault-id:01", 1)
	for _, opID := range []string{" x ", "MiXeD/二", strings.Repeat("x", MaxReceiptOperationIDBytes)} {
		claim, err := NewReceiptClaim(operation, scope, opID, []byte("{}"))
		if err != nil {
			t.Fatalf("NewReceiptClaim(%q) error = %v", opID, err)
		}
		if claim.OpID() != opID {
			t.Fatalf("op id changed: got %q, want exact %q", claim.OpID(), opID)
		}
	}
	for name, opID := range map[string]string{
		"empty":         "",
		"over boundary": strings.Repeat("x", MaxReceiptOperationIDBytes+1),
		"invalid utf8":  string([]byte{0xff}),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewReceiptClaim(operation, scope, opID, []byte("{}")); !errors.Is(err, ErrInvalidReceiptClaim) {
				t.Fatalf("error = %v, want ErrInvalidReceiptClaim", err)
			}
		})
	}
}

func TestReceiptIdentityUsesStableVaultLifecycleNotCanonicalName(t *testing.T) {
	beforeRename := authorizedReceiptOperation(t, "client-a", "muninn_forget")
	afterRename := authorizedReceiptOperation(t, "client-renamed", "muninn_forget")
	beforeScope := stableScopeForOperation(t, beforeRename, "vault-id:01", 7)
	afterScope := stableScopeForOperation(t, afterRename, "vault-id:01", 7)

	before, err := NewReceiptClaim(beforeRename, beforeScope, "op-1", []byte(`{"id":"01"}`))
	if err != nil {
		t.Fatal(err)
	}
	after, err := NewReceiptClaim(afterRename, afterScope, "op-1", []byte(`{"id":"01"}`))
	if err != nil {
		t.Fatal(err)
	}
	if !before.sameIdentity(after) {
		t.Fatal("same stable identity and generation did not survive canonical rename")
	}
	committed, err := NewCommittedReceipt(before, testReceiptCompletion(t))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := EvaluateReceipt(after, &committed); err != nil || got != ReceiptResumeCommitted {
		t.Fatalf("renamed evaluation = %v, %v", got, err)
	}

	recreatedScope := stableScopeForOperation(t, afterRename, "vault-id:02", 1)
	recreated, err := NewReceiptClaim(afterRename, recreatedScope, "op-1", []byte(`{"id":"01"}`))
	if err != nil {
		t.Fatal(err)
	}
	nextGenerationScope := stableScopeForOperation(t, afterRename, "vault-id:01", 8)
	nextGeneration, err := NewReceiptClaim(afterRename, nextGenerationScope, "op-1", []byte(`{"id":"01"}`))
	if err != nil {
		t.Fatal(err)
	}
	if before.sameIdentity(recreated) || before.sameIdentity(nextGeneration) {
		t.Fatal("delete/recreate identity or generation change reused receipt identity")
	}
}

func TestNewReceiptClaimRejectsStableScopeBoundToDifferentAuthorization(t *testing.T) {
	operationA := authorizedReceiptOperation(t, "client-a", "muninn_forget")
	operationB := authorizedReceiptOperation(t, "client-b", "muninn_forget")
	scopeA := stableScopeForOperation(t, operationA, "vault-id:01", 1)
	if _, err := NewReceiptClaim(operationB, scopeA, "op-1", []byte("{}")); !errors.Is(err, ErrInvalidReceiptClaim) {
		t.Fatalf("mismatched scope error = %v, want ErrInvalidReceiptClaim", err)
	}
}

func TestReceiptCompletionAndRecordOwnMutableInputs(t *testing.T) {
	seed := []byte("result-seed")
	completion, err := NewReceiptCompletion("engram:01TEST", seed)
	if err != nil {
		t.Fatal(err)
	}
	copy(seed, []byte("XXXXXXXXXXX"))
	if got := string(completion.ResultSeed()); got != "result-seed" {
		t.Fatalf("completion retained caller alias: %q", got)
	}
	returned := completion.ResultSeed()
	returned[0] = 'X'
	if got := string(completion.ResultSeed()); got != "result-seed" {
		t.Fatalf("completion getter leaked alias: %q", got)
	}

	claim := testReceiptClaim(t, "client-a", "muninn_forget", "op-1", `{"id":"01"}`)
	record, err := NewCommittedReceipt(claim, completion)
	if err != nil {
		t.Fatal(err)
	}
	envelope := []byte(`{"id":"01TEST","idempotent":false}`)
	settled, transition, err := SettleReceipt(record, claim, envelope)
	if err != nil || transition != ReceiptTransitionApplied {
		t.Fatalf("SettleReceipt = %v, %v", transition, err)
	}
	copy(envelope, bytes.Repeat([]byte{'X'}, len(envelope)))
	if bytes.Contains(settled.Envelope(), []byte("XXX")) {
		t.Fatal("settled record retained caller envelope alias")
	}
	returnedEnvelope := settled.Envelope()
	returnedEnvelope[0] = 'X'
	if settled.Envelope()[0] == 'X' {
		t.Fatal("record envelope getter leaked alias")
	}
}

func TestEvaluateReceiptDistinguishesAbsentResumeReplayConflictCollisionAndCorruption(t *testing.T) {
	claim := testReceiptClaim(t, "client-a", "muninn_forget", "op-1", `{"id":"01"}`)
	if got, err := EvaluateReceipt(claim, nil); err != nil || got != ReceiptAbsent {
		t.Fatalf("absent evaluation = %v, %v", got, err)
	}
	committed, err := NewCommittedReceipt(claim, testReceiptCompletion(t))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := EvaluateReceipt(claim, &committed); err != nil || got != ReceiptResumeCommitted {
		t.Fatalf("committed evaluation = %v, %v", got, err)
	}
	settled, _, err := SettleReceipt(committed, claim, []byte(`{"id":"01TEST"}`))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := EvaluateReceipt(claim, &settled); err != nil || got != ReceiptReplaySettled {
		t.Fatalf("settled evaluation = %v, %v", got, err)
	}

	changedDigest := testReceiptClaim(t, "client-a", "muninn_forget", "op-1", `{"id":"02"}`)
	if got, err := EvaluateReceipt(changedDigest, &settled); err != nil || got != ReceiptEvaluationConflict {
		t.Fatalf("digest conflict = %v, %v", got, err)
	}
	otherScope := testReceiptClaim(t, "client-b", "muninn_forget", "op-1", `{"id":"01"}`)
	if got, err := EvaluateReceipt(otherScope, &settled); got != ReceiptEvaluationCollision || !errors.Is(err, ErrReceiptCollision) {
		t.Fatalf("identity collision = %v, %v", got, err)
	}
	corrupt := settled
	corrupt.version++
	if _, err := EvaluateReceipt(claim, &corrupt); !errors.Is(err, ErrReceiptCorrupt) {
		t.Fatalf("corrupt record error = %v, want ErrReceiptCorrupt", err)
	}
	zeroClaim := ReceiptClaim{}
	if _, err := EvaluateReceipt(zeroClaim, nil); !errors.Is(err, ErrInvalidReceiptClaim) {
		t.Fatalf("zero claim error = %v, want ErrInvalidReceiptClaim", err)
	}
}

func TestReceiptRecordValidationRejectsImpossibleStates(t *testing.T) {
	claim := testReceiptClaim(t, "client-a", "muninn_forget", "op-1", `{"id":"01"}`)
	committed, err := NewCommittedReceipt(claim, testReceiptCompletion(t))
	if err != nil {
		t.Fatal(err)
	}
	settled, _, err := SettleReceipt(committed, claim, []byte(`{"id":"01TEST"}`))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		record ReceiptRecord
	}{
		{name: "zero", record: ReceiptRecord{}},
		{name: "unknown version", record: func() ReceiptRecord {
			record := committed
			record.version++
			return record
		}()},
		{name: "unknown state", record: func() ReceiptRecord {
			record := committed
			record.state = ReceiptState(99)
			return record
		}()},
		{name: "missing claim", record: func() ReceiptRecord {
			record := committed
			record.claim = ReceiptClaim{}
			return record
		}()},
		{name: "missing completion", record: func() ReceiptRecord {
			record := committed
			record.completion = ReceiptCompletion{}
			return record
		}()},
		{name: "committed with envelope", record: func() ReceiptRecord {
			record := committed
			record.envelope = []byte("unexpected")
			return record
		}()},
		{name: "settled missing envelope", record: func() ReceiptRecord {
			record := settled
			record.envelope = nil
			return record
		}()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.record.validate(); !errors.Is(err, ErrReceiptCorrupt) {
				t.Fatalf("validation error = %v, want ErrReceiptCorrupt", err)
			}
			if _, err := EvaluateReceipt(claim, &tc.record); !errors.Is(err, ErrReceiptCorrupt) {
				t.Fatalf("evaluation error = %v, want ErrReceiptCorrupt", err)
			}
		})
	}
}

func TestSettleReceiptIsForwardOnlyAndExactlyIdempotent(t *testing.T) {
	claim := testReceiptClaim(t, "client-a", "muninn_forget", "op-1", `{"id":"01"}`)
	committed, err := NewCommittedReceipt(claim, testReceiptCompletion(t))
	if err != nil {
		t.Fatal(err)
	}
	envelope := []byte(`{"id":"01TEST"}`)
	settled, transition, err := SettleReceipt(committed, claim, envelope)
	if err != nil || transition != ReceiptTransitionApplied || settled.State() != ReceiptSettled {
		t.Fatalf("first settle = %v, %v, state=%v", transition, err, settled.State())
	}
	again, transition, err := SettleReceipt(settled, claim, envelope)
	if err != nil || transition != ReceiptTransitionIdempotent || !bytes.Equal(again.Envelope(), envelope) {
		t.Fatalf("repeat settle = %v, %v", transition, err)
	}
	if _, _, err := SettleReceipt(settled, claim, []byte(`{"id":"DIFFERENT"}`)); !errors.Is(err, ErrReceiptInconsistentSettlement) {
		t.Fatalf("changed envelope error = %v", err)
	}
	changedDigest := testReceiptClaim(t, "client-a", "muninn_forget", "op-1", `{"id":"02"}`)
	if _, _, err := SettleReceipt(committed, changedDigest, envelope); !errors.Is(err, ErrReceiptConflict) {
		t.Fatalf("changed digest error = %v", err)
	}
	otherScope := testReceiptClaim(t, "client-b", "muninn_forget", "op-1", `{"id":"01"}`)
	if _, _, err := SettleReceipt(committed, otherScope, envelope); !errors.Is(err, ErrReceiptCollision) {
		t.Fatalf("changed identity error = %v", err)
	}
}

func TestReceiptOutcomesAreTypedImmutableAndConflictDoesNotLeak(t *testing.T) {
	claim := testReceiptClaim(t, "client-a", "muninn_forget", "op-1", `{"id":"01"}`)
	committed, err := NewCommittedReceipt(claim, testReceiptCompletion(t))
	if err != nil {
		t.Fatal(err)
	}
	settled, _, err := SettleReceipt(committed, claim, []byte(`{"id":"01TEST"}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name        string
		newOutcome  func(ReceiptRecord) (ReceiptOutcome, error)
		disposition ReceiptDisposition
	}{
		{name: "executed", newOutcome: NewExecutedReceiptOutcome, disposition: ReceiptExecuted},
		{name: "replayed", newOutcome: NewReplayedReceiptOutcome, disposition: ReceiptReplayed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			outcome, err := tc.newOutcome(settled)
			if err != nil || outcome.Disposition() != tc.disposition || outcome.validate() != nil {
				t.Fatalf("outcome = %#v, %v", outcome, err)
			}
			envelope := outcome.Envelope()
			envelope[0] = 'X'
			if outcome.Envelope()[0] == 'X' {
				t.Fatal("outcome leaked envelope alias")
			}
		})
	}
	if _, err := NewExecutedReceiptOutcome(committed); !errors.Is(err, ErrReceiptCorrupt) {
		t.Fatalf("committed executed outcome error = %v", err)
	}
	conflict := NewConflictReceiptOutcome()
	if conflict.Disposition() != ReceiptInvocationConflict || conflict.Envelope() != nil || conflict.validate() != nil {
		t.Fatalf("conflict leaked data or was invalid: %#v", conflict)
	}
	if err := (ReceiptOutcome{}).validate(); !errors.Is(err, ErrReceiptCorrupt) {
		t.Fatalf("zero outcome error = %v", err)
	}
}

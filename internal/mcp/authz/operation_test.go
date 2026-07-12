package authz

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/scrypster/muninndb/internal/auth"
)

func TestAuthorizeOperationReturnsSealedMutationCapability(t *testing.T) {
	session, store := testSession(t, auth.ModeFull)
	authorizedContext, operation, err := AuthorizeOperation(
		context.Background(),
		store,
		session,
		"",
		"muninn_forget",
	)
	if err != nil {
		t.Fatal(err)
	}
	if operation.Vault() != "client-a" || operation.Tool() != "muninn_forget" ||
		operation.Operation().String() != "mcp/muninn_forget@v1" {
		t.Fatalf("authorized operation = %#v", operation)
	}
	principal, ok := PrincipalFromContext(authorizedContext)
	if !ok || principal.Vault() != "client-a" || principal.Mode() != auth.ModeFull {
		t.Fatalf("authorized context principal = %#v, %v", principal, ok)
	}
	if _, refreshed, err := operation.Revalidate(context.Background(), store); err != nil ||
		refreshed.Operation() != operation.Operation() {
		t.Fatalf("Revalidate = %#v, %v", refreshed, err)
	}
}

func TestAuthorizeOperationRejectsReadsAndPreservesExistingGates(t *testing.T) {
	fullSession, fullStore := testSession(t, auth.ModeFull)
	if _, _, err := AuthorizeOperation(
		context.Background(), fullStore, fullSession, "", "muninn_status",
	); !errors.Is(err, ErrOperationNotMutation) {
		t.Fatalf("read operation error = %v, want ErrOperationNotMutation", err)
	}
	for _, tool := range []string{"muninn_remember", "muninn_remember_batch"} {
		if _, _, err := AuthorizeOperation(
			context.Background(), fullStore, fullSession, "", tool,
		); !errors.Is(err, ErrEntityPolicyDisabled) {
			t.Errorf("%s error = %v, want ErrEntityPolicyDisabled", tool, err)
		}
	}
	if _, _, err := AuthorizeOperation(
		context.Background(), fullStore, fullSession, "client-b", "muninn_forget",
	); !errors.Is(err, ErrVaultMismatch) {
		t.Fatalf("cross-vault error = %v, want ErrVaultMismatch", err)
	}
	if _, _, err := AuthorizeOperation(
		context.Background(), fullStore, fullSession, "", "muninn_future_tool",
	); !errors.Is(err, ErrUnknownTool) {
		t.Fatalf("unknown tool error = %v, want ErrUnknownTool", err)
	}

	observeSession, observeStore := testSession(t, auth.ModeObserve)
	if _, _, err := AuthorizeOperation(
		context.Background(), observeStore, observeSession, "", "muninn_forget",
	); !errors.Is(err, ErrToolForbidden) {
		t.Fatalf("observe mutation error = %v, want ErrToolForbidden", err)
	}
}

func TestAuthorizedOperationRevalidationFailsClosed(t *testing.T) {
	if _, _, err := (AuthorizedOperation{}).Revalidate(context.Background(), nil); !errors.Is(err, ErrInvalidAuthorizedOperation) {
		t.Fatalf("zero operation error = %v, want ErrInvalidAuthorizedOperation", err)
	}

	session, store := testSession(t, auth.ModeFull)
	_, operation, err := AuthorizeOperation(
		context.Background(), store, session, "", "muninn_forget",
	)
	if err != nil {
		t.Fatal(err)
	}
	store.errs[operation.session.principal.CredentialRef()] = errNotAuthorized
	if _, _, err := operation.Revalidate(context.Background(), store); !errors.Is(err, errNotAuthorized) {
		t.Fatalf("revoked revalidation error = %v, want store denial", err)
	}
}

func TestMutationOperationRegistryHasExactPolicyParity(t *testing.T) {
	seenIDs := make(map[string]string)
	for _, tool := range KnownToolNames() {
		policy, ok := PolicyFor(tool)
		if !ok {
			t.Fatalf("missing policy for %q", tool)
		}
		operation, mapped := mutationOperationIDs[tool]
		if policy.Effect == EffectMutation {
			if !mapped || !operation.valid || operation.value == "" {
				t.Errorf("mutation %q lacks canonical operation ID", tool)
				continue
			}
			if prior, duplicate := seenIDs[operation.value]; duplicate {
				t.Errorf("operation ID %q reused by %q and %q", operation.value, prior, tool)
			}
			seenIDs[operation.value] = tool
			continue
		}
		if mapped {
			t.Errorf("read tool %q unexpectedly has receipt operation %q", tool, operation.value)
		}
	}
	if len(seenIDs) != len(mutationOperationIDs) {
		t.Fatalf("mapped mutation count = %d, registry count = %d", len(seenIDs), len(mutationOperationIDs))
	}
}

func TestResolveStableVaultScopeValidatesExactOpaqueLifecycleClaims(t *testing.T) {
	operation := authorizedReceiptOperation(t, "client-a", "muninn_forget")
	valid := StableVaultScopeClaims{
		CanonicalVault: "client-a",
		Identity:       strings.Repeat("i", MaxStableVaultIdentityBytes),
		Generation:     1,
	}
	scope, err := ResolveStableVaultScope(
		context.Background(),
		staticStableVaultScopeSource{claims: valid},
		operation,
	)
	if err != nil || scope.CanonicalVault() != valid.CanonicalVault ||
		scope.Identity() != valid.Identity || scope.Generation() != valid.Generation {
		t.Fatalf("scope = %#v, %v", scope, err)
	}

	for name, mutate := range map[string]func(*StableVaultScopeClaims){
		"canonical mismatch": func(c *StableVaultScopeClaims) { c.CanonicalVault = "client-b" },
		"empty identity":     func(c *StableVaultScopeClaims) { c.Identity = "" },
		"identity too long": func(c *StableVaultScopeClaims) {
			c.Identity = strings.Repeat("i", MaxStableVaultIdentityBytes+1)
		},
		"zero generation": func(c *StableVaultScopeClaims) { c.Generation = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			claims := valid
			mutate(&claims)
			if _, err := ResolveStableVaultScope(
				context.Background(),
				staticStableVaultScopeSource{claims: claims},
				operation,
			); !errors.Is(err, ErrInvalidStableVaultScope) {
				t.Fatalf("error = %v, want ErrInvalidStableVaultScope", err)
			}
		})
	}

	resolverErr := errors.New("vault catalog unavailable")
	if _, err := ResolveStableVaultScope(
		context.Background(),
		staticStableVaultScopeSource{err: resolverErr},
		operation,
	); !errors.Is(err, resolverErr) {
		t.Fatalf("resolver error = %v", err)
	}
	if _, err := ResolveStableVaultScope(context.Background(), nil, operation); !errors.Is(err, ErrInvalidStableVaultScope) {
		t.Fatalf("nil resolver error = %v", err)
	}
}

package authz

import (
	"context"
	"errors"
	"fmt"
)

var (
	ErrInvalidAuthorizedOperation = errors.New("mcp authz: invalid authorized operation")
	ErrOperationNotMutation       = errors.New("mcp authz: receipt operation must be a mutation")
	ErrOperationMappingMissing    = errors.New("mcp authz: canonical operation mapping missing")
	ErrInvalidStableVaultScope    = errors.New("mcp authz: invalid stable vault scope")
	ErrStableVaultScopeChanged    = errors.New("mcp authz: stable vault scope changed")
)

// MaxStableVaultIdentityBytes bounds an opaque, resolver-owned vault identity.
// The contract deliberately does not prescribe its format or derive it from a
// mutable/reusable vault name.
const MaxStableVaultIdentityBytes = 256

// OperationID is a versioned, canonical receipt operation identifier. Its
// fields are private so a caller cannot substitute an arbitrary operation for
// the tool that was authorized.
type OperationID struct {
	valid bool
	value string
}

func (o OperationID) String() string { return o.value }

// mutationOperationIDs is deliberately explicit. Adding or renaming a
// mutation tool must also make a conscious decision about its durable
// operation identity and request-schema version.
var mutationOperationIDs = map[string]OperationID{
	"muninn_remember":           {valid: true, value: "mcp/muninn_remember@v1"},
	"muninn_remember_batch":     {valid: true, value: "mcp/muninn_remember_batch@v1"},
	"muninn_forget":             {valid: true, value: "mcp/muninn_forget@v1"},
	"muninn_link":               {valid: true, value: "mcp/muninn_link@v1"},
	"muninn_evolve":             {valid: true, value: "mcp/muninn_evolve@v1"},
	"muninn_consolidate":        {valid: true, value: "mcp/muninn_consolidate@v1"},
	"muninn_decide":             {valid: true, value: "mcp/muninn_decide@v1"},
	"muninn_restore":            {valid: true, value: "mcp/muninn_restore@v1"},
	"muninn_state":              {valid: true, value: "mcp/muninn_state@v1"},
	"muninn_retry_enrich":       {valid: true, value: "mcp/muninn_retry_enrich@v1"},
	"muninn_entity_state":       {valid: true, value: "mcp/muninn_entity_state@v1"},
	"muninn_entity_state_batch": {valid: true, value: "mcp/muninn_entity_state_batch@v1"},
	"muninn_remember_tree":      {valid: true, value: "mcp/muninn_remember_tree@v1"},
	"muninn_add_child":          {valid: true, value: "mcp/muninn_add_child@v1"},
	"muninn_merge_entity":       {valid: true, value: "mcp/muninn_merge_entity@v1"},
	"muninn_replay_enrichment":  {valid: true, value: "mcp/muninn_replay_enrichment@v1"},
	"muninn_feedback":           {valid: true, value: "mcp/muninn_feedback@v1"},
}

// AuthorizedOperation is a sealed, freshly authorized mutation capability.
// It is intentionally not an execution or persistence capability: a future
// atomic store must still define its own fencing and durable commit contract.
type AuthorizedOperation struct {
	valid     bool
	vault     string
	tool      string
	operation OperationID
	session   SessionPin
}

func (a AuthorizedOperation) Vault() string          { return a.vault }
func (a AuthorizedOperation) Tool() string           { return a.tool }
func (a AuthorizedOperation) Operation() OperationID { return a.operation }

func (a AuthorizedOperation) validate() error {
	if !a.valid || a.vault == "" || a.tool == "" || !a.operation.valid || a.operation.value == "" || !a.session.principal.valid {
		return ErrInvalidAuthorizedOperation
	}
	return nil
}

func (a AuthorizedOperation) sameCapability(other AuthorizedOperation) bool {
	return a.validate() == nil && other.validate() == nil &&
		a.vault == other.vault && a.tool == other.tool && a.operation == other.operation &&
		a.session.principal.claimsEqual(other.session.principal)
}

// StableVaultScopeClaims are supplied by a future vault-catalog boundary.
// Identity is an opaque, stable identifier. Generation must increase when a
// deleted identity is recreated, preventing old operation IDs from binding to
// a different vault lifecycle. CanonicalVault remains display/routing metadata
// and is intentionally not durable receipt identity.
type StableVaultScopeClaims struct {
	CanonicalVault string
	Identity       string
	Generation     uint64
}

// StableVaultScopeSource is an unwired, policy-neutral resolver boundary. No
// production implementation is provided in this slice.
type StableVaultScopeSource interface {
	ResolveStableVaultScope(ctx context.Context, canonicalVault string) (StableVaultScopeClaims, error)
}

// StableVaultScope is a sealed lifecycle identity bound to one freshly
// authorized operation. Private fields prevent callers from substituting an
// identity or generation obtained for a different authorization capability.
type StableVaultScope struct {
	valid          bool
	canonicalVault string
	identity       string
	generation     uint64
	authorized     AuthorizedOperation
}

func (s StableVaultScope) CanonicalVault() string { return s.canonicalVault }
func (s StableVaultScope) Identity() string       { return s.identity }
func (s StableVaultScope) Generation() uint64     { return s.generation }

func (s StableVaultScope) validate() error {
	if !s.valid || s.canonicalVault == "" || len(s.identity) == 0 ||
		len(s.identity) > MaxStableVaultIdentityBytes || s.generation == 0 ||
		s.authorized.validate() != nil || s.canonicalVault != s.authorized.vault {
		return ErrInvalidStableVaultScope
	}
	return nil
}

func (s StableVaultScope) matchesAuthorized(authorized AuthorizedOperation) bool {
	return s.validate() == nil && s.authorized.sameCapability(authorized)
}

// ResolveStableVaultScope resolves and validates the current lifecycle scope
// for exactly the canonical vault authorized by operation. Resolver output is
// never normalized: identity is opaque and canonical names must match exactly.
func ResolveStableVaultScope(
	ctx context.Context,
	source StableVaultScopeSource,
	authorized AuthorizedOperation,
) (StableVaultScope, error) {
	if ctx == nil || source == nil || authorized.validate() != nil {
		return StableVaultScope{}, ErrInvalidStableVaultScope
	}
	claims, err := source.ResolveStableVaultScope(ctx, authorized.vault)
	if err != nil {
		return StableVaultScope{}, err
	}
	if err := ctx.Err(); err != nil {
		return StableVaultScope{}, err
	}
	if claims.CanonicalVault != authorized.vault || len(claims.Identity) == 0 ||
		len(claims.Identity) > MaxStableVaultIdentityBytes || claims.Generation == 0 {
		return StableVaultScope{}, ErrInvalidStableVaultScope
	}
	return StableVaultScope{
		valid:          true,
		canonicalVault: claims.CanonicalVault,
		identity:       claims.Identity,
		generation:     claims.Generation,
		authorized:     authorized,
	}, nil
}

// AuthorizeOperation reuses the existing fail-closed request path, then
// narrows the result to a versioned mutation operation. Read tools cannot
// create receipt claims. Entity-gated mutations such as remember remain
// blocked by AuthorizeRequest before a capability can be returned.
func AuthorizeOperation(
	ctx context.Context,
	store PrincipalStore,
	session SessionPin,
	requestedVault string,
	tool string,
) (context.Context, AuthorizedOperation, error) {
	authorizedContext, vault, decision, err := AuthorizeRequest(
		ctx,
		store,
		session,
		requestedVault,
		tool,
	)
	if err != nil {
		return nil, AuthorizedOperation{}, err
	}
	policy, ok := PolicyFor(decision.Tool)
	if !ok {
		return nil, AuthorizedOperation{}, fmt.Errorf("%w: %q", ErrUnknownTool, decision.Tool)
	}
	if policy.Effect != EffectMutation {
		return nil, AuthorizedOperation{}, fmt.Errorf("%w: %q", ErrOperationNotMutation, decision.Tool)
	}
	operation, ok := mutationOperationIDs[decision.Tool]
	if !ok || !operation.valid || operation.value == "" {
		return nil, AuthorizedOperation{}, fmt.Errorf("%w: %q", ErrOperationMappingMissing, decision.Tool)
	}
	return authorizedContext, AuthorizedOperation{
		valid:     true,
		vault:     vault,
		tool:      decision.Tool,
		operation: operation,
		session:   session,
	}, nil
}

// Revalidate repeats the complete authorization path for this exact pinned
// vault and tool. A zero or forged capability fails before store access.
func (a AuthorizedOperation) Revalidate(
	ctx context.Context,
	store PrincipalStore,
) (context.Context, AuthorizedOperation, error) {
	if err := a.validate(); err != nil {
		return nil, AuthorizedOperation{}, ErrInvalidAuthorizedOperation
	}
	authorizedContext, refreshed, err := AuthorizeOperation(
		ctx,
		store,
		a.session,
		a.vault,
		a.tool,
	)
	if err != nil {
		return nil, AuthorizedOperation{}, err
	}
	if refreshed.operation != a.operation || refreshed.vault != a.vault || refreshed.tool != a.tool {
		return nil, AuthorizedOperation{}, ErrClaimsChanged
	}
	return authorizedContext, refreshed, nil
}

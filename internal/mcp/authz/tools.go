package authz

import (
	"errors"
	"fmt"
	"sort"

	"github.com/scrypster/muninndb/internal/auth"
)

var (
	ErrUnknownTool          = errors.New("mcp authz: unknown tool")
	ErrToolForbidden        = errors.New("mcp authz: tool forbidden for principal mode")
	ErrVaultMismatch        = errors.New("mcp authz: vault mismatch")
	ErrEntityPolicyDisabled = errors.New("mcp authz: entity operations disabled pending isolation policy")
)

type ToolEffect uint8

const (
	EffectRead ToolEffect = iota + 1
	EffectMutation
)

// EntityAccess identifies direct or indirect access to the unresolved global
// entity surface. The registry is capability-based: a tool is gated if any
// valid invocation can read or write entity state.
type EntityAccess uint8

const (
	EntityNone EntityAccess = iota
	EntityRead
	EntityWrite
)

// ToolPolicy is a value copy of one registry entry.
type ToolPolicy struct {
	Name             string
	Effect           ToolEffect
	EntityAccess     EntityAccess
	WriteOnlyAllowed bool
}

var toolPolicies = map[string]ToolPolicy{
	"muninn_remember":           {Name: "muninn_remember", Effect: EffectMutation, EntityAccess: EntityWrite, WriteOnlyAllowed: true},
	"muninn_remember_batch":     {Name: "muninn_remember_batch", Effect: EffectMutation, EntityAccess: EntityWrite, WriteOnlyAllowed: true},
	"muninn_recall":             {Name: "muninn_recall", Effect: EffectRead, EntityAccess: EntityRead},
	"muninn_read":               {Name: "muninn_read", Effect: EffectRead, EntityAccess: EntityRead},
	"muninn_forget":             {Name: "muninn_forget", Effect: EffectMutation},
	"muninn_link":               {Name: "muninn_link", Effect: EffectMutation},
	"muninn_contradictions":     {Name: "muninn_contradictions", Effect: EffectRead},
	"muninn_status":             {Name: "muninn_status", Effect: EffectRead},
	"muninn_evolve":             {Name: "muninn_evolve", Effect: EffectMutation, EntityAccess: EntityWrite},
	"muninn_consolidate":        {Name: "muninn_consolidate", Effect: EffectMutation, EntityAccess: EntityWrite},
	"muninn_session":            {Name: "muninn_session", Effect: EffectRead},
	"muninn_decide":             {Name: "muninn_decide", Effect: EffectMutation, EntityAccess: EntityWrite},
	"muninn_restore":            {Name: "muninn_restore", Effect: EffectMutation, EntityAccess: EntityWrite},
	"muninn_traverse":           {Name: "muninn_traverse", Effect: EffectRead, EntityAccess: EntityRead},
	"muninn_explain":            {Name: "muninn_explain", Effect: EffectRead, EntityAccess: EntityRead},
	"muninn_state":              {Name: "muninn_state", Effect: EffectMutation, EntityAccess: EntityWrite},
	"muninn_list_deleted":       {Name: "muninn_list_deleted", Effect: EffectRead},
	"muninn_retry_enrich":       {Name: "muninn_retry_enrich", Effect: EffectMutation, EntityAccess: EntityWrite},
	"muninn_guide":              {Name: "muninn_guide", Effect: EffectRead},
	"muninn_where_left_off":     {Name: "muninn_where_left_off", Effect: EffectRead},
	"muninn_find_by_entity":     {Name: "muninn_find_by_entity", Effect: EffectRead, EntityAccess: EntityRead},
	"muninn_entity_state":       {Name: "muninn_entity_state", Effect: EffectMutation, EntityAccess: EntityWrite},
	"muninn_entity_state_batch": {Name: "muninn_entity_state_batch", Effect: EffectMutation, EntityAccess: EntityWrite},
	"muninn_remember_tree":      {Name: "muninn_remember_tree", Effect: EffectMutation, EntityAccess: EntityWrite},
	"muninn_recall_tree":        {Name: "muninn_recall_tree", Effect: EffectRead},
	"muninn_entity_clusters":    {Name: "muninn_entity_clusters", Effect: EffectRead, EntityAccess: EntityRead},
	"muninn_export_graph":       {Name: "muninn_export_graph", Effect: EffectRead, EntityAccess: EntityRead},
	"muninn_add_child":          {Name: "muninn_add_child", Effect: EffectMutation, EntityAccess: EntityWrite},
	"muninn_similar_entities":   {Name: "muninn_similar_entities", Effect: EffectRead, EntityAccess: EntityRead},
	"muninn_merge_entity":       {Name: "muninn_merge_entity", Effect: EffectMutation, EntityAccess: EntityWrite},
	"muninn_replay_enrichment":  {Name: "muninn_replay_enrichment", Effect: EffectMutation, EntityAccess: EntityWrite},
	"muninn_provenance":         {Name: "muninn_provenance", Effect: EffectRead},
	"muninn_entity_timeline":    {Name: "muninn_entity_timeline", Effect: EffectRead, EntityAccess: EntityRead},
	"muninn_feedback":           {Name: "muninn_feedback", Effect: EffectMutation},
	"muninn_entity":             {Name: "muninn_entity", Effect: EffectRead, EntityAccess: EntityRead},
	"muninn_entities":           {Name: "muninn_entities", Effect: EffectRead, EntityAccess: EntityRead},
}

func PolicyFor(tool string) (ToolPolicy, bool) {
	policy, ok := toolPolicies[tool]
	return policy, ok
}

// KnownToolNames returns a sorted copy for deterministic parity checks.
func KnownToolNames() []string {
	names := make([]string, 0, len(toolPolicies))
	for name := range toolPolicies {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

type Decision struct {
	Tool    string
	Mode    string
	Observe bool
}

// authorizeTool applies both the conservative mode contract and the mandatory
// disabled entity gate. It requires a freshly revalidated capability; a
// constructed or pinned Principal cannot be authorized. Unknown tools and
// modes fail closed. Write-only mode passes its mode gate only for remember and
// remember_batch, which then remain entity-blocked until isolation is chosen.
func authorizeTool(current RevalidatedPrincipal, tool string) (Decision, error) {
	principal := current.principal
	if !principal.valid {
		return Decision{}, ErrInvalidPrincipal
	}
	policy, ok := PolicyFor(tool)
	if !ok {
		return Decision{}, fmt.Errorf("%w: %q", ErrUnknownTool, tool)
	}

	decision := Decision{Tool: tool, Mode: principal.mode, Observe: principal.mode == auth.ModeObserve}
	modeAllowed := false
	switch principal.mode {
	case auth.ModeFull:
		modeAllowed = true
	case auth.ModeObserve:
		if policy.Effect == EffectRead {
			modeAllowed = true
		}
	case auth.ModeWrite:
		if policy.WriteOnlyAllowed {
			modeAllowed = true
		}
	default:
		return Decision{}, ErrInvalidPrincipal
	}
	if !modeAllowed {
		return Decision{}, fmt.Errorf("%w: %q in %q mode", ErrToolForbidden, tool, principal.mode)
	}
	if policy.EntityAccess != EntityNone {
		return Decision{}, fmt.Errorf("%w: %q", ErrEntityPolicyDisabled, tool)
	}
	return decision, nil
}

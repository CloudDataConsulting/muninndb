package authz

import (
	"errors"
	"testing"

	"github.com/scrypster/muninndb/internal/auth"
)

func TestToolRegistryHasCurrent36Tools(t *testing.T) {
	if got := len(KnownToolNames()); got != 36 {
		t.Fatalf("known tool count = %d, want 36", got)
	}

	readTools := map[string]bool{
		"muninn_recall": true, "muninn_read": true, "muninn_contradictions": true,
		"muninn_status": true, "muninn_session": true, "muninn_traverse": true,
		"muninn_explain": true, "muninn_list_deleted": true, "muninn_guide": true,
		"muninn_where_left_off": true, "muninn_find_by_entity": true,
		"muninn_recall_tree": true, "muninn_entity_clusters": true,
		"muninn_export_graph": true, "muninn_similar_entities": true,
		"muninn_provenance": true, "muninn_entity_timeline": true,
		"muninn_entity": true, "muninn_entities": true,
	}
	entityTools := map[string]bool{
		"muninn_remember": true, "muninn_remember_batch": true,
		"muninn_recall": true, "muninn_read": true, "muninn_evolve": true,
		"muninn_consolidate": true, "muninn_decide": true, "muninn_traverse": true,
		"muninn_explain": true, "muninn_restore": true, "muninn_state": true,
		"muninn_retry_enrich":   true,
		"muninn_find_by_entity": true, "muninn_entity_state": true,
		"muninn_entity_state_batch": true, "muninn_remember_tree": true,
		"muninn_entity_clusters": true, "muninn_export_graph": true,
		"muninn_add_child": true, "muninn_similar_entities": true,
		"muninn_merge_entity": true, "muninn_replay_enrichment": true,
		"muninn_entity_timeline": true, "muninn_entity": true, "muninn_entities": true,
	}
	for _, name := range KnownToolNames() {
		policy, ok := PolicyFor(name)
		if !ok {
			t.Fatalf("KnownToolNames returned unclassified %q", name)
		}
		want := EffectMutation
		if readTools[name] {
			want = EffectRead
		}
		if policy.Effect != want {
			t.Errorf("%s effect = %v, want %v", name, policy.Effect, want)
		}
		if entityTools[name] && policy.EntityAccess == EntityNone {
			t.Errorf("%s must be entity-gated", name)
		}
		if !entityTools[name] && policy.EntityAccess != EntityNone {
			t.Errorf("%s unexpectedly classified as entity access", name)
		}
	}
}

func TestAuthorizeToolModes(t *testing.T) {
	full := testRevalidatedPrincipal(t, auth.ModeFull)
	observe := testRevalidatedPrincipal(t, auth.ModeObserve)
	write := testRevalidatedPrincipal(t, auth.ModeWrite)

	for _, tool := range KnownToolNames() {
		policy, _ := PolicyFor(tool)
		_, err := authorizeTool(full, tool)
		if policy.EntityAccess != EntityNone {
			if !errors.Is(err, ErrEntityPolicyDisabled) {
				t.Errorf("full mode %s error = %v, want ErrEntityPolicyDisabled", tool, err)
			}
		} else if err != nil {
			t.Errorf("full mode rejected non-entity tool %s: %v", tool, err)
		}
	}

	if decision, err := authorizeTool(observe, "muninn_status"); err != nil || !decision.Observe {
		t.Fatalf("observe status = %+v, %v", decision, err)
	}
	if _, err := authorizeTool(observe, "muninn_recall"); !errors.Is(err, ErrEntityPolicyDisabled) {
		t.Fatalf("observe recall error = %v, want ErrEntityPolicyDisabled", err)
	}
	for _, tool := range []string{"muninn_remember", "muninn_forget", "muninn_feedback", "muninn_replay_enrichment"} {
		if _, err := authorizeTool(observe, tool); !errors.Is(err, ErrToolForbidden) {
			t.Errorf("observe %s error = %v, want ErrToolForbidden", tool, err)
		}
	}

	for _, tool := range []string{"muninn_remember", "muninn_remember_batch"} {
		if _, err := authorizeTool(write, tool); !errors.Is(err, ErrEntityPolicyDisabled) {
			t.Errorf("write mode %s error = %v, want ErrEntityPolicyDisabled after mode allow", tool, err)
		}
	}
	for _, tool := range KnownToolNames() {
		if tool == "muninn_remember" || tool == "muninn_remember_batch" {
			continue
		}
		if _, err := authorizeTool(write, tool); !errors.Is(err, ErrToolForbidden) {
			t.Errorf("write mode %s error = %v, want ErrToolForbidden", tool, err)
		}
	}
}

func TestUnknownToolsFailClosed(t *testing.T) {
	if _, ok := PolicyFor("muninn_future_tool"); ok {
		t.Fatal("future tool unexpectedly classified")
	}
	if _, err := authorizeTool(testRevalidatedPrincipal(t, auth.ModeFull), "muninn_future_tool"); !errors.Is(err, ErrUnknownTool) {
		t.Fatalf("AuthorizeTool error = %v, want ErrUnknownTool", err)
	}
}

func TestUnrevalidatedCapabilityCannotAuthorize(t *testing.T) {
	if _, err := authorizeTool(RevalidatedPrincipal{}, "muninn_status"); !errors.Is(err, ErrInvalidPrincipal) {
		t.Fatalf("zero revalidated capability error = %v, want ErrInvalidPrincipal", err)
	}
}

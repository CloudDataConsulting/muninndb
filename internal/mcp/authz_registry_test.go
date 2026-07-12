package mcp

import (
	"testing"

	"github.com/scrypster/muninndb/internal/mcp/authz"
)

// This parity test intentionally lives beside allToolDefinitions. Adding or
// removing an MCP tool must update authz classification in the same change.
func TestAuthorizationRegistryMatchesToolDefinitions(t *testing.T) {
	definitions := allToolDefinitions()
	known := authz.KnownToolNames()
	if len(definitions) != len(known) {
		t.Fatalf("MCP definitions = %d, authorization policies = %d", len(definitions), len(known))
	}

	defined := make(map[string]bool, len(definitions))
	for _, definition := range definitions {
		if defined[definition.Name] {
			t.Fatalf("duplicate MCP tool definition %q", definition.Name)
		}
		defined[definition.Name] = true
		if _, ok := authz.PolicyFor(definition.Name); !ok {
			t.Errorf("MCP tool %q has no authorization policy", definition.Name)
		}
	}
	for _, name := range known {
		if !defined[name] {
			t.Errorf("authorization policy %q has no MCP tool definition", name)
		}
	}
}

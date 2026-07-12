package auth

import (
	"strings"
	"testing"
	"time"
)

func TestValidVaultName(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"default", true},
		{"client-1_memory", true},
		{"a", true},
		{strings.Repeat("a", 64), true},
		{"", false},
		{strings.Repeat("a", 65), false},
		{"Upper", false},
		{" leading", false},
		{"trailing ", false},
		{"slash/name", false},
		{"ümlaut", false},
	}
	for _, tt := range tests {
		if got := ValidVaultName(tt.name); got != tt.want {
			t.Errorf("ValidVaultName(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestAuthStoreRejectsInvalidVaultNamesBeforeLookup(t *testing.T) {
	store := NewStore(openAuthTestDB(t))
	unconfiguredVaultWarnings.Lock()
	unconfiguredVaultWarnings.windowStart = time.Time{}
	unconfiguredVaultWarnings.emitted = 0
	unconfiguredVaultWarnings.Unlock()

	invalid := strings.Repeat("a", 65)
	if _, err := store.GetVaultConfig(invalid); err == nil {
		t.Fatal("expected invalid vault config lookup to fail")
	}
	if _, _, err := store.GenerateAPIKey(invalid, "test", ModeFull, nil); err == nil {
		t.Fatal("expected invalid API key scope to fail")
	}
	unconfiguredVaultWarnings.Lock()
	emitted := unconfiguredVaultWarnings.emitted
	unconfiguredVaultWarnings.Unlock()
	if emitted != 0 {
		t.Fatalf("invalid names consumed unconfigured-vault warning budget: %d", emitted)
	}
}

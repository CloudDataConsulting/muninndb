package auth

// ValidVaultName reports whether name is a canonical vault identifier: 1–64
// ASCII lowercase letters, digits, hyphens, or underscores. Keeping this rule
// in auth prevents transports and direct store callers from disagreeing about
// the identity that a key or vault configuration names.
func ValidVaultName(name string) bool {
	if len(name) == 0 || len(name) > 64 {
		return false
	}
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

package keys

// PrefixLowerBound returns the lower bound for a prefix scan (inclusive).
func PrefixLowerBound(prefix []byte) []byte {
	return prefix
}

// PrefixUpperBound returns the exclusive upper bound for a prefix scan.
// It returns the shortest lexicographic successor, truncating bytes after the
// incremented position. Nil means the prefix has no finite upper bound.
func PrefixUpperBound(prefix []byte) []byte {
	if len(prefix) == 0 {
		return nil
	}

	bound := make([]byte, len(prefix))
	copy(bound, prefix)
	for i := len(bound) - 1; i >= 0; i-- {
		if bound[i] < 0xFF {
			bound[i]++
			return bound[:i+1]
		}
	}
	return nil
}

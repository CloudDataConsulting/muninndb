package storage

// keyspaceScope describes where a physical Pebble key stores its vault scope.
// The registry is deliberately package-private and returned by value: callers
// cannot register new layouts at runtime or obtain a generic raw-write path.
type keyspaceScope uint8

const (
	keyspaceVaultFirst keyspaceScope = iota
	keyspaceGlobal
	keyspaceLifecycle
	keyspaceCrossVault
	keyspaceReserved
)

type keyspaceClearAction uint8

const (
	clearPreserve keyspaceClearAction = iota
	clearRangeDelete
	clearExactPointDelete
	clearValueAwarePointDelete
	clearFilteredPointDelete
)

type keyspaceDescriptor struct {
	id              string
	owner           string
	prefix          byte
	scope           keyspaceScope
	workspaceOffset int
	keyLength       int
	valueLength     int
	clear           keyspaceClearAction
}

// storageKeyspaceRegistry is the single inventory for physical key ownership
// relevant to vault lifecycle clearing. Multiple descriptors intentionally may
// share a first byte: auth currently overlaps storage at 0x11-0x14, and 0x19
// has several unrelated global owners. Namespace migration is tracked
// separately; this registry makes the current layouts explicit and fail-safe.
func storageKeyspaceRegistry() []keyspaceDescriptor {
	return []keyspaceDescriptor{
		{id: "engram", owner: "storage", prefix: 0x01, scope: keyspaceVaultFirst, workspaceOffset: 1, keyLength: 25, clear: clearRangeDelete},
		{id: "metadata", owner: "storage", prefix: 0x02, scope: keyspaceVaultFirst, workspaceOffset: 1, keyLength: 25, clear: clearRangeDelete},
		{id: "association-forward", owner: "storage", prefix: 0x03, scope: keyspaceVaultFirst, workspaceOffset: 1, keyLength: 45, clear: clearRangeDelete},
		{id: "association-reverse", owner: "storage", prefix: 0x04, scope: keyspaceVaultFirst, workspaceOffset: 1, keyLength: 45, clear: clearRangeDelete},
		{id: "fts-posting", owner: "storage", prefix: 0x05, scope: keyspaceVaultFirst, workspaceOffset: 1, clear: clearRangeDelete},
		{id: "trigram", owner: "storage", prefix: 0x06, scope: keyspaceVaultFirst, workspaceOffset: 1, keyLength: 28, clear: clearRangeDelete},
		{id: "hnsw-neighbor", owner: "storage", prefix: 0x07, scope: keyspaceVaultFirst, workspaceOffset: 1, keyLength: 26, clear: clearRangeDelete},
		{id: "fts-stats", owner: "storage", prefix: 0x08, scope: keyspaceVaultFirst, workspaceOffset: 1, keyLength: 14, clear: clearRangeDelete},
		{id: "term-stats", owner: "storage", prefix: 0x09, scope: keyspaceVaultFirst, workspaceOffset: 1, clear: clearRangeDelete},
		{id: "contradiction", owner: "storage", prefix: 0x0A, scope: keyspaceVaultFirst, workspaceOffset: 1, keyLength: 31, clear: clearRangeDelete},
		{id: "state-index", owner: "storage", prefix: 0x0B, scope: keyspaceVaultFirst, workspaceOffset: 1, keyLength: 26, clear: clearRangeDelete},
		{id: "tag-index", owner: "storage", prefix: 0x0C, scope: keyspaceVaultFirst, workspaceOffset: 1, keyLength: 29, clear: clearRangeDelete},
		{id: "creator-index", owner: "storage", prefix: 0x0D, scope: keyspaceVaultFirst, workspaceOffset: 1, keyLength: 29, clear: clearRangeDelete},
		{id: "vault-metadata", owner: "storage", prefix: 0x0E, scope: keyspaceLifecycle, workspaceOffset: 1, keyLength: 9, clear: clearPreserve},
		{id: "vault-name-index", owner: "storage", prefix: 0x0F, scope: keyspaceLifecycle, workspaceOffset: -1, keyLength: 9, clear: clearPreserve},
		{id: "relevance-bucket", owner: "storage", prefix: 0x10, scope: keyspaceVaultFirst, workspaceOffset: 1, keyLength: 26, clear: clearRangeDelete},
		{id: "digest-flags", owner: "storage", prefix: 0x11, scope: keyspaceGlobal, workspaceOffset: -1, keyLength: 17, clear: clearPreserve},
		{id: "auth-admin-user", owner: "auth", prefix: 0x11, scope: keyspaceReserved, workspaceOffset: -1, clear: clearPreserve},
		{id: "coherence", owner: "storage", prefix: 0x12, scope: keyspaceVaultFirst, workspaceOffset: 1, keyLength: 9, clear: clearExactPointDelete},
		{id: "auth-api-key", owner: "auth", prefix: 0x12, scope: keyspaceReserved, workspaceOffset: -1, keyLength: 17, clear: clearPreserve},
		{id: "vault-weights", owner: "storage", prefix: 0x13, scope: keyspaceVaultFirst, workspaceOffset: 1, keyLength: 9, clear: clearExactPointDelete},
		{id: "auth-api-key-vault-index", owner: "auth", prefix: 0x13, scope: keyspaceReserved, workspaceOffset: -1, clear: clearPreserve},
		{id: "association-weight-index", owner: "storage", prefix: 0x14, scope: keyspaceVaultFirst, workspaceOffset: 1, keyLength: 41, valueLength: 4, clear: clearValueAwarePointDelete},
		{id: "auth-vault-config", owner: "auth", prefix: 0x14, scope: keyspaceReserved, workspaceOffset: -1, clear: clearPreserve},
		{id: "vault-count", owner: "storage", prefix: 0x15, scope: keyspaceVaultFirst, workspaceOffset: 1, keyLength: 9, clear: clearRangeDelete},
		{id: "provenance", owner: "storage", prefix: 0x16, scope: keyspaceVaultFirst, workspaceOffset: 1, clear: clearRangeDelete},
		{id: "bucket-migration", owner: "storage", prefix: 0x17, scope: keyspaceVaultFirst, workspaceOffset: 1, keyLength: 9, clear: clearRangeDelete},
		{id: "embedding", owner: "storage", prefix: 0x18, scope: keyspaceVaultFirst, workspaceOffset: 1, keyLength: 25, clear: clearRangeDelete},
		{id: "idempotency-receipt", owner: "storage", prefix: 0x19, scope: keyspaceGlobal, workspaceOffset: -1, keyLength: 9, clear: clearPreserve},
		{id: "replication-log", owner: "replication", prefix: 0x19, scope: keyspaceReserved, workspaceOffset: -1, keyLength: 9, clear: clearPreserve},
		{id: "hebbian-metadata", owner: "cognitive", prefix: 0x19, scope: keyspaceReserved, workspaceOffset: -1, clear: clearPreserve},
		{id: "replication-last-applied", owner: "replication", prefix: 0x19, scope: keyspaceReserved, workspaceOffset: -1, clear: clearPreserve},
		{id: "replication-cluster-metadata", owner: "replication", prefix: 0x19, scope: keyspaceReserved, workspaceOffset: -1, clear: clearPreserve},
		{id: "replication-snapshot-sentinel", owner: "replication", prefix: 0x19, scope: keyspaceReserved, workspaceOffset: -1, clear: clearPreserve},
		{id: "episode", owner: "storage", prefix: 0x1A, scope: keyspaceVaultFirst, workspaceOffset: 1, keyLength: 25, clear: clearRangeDelete},
		{id: "episode-frame", owner: "storage", prefix: 0x1A, scope: keyspaceVaultFirst, workspaceOffset: 1, keyLength: 30, clear: clearRangeDelete},
		{id: "fts-schema-version", owner: "storage", prefix: 0x1B, scope: keyspaceVaultFirst, workspaceOffset: 1, keyLength: 9, clear: clearRangeDelete},
		{id: "pas-transition", owner: "storage", prefix: 0x1C, scope: keyspaceVaultFirst, workspaceOffset: 1, keyLength: 41, clear: clearRangeDelete},
		{id: "embedding-model", owner: "storage", prefix: 0x1D, scope: keyspaceVaultFirst, workspaceOffset: 1, keyLength: 9, clear: clearRangeDelete},
		{id: "ordinal", owner: "storage", prefix: 0x1E, scope: keyspaceVaultFirst, workspaceOffset: 1, keyLength: 41, clear: clearRangeDelete},
		{id: "entity-registry", owner: "storage", prefix: 0x1F, scope: keyspaceGlobal, workspaceOffset: -1, keyLength: 9, clear: clearPreserve},
		{id: "entity-engram-link", owner: "storage", prefix: 0x20, scope: keyspaceVaultFirst, workspaceOffset: 1, keyLength: 33, clear: clearRangeDelete},
		{id: "entity-relationship", owner: "storage", prefix: 0x21, scope: keyspaceVaultFirst, workspaceOffset: 1, keyLength: 42, clear: clearRangeDelete},
		{id: "last-access-index", owner: "storage", prefix: 0x22, scope: keyspaceVaultFirst, workspaceOffset: 1, keyLength: 33, clear: clearRangeDelete},
		{id: "entity-reverse-index", owner: "storage", prefix: 0x23, scope: keyspaceCrossVault, workspaceOffset: 9, keyLength: 33, clear: clearFilteredPointDelete},
		{id: "entity-co-occurrence", owner: "storage", prefix: 0x24, scope: keyspaceVaultFirst, workspaceOffset: 1, keyLength: 25, clear: clearRangeDelete},
		{id: "archive-association", owner: "storage", prefix: 0x25, scope: keyspaceVaultFirst, workspaceOffset: 1, keyLength: 41, clear: clearRangeDelete},
		{id: "relationship-entity-index", owner: "storage", prefix: 0x26, scope: keyspaceVaultFirst, workspaceOffset: 1, keyLength: 33, clear: clearRangeDelete},
		{id: "migration-version", owner: "storage-migrations", prefix: 0xFF, scope: keyspaceReserved, workspaceOffset: -1, clear: clearPreserve},
		{id: "mol-last-sequence", owner: "wal", prefix: 0xFF, scope: keyspaceReserved, workspaceOffset: -1, clear: clearPreserve},
	}
}

type vaultClearStep struct {
	prefix          byte
	action          keyspaceClearAction
	workspaceOffset int
	keyLength       int
	valueLength     int
}

func vaultClearPlan() []vaultClearStep {
	steps := make([]vaultClearStep, 0, 32)
	seen := make(map[[2]byte]struct{})
	for _, descriptor := range storageKeyspaceRegistry() {
		if descriptor.owner != "storage" || descriptor.clear == clearPreserve {
			continue
		}
		key := [2]byte{descriptor.prefix, byte(descriptor.clear)}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		steps = append(steps, vaultClearStep{
			prefix:          descriptor.prefix,
			action:          descriptor.clear,
			workspaceOffset: descriptor.workspaceOffset,
			keyLength:       descriptor.keyLength,
			valueLength:     descriptor.valueLength,
		})
	}
	return steps
}

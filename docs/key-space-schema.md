# Key-Space Schema

MuninnDB stores all state in a single Pebble instance using a prefix-partitioned key space. Current storage keys extend through 0x26, with unrelated operational records at 0xFF. A first byte is not always a unique owner: legacy auth/storage overlap exists at 0x11–0x14, and several subsystems share 0x19 and 0xFF. Most storage prefixes are vault-scoped and begin with an eight-byte workspace prefix (`wsPrefix`). A vault's initial workspace is derived from its original name, but rename preserves that persisted workspace.

The immutable lifecycle inventory and clear policy in `internal/storage/keyspace_registry.go` is the code authority for physical ownership relevant to vault clearing. This document is its human-readable companion. Update both before merging a change that introduces or modifies a key layout.

---

## Key Scoping Model

**Vault-scoped keys** follow the pattern: `prefix(1) | wsPrefix(8) | ...payload`. The persisted `wsPrefix` provides constant-size namespace isolation without embedding variable-length vault names in every key. Existing-vault destructive and bulk operations must resolve and validate the persisted 0x0F→0x0E mapping; they must not recompute a workspace from the current name.

**Global keys** follow the pattern: `prefix(1) | ...payload`. These store data that spans vaults (the entity registry, idempotency receipts, vault name index, digest flags).

**Cross-vault keys** are a special case of global keys where the payload includes a `wsPrefix` as a data field (not a namespace prefix). The entity reverse index (0x23) uses this pattern to map entities back to engrams across vaults.

---

## Complete Prefix Table

| Byte | Name | Scope | Key Layout | Durability | Purpose |
|---|---|---|---|---|---|
| 0x01 | Engram | Vault | `ws(8) \| id(16)` | Sync* | Full engram body (ERF v2 encoding). |
| 0x02 | Metadata | Vault | `ws(8) \| id(16)` | Sync* | 248-byte metadata slice (access counts, timestamps, scores, lifecycle state). |
| 0x03 | Assoc Forward | Vault | `ws(8) \| src(16) \| weightComplement(4) \| dst(16)` | NoSync | Association edge, sorted by weight descending (complement encoding). |
| 0x04 | Assoc Reverse | Vault | `ws(8) \| dst(16) \| weightComplement(4) \| src(16)` | NoSync | Reverse association index for incoming-edge queries. |
| 0x05 | FTS Posting | Vault | `ws(8) \| term \| 0x00 \| id(16)` | NoSync | Full-text search posting list. Term is variable-length, null-terminated. |
| 0x06 | Trigram | Vault | `ws(8) \| trigram(3) \| id(16)` | NoSync | Trigram index for fuzzy/substring matching. |
| 0x07 | HNSW Neighbors | Vault | `ws(8) \| id(16) \| layer(1)` | NoSync | HNSW graph node neighbor lists per layer. |
| 0x08 | FTS Global Stats | Vault | `ws(8) \| "stats"` | NoSync | Aggregate FTS statistics (document count, avg length). |
| 0x09 | FTS Term Stats | Vault | `ws(8) \| term` | NoSync | Per-term document frequency for BM25 scoring. |
| 0x0A | Contradiction | Vault | `ws(8) \| conceptHash(4) \| relType(2) \| id(16)` | NoSync | Contradiction detection index. |
| 0x0B | State Index | Vault | `ws(8) \| state(1) \| id(16)` | NoSync | Secondary index on lifecycle state. |
| 0x0C | Tag Index | Vault | `ws(8) \| tagHash(4) \| id(16)` | NoSync | Secondary index on tags. Hash is FNV-1a. |
| 0x0D | Creator Index | Vault | `ws(8) \| creatorHash(4) \| id(16)` | NoSync | Secondary index on creator identifier. |
| 0x0E | Vault Metadata | Vault | `ws(8)` | NoSync | Vault display name and configuration. |
| 0x0F | Vault Name Index | Global | `siphash(name)(8)` | NoSync | Reverse lookup: vault name → workspace prefix. |
| 0x10 | Relevance Bucket | Vault | `ws(8) \| bucket(1) \| id(16)` | NoSync | Secondary index on relevance score. Bucket is inverted for descending scan order. |
| 0x11 | Digest Flags / Auth Admin | Global + reserved overlap | Storage: `id(16)`; auth: `username(variable)` | Mixed | Global digest flags and legacy auth admin records share the byte. Vault clear preserves the entire prefix. |
| 0x12 | Coherence Counter / Auth API Key | Vault + reserved overlap | Storage: `ws(8)`; auth: `storageHash(16)` | Mixed | Vault clear point-deletes only the exact nine-byte coherence key; it never range-deletes this shared prefix. |
| 0x13 | Scoring Weights / Auth Vault Index | Vault + reserved overlap | Storage: `ws(8)`; auth: `vaultName \| 0x00 \| keyID(8)` | Mixed | Vault clear point-deletes only the exact nine-byte weights key. |
| 0x14 | Assoc Weight Lookup / Auth Vault Config | Vault + reserved overlap | Storage: `ws(8) \| src(16) \| dst(16)` with 4-byte value; auth: `vaultName(variable)` with JSON value | Mixed | O(1) association lookup plus auth config. Clear uses value-aware point deletion; physical namespace separation remains required. |
| 0x15 | Vault Engram Count | Vault | `ws(8)` | **Sync** | Engram count for quota enforcement. Must survive crashes. |
| 0x16 | Provenance | Vault | `ws(8) \| id(16) \| ts_ns(8) \| seq(4)` | NoSync | Append-only audit trail entries. |
| 0x17 | Bucket Migration | Vault | `ws(8)` | NoSync | Tracks which relevance-bucket migration version has been applied. |
| 0x18 | Quantized Embedding | Vault | `ws(8) \| id(16)` | NoSync | Standalone quantized vector for similarity search. |
| 0x19 | Shared Global Operations | Global overlap | Multiple layouts; see below | Mixed | Idempotency, replication log/counter/metadata/snapshot state, and Hebbian metadata reservation currently share this byte. Never vault-cleared. |
| 0x1A | Episode Record | Vault | `ws(8) \| episodeID(16)` | NoSync | Episode metadata (create/close lifecycle). |
| 0x1A+0xFF | Episode Frame | Vault | `ws(8) \| episodeID(16) \| 0xFF \| position(4)` | **Sync** | Ordered frame within an episode. 0xFF separator distinguishes frames from the episode record. Atomic batch with FrameCount. |
| 0x1B | FTS Schema Version | Vault | `ws(8)` | NoSync | Tracks FTS schema version for migration gating. |
| 0x1C | PAS Transition | Vault | `ws(8) \| src(16) \| dst(16)` | NoSync | State-transition table for Predictive Associative State machine. |
| 0x1D | Embedding Model | Vault | `ws(8)` | NoSync | Marker recording which embedding model was used for this vault. |
| 0x1E | Ordinal | Vault | `ws(8) \| parentID(16) \| childID(16)` | **Sync** | Parent→child ordering. WriteOrdinal uses Sync. |
| 0x1F | Entity Registry | Global | `nameHash(8)` | NoSync | Global entity record. Confidence-preserving merge on conflict. |
| 0x20 | Entity Forward Link | Vault | `ws(8) \| engramID(16) \| nameHash(8)` | NoSync | Engram→entity link. Always written atomically with 0x23. |
| 0x21 | Entity Relationship | Vault | `ws(8) \| engramID(16) \| fromHash(8) \| relTypeByte(1) \| toHash(8)` | NoSync | Typed relationship between two entities, scoped to an engram. |
| 0x22 | Last Access Index | Vault | `ws(8) \| invertedMillis(8) \| engramID(16)` | NoSync | Derived index sorted most-recent access first. |
| 0x23 | Entity Reverse Index | Cross-vault | `nameHash(8) \| ws(8) \| engramID(16)` | NoSync | Entity←engram reverse lookup across vaults. Always written atomically with 0x20. |
| 0x24 | Entity Co-occurrence | Vault | `ws(8) \| hashA(8) \| hashB(8)` | NoSync | Pairwise entity co-occurrence count. Hash pair is canonically ordered (hashA < hashB). |
| 0x25 | Archived Association | Vault | `ws(8) \| src(16) \| dst(16)` | NoSync | Canonical archived outbound association history. |
| 0x26 | Relationship Entity Index | Vault | `ws(8) \| entityHash(8) \| engramID(16)` | NoSync | Derived reverse index for relationships involving an entity. |
| 0xFF | Shared Operational Reservation | Global overlap | Migration: `"mig_ver"`; MOL: `"last_mol_seq"` | Mixed | Migration runner and memory-operation-log sequence metadata. Never vault-cleared. |

\* Engram (0x01) and Metadata (0x02) default to Sync. When `NoSyncEngrams=true`, they move to NoSync tier (WAL syncer provides ≤10ms durability).

## Auth overlap and lifecycle ownership

Auth and storage use the same Pebble database. Auth owns reserved layouts under 0x11–0x14, while storage owns other layouts under the same first bytes. Until namespace migration separates them:

- storage vault clearing must not delete auth records;
- 0x12 coherence and 0x13 weights use exact nine-byte point deletes;
- 0x14 association-weight records use an exact 41-byte key plus four-byte value match and point deletes, never a range tombstone;
- auth lifecycle cleanup remains auth-owned and must validate both API-key records and vault indexes before one Sync batch;
- these containment rules do not provide durable vault identity, lifecycle generation, or a process-independent write fence.

The 0x19 byte also has multiple owners: the exact nine-byte idempotency receipt overlaps the replication log's exact nine-byte sequence layout; reserved sublayouts hold Hebbian metadata (`0x01`), replication last-applied (`0x02`), cluster/schema metadata (`0x03`), and snapshot completion (`0x10`). Migration issue #138 owns physical separation. Vault lifecycle operations preserve all 0x19 and 0xFF records.

## Vault clear policy

`ClearVault` consumes the immutable registry clear plan. Vault-first namespaces use range tombstones except the shared auth bytes above. The 0x23 reverse index is cross-vault (`ws` at bytes 9:17), so clear validates the current exact 33-byte layout and point-deletes only matching workspace keys in the same Pebble batch. Malformed owned 0x23 layouts abort before the batch commits.

---

## Layer-by-Layer Deep Dive

### Engram and Metadata Layer (0x01, 0x02, 0x18)

The foundational layer. Every piece of knowledge in MuninnDB is an engram — a self-contained record encoded in ERF v2 format (0x01) with a fixed-size metadata sidecar (0x02). The quantized embedding (0x18) stores a compressed vector representation separately from the engram body, allowing similarity search without deserializing the full record. Engram and metadata keys are always written together in the same Pebble batch.

### Association Layer (0x03, 0x04, 0x14)

Weighted, directed edges between engrams. The forward index (0x03) stores edges sorted by weight descending using complement encoding — a Pebble prefix scan from any source engram yields its strongest associations first. The reverse index (0x04) enables incoming-edge queries. The weight lookup key (0x14) provides O(1) access to a specific edge's weight without scanning. All three are written atomically in `WriteAssociation`.

### Full-Text Search Layer (0x05, 0x06, 0x07, 0x08, 0x09, 0x1B)

A self-contained FTS engine built on Pebble primitives. Posting lists (0x05) map terms to engram IDs. Trigram indexes (0x06) support fuzzy and substring queries. HNSW neighbor lists (0x07) back the approximate nearest-neighbor graph for vector search. Global stats (0x08) and per-term stats (0x09) feed BM25 scoring. The schema version marker (0x1B) gates FTS migrations.

### Entity Graph Layer (0x1F, 0x20, 0x21, 0x23, 0x24, 0x26)

Added in the entity extraction pipeline. Entities are globally registered (0x1F) with confidence-preserving merge semantics — if two vaults extract the same entity, the higher confidence wins. Forward links (0x20) and reverse links (0x23) connect engrams to entities bidirectionally and are always written as an atomic pair. Relationship records (0x21) capture typed relations (manages, depends_on, contradicts, etc.) between entity pairs scoped to a source engram. Co-occurrence counts (0x24) track how often two entities appear together, using canonically ordered hash pairs to avoid duplicates.

### Secondary Index Layer (0x0A, 0x0B, 0x0C, 0x0D, 0x10, 0x22)

Derived indexes that accelerate filtered queries. Each maps a single attribute (lifecycle state, tag, creator, relevance score, contradiction relationship) to the set of engram IDs matching that value. These are always rebuildable from engram metadata — they are optimization structures, not source-of-truth data. The relevance bucket index (0x10) uses inverted bucket values so a forward Pebble scan returns the highest-relevance engrams first.

### Configuration and Metadata (0x0E, 0x0F, 0x11, 0x12, 0x13, 0x15, 0x17, 0x19, 0x1D, 0xFF)

Singleton or low-cardinality keys that store per-vault configuration (vault name, scoring weights, migration versions, embedding model marker, coherence counter) and global operational state (vault name index, digest flags, idempotency receipts). The vault engram count (0x15) is the only key in this group that uses `pebble.Sync` — it enforces storage quotas and must survive crashes to prevent over-allocation.

### Structural Layer (0x16, 0x1A, 0x1C, 0x1E)

Keys that encode temporal and structural relationships. Provenance entries (0x16) form an append-only audit log keyed by engram ID, nanosecond timestamp, and sequence number. Episodes (0x1A) group related engrams into sessions; episode frames use a 0xFF separator byte and are synced atomically with their frame count. PAS transitions (0x1C) record state-machine edges. Ordinals (0x1E) define parent→child ordering and are Sync-tier because ordering correctness is critical.

---

## Atomicity Guarantees

Several key groups are always written in the same Pebble `Batch` to maintain cross-prefix consistency:

| Keys | Operation | Guarantee |
|---|---|---|
| 0x01 + 0x02 | `WriteEngram` | Engram body and metadata are never out of sync. |
| 0x20 + 0x23 | `WriteEntityEngramLink` | Forward and reverse entity links are never orphaned. |
| 0x03 + 0x04 + 0x14 | `WriteAssociation` | All three association indexes reflect the same edge state. |
| 0x1A frame + 0x1A FrameCount | `AppendFrame` | Frame content and the episode's frame counter advance atomically. Uses `pebble.Sync`. |

---

## Caching Strategy

| Prefix | Cache | Scope | Eviction | Invalidation |
|---|---|---|---|---|
| 0x01 (Engram) | L1 engram cache | Per-vault | Size-based | Pessimistic — cache entry is evicted *before* the write reaches Pebble. Prevents stale reads on write-path failures. |
| 0x02 (Metadata) | metaCache | Global, keyed by ULID | Size-based | Manual — callers explicitly invalidate after mutation. |
| 0x03 (Assoc Forward) | assocCache | Global | TTL-based | Stale reads are acceptable for traversal workloads. Returns copies (copy-on-return) to prevent caller mutation of cached data. |

All other prefixes are read directly from Pebble with no application-level cache. Pebble's own block cache provides transparent read acceleration for hot keys.

---

## Relationship Type Bytes

The entity relationship prefix (0x21) encodes the relationship type as a single byte in the key. The mapping is fixed and must not be reordered — existing data on disk depends on these values.

| Byte | Relationship Type |
|---|---|
| 0x01 | manages |
| 0x02 | uses |
| 0x03 | depends_on |
| 0x04 | implements |
| 0x05 | created_by |
| 0x06 | part_of |
| 0x07 | causes |
| 0x08 | contradicts |
| 0x09 | supports |
| 0x0A | co_occurs_with |
| 0x0B | caches_with |
| 0xFF | unknown |

---

## Rules for Adding a New Key Space

1. **Pick a prefix byte.** Choose the next unused byte. Check this document, `internal/storage/keyspace_registry.go`, and all persistence packages. Never copy the legacy 0x11–0x14, 0x19, or 0xFF overlap pattern; data may already exist under every reserved layout.

2. **Document it here.** Add a row to the Complete Prefix Table and a description in the appropriate layer section before the code review.

3. **Implement a key construction function and registry descriptor.** Storage key assembly normally lives under `internal/storage/keys`; other owning packages keep their own constructors. Add explicit scope, owner, layout, and clear behavior to the immutable registry. Do not add runtime registration or a generic raw-write API.

4. **Choose a durability tier.** Default to `pebble.NoSync` unless the data is a source of truth that cannot be re-derived. If you choose `pebble.Sync`, document why in the code and add it to `docs/durability-guarantees.md`.

5. **Define atomicity requirements.** If this key must be written atomically with other prefixes, use a single `pebble.Batch` and document the batch group in the Atomicity Guarantees section above.

6. **Consider caching.** If the key will be read on hot paths, evaluate whether an application-level cache is warranted. Document the invalidation strategy.

7. **Write a migration if needed.** If existing databases need to be backfilled, add a numbered migration in the `migrations` package and bump the migration version. The migration must be idempotent.

8. **Test the key layout.** Write a test that round-trips key construction and extraction. Verify sort order if the key encodes ordered fields (weights, timestamps, bucket values).

---

**See also:** [Durability Guarantees](durability-guarantees.md) · [Architecture](architecture.md) · [Entity Graph](entity-graph.md)

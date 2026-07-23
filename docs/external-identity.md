# Durable External Identity

MuninnDB treats `idempotent_id` (REST and MBP; also the gRPC engine adapter once that transport's wire types are repaired) and MCP `op_id` as a durable external identity, not as a temporary request receipt. The identity is scoped to the resolved canonical vault and stored under the 0x27 namespace in the same Pebble batch as the canonical engram.

## Contract

- The first write creates one engram and an immutable `vault + external_id` binding.
- An identical retry returns the original engram ID and original creation timestamp without repeating enrichment, indexing, trigger, counter, or callback side effects.
- Reusing the identity with a changed canonical payload fails closed. REST returns HTTP 409; batch transports report an item error.
- Concurrent identical requests converge on one engram. Concurrent conflicting requests produce one winner and conflict errors for the others.
- The key contains SHA-256 of the exact UTF-8 external ID. The value also retains the full ID, so a theoretical digest collision is detected rather than aliased. IDs are limited to 1024 bytes.
- Empty vault names canonicalize to `default`; stored vault aliases resolve through the existing vault-name index before the 0x27 key is constructed.

The payload digest excludes the vault and external ID because those are represented by the key. `created_at` is normalized to UTC (a zero timestamp is equivalent to omission), and zero confidence/stability normalize to the storage defaults 1/30. Nil and empty optional slices are equivalent; slice order is otherwise significant. Every supported caller-visible write field participates in the digest.

The digest is domain-separated and versioned as `muninndb/external-identity-payload/v1`. Any future canonicalization change must introduce a new record/digest version and retain verification support for existing bindings; it must not reinterpret stored hashes in place.

The version-1 value layout is `version(1) | engram_id(16) | payload_hash(32) | external_id_length(2) | external_id(bytes)`. Decoding validates every length and version before trusting the target.

Caller-owned inline `entities`, engram `relationships`, and `entity_relationships` are currently rejected when an external identity is present. Those records are written by post-commit auxiliary paths today, so accepting them would leave a crash window where the 0x27 binding exists but some caller data does not. Initial MBP `associations` remain supported because they are part of the canonical engram batch. This restriction can be removed only after the auxiliary records join that atomic batch or gain a durable completion/retry protocol.

Legacy global 0x19 MCP receipts remain readable and purgeable for backward compatibility. They are not consulted or written for new external identities because they contain no vault or payload hash and therefore cannot safely prove equivalence.

## Crash and concurrency behavior

Pebble commits the 0x27 binding with the 0x01 engram, 0x02 metadata, and initial indexes in one batch. A failed commit exposes neither side. When `NoSyncEngrams=false` (the default), that batch is fsynced before success is returned. `NoSyncEngrams=true` preserves atomicity but gives the entire batch the documented WAL-sync durability window.

A bounded process-wide mutex supplies conditional-insert semantics on a standalone node; Pebble batches alone do not provide compare-and-set. Context cancellation is checked before lock acquisition, after acquisition, during batch preparation, and before commit.

## Lifecycle and deployment limits

| Operation | Current behavior |
|---|---|
| Soft delete / restore | Binding remains and retries return the same soft-deleted/restored engram. |
| Hard delete | Binding and engram are deleted in one batch; the external ID can then create a new engram. |
| Clear / delete vault | All vault-scoped 0x27 bindings are cleared with the vault. |
| Clone / merge / export | Fails before copying if the source vault has external identities. A collision/portability policy must land first. |
| Import | Rejects archives containing 0x27 keys. Current exports cannot create such archives. |
| Cluster replication | Cluster startup/activation fails if 0x27 records already exist, and external-identity writes fail while cluster mode is enabled. The 0x27 batch must join the replication protocol before this can be enabled. |
| gRPC wire transport | The adapter preserves `idempotent_id`, but the repository's hand-written protobuf message types do not currently implement the protobuf reflection contract. Do not claim wire-level gRPC support until that independent blocker is fixed and authenticated. |

These restrictions are deliberate: silently dropping, overwriting, or forking an external identity would be worse than declining the operation.

## Landing prerequisites

This storage contract does not replace transport authorization. Land and revalidate the REST mode guards plus the gRPC and MBP vault-auth fixes before exposing externally identified writes through those transports. Rebase after the scoped-statistics change as both branches touch storage contracts and key-space documentation. Until the gRPC wire repair is complete, only its adapter—not a usable network path—has this identity behavior.

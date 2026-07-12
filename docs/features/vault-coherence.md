# Vault Coherence Score

## What it does

MuninnDB continuously tracks the health of each vault's memory graph using four incremental counters. These combine into a single 0.0–1.0 coherence score that tells you how "well-organized" the vault's memory is.

**Score of 1.0** = perfectly organized: all engrams are connected, no contradictions, no duplicates, uniform confidence.
**Score of 0.0** = maximum disorder: all engrams are isolated orphans with contradictions and duplicates everywhere.

## Why it matters

Most databases give you storage metrics (bytes used, index size, row count). MuninnDB gives you a **cognitive health metric** — a measure of whether your memory is actually useful, not just filled. A low coherence score is an actionable signal:

- **High orphan ratio** → write more engrams with tags, or manually link existing ones.
- **High contradiction density** → run contradiction resolution.
- **High duplication pressure** → call `CONSOLIDATE` on near-duplicate clusters.
- **High temporal variance** → some memories are fading while others are active; consider archiving stale ones.

## How it works

### Incremental Counters (no full scans)

Coherence is computed in O(1) from atomic counters updated at every write/link/contradiction event:

| Counter | Updated when |
|---------|-------------|
| `TotalEngrams` | Every write |
| `OrphanCount` | Write (↑), first link created (↓), last link deleted (↑) |
| `Contradictions` | Contradiction detected (↑), resolved (↓) |
| `RefinesCount` | REFINES link created (↑), deleted (↓) |
| `ConfidenceSum/SumSq` | Every write + confidence update (Welford variance) |

### Formula

```
coherence = 1.0 - (orphanRatio × 0.3
                 + contradictionDensity × 0.3
                 + temporalVariance × 0.2
                 + duplicationPressure × 0.2)
```

All components are clamped to [0, 1] before combining.

## What is new / never done before (to our knowledge)

A **cognitive health score native to the memory model** has not been implemented in any database we are aware of. Traditional database health metrics measure infrastructure (disk I/O, query time, cache hit rate). MuninnDB's coherence score measures the **semantic quality of the stored knowledge** — a fundamentally different class of metric that only makes sense in a cognitive data model.

## API

Vault-scoped `GET /api/stats` intentionally omits coherence until the live
registry, clone/merge/import jobs, and canonical cardinality can be reconciled
as one source of truth. It currently returns only values that can be stated
exactly:

```json
{
  "engram_count": 1842,
  "vault_count": 1,
  "stats_scope": "vault",
  "storage_bytes": 0,
  "storage_bytes_available": false,
  "index_size_available": false
}
```

Vault-authenticated stats responses include only the requested vault. Pebble
does not expose truthful per-vault disk or index size measurements, so their
availability fields are `false` and clients must render them as unavailable;
the numeric zeroes are retained only for wire compatibility. Internal/admin
calls that omit the vault retain the legacy database-wide aggregate response
with `stats_scope: "global"`, `storage_bytes_available: true`, and incremental
coherence diagnostics. Those global coherence values are operational counters,
not yet a canonical per-vault contract.

`engram_count` uses the maintained per-vault counter. On first access after a
process start, MuninnDB reconciles that counter once from canonical engram keys;
subsequent stats requests are constant-time and writes update it in memory.

SDK coherence fields remain optional so clients can read legacy/global
responses, but applications must not expect them on a vault-scoped response.

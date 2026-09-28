# ADR 0018 — Sharded in-memory concurrency and checked heapbytes accounting

- **Status**: accepted
- **Date**: 2026-09-27
- **Phase**: 4 — Answer cache

## Context

The answer cache serves high-throughput queries across concurrent UDP and TCP worker tasks
on a single host. A single global `RwLock` or `Mutex` over the entire cache would serialise
lookups and updates, creating thread contention bottlenecks. Conversely, wholesale atomic
pointer replacement (`ArcSwap`, as used for filtering matchers) is unsuitable because the
cache undergoes continuous granular mutations on every cache miss.

Furthermore, running on resource-constrained hardware alongside in-memory adblock matchers
(projected at 45–75MB per million domains) requires strict upper bounds on both entry count
and estimated memory usage. Because workspace-wide lint rules enforce
`arithmetic_side_effects = deny`, any manually accumulated byte counter must not be
susceptible to integer overflow or underflow.

## Decision

**Implement a sharded in-memory cache protected by granular `RwLock`s with no lock held
across an `.await`, enforce hard capacity bounds via two-phase eviction, and wrap byte
accounting in a checked `HeapBytes` newtype.**

- **Sharding**: The store distributes cache entries across an array of shards (default 32)
  based on the hash of the `CacheKey`. Each shard owns an independent `RwLock<ShardInner>`.
- **Synchronous locking**: Lock acquisition is strictly synchronous; locks are never held
  across asynchronous suspension points (`.await`).
- **Two-phase eviction**: When a shard exceeds its capacity limit (either max entries or
  max bytes), it performs bounded eviction in two passes:
  1. *Expired pass*: Sweeps and reclaims entries that have already expired against the
     current `Instant`.
  2. *LRU fresh pass*: If still over capacity, evicts least-recently-used fresh entries.
- **Checked arithmetic with `HeapBytes`**: Manual byte accounting is wrapped in the
  `HeapBytes` newtype. `HeapBytes::checked_add` returns
  `CacheError::ByteAccountingOverflow` on overflow, and `HeapBytes::saturating_sub`
  saturates at zero on eviction.

## Consequences

- Read and write contention is minimized across concurrent query workers.
- The cache cannot trigger an out-of-memory condition on low-resource hardware; memory
  growth is bounded deterministically.
- Expiries and evictions are separately observable through atomic statistics
  (`CacheStats::expired` vs `CacheStats::evicted`).
- No unchecked arithmetic exists on the memory accounting hot path, strictly conforming to
  workspace lints.

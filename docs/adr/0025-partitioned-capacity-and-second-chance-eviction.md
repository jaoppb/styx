# ADR 0025 — Partitioned capacity and second-chance eviction

- **Status**: accepted
- **Date**: 2026-10-16
- **Phase**: 4 — Answer cache
- **Extends**: [ADR 0018](0018-sharded-in-memory-concurrency-and-checked-heapbytes-accounting.md)
- **Supersedes in part**: [ADR 0018](0018-sharded-in-memory-concurrency-and-checked-heapbytes-accounting.md),
  its two-phase eviction (an expired pass, then a least-recently-used pass), and its
  Consequences line that memory growth is bounded deterministically. ADR 0018 is not
  edited; read it with this record.

## Context

[ADR 0018](0018-sharded-in-memory-concurrency-and-checked-heapbytes-accounting.md) promised
hard capacity bounds. Issue #80 found two defects in how `ShardedAnswerCache` kept them:

- `CacheCapacity` was compared with one shard's entry count and bytes, so the cache as a
  whole could hold `shard_count` times what was configured: about 320,000 entries and
  640 MiB at the defaults of 10,000 entries, 20 MiB and 32 shards.
- Every hit took the shard's write lock and ran `VecDeque::retain` over the shard's whole
  recency list, and each admission into a full shard rebuilt that list to sweep expired
  entries. Reads of a hot shard queued behind a scan that grew with the shard.

## Decision

**The configured capacity is split across the shards once, at construction.**
`CacheCapacity::partition` gives each shard `total / shard_count`, and the first
`total % shard_count` shards one more, so the shares sum to exactly the configured entries
and bytes. Each shard enforces only its own share, which makes the whole-cache bound hard
and deterministic under concurrency. Hash skew can make a shard evict while another has
room; that costs effective capacity, not the bound. Shared atomic counters were rejected:
they cannot give a global least-recently-used victim and overshoot transiently between a
check and an act.

**Construction is fallible, and the operator sets the budget.**
`ShardedAnswerCache::new` returns `CacheError::ZeroShards` for no shards,
`CacheError::BudgetBelowShardCount` when there are fewer entries than shards, and
`CacheError::ByteShareBelowFloor` when the smallest byte share could not hold
`MIN_SHARD_BYTES` (256 KiB, one maximum-size answer: a 64 KiB wire message is about four
times that in the heap estimate). Each would leave a shard that holds nothing or refuses
ordinary answers, and a cache that silently stops caching. The `[cache]` section of the
TOML file (`max_entries`, `max_bytes`, `shards`) feeds this check at startup, so a budget
that fails it stops styx with an error naming the minimum total for the chosen shard count.
`with_defaults` stays infallible: a const assertion ties the default budget to the default
shard count and the floor.

**Recency is a CLOCK ring, not a list.** A shard keeps its entries in a slab with an
atomic `visited` bit per slot. A hit sets the bit through a shared reference, so
`lookup` runs entirely under the shard's read lock and takes no write lock and no scan.
Eviction sweeps a hand round the slab: it clears a set bit and moves on, and takes the
first entry whose bit is clear. Each step is O(1) and each set bit costs one step to clear,
so admission is amortised O(1). The slab grows only when no slot is free, and admission
evicts down to the shard's entry share, so the slab never holds more slots than that
share: the hand's sweep is bounded by configuration, not by the peak of past traffic. A
new entry starts unvisited. CLOCK was chosen over SIEVE because the slab is the ring:
removing an arbitrary entry (expiry, overwrite) is clearing its slot and recycling the
index, with no link pointers to keep consistent and nothing to index into.

**The expired sweep is folded into the hand.** The separate full scan is gone. The hand
takes an expired entry on sight, whatever its visited bit, and counts it as `expired`; a
fresh one it takes counts as `evicted`. The two statistics stay separable.

**Room is made before the insert, and an oversized entry is refused.** `admit` removes any
entry already stored under the key, then evicts until one more entry fits, then inserts, so
the entry just admitted is never its own victim. An entry larger than its shard's whole byte
budget is refused after that removal, but before any eviction: it would only empty the shard
to no purpose. The removal comes first so that a refused refresh does not leave the
superseded answer to be served until its TTL runs out; the next lookup is a miss and
re-resolves. A refused entry is not counted as admitted; `CacheStats::rejected_oversized`
counts it and a `debug` event logs it.

**An expired hit is re-checked under the write lock.** `lookup` finds the entry stale under
the read lock and then takes the write lock to purge it. Between the two another thread may
have admitted a fresh entry for the same key, so the purge confirms staleness first.

## Consequences

- The cache never holds more than the configured entries or bytes, in total, including under
  concurrent admission.
- A hit is a read-locked lookup, a clone and one atomic store, so its cost no longer depends
  on how many entries the shard holds. The `cache_hit` benchmark compares 100 and 10,000
  entries per shard, single-threaded and from eight threads; before this record the
  10,000-entry case was three orders of magnitude slower.
- Eviction is second-chance, not strict least-recently-used. An entry hit once since the
  hand last passed survives one more sweep, and an entry hit many times is no safer than
  one hit once.
- An expired entry is no longer preferred over a fresh one for eviction. The hand can take
  an unvisited fresh entry while an expired one sits further round the ring, and that
  expired entry stays until the hand reaches it or a lookup finds it. Restoring
  expired-first would need a structure ordered by deadline, which this record does not add.
- `ShardedAnswerCache::new` can fail, and every caller handles it. A budget that cannot give
  every shard an entry and a maximum-size answer is a configuration error reported at startup,
  not a quietly disabled cache. The byte floor scales with the shard count (8 MiB at 32
  shards), so a small deployment lowers `shards`, which lowers write concurrency.
- An oversized refresh costs one upstream query each time it is asked for, because the old
  answer is gone and the new one is not stored.
- Effective capacity is somewhat below the configured total when keys hash unevenly, most
  visibly for small budgets. Nothing measures that loss.
- `CacheStats` gains `rejected_oversized`.

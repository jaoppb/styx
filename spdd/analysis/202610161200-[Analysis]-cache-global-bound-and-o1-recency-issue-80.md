# Issue #80 — Cache: global capacity bound and O(1) recency

Source: <https://github.com/jaoppb/styx/issues/80>. Files in scope:
`crates/styx-resolution/src/infrastructure/cache/sharded.rs`, `eviction.rs`,
`domain/cache/capacity.rs`, `benches/pipeline.rs`, and a new ADR superseding the
"LRU fresh pass" wording of ADR 0018.

## Problem

1. `CacheCapacity` is checked against one shard's `map.len()` and `bytes`, so the real
   ceiling is `shard_count` times the configured one.
2. Every hit takes the shard write lock and runs `VecDeque::retain` over the recency
   list. `admit` does the same.
3. Not in the issue, found while reading: `Eviction::evict` pass 1 walks and rebuilds
   the whole recency list on every over-capacity admission, so a full cache pays an
   O(n) scan under the write lock on every miss.

## Decisions

- **Bound model: static split per shard.** Each shard gets `max_entries / shard_count`
  and `max_bytes / shard_count`, fixed at construction, with the remainder spread so
  the per-shard budgets sum exactly to the configured total. The bound is hard and
  deterministic; hash skew (a shard evicting while others have room) is accepted.
- **Tiny budget: fallible constructor.** `ShardedAnswerCache::new` returns
  `Result<_, CacheError>` and rejects a budget smaller than `shard_count`. A
  `shard_count` of 0 is rejected too, where it is clamped to 1 today. All call sites
  (tests and `main.rs`) change.
- **Recency: SIEVE/CLOCK with read-lock hits.** Each entry carries an atomic visited
  bit, set on a hit under the existing read lock. `touch_key` and the `VecDeque` go
  away. The policy is no longer strict LRU, so a new ADR supersedes the LRU wording of
  ADR 0018; ADR 0018 itself is not edited except for its status line.
- **Expired sweep: folded into the hand.** The separate full-scan pass is removed. The
  eviction hand evicts an expired entry on sight regardless of its visited bit and
  counts it as `expired`, not `evicted`, so the two stats stay separable. Each
  admission is amortised O(1).
- **Oversized entry: refused before insert.** An entry whose heap size exceeds its
  shard's whole byte budget is not inserted, evicts nothing, is not counted as
  admitted, and gets its own counter (in `AtomicCacheCounters` and `CacheStats`) and a
  `tracing::debug!` event.
- **Bench bar.** Extend `benches/pipeline.rs` with hit-path cases at 100 and 10,000
  entries per shard, each single-threaded and with N threads on a hot key set. Pass
  bar: the 10,000-entry median is within 10% of the 100-entry median in both shapes,
  over at least 10 runs. The PR reports both tables.

## Acceptance tests (fixed by the decisions above)

- `CacheCapacity::new(100, …)` with 32 shards never holds more than 100 entries after
  3,000 admissions, including under concurrent admission.
- The byte bound holds the same way.
- `new` rejects `max_entries` or `max_bytes` below `shard_count`, and a `shard_count`
  of 0.
- An oversized entry is refused, evicts nothing and bumps the new counter.
- An expired entry reached by the hand is counted as `expired`, never `evicted`.

## Non-goals

- A global LRU or any cross-shard eviction. Eviction stays per shard.
- Shared atomic counters for the bound.
- Rebalancing budgets between shards to correct skew.
- Adding the `lru` crate or any new workspace dependency for recency.
- Changing `shard_index` hashing or the default shard count.

## Open questions

None left open by the grill. Settled during implementation: the ring is CLOCK (the slab is
the ring, so arbitrary removal is clearing a slot), and the visited bit sits in an
infrastructure slot beside `CacheEntry`, not on it.

## Risks

- Hash skew under the static split can hold effective capacity noticeably below the
  configured total on small budgets. Nothing in the tests measures that loss.
- `heap_size` is an estimate; a systematic under-estimate keeps the real heap above
  the configured byte bound whichever bound model is used.
- The N-thread bench is only meaningful on a multi-core machine. On a one- or
  two-core CI runner the contention case may not separate the old and new designs.
- The eviction-order tests (for example `cache_store_tests.rs` with capacity 3 and one
  shard) assert strict LRU order and will need rewriting for second-chance order.
- `Shard`, `Eviction` and `EvictionReport` are re-exported from the crate root, so
  reshaping them is a visible API change inside the workspace.

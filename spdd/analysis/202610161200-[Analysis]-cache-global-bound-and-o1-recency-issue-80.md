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

### Decisions from the review of PR #125

- **Oversized refresh drops the old entry.** Refusing an oversized entry still evicts
  nothing else, but the entry already stored under its key is removed first. A refused
  refresh must not leave the superseded answer being served until its TTL runs out. The
  next lookup is a miss and re-resolves.
- **Capacity is operator-configurable in this PR.** A `[cache]` section sets
  `max_entries`, `max_bytes` and `shards`, wired through `main.rs` and
  `config/styx.example.toml`, so `BudgetBelowShardCount` is a real startup error.
- **Byte floor per shard.** Startup rejects a budget unless every shard's byte share can
  hold one maximum-size answer. The error names the minimum total for the configured
  shard count. `max_bytes >= shard_count` is no longer the rule.
- **Slab bounded by the entry share.** The ring never holds more slots than the shard's
  entry share (a slot is added only when none is free, which means all are live, and
  admission evicts down to the share). The hand's sweep is therefore bounded by
  configuration, and the ADR says "at most the entry share" instead of "whatever the
  shard holds". A test proves the slab length.
- **Bench bar met on one quiet run.** `cache_hit`, 20 samples, load 0.9 to 4.7 on 16
  cores: single-threaded 239.1 ns (100 entries) vs 248.3 ns (10,000), +3.8%; 8 threads
  1.262 µs vs 1.187 µs, -5.9%. Criterion point estimates, one run, not the n >= 10
  median the bar asked for.

## Acceptance tests (fixed by the decisions above)

- `CacheCapacity::new(100, …)` with 32 shards never holds more than 100 entries after
  3,000 admissions, including under concurrent admission.
- The byte bound holds the same way.
- `new` rejects `max_entries` or `max_bytes` below `shard_count`, and a `shard_count`
  of 0.
- An oversized entry is refused, evicts nothing and bumps the new counter.
- An oversized refresh for a key already cached removes the old entry for that key.
- A byte budget below the per-shard floor is rejected at startup, and so is the config
  that produces it.
- The ring's slab length never exceeds the shard's entry share after churn and expiry.
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

Left to implementation, not decided by the review grill:

- `AnswerCache::admit` takes a `Vec<CacheEntry>` under one key, but the shard holds one
  entry per key, and today admission builds at most one entry per outcome. If a second
  entry ever appears, the loop would overwrite the earlier ones while still counting each
  as admitted. Either narrow the type to one entry or define what several entries under
  one key mean.
- A hit deep-clones the `CacheEntry` under the shard's read lock. Returning an `Arc` or
  cloning after the lock is released would shorten the critical section; not measured.

## Risks

- Hash skew under the static split can hold effective capacity noticeably below the
  configured total on small budgets. Nothing in the tests measures that loss.
- `heap_size` is an estimate; a systematic under-estimate keeps the real heap above
  the configured byte bound whichever bound model is used.
- The N-thread bench is only meaningful on a multi-core machine. On a one- or
  two-core CI runner the contention case may not separate the old and new designs.
- The eviction-order tests (for example `cache_store_tests.rs` with capacity 3 and one
  shard) assert strict LRU order and will need rewriting for second-chance order.
- The per-shard byte floor scales with the shard count: 32 shards need a total of 32
  times one maximum-size answer's heap size. A small-memory deployment has to lower
  `shards`, which lowers write concurrency.
- The bench evidence is a single run with a point estimate, so the 10% bar is shown on
  this run only; the single-threaded 100 and 10,000 intervals overlap.
- `Shard`, `Eviction` and `EvictionReport` are re-exported from the crate root, so
  reshaping them is a visible API change inside the workspace.

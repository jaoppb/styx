//! Issue #80: the configured capacity is a bound on the whole cache, not on each shard.

// The helpers below sit outside `#[test]` functions, where clippy's expect allowance stops.
#![allow(clippy::expect_used)]

use std::net::Ipv4Addr;
use std::sync::Arc;

use styx_core::{Clock, TestClock};
use styx_proto::{Message, Name, Question, RData, RecordClass, RecordType, ResourceRecord, Ttl};
use styx_resolution::{
    Admission, AdmissionRequest, AnswerCache, AnswerSource, CacheCapacity, CacheError, CacheKey,
    HeapBytes, Lookup, ShardedAnswerCache, TtlPolicy, MIN_SHARD_BYTES,
};

const SHARDS: usize = 32;
const ADMISSIONS: usize = 3_000;
const BOUND: usize = 100;
const THREADS: usize = 8;
const PER_THREAD: usize = 375;
/// Large enough that only the bound under test can bind.
const UNBOUNDED: usize = usize::MAX;

fn admit_host<C: Clock>(cache: &ShardedAnswerCache<C>, clock: &TestClock, index: usize) {
    admit_named(cache, clock, &format!("h{index:05}.test."));
}

fn admit_named<C: Clock>(cache: &ShardedAnswerCache<C>, clock: &TestClock, name: &str) {
    admit_sized(cache, clock, name, 1);
}

/// Admits one answer for `name` holding `records` distinct addresses, about 16 bytes each.
fn admit_sized<C: Clock>(
    cache: &ShardedAnswerCache<C>,
    clock: &TestClock,
    name: &str,
    records: u32,
) {
    let qname = Name::from_ascii(name).expect("qname");
    let question = Question::new(qname.clone(), RecordType::A, RecordClass::In);
    let mut message = Message::response_to(0x1000, question.clone());
    for address in 0..records {
        message.answers.push(ResourceRecord::new(
            qname.clone(),
            RecordType::A,
            RecordClass::In,
            Ttl::from_secs(300),
            RData::A(Ipv4Addr::from(0x0a00_0000_u32.saturating_add(address))),
        ));
    }
    let request = AdmissionRequest::new(
        &question,
        &message,
        AnswerSource::Upstream,
        clock.now_monotonic(),
    )
    .expect("request");
    let outcome = Admission::new(TtlPolicy::default()).evaluate(request);
    cache.admit(outcome).expect("admit");
}

/// Records per answer that make one entry about 16 KiB, so a few dozen fill a shard's share.
const BULKY: u32 = 1_000;
/// More records than the smallest allowed shard share can hold at 16 bytes apiece.
const OVERSIZED: u32 = 20_000;

/// Few shards keep the smallest allowed budget small enough to fill with a few hundred answers.
const BYTE_TEST_SHARDS: usize = 4;
const BYTE_TEST_ADMISSIONS: usize = 400;

fn byte_budget() -> HeapBytes {
    HeapBytes::new(BYTE_TEST_SHARDS.saturating_mul(MIN_SHARD_BYTES))
}

#[test]
fn entry_bound_holds_across_all_shards() {
    let clock = Arc::new(TestClock::new());
    let capacity = CacheCapacity::new(BOUND, HeapBytes::new(UNBOUNDED));
    let cache = ShardedAnswerCache::new(Arc::clone(&clock), capacity, TtlPolicy::default(), SHARDS)
        .expect("cache");

    for index in 0..ADMISSIONS {
        admit_host(&cache, &clock, index);
    }

    let entries = cache.stats().entries;
    assert!(entries <= BOUND, "{entries} entries held, bound is {BOUND}");
    assert!(entries > 0, "the cache must still hold something");
}

#[test]
fn byte_bound_holds_across_all_shards() {
    let clock = Arc::new(TestClock::new());
    let budget = byte_budget();
    let capacity = CacheCapacity::new(UNBOUNDED, budget);
    let cache = ShardedAnswerCache::new(
        Arc::clone(&clock),
        capacity,
        TtlPolicy::default(),
        BYTE_TEST_SHARDS,
    )
    .expect("cache");

    for index in 0..BYTE_TEST_ADMISSIONS {
        admit_sized(&cache, &clock, &format!("h{index:05}.test."), BULKY);
    }

    let held = cache.stats().bytes;
    assert!(held <= budget, "{held} held, bound is {budget}");
    assert!(
        held > HeapBytes::zero(),
        "the cache must still hold something"
    );
}

/// Admits `PER_THREAD` hosts that no other thread's batch overlaps.
fn admit_batch<C: Clock>(cache: &ShardedAnswerCache<C>, clock: &TestClock, thread: usize) {
    let first = thread.saturating_mul(PER_THREAD);
    for index in first..first.saturating_add(PER_THREAD) {
        admit_host(cache, clock, index);
    }
}

#[test]
fn entry_bound_holds_under_concurrent_admission() {
    let clock = Arc::new(TestClock::new());
    let capacity = CacheCapacity::new(BOUND, HeapBytes::new(UNBOUNDED));
    let cache = ShardedAnswerCache::new(Arc::clone(&clock), capacity, TtlPolicy::default(), SHARDS)
        .expect("cache");

    std::thread::scope(|scope| {
        for thread in 0..THREADS {
            scope.spawn({
                let (cache, clock) = (&cache, &clock);
                move || admit_batch(cache, clock, thread)
            });
        }
    });

    let entries = cache.stats().entries;
    assert!(entries <= BOUND, "{entries} entries held, bound is {BOUND}");
}

#[test]
fn new_rejects_a_budget_that_cannot_be_split() {
    let clock = Arc::new(TestClock::new());
    let build = |entries: usize, bytes: usize, shards: usize| {
        ShardedAnswerCache::new(
            Arc::clone(&clock),
            CacheCapacity::new(entries, HeapBytes::new(bytes)),
            TtlPolicy::default(),
            shards,
        )
        .err()
    };

    assert_eq!(build(10, 1 << 30, 0), Some(CacheError::ZeroShards));
    assert!(matches!(
        build(31, 1 << 30, 32),
        Some(CacheError::BudgetBelowShardCount { .. })
    ));
    assert_eq!(
        build(1000, 31, 32),
        Some(CacheError::ByteShareBelowFloor {
            shards: 32,
            max_bytes: 31,
            minimum_bytes: 32 * MIN_SHARD_BYTES,
        })
    );
    assert_eq!(build(32, 32 * MIN_SHARD_BYTES, 32), None);
}

fn one_shard_at_the_floor(clock: &Arc<TestClock>) -> ShardedAnswerCache<TestClock> {
    let capacity = CacheCapacity::new(10, HeapBytes::new(MIN_SHARD_BYTES));
    ShardedAnswerCache::new(Arc::clone(clock), capacity, TtlPolicy::default(), 1).expect("cache")
}

#[test]
fn an_entry_larger_than_its_shard_budget_is_refused_and_evicts_nothing() {
    let clock = Arc::new(TestClock::new());
    let cache = one_shard_at_the_floor(&clock);
    admit_host(&cache, &clock, 1);
    admit_host(&cache, &clock, 2);
    let before = cache.stats();

    admit_sized(&cache, &clock, "huge.test.", OVERSIZED);

    let after = cache.stats();
    assert_eq!(after.rejected_oversized, 1);
    assert_eq!(after.admitted, before.admitted, "refused, not admitted");
    assert_eq!(after.evicted, 0, "nothing was evicted to make room");
    assert_eq!(after.entries, 2);
    assert_eq!(after.bytes, before.bytes);
}

#[test]
fn an_oversized_refresh_removes_the_entry_it_supersedes() {
    let clock = Arc::new(TestClock::new());
    let cache = one_shard_at_the_floor(&clock);
    admit_sized(&cache, &clock, "huge.test.", 1);
    admit_host(&cache, &clock, 1);
    let name = Name::from_ascii("huge.test.").expect("name");
    let key =
        CacheKey::from_question(&Question::new(name, RecordType::A, RecordClass::In)).expect("key");
    assert!(matches!(cache.lookup(&key), Lookup::Hit(_)));

    admit_sized(&cache, &clock, "huge.test.", OVERSIZED);

    assert!(
        matches!(cache.lookup(&key), Lookup::Miss),
        "the superseded answer must not be served"
    );
    let stats = cache.stats();
    assert_eq!(stats.rejected_oversized, 1);
    assert_eq!(stats.entries, 1, "only the unrelated entry remains");
}

#[test]
fn the_ring_never_holds_more_slots_than_the_entry_share() {
    let clock = Arc::new(TestClock::new());
    let cache = one_shard_at_the_floor(&clock);

    for round in 0..5 {
        for index in 0..25 {
            admit_host(&cache, &clock, round * 25 + index);
        }
        clock.advance(std::time::Duration::from_secs(301));
    }

    let shard = cache.shard(0).expect("shard");
    assert!(shard.slot_count() <= 10, "{} slots", shard.slot_count());
}

#[test]
fn eviction_still_makes_room_when_every_entry_was_recently_hit() {
    let clock = Arc::new(TestClock::new());
    let capacity = CacheCapacity::new(3, HeapBytes::new(1 << 20));
    let cache = ShardedAnswerCache::new(Arc::clone(&clock), capacity, TtlPolicy::default(), 1)
        .expect("cache");
    for index in 0..3 {
        admit_host(&cache, &clock, index);
    }
    for index in 0..3 {
        let name = Name::from_ascii(&format!("h{index:05}.test.")).expect("name");
        let question = Question::new(name, RecordType::A, RecordClass::In);
        let key = CacheKey::from_question(&question).expect("key");
        assert!(matches!(cache.lookup(&key), Lookup::Hit(_)));
    }

    admit_host(&cache, &clock, 3);

    let stats = cache.stats();
    assert_eq!(stats.entries, 3);
    assert_eq!(stats.evicted, 1);
}

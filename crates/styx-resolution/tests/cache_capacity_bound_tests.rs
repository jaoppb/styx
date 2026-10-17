//! Issue #80: the configured capacity is a bound on the whole cache, not on each shard.

// The helpers below sit outside `#[test]` functions, where clippy's expect allowance stops.
#![allow(clippy::expect_used)]

use std::net::Ipv4Addr;
use std::sync::Arc;

use styx_core::{Clock, TestClock};
use styx_proto::{Message, Name, Question, RData, RecordClass, RecordType, ResourceRecord, Ttl};
use styx_resolution::{
    Admission, AdmissionRequest, AnswerCache, AnswerSource, CacheCapacity, CacheError, CacheKey,
    HeapBytes, Lookup, ShardedAnswerCache, TtlPolicy,
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
    let qname = Name::from_ascii(name).expect("qname");
    let question = Question::new(qname.clone(), RecordType::A, RecordClass::In);
    let mut message = Message::response_to(0x1000, question.clone());
    message.answers.push(ResourceRecord::new(
        qname,
        RecordType::A,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::A(Ipv4Addr::new(10, 0, 0, 1)),
    ));
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

fn bytes_of_one_entry() -> HeapBytes {
    let clock = Arc::new(TestClock::new());
    let cache = ShardedAnswerCache::with_defaults(Arc::clone(&clock));
    admit_host(&cache, &clock, 0);
    cache.stats().bytes
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
    let one = bytes_of_one_entry();
    let budget = HeapBytes::new(one.get().saturating_mul(BOUND));
    let capacity = CacheCapacity::new(UNBOUNDED, budget);
    let cache = ShardedAnswerCache::new(Arc::clone(&clock), capacity, TtlPolicy::default(), SHARDS)
        .expect("cache");

    for index in 0..ADMISSIONS {
        admit_host(&cache, &clock, index);
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

    assert_eq!(build(10, 1 << 20, 0), Some(CacheError::ZeroShards));
    assert!(matches!(
        build(31, 1 << 20, 32),
        Some(CacheError::BudgetBelowShardCount { .. })
    ));
    assert!(matches!(
        build(1000, 31, 32),
        Some(CacheError::BudgetBelowShardCount { .. })
    ));
    assert_eq!(build(32, 32, 32), None);
}

#[test]
fn an_entry_larger_than_its_shard_budget_is_refused_and_evicts_nothing() {
    let clock = Arc::new(TestClock::new());
    let short = bytes_of_one_entry();
    let budget = HeapBytes::new(short.get().saturating_mul(2));
    let capacity = CacheCapacity::new(10, budget);
    let cache = ShardedAnswerCache::new(Arc::clone(&clock), capacity, TtlPolicy::default(), 1)
        .expect("cache");
    admit_host(&cache, &clock, 1);
    admit_host(&cache, &clock, 2);
    let before = cache.stats();

    let long_label = "x".repeat(60);
    let oversized = format!("{long_label}.{long_label}.{long_label}.{long_label}.test.");
    admit_named(&cache, &clock, &oversized);

    let after = cache.stats();
    assert_eq!(after.rejected_oversized, 1);
    assert_eq!(after.admitted, before.admitted, "refused, not admitted");
    assert_eq!(after.evicted, 0, "nothing was evicted to make room");
    assert_eq!(after.entries, 2);
    assert_eq!(after.bytes, before.bytes);
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

//! Review of PR #125: shard placement is unpredictable in production and a hit shares the
//! cached entry instead of copying it.

// The helpers below sit outside `#[test]` functions, where clippy's expect allowance stops.
#![allow(clippy::expect_used)]

use std::collections::hash_map::{DefaultHasher, RandomState};
use std::hash::{BuildHasher, BuildHasherDefault};
use std::net::Ipv4Addr;
use std::sync::Arc;

use styx_core::{Clock, TestClock};
use styx_proto::{Message, Name, Question, RData, RecordClass, RecordType, ResourceRecord, Ttl};
use styx_resolution::{
    Admission, AdmissionRequest, AnswerCache, AnswerSource, CacheCapacity, CacheKey, Lookup,
    ShardedAnswerCache, TtlPolicy, DEFAULT_SHARDS,
};

const NAMES: usize = 256;

type FixedSeed = BuildHasherDefault<DefaultHasher>;

fn question(index: usize) -> Question {
    let qname = Name::from_ascii(&format!("h{index:05}.test.")).expect("qname");
    Question::new(qname, RecordType::A, RecordClass::In)
}

fn key(index: usize) -> CacheKey {
    CacheKey::from_question(&question(index)).expect("key")
}

fn admit<C: Clock, S: BuildHasher + Send + Sync>(
    cache: &ShardedAnswerCache<C, S>,
    clock: &TestClock,
    index: usize,
) {
    let question = question(index);
    let mut message = Message::response_to(0x1000, question.clone());
    message.answers.push(ResourceRecord::new(
        question.qname.clone(),
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

fn placements<S: BuildHasher>(cache: &ShardedAnswerCache<TestClock, S>) -> Vec<usize> {
    (0..NAMES)
        .map(|index| cache.shard_index(&key(index)))
        .collect()
}

fn fixed_seed_cache(clock: &Arc<TestClock>) -> ShardedAnswerCache<TestClock, FixedSeed> {
    ShardedAnswerCache::with_hasher(
        Arc::clone(clock),
        CacheCapacity::default(),
        TtlPolicy::default(),
        DEFAULT_SHARDS,
        FixedSeed::default(),
    )
    .expect("cache")
}

#[test]
fn an_injected_fixed_seed_places_keys_the_same_way_every_time() {
    let clock = Arc::new(TestClock::new());
    assert_eq!(
        placements(&fixed_seed_cache(&clock)),
        placements(&fixed_seed_cache(&clock))
    );
}

#[test]
fn the_default_hasher_places_keys_differently_in_each_cache() {
    let build = || -> ShardedAnswerCache<TestClock, RandomState> {
        ShardedAnswerCache::with_defaults(Arc::new(TestClock::new()))
    };
    // Two random seeds agreeing on all 256 names has odds of 32 to the power -256.
    assert_ne!(placements(&build()), placements(&build()));
}

#[test]
fn a_hit_shares_the_cached_entry_instead_of_copying_it() {
    let clock = Arc::new(TestClock::new());
    let cache = fixed_seed_cache(&clock);
    admit(&cache, &clock, 0);

    let (Lookup::Hit(first), Lookup::Hit(second)) = (cache.lookup(&key(0)), cache.lookup(&key(0)))
    else {
        panic!("expected two hits");
    };

    assert!(Arc::ptr_eq(&first, &second));
}

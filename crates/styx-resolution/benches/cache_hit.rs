//! Hit-path cost of `ShardedAnswerCache` as a shard grows (issue #80).
//!
//! Each case fills a 32-shard cache to `N` entries per shard and then reads a small hot
//! set. A hit that scans its shard gets slower as `N` grows; one that does not stays flat.
//! The `threads8` cases read the same hot set from eight threads, which is where a hit
//! that takes the shard's write lock serialises.
//!
//! The `contended` case holds one shard and a large hot answer: reader threads hit it
//! while a writer keeps admitting into the same shard. A hit that copies the answer while
//! holding the read lock makes the queued writer, and the readers behind it, wait on that
//! copy.

#![allow(missing_docs, clippy::expect_used)]

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use styx_core::{Clock, TestClock};
use styx_proto::{Message, Name, Question, RData, RecordClass, RecordType, ResourceRecord, Ttl};
use styx_resolution::{
    Admission, AdmissionRequest, AnswerCache, AnswerSource, CacheCapacity, CacheKey, HeapBytes,
    Lookup, ShardedAnswerCache, TtlPolicy, DEFAULT_SHARDS,
};

const HOT_KEYS: usize = 64;
const THREADS: usize = 8;
/// Readers in the `contended` case; the remaining thread writes.
const CONTENDED_READERS: usize = THREADS - 1;
/// Addresses in the large hot answer, about 16 bytes of heap apiece.
const LARGE_ANSWER_RECORDS: u32 = 2_000;
/// Distinct small names the writer cycles through, more than the shard holds.
const WRITER_NAMES: usize = 4_000;
const CONTENDED_ENTRIES: usize = 1_000;
const CONTENDED_BYTES: usize = 64 * 1024 * 1024;
const ENTRIES_PER_SHARD: [usize; 2] = [100, 10_000];

fn question(index: usize) -> Question {
    let qname = Name::from_ascii(&format!("h{index:07}.bench.")).expect("qname");
    Question::new(qname, RecordType::A, RecordClass::In)
}

fn admit(cache: &ShardedAnswerCache<TestClock>, clock: &TestClock, index: usize) {
    admit_sized(cache, clock, index, 1);
}

/// Admits one answer for host `index` holding `records` distinct addresses.
fn admit_sized(
    cache: &ShardedAnswerCache<TestClock>,
    clock: &TestClock,
    index: usize,
    records: u32,
) {
    let question = question(index);
    let mut message = Message::response_to(0x1000, question.clone());
    for address in 0..records {
        message.answers.push(ResourceRecord::new(
            question.qname.clone(),
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

/// A cache holding about `per_shard` entries in each shard, with room to spare so the
/// fill itself never evicts, and the keys of a hot set to read.
fn filled(per_shard: usize) -> (ShardedAnswerCache<TestClock>, Vec<CacheKey>) {
    let clock = Arc::new(TestClock::new());
    let total = per_shard.saturating_mul(DEFAULT_SHARDS);
    let capacity = CacheCapacity::new(total.saturating_mul(2), HeapBytes::new(usize::MAX));
    let cache = ShardedAnswerCache::new(
        Arc::clone(&clock),
        capacity,
        TtlPolicy::default(),
        DEFAULT_SHARDS,
    )
    .expect("cache");
    for index in 0..total {
        admit(&cache, &clock, index);
    }
    let hot = (0..HOT_KEYS)
        .map(|index| CacheKey::from_question(&question(index)).expect("key"))
        .collect();
    (cache, hot)
}

fn read_hot(cache: &ShardedAnswerCache<TestClock>, hot: &[CacheKey], reads: u64) {
    for key in hot.iter().cycle().take(usize::try_from(reads).unwrap_or(0)) {
        assert!(matches!(black_box(cache.lookup(key)), Lookup::Hit(_)));
    }
}

fn read_hot_from_threads(cache: &ShardedAnswerCache<TestClock>, hot: &[CacheKey], reads: u64) {
    std::thread::scope(|scope| {
        for _ in 0..THREADS {
            scope.spawn(|| read_hot(cache, hot, reads));
        }
    });
}

/// Reader threads hit the large answer in `cache` while a writer admits small entries into
/// the same shard until they finish. Returns the readers' wall time.
fn read_large_while_writing(
    cache: &ShardedAnswerCache<TestClock>,
    clock: &TestClock,
    hot: &CacheKey,
    reads: u64,
) -> Duration {
    let done = AtomicBool::new(false);
    std::thread::scope(|scope| {
        scope.spawn(|| {
            let mut index = 1;
            while !done.load(Ordering::Relaxed) {
                admit(cache, clock, index);
                index = index
                    .checked_rem(WRITER_NAMES)
                    .unwrap_or(0)
                    .saturating_add(1);
            }
        });
        let started = Instant::now();
        let readers: Vec<_> = (0..CONTENDED_READERS)
            .map(|_| scope.spawn(|| read_hot(cache, std::slice::from_ref(hot), reads)))
            .collect();
        for reader in readers {
            reader.join().expect("reader");
        }
        let elapsed = started.elapsed();
        done.store(true, Ordering::Relaxed);
        elapsed
    })
}

fn bench_contended(c: &mut Criterion) {
    let clock = Arc::new(TestClock::new());
    let capacity = CacheCapacity::new(CONTENDED_ENTRIES, HeapBytes::new(CONTENDED_BYTES));
    let cache = ShardedAnswerCache::new(Arc::clone(&clock), capacity, TtlPolicy::default(), 1)
        .expect("cache");
    admit_sized(&cache, &clock, 0, LARGE_ANSWER_RECORDS);
    let hot = CacheKey::from_question(&question(0)).expect("key");

    let mut group = c.benchmark_group("cache_hit");
    group.sample_size(20);
    group.measurement_time(Duration::from_secs(5));
    group.bench_function("contended", |b| {
        b.iter_custom(|iters| read_large_while_writing(&cache, &clock, &hot, iters));
    });
    group.finish();
}

fn bench_cache_hit(c: &mut Criterion) {
    let mut group = c.benchmark_group("cache_hit");
    group.sample_size(20);
    group.measurement_time(Duration::from_secs(5));

    for per_shard in ENTRIES_PER_SHARD {
        let (cache, hot) = filled(per_shard);
        group.bench_function(BenchmarkId::new("single", per_shard), |b| {
            b.iter_custom(|iters| {
                let started = Instant::now();
                read_hot(&cache, &hot, iters);
                started.elapsed()
            });
        });
        group.bench_function(BenchmarkId::new("threads8", per_shard), |b| {
            b.iter_custom(|iters| {
                let started = Instant::now();
                read_hot_from_threads(&cache, &hot, iters);
                started.elapsed()
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_cache_hit, bench_contended);
criterion_main!(benches);

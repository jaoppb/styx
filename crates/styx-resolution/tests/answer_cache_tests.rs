//! End-to-end socket-level tests for the answer cache.

mod harness;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use harness::{CommandableUpstream, DnsClient, TestClock, TestServer, UpstreamBehavior};
use styx_core::UpstreamId;
use styx_proto::{
    Header, Message, Name, Opcode, Question, RecordClass, RecordType, ResponseCode, Ttl,
};
use styx_resolution::{
    Admission, AllowAllFilter, AnswerCache, CacheCapacity, CacheKey, CacheStage, CircuitConfig,
    ClientId, DiscardObserver, Do53Forwarder, EdnsBufferSize, FilterPolicy, FilterVerdict,
    NoLocalRecords, OrderedFailover, PoolMember, ProbeConfig, ProbePolicy, ShardedAnswerCache,
    TtlPolicy, UpstreamPool,
};

fn make_query(name: &str, rtype: RecordType) -> Message {
    let qname = Name::from_ascii(name).unwrap_or_else(|_| Name::root());
    let mut msg = Message::new(Header::new_query(0x1234, Opcode::Query, true));
    msg.header.recursion_desired = true;
    msg.questions
        .push(Question::new(qname, rtype, RecordClass::In));
    msg
}

fn create_member(
    id_str: &str,
    upstream: &CommandableUpstream,
    clock: Arc<TestClock>,
) -> PoolMember<Do53Forwarder<TestClock>> {
    let id = UpstreamId::new(id_str);
    let forwarder = Do53Forwarder::new(
        id.clone(),
        upstream.udp_addr(),
        EdnsBufferSize::default(),
        Duration::from_millis(500),
        Duration::from_millis(500),
        clock,
    );
    let canary = Name::from_ascii("canary.check.").unwrap_or_else(|_| Name::root());
    PoolMember::new(
        id,
        forwarder,
        styx_resolution::Weight::new(1),
        styx_resolution::CanaryConfig {
            qname: canary,
            qtype: RecordType::A,
            timeout: Duration::from_millis(500),
        },
    )
}

fn create_cache_stage_with_admission(
    cache: Arc<ShardedAnswerCache<TestClock>>,
    upstream: &CommandableUpstream,
    clock: Arc<TestClock>,
    admission: Admission,
) -> Arc<
    CacheStage<ShardedAnswerCache<TestClock>, OrderedFailover, Do53Forwarder<TestClock>, TestClock>,
> {
    let member = create_member("up1", upstream, Arc::clone(&clock));
    let pool = Arc::new(UpstreamPool::new(
        vec![member],
        OrderedFailover::new(),
        Arc::clone(&clock),
        CircuitConfig {
            failure_threshold: 3,
            open_cooldown: Duration::from_secs(30),
            half_open_successes: 1,
        },
        ProbePolicy::new(ProbeConfig::default()),
    ));
    Arc::new(CacheStage::with_admission(cache, pool, admission, clock))
}

fn create_cache_stage(
    cache: Arc<ShardedAnswerCache<TestClock>>,
    upstream: &CommandableUpstream,
    clock: Arc<TestClock>,
) -> Arc<
    CacheStage<ShardedAnswerCache<TestClock>, OrderedFailover, Do53Forwarder<TestClock>, TestClock>,
> {
    create_cache_stage_with_admission(cache, upstream, clock, Admission::new(TtlPolicy::default()))
}

#[tokio::test]
async fn test_cache_hit_vs_miss() {
    let clock = Arc::new(TestClock::new());
    let cache = Arc::new(ShardedAnswerCache::with_defaults(Arc::clone(&clock)));
    let upstream = CommandableUpstream::start().await.expect("upstream start");
    let stage = create_cache_stage(Arc::clone(&cache), &upstream, Arc::clone(&clock));

    let mut server = TestServer::boot_with_terminal_and_clock(
        Arc::new(NoLocalRecords::new()),
        Arc::new(AllowAllFilter::new()),
        Arc::new(DiscardObserver::new()),
        stage,
        Arc::clone(&clock),
    )
    .await
    .expect("boot server");

    let client = DnsClient::new();
    let query = make_query("hitmiss.example.com.", RecordType::A);

    // First query: cache miss, forwards to upstream
    let resp1 = client
        .query_udp(server.udp_addr(), &query)
        .await
        .expect("query 1");
    assert_eq!(resp1.header.rcode, ResponseCode::NOERROR);
    assert_eq!(resp1.answers.len(), 1);
    assert_eq!(upstream.query_count(), 1);
    assert_eq!(cache.stats().hits, 0);
    assert_eq!(cache.stats().misses, 1);

    // Second query: cache hit, served without forwarding
    let resp2 = client
        .query_udp(server.udp_addr(), &query)
        .await
        .expect("query 2");
    assert_eq!(resp2.header.rcode, ResponseCode::NOERROR);
    assert_eq!(resp2.answers.len(), 1);
    assert_eq!(upstream.query_count(), 1);
    assert_eq!(cache.stats().hits, 1);
    assert_eq!(cache.stats().misses, 1);

    server.shutdown().await.expect("shutdown");
    upstream.shutdown();
}

#[tokio::test]
async fn test_ttl_expiration_and_clamp() {
    let clock = Arc::new(TestClock::new());
    let ttl_policy = TtlPolicy::new(Ttl::from_secs(5), Ttl::from_secs(30), Ttl::from_secs(10))
        .expect("valid ttl policy");
    let cache = Arc::new(ShardedAnswerCache::new(
        Arc::clone(&clock),
        CacheCapacity::default(),
        ttl_policy,
        4,
    ));
    let upstream = CommandableUpstream::start().await.expect("upstream start");
    let stage = create_cache_stage_with_admission(
        Arc::clone(&cache),
        &upstream,
        Arc::clone(&clock),
        Admission::new(ttl_policy),
    );

    let mut server = TestServer::boot_with_terminal_and_clock(
        Arc::new(NoLocalRecords::new()),
        Arc::new(AllowAllFilter::new()),
        Arc::new(DiscardObserver::new()),
        stage,
        Arc::clone(&clock),
    )
    .await
    .expect("boot server");

    let client = DnsClient::new();
    let query = make_query("clamp.example.com.", RecordType::A);

    // Initial query: cache miss, upstream returns answer, admitted with clamped TTL
    let resp1 = client
        .query_udp(server.udp_addr(), &query)
        .await
        .expect("query 1");
    assert_eq!(resp1.header.rcode, ResponseCode::NOERROR);
    assert_eq!(upstream.query_count(), 1);

    // Advance clock by 10s: TTL decremented by 10s
    clock.advance(Duration::from_secs(10));
    let resp2 = client
        .query_udp(server.udp_addr(), &query)
        .await
        .expect("query 2");
    let answer2 = resp2.answers.first().expect("answer record");
    assert_eq!(answer2.ttl.seconds(), 20);
    assert_eq!(upstream.query_count(), 1);

    // Advance clock by 25s (total 35s > 30s): entry expired, triggers re-query
    clock.advance(Duration::from_secs(25));
    let resp3 = client
        .query_udp(server.udp_addr(), &query)
        .await
        .expect("query 3");
    assert_eq!(resp3.header.rcode, ResponseCode::NOERROR);
    assert_eq!(upstream.query_count(), 2);

    server.shutdown().await.expect("shutdown");
    upstream.shutdown();
}

#[tokio::test]
async fn test_rfc2308_negative_caching_nxdomain_and_nodata() {
    let clock = Arc::new(TestClock::new());
    let cache = Arc::new(ShardedAnswerCache::with_defaults(Arc::clone(&clock)));
    let upstream = CommandableUpstream::start().await.expect("upstream start");
    upstream.set_behavior(UpstreamBehavior::NxdomainWithSoa {
        zone: "example.com.".to_string(),
        ttl: 300,
        minimum: 60,
    });
    let stage = create_cache_stage(Arc::clone(&cache), &upstream, Arc::clone(&clock));

    let mut server = TestServer::boot_with_terminal_and_clock(
        Arc::new(NoLocalRecords::new()),
        Arc::new(AllowAllFilter::new()),
        Arc::new(DiscardObserver::new()),
        stage,
        Arc::clone(&clock),
    )
    .await
    .expect("boot server");

    let client = DnsClient::new();
    let query_nx = make_query("nonexistent.example.com.", RecordType::A);

    // 1. NXDOMAIN with SOA: cached
    let resp1 = client
        .query_udp(server.udp_addr(), &query_nx)
        .await
        .expect("query nx");
    assert_eq!(resp1.header.rcode, ResponseCode::NXDOMAIN);
    assert_eq!(resp1.authorities.len(), 1);
    assert_eq!(upstream.query_count(), 1);

    // Second NXDOMAIN query: served from cache
    let resp2 = client
        .query_udp(server.udp_addr(), &query_nx)
        .await
        .expect("query nx 2");
    assert_eq!(resp2.header.rcode, ResponseCode::NXDOMAIN);
    assert_eq!(upstream.query_count(), 1);
    assert_eq!(cache.stats().negative_hits, 1);

    // 2. NODATA (NOERROR, 0 answers) with SOA: cached
    upstream.set_behavior(UpstreamBehavior::NodataWithSoa {
        zone: "example.com.".to_string(),
        ttl: 300,
        minimum: 60,
    });
    let query_nodata = make_query("nodata.example.com.", RecordType::A);

    let resp3 = client
        .query_udp(server.udp_addr(), &query_nodata)
        .await
        .expect("query nodata");
    assert_eq!(resp3.header.rcode, ResponseCode::NOERROR);
    assert!(resp3.answers.is_empty());
    assert_eq!(upstream.query_count(), 2);

    // Second NODATA query: served from cache
    let resp4 = client
        .query_udp(server.udp_addr(), &query_nodata)
        .await
        .expect("query nodata 2");
    assert_eq!(resp4.header.rcode, ResponseCode::NOERROR);
    assert!(resp4.answers.is_empty());
    assert_eq!(upstream.query_count(), 2);
    assert_eq!(cache.stats().negative_hits, 2);

    server.shutdown().await.expect("shutdown");
    upstream.shutdown();
}

#[tokio::test]
async fn test_rfc2308_uncacheable_denial_without_soa() {
    let clock = Arc::new(TestClock::new());
    let cache = Arc::new(ShardedAnswerCache::with_defaults(Arc::clone(&clock)));
    let upstream = CommandableUpstream::start().await.expect("upstream start");
    upstream.set_behavior(UpstreamBehavior::NxdomainWithoutSoa);
    let stage = create_cache_stage(Arc::clone(&cache), &upstream, Arc::clone(&clock));

    let mut server = TestServer::boot_with_terminal_and_clock(
        Arc::new(NoLocalRecords::new()),
        Arc::new(AllowAllFilter::new()),
        Arc::new(DiscardObserver::new()),
        stage,
        Arc::clone(&clock),
    )
    .await
    .expect("boot server");

    let client = DnsClient::new();
    let query = make_query("nosoa.example.com.", RecordType::A);

    let resp1 = client
        .query_udp(server.udp_addr(), &query)
        .await
        .expect("query 1");
    assert_eq!(resp1.header.rcode, ResponseCode::NXDOMAIN);
    assert_eq!(upstream.query_count(), 1);

    // Second query must NOT hit cache because missing SOA makes it uncacheable
    let resp2 = client
        .query_udp(server.udp_addr(), &query)
        .await
        .expect("query 2");
    assert_eq!(resp2.header.rcode, ResponseCode::NXDOMAIN);
    assert_eq!(upstream.query_count(), 2);
    assert_eq!(cache.stats().negative_hits, 0);

    server.shutdown().await.expect("shutdown");
    upstream.shutdown();
}

struct TestDynamicFilter {
    blocked: AtomicBool,
}

impl FilterPolicy for TestDynamicFilter {
    fn evaluate(&self, _client: &ClientId, _question: &Question) -> FilterVerdict {
        if self.blocked.load(Ordering::SeqCst) {
            FilterVerdict::Block
        } else {
            FilterVerdict::Allow
        }
    }
}

#[tokio::test]
async fn test_unblock_honesty_egress_filtering() {
    let clock = Arc::new(TestClock::new());
    let cache = Arc::new(ShardedAnswerCache::with_defaults(Arc::clone(&clock)));
    let upstream = CommandableUpstream::start().await.expect("upstream start");
    let stage = create_cache_stage(Arc::clone(&cache), &upstream, Arc::clone(&clock));
    let filter = Arc::new(TestDynamicFilter {
        blocked: AtomicBool::new(true),
    });

    let mut server = TestServer::boot_with_terminal_and_clock(
        Arc::new(NoLocalRecords::new()),
        Arc::clone(&filter),
        Arc::new(DiscardObserver::new()),
        stage,
        Arc::clone(&clock),
    )
    .await
    .expect("boot server");

    let client = DnsClient::new();
    let query = make_query("unblock.example.com.", RecordType::A);

    // Blocked: Synthesizes blocked response, cache never populated, upstream untouched
    let resp1 = client
        .query_udp(server.udp_addr(), &query)
        .await
        .expect("query 1");
    assert_eq!(resp1.header.rcode, ResponseCode::NXDOMAIN);
    assert_eq!(upstream.query_count(), 0);

    let q = Question::new(
        Name::from_ascii("unblock.example.com.").expect("name"),
        RecordType::A,
        RecordClass::In,
    );
    let key = CacheKey::from_question(&q).expect("cache key");
    assert!(matches!(cache.lookup(&key), styx_resolution::Lookup::Miss));

    // Unblock policy: next query immediately resolves via upstream without cache flush
    filter.blocked.store(false, Ordering::SeqCst);
    let resp2 = client
        .query_udp(server.udp_addr(), &query)
        .await
        .expect("query 2");
    assert_eq!(resp2.header.rcode, ResponseCode::NOERROR);
    assert_eq!(upstream.query_count(), 1);

    // Subsequent query hits cache
    let resp3 = client
        .query_udp(server.udp_addr(), &query)
        .await
        .expect("query 3");
    assert_eq!(resp3.header.rcode, ResponseCode::NOERROR);
    assert_eq!(upstream.query_count(), 1);
    assert_eq!(cache.stats().hits, 1);

    server.shutdown().await.expect("shutdown");
    upstream.shutdown();
}

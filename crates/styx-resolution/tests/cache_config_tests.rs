//! Issue #82: the `[cache]` table reaches the cache and admission policy the binary builds,
//! not just the parsed struct.

// The helpers below sit outside `#[test]` functions, where clippy's expect allowance stops.
#![allow(clippy::expect_used)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use styx_core::{
    Clock, TestClock, Upstream, UpstreamError, UpstreamId, UpstreamKind, UpstreamResponse,
};
use styx_proto::{
    Header, Message, Name, Opcode, Question, RData, RecordClass, RecordType, ResourceRecord, Ttl,
};
use styx_resolution::{
    Admission, AnswerCache, CacheConfig, CacheStage, CanaryConfig, CircuitConfig, ClientId,
    MaxResponseSize, OrderedFailover, PoolMember, ProbeConfig, ProbePolicy, RequestContext,
    ShardedAnswerCache, TerminalHandler, Transport, UpstreamPool, Weight,
};

#[derive(Clone)]
struct FixedTtlUpstream {
    ttl: Ttl,
}

impl Upstream for FixedTtlUpstream {
    fn id(&self) -> UpstreamId {
        UpstreamId::new("fixed-ttl")
    }

    fn kind(&self) -> UpstreamKind {
        UpstreamKind::Forwarder
    }

    fn resolve(
        &self,
        query: &Question,
        _deadline: Instant,
    ) -> impl std::future::Future<Output = Result<UpstreamResponse, UpstreamError>> + Send {
        let mut message = Message::response_to(0x1000, query.clone());
        message.answers.push(ResourceRecord::new(
            query.qname.clone(),
            RecordType::A,
            RecordClass::In,
            self.ttl,
            RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        ));
        async move {
            Ok(UpstreamResponse {
                message,
                answered_by: UpstreamId::new("fixed-ttl"),
                kind: UpstreamKind::Forwarder,
                elapsed: Duration::ZERO,
                via_tcp: false,
                raced_count: 1,
            })
        }
    }
}

struct CacheFixture {
    config: CacheConfig,
    cache: Arc<ShardedAnswerCache<TestClock>>,
    clock: Arc<TestClock>,
}

fn cache_fixture(content: &str) -> CacheFixture {
    let config = CacheConfig::from_toml_str(content).expect("valid [cache]");
    let clock = Arc::new(TestClock::new());
    let cache = Arc::new(
        ShardedAnswerCache::new(Arc::clone(&clock), config.capacity, config.shards)
            .expect("sized cache"),
    );
    CacheFixture {
        config,
        cache,
        clock,
    }
}

type ConfigStage =
    CacheStage<ShardedAnswerCache<TestClock>, OrderedFailover, FixedTtlUpstream, TestClock>;

struct StageFixture {
    stage: ConfigStage,
    cache: Arc<ShardedAnswerCache<TestClock>>,
    clock: Arc<TestClock>,
}

fn stage_from(content: &str, upstream_ttl: Ttl) -> StageFixture {
    let CacheFixture {
        config,
        cache,
        clock,
    } = cache_fixture(content);
    let canary = Name::from_ascii("canary.check.").expect("canary name");
    let member = PoolMember::new(
        UpstreamId::new("fixed-ttl"),
        FixedTtlUpstream { ttl: upstream_ttl },
        Weight::new(1),
        CanaryConfig {
            qname: canary,
            qtype: RecordType::A,
            timeout: Duration::from_millis(500),
        },
    );
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
    let stage = CacheStage::with_admission(
        Arc::clone(&cache),
        pool,
        Admission::new(config.ttl),
        Arc::clone(&clock),
        Duration::from_secs(2),
    );
    StageFixture {
        stage,
        cache,
        clock,
    }
}

fn query_context(qname: &str, clock: &TestClock) -> RequestContext {
    let mut query = Message::new(Header::new_query(0x1234, Opcode::Query, true));
    query.questions.push(Question::new(
        Name::from_ascii(qname).expect("qname"),
        RecordType::A,
        RecordClass::In,
    ));
    RequestContext::new(
        query,
        ClientId::from_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        Transport::Udp,
        MaxResponseSize::classic(),
        MaxResponseSize::classic(),
        clock.now_monotonic(),
    )
}

#[test]
fn max_entries_from_the_file_bounds_the_built_cache() {
    let fixture = cache_fixture("[cache]\nmax_entries = 500\n");
    assert_eq!(fixture.cache.capacity().max_entries(), 500);
}

#[tokio::test]
async fn ttl_bounds_from_the_file_clamp_admitted_answers() {
    let config = "[cache]\nttl_floor_secs = 30\nttl_ceiling_secs = 600\n";

    let ceiling = stage_from(config, Ttl::from_secs(3600));
    let ctx = query_context("above-ceiling.example.", &ceiling.clock);
    ceiling.stage.handle_terminal(&ctx).await.expect("miss");
    let cached = ceiling.stage.handle_terminal(&ctx).await.expect("hit");
    assert_eq!(ceiling.cache.stats().hits, 1);
    assert_eq!(first_answer_ttl(&cached), Ttl::from_secs(600));

    let floor = stage_from(config, Ttl::from_secs(5));
    let ctx = query_context("below-floor.example.", &floor.clock);
    floor.stage.handle_terminal(&ctx).await.expect("miss");
    let cached = floor.stage.handle_terminal(&ctx).await.expect("hit");
    assert_eq!(floor.cache.stats().hits, 1);
    assert_eq!(first_answer_ttl(&cached), Ttl::from_secs(30));
}

fn first_answer_ttl(response: &styx_resolution::ResolutionResponse) -> Ttl {
    response.message().answers.first().expect("answer").ttl
}

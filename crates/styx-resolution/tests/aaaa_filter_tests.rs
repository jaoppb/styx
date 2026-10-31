//! `filter_aaaa`: AAAA questions are answered NODATA without reaching the cache or an
//! upstream (issue #94).

mod harness;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use harness::{CommandableUpstream, DnsClient};
use styx_core::{SystemClock, SystemSleeper, UpstreamId};
use styx_proto::{Header, Message, Name, Opcode, Question, RecordClass, RecordType, ResponseCode};
use styx_resolution::{
    AaaaPolicy, AllowAllFilter, AnswerCache, AnswerSource, CacheKey, CacheStage, CanaryConfig,
    ClientId, ConfiguredStrategy, Do53Forwarder, Lookup, NoLocalRecords, Pipeline, PoolMember,
    ProbePolicy, QueryDetail, QueryObserver, ResolutionOutcome, Server, ServerConfig,
    ShardedAnswerCache, UpstreamPool,
};

#[derive(Default)]
struct RecordingObserver {
    outcomes: Mutex<Vec<ResolutionOutcome>>,
}

impl RecordingObserver {
    fn last(&self) -> Option<ResolutionOutcome> {
        self.outcomes.lock().ok()?.last().cloned()
    }
}

impl QueryObserver for RecordingObserver {
    fn record_outcome(&self, _: &ClientId, _: &Question, outcome: &ResolutionOutcome) {
        if let Ok(mut outcomes) = self.outcomes.lock() {
            outcomes.push(outcome.clone());
        }
    }

    fn offer_detail(&self, _: QueryDetail) {}

    fn dropped_detail(&self) -> u64 {
        0
    }
}

type TestCache = ShardedAnswerCache<SystemClock>;
type TestPool = UpstreamPool<ConfiguredStrategy, Do53Forwarder<SystemClock>, SystemClock>;
type TestStage = CacheStage<TestCache, ConfiguredStrategy, Do53Forwarder<SystemClock>, SystemClock>;
type TestServer = Server<NoLocalRecords, AllowAllFilter, RecordingObserver, SystemClock, TestStage>;

struct Fixture {
    upstream: CommandableUpstream,
    cache: Arc<TestCache>,
    observer: Arc<RecordingObserver>,
    server: TestServer,
}

fn server_config(filter_line: &str, upstream: SocketAddr) -> Option<ServerConfig> {
    ServerConfig::from_toml_str(&format!(
        r#"
listen_addrs = ["127.0.0.1:0"]
{filter_line}

[upstream]
strategy = "ordered_failover"

[[upstream.members]]
name = "fake-upstream"
kind = "forwarder"
addr = "{upstream}"
# The fake answers every question with an A record, so an AAAA that reaches it waits
# out this timeout instead of the 2 s default.
udp_timeout_ms = 200
"#
    ))
    .ok()
}

fn single_member_pool(config: &ServerConfig, clock: &Arc<SystemClock>) -> Option<Arc<TestPool>> {
    let pool_config = config.upstream.as_ref()?;
    let member_cfg = pool_config.members.first()?;
    let id = UpstreamId::new(member_cfg.name.as_str());
    let forwarder = Do53Forwarder::new(
        id.clone(),
        member_cfg.addr,
        member_cfg.edns_buffer,
        member_cfg.timeouts.udp,
        member_cfg.timeouts.tcp,
        Arc::clone(clock),
    );
    let canary = CanaryConfig::for_kind(member_cfg.kind);
    Some(Arc::new(UpstreamPool::new(
        vec![PoolMember::new(id, forwarder, member_cfg.weight, canary)],
        ConfiguredStrategy::from_name(pool_config.strategy),
        Arc::clone(clock),
        pool_config.circuit.clone(),
        ProbePolicy::new(pool_config.probe.clone()),
    )))
}

impl Fixture {
    async fn boot(filter_line: &str) -> Option<Self> {
        let upstream = CommandableUpstream::start().await.ok()?;
        let config = server_config(filter_line, upstream.udp_addr())?;
        let clock = Arc::new(SystemClock::new());
        let pool = single_member_pool(&config, &clock)?;
        let cache = Arc::new(ShardedAnswerCache::with_defaults(clock.clone()));
        let stage = CacheStage::new(cache.clone(), pool, clock.clone(), config.query_timeout);
        let observer = Arc::new(RecordingObserver::default());
        let pipeline = Pipeline::new(
            Arc::new(NoLocalRecords::new()),
            Arc::new(AllowAllFilter::new()),
            observer.clone(),
            clock.clone(),
        )
        .with_aaaa_policy(config.aaaa_policy)
        .with_terminal(Arc::new(stage));
        let sleeper = Arc::new(SystemSleeper::new());
        let server = Server::bind(config, Arc::new(pipeline), clock, sleeper)
            .await
            .ok()?;
        Some(Self {
            upstream,
            cache,
            observer,
            server,
        })
    }

    async fn ask(&self, qtype: RecordType) -> Option<Message> {
        let mut header = Header::new_query(0x9400, Opcode::Query, true);
        header.recursion_desired = true;
        let mut query = Message::new(header);
        query.questions.push(question(qtype));
        let udp = *self.server.local_addrs().first()?;
        DnsClient::new().query_udp(udp, &query).await.ok()
    }
}

fn question(qtype: RecordType) -> Question {
    let qname = Name::from_ascii("example.com.").unwrap_or_else(|_| Name::root());
    Question::new(qname, qtype, RecordClass::In)
}

#[tokio::test]
async fn test_filtered_aaaa_is_nodata_and_never_reaches_the_upstream() {
    let mut fixture = Fixture::boot("filter_aaaa = true").await.expect("boot");

    let response = fixture.ask(RecordType::AAAA).await.expect("answer");

    assert_eq!(response.header.rcode, ResponseCode::NOERROR);
    assert!(response.answers.is_empty(), "NODATA carries no answer");
    assert!(!response.header.authentic_data, "a forged reply has AD=0");
    assert_eq!(response.questions, vec![question(RecordType::AAAA)]);
    assert_eq!(fixture.upstream.query_count(), 0, "no AAAA leaves styx");

    let outcome = fixture.observer.last().expect("outcome recorded");
    assert_eq!(outcome.source(), AnswerSource::AaaaFiltered);
    assert!(outcome.is_forged());
    assert!(!outcome.is_cacheable());
    let key = CacheKey::from_question(&question(RecordType::AAAA)).expect("cache key");
    assert_eq!(
        fixture.cache.lookup(&key),
        Lookup::Miss,
        "nothing was cached"
    );

    fixture.server.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn test_a_questions_still_resolve_with_the_filter_on() {
    let mut fixture = Fixture::boot("filter_aaaa = true").await.expect("boot");

    let response = fixture.ask(RecordType::A).await.expect("answer");

    assert_eq!(response.header.rcode, ResponseCode::NOERROR);
    assert_eq!(response.answers.len(), 1);
    assert_eq!(fixture.upstream.query_count(), 1);
    let outcome = fixture.observer.last().expect("outcome recorded");
    assert_eq!(outcome.source(), AnswerSource::Upstream);

    fixture.server.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn test_aaaa_reaches_the_upstream_when_the_key_is_absent() {
    let mut fixture = Fixture::boot("").await.expect("boot");

    fixture.ask(RecordType::AAAA).await.expect("answer");

    assert_eq!(fixture.upstream.query_count(), 1);
    let outcome = fixture.observer.last().expect("outcome recorded");
    assert_ne!(outcome.source(), AnswerSource::AaaaFiltered);

    fixture.server.shutdown().await.expect("shutdown");
}

#[test]
fn test_filter_aaaa_parses_to_the_policy_and_defaults_to_resolve() {
    let parse = |line: &str| ServerConfig::from_toml_str(line).map(|config| config.aaaa_policy);
    assert_eq!(parse("filter_aaaa = true").ok(), Some(AaaaPolicy::Filter));
    assert_eq!(parse("filter_aaaa = false").ok(), Some(AaaaPolicy::Resolve));
    assert_eq!(parse("").ok(), Some(AaaaPolicy::Resolve));
    assert!(parse("filter_aaaa = \"yes\"").is_err());
}

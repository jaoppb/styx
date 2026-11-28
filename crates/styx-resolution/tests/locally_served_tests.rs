//! Locally served names are answered by styx over the wire, never reach the cache or an
//! upstream, and the DoH canary follows `doh_canary` (issue #97).

// The helpers below sit outside `#[test]` functions, where clippy's expect allowance stops.
#![allow(clippy::expect_used)]

mod harness;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use harness::{CommandableUpstream, DnsClient};
use styx_core::{SystemClock, SystemSleeper, UpstreamId};
use styx_proto::{
    Header, Message, Name, Opcode, Question, RData, RecordClass, RecordType, ResponseCode,
};
use styx_resolution::{
    AllowAllFilter, AnswerCache, AnswerSource, CacheKey, CacheStage, CanaryConfig, ClientId,
    ConfiguredStrategy, Do53Forwarder, Lookup, NoLocalRecords, Pipeline, PoolMember, ProbePolicy,
    QueryDetail, QueryObserver, ResolutionOutcome, Server, ServerConfig, ShardedAnswerCache,
    UpstreamPool,
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
type TestStage = CacheStage<TestCache, ConfiguredStrategy, Do53Forwarder<SystemClock>, SystemClock>;

struct Fixture {
    upstream: CommandableUpstream,
    cache: Arc<TestCache>,
    observer: Arc<RecordingObserver>,
    server: Server<NoLocalRecords, AllowAllFilter, RecordingObserver, SystemClock, TestStage>,
}

fn server_config(top_level: &str, upstream: SocketAddr) -> Option<ServerConfig> {
    ServerConfig::from_toml_str(&format!(
        r#"
listen_addrs = ["127.0.0.1:0"]
{top_level}

[upstream]
strategy = "ordered_failover"

[[upstream.members]]
name = "fake-upstream"
kind = "forwarder"
addr = "{upstream}"
"#
    ))
    .ok()
}

impl Fixture {
    async fn boot(top_level: &str) -> Option<Self> {
        let upstream = CommandableUpstream::start().await.ok()?;
        let config = server_config(top_level, upstream.udp_addr())?;
        let clock = Arc::new(SystemClock::new());
        let member = config.upstream.as_ref()?.members.first()?.clone();
        let id = UpstreamId::new(member.name.as_str());
        let forwarder = Do53Forwarder::new(
            id.clone(),
            member.addr,
            member.edns_buffer,
            member.timeouts.udp,
            member.timeouts.tcp,
            Arc::clone(&clock),
        );
        let pool_config = config.upstream.as_ref()?;
        let pool = Arc::new(UpstreamPool::new(
            vec![PoolMember::new(
                id,
                forwarder,
                member.weight,
                CanaryConfig::for_kind(member.kind),
            )],
            ConfiguredStrategy::from_name(pool_config.strategy),
            Arc::clone(&clock),
            pool_config.circuit.clone(),
            ProbePolicy::new(pool_config.probe.clone()),
        ));
        let cache = Arc::new(ShardedAnswerCache::with_defaults(clock.clone()));
        let stage = CacheStage::new(cache.clone(), pool, clock.clone(), config.query_timeout);
        let observer = Arc::new(RecordingObserver::default());
        let pipeline = Pipeline::new(
            Arc::new(NoLocalRecords::new()),
            Arc::new(AllowAllFilter::new()),
            observer.clone(),
            clock.clone(),
        )
        .with_locally_served(config.locally_served())
        .with_terminal(Arc::new(stage));
        let server = Server::bind(
            config,
            Arc::new(pipeline),
            clock,
            Arc::new(SystemSleeper::new()),
        )
        .await
        .ok()?;
        Some(Self {
            upstream,
            cache,
            observer,
            server,
        })
    }

    async fn ask(&self, qname: &str, qtype: RecordType) -> Option<Message> {
        let mut header = Header::new_query(0x9700, Opcode::Query, true);
        header.recursion_desired = true;
        let mut query = Message::new(header);
        query.questions.push(question(qname, qtype));
        let udp = *self.server.local_addrs().first()?;
        DnsClient::new().query_udp(udp, &query).await.ok()
    }

    /// Asserts the reply was forged by the locally served stage and left nothing behind.
    fn assert_locally_served(&self, response: &Message, qname: &str, qtype: RecordType) {
        assert!(!response.header.authentic_data, "a forged reply has AD=0");
        assert_eq!(self.upstream.query_count(), 0, "{qname} never left styx");
        let outcome = self.observer.last().expect("outcome recorded");
        assert_eq!(outcome.source(), AnswerSource::LocallyServed);
        assert!(outcome.is_forged() && !outcome.is_cacheable());
        let key = CacheKey::from_question(&question(qname, qtype)).expect("cache key");
        assert_eq!(self.cache.lookup(&key), Lookup::Miss, "nothing was cached");
    }
}

fn question(qname: &str, qtype: RecordType) -> Question {
    let qname = Name::from_ascii(qname).unwrap_or_else(|_| Name::root());
    Question::new(qname, qtype, RecordClass::In)
}

#[tokio::test]
async fn test_a_private_reverse_name_is_nxdomain_with_the_empty_zone_soa() {
    let mut fixture = Fixture::boot("").await.expect("boot");
    let qname = "10.1.168.192.in-addr.arpa.";

    let response = fixture.ask(qname, RecordType::PTR).await.expect("answer");

    assert_eq!(response.header.rcode, ResponseCode::NXDOMAIN);
    assert!(response.answers.is_empty());
    let soa = response.authorities.first().expect("an SOA in authority");
    assert_eq!(soa.rtype, RecordType::SOA);
    assert_eq!(
        soa.owner,
        Name::from_ascii("168.192.in-addr.arpa.").expect("zone")
    );
    fixture.assert_locally_served(&response, qname, RecordType::PTR);

    fixture.server.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn test_localhost_answers_the_loopback_address() {
    let mut fixture = Fixture::boot("").await.expect("boot");

    let response = fixture
        .ask("localhost.", RecordType::A)
        .await
        .expect("answer");

    assert_eq!(response.header.rcode, ResponseCode::NOERROR);
    assert_eq!(
        response.answers.first().map(|record| &record.rdata),
        Some(&RData::A(Ipv4Addr::LOCALHOST))
    );
    fixture.assert_locally_served(&response, "localhost.", RecordType::A);

    fixture.server.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn test_an_invalid_name_and_the_doh_canary_are_nxdomain() {
    let mut fixture = Fixture::boot("").await.expect("boot");

    for qname in ["foo.invalid.", "use-application-dns.net."] {
        let response = fixture.ask(qname, RecordType::A).await.expect("answer");
        assert_eq!(response.header.rcode, ResponseCode::NXDOMAIN, "{qname}");
        assert!(response.answers.is_empty(), "{qname}");
        fixture.assert_locally_served(&response, qname, RecordType::A);
    }

    fixture.server.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn test_the_doh_canary_reaches_the_upstream_with_the_switch_off() {
    let mut fixture = Fixture::boot("doh_canary = false").await.expect("boot");

    let response = fixture
        .ask("use-application-dns.net.", RecordType::A)
        .await
        .expect("answer");

    assert_eq!(response.header.rcode, ResponseCode::NOERROR);
    assert_eq!(fixture.upstream.query_count(), 1);
    let outcome = fixture.observer.last().expect("outcome recorded");
    assert_eq!(outcome.source(), AnswerSource::Upstream);

    fixture.server.shutdown().await.expect("shutdown");
}

#[test]
fn test_doh_canary_parses_to_bool_and_defaults_to_true() {
    let parse = |line: &str| ServerConfig::from_toml_str(line).map(|config| config.doh_canary);
    assert_eq!(parse("doh_canary = false").ok(), Some(false));
    assert_eq!(parse("doh_canary = true").ok(), Some(true));
    assert_eq!(parse("").ok(), Some(true));
    assert!(parse("doh_canary = \"no\"").is_err());
}

fn is_served(config: &ServerConfig, qname: &str) -> bool {
    config
        .locally_served()
        .answer(&question(qname, RecordType::PTR))
        .is_some()
}

#[test]
fn test_locally_served_defers_the_domains_of_every_conditional_entry() {
    let config = ServerConfig::from_toml_str(
        r#"
[upstream]
strategy = "ordered_failover"

[[upstream.members]]
name = "main"
kind = "forwarder"
addr = "127.0.0.1:5301"

[[upstream.conditional]]
domains = ["lan", "1.168.192.in-addr.arpa"]

[[upstream.conditional.members]]
name = "router"
kind = "forwarder"
addr = "127.0.0.1:5302"

[[upstream.conditional]]
domains = ["16.172.in-addr.arpa"]

[[upstream.conditional.members]]
name = "hub"
kind = "forwarder"
addr = "127.0.0.1:5303"
"#,
    )
    .expect("valid conditional configuration");

    assert!(
        !is_served(&config, "10.1.168.192.in-addr.arpa."),
        "first entry"
    );
    assert!(
        !is_served(&config, "1.16.172.in-addr.arpa."),
        "second entry"
    );
    assert!(is_served(&config, "10.2.168.192.in-addr.arpa."));
    assert!(is_served(&config, "1.17.172.in-addr.arpa."));
}

#[test]
fn test_locally_served_without_an_upstream_section_defers_nothing() {
    let config = ServerConfig::from_toml_str("doh_canary = false").expect("valid configuration");
    assert!(config.upstream.is_none());

    assert!(is_served(&config, "10.1.168.192.in-addr.arpa."));
    assert!(is_served(&config, "localhost."));
    assert!(
        !is_served(&config, "use-application-dns.net."),
        "the canary follows doh_canary"
    );
}

//! `[[upstream.conditional]]` sends the configured zones to their own forwarders and every
//! other name to the main pool (issue #96).
//!
//! Each upstream is a real socket that counts the queries it receives, so "reaches only B"
//! is asserted on what B and the main pool actually saw.

// The helpers below sit outside `#[test]` functions, where clippy's expect allowance stops.
#![allow(clippy::expect_used)]

mod harness;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use harness::{CommandableUpstream, FakeNameServer, FakeRole, UpstreamBehavior, ZoneScript};
use styx_core::{Clock, SystemClock, UpstreamId};
use styx_proto::{Header, Message, Name, Opcode, Question, RecordClass, RecordType, ResponseCode};
use styx_resolution::{
    CacheStage, CanaryConfig, ClientId, ConditionalRoute, ConditionalRoutes, ConfiguredStrategy,
    Do53Forwarder, MaxResponseSize, PoolConfig, PoolMember, ProbePolicy, RequestContext,
    ServerConfig, ShardedAnswerCache, StrategyName, TerminalHandler, Transport, UpstreamConfig,
    UpstreamPool,
};

type Pool = UpstreamPool<ConfiguredStrategy, Do53Forwarder<SystemClock>, SystemClock>;
type Stage = CacheStage<
    ShardedAnswerCache<SystemClock>,
    ConfiguredStrategy,
    Do53Forwarder<SystemClock>,
    SystemClock,
>;

/// The main pool's upstream, and the conditional forwarders `router` and `hub`.
struct Upstreams {
    main: CommandableUpstream,
    router: CommandableUpstream,
    hub: CommandableUpstream,
}

impl Upstreams {
    async fn start() -> Self {
        Self {
            main: CommandableUpstream::start().await.expect("main upstream"),
            router: CommandableUpstream::start().await.expect("router upstream"),
            hub: CommandableUpstream::start().await.expect("hub upstream"),
        }
    }

    /// `lan` and the LAN's reverse zone go to `router`; `iot.lan`, inside `lan`, to `hub`.
    fn config(&self) -> ServerConfig {
        self.config_with_router(self.router.udp_addr())
    }

    fn config_with_router(&self, router: SocketAddr) -> ServerConfig {
        let toml = format!(
            r#"
listen_addrs = ["127.0.0.1:0"]
query_timeout_secs = 5

[upstream]
strategy = "ordered_failover"

[[upstream.members]]
name = "main"
kind = "forwarder"
addr = "{main}"

[[upstream.conditional]]
domains = ["lan", "1.168.192.in-addr.arpa"]

[[upstream.conditional.members]]
name = "router"
kind = "forwarder"
addr = "{router}"

[[upstream.conditional]]
domains = ["iot.lan."]

[[upstream.conditional.members]]
name = "hub"
kind = "forwarder"
addr = "{hub}"
"#,
            main = self.main.udp_addr(),
            router = router,
            hub = self.hub.udp_addr(),
        );
        ServerConfig::from_toml_str(&toml).expect("valid conditional configuration")
    }

    fn counts(&self) -> [usize; 3] {
        [
            self.main.query_count(),
            self.router.query_count(),
            self.hub.query_count(),
        ]
    }
}

fn pool(
    pool_config: &PoolConfig,
    members: &[UpstreamConfig],
    strategy: StrategyName,
    clock: &Arc<SystemClock>,
) -> Arc<Pool> {
    let members = members
        .iter()
        .map(|member| {
            let id = UpstreamId::new(member.name.as_str());
            let forwarder = Do53Forwarder::new(
                id.clone(),
                member.addr,
                member.edns_buffer,
                member.timeouts.udp,
                member.timeouts.tcp,
                Arc::clone(clock),
            );
            PoolMember::new(
                id,
                forwarder,
                member.weight,
                CanaryConfig::for_kind(member.kind),
            )
        })
        .collect();
    Arc::new(UpstreamPool::new(
        members,
        ConfiguredStrategy::from_name(strategy),
        Arc::clone(clock),
        pool_config.circuit.clone(),
        ProbePolicy::new(pool_config.probe.clone()),
    ))
}

/// The stage `main.rs` builds from the same configuration: one pool per conditional entry.
fn stage(config: &ServerConfig, clock: &Arc<SystemClock>) -> Stage {
    let pool_config = config.upstream.as_ref().expect("an [upstream] section");
    let routes = pool_config
        .conditional
        .iter()
        .map(|entry| ConditionalRoute {
            domains: entry.domains.clone(),
            target: pool(
                pool_config,
                &entry.members,
                StrategyName::OrderedFailover,
                clock,
            ),
        })
        .collect();
    CacheStage::new(
        Arc::new(ShardedAnswerCache::with_defaults(Arc::clone(clock))),
        pool(
            pool_config,
            &pool_config.members,
            pool_config.strategy,
            clock,
        ),
        Arc::clone(clock),
        config.query_timeout,
    )
    .with_conditional(ConditionalRoutes::new(routes))
}

async fn ask(stage: &Stage, clock: &SystemClock, qname: &str, qtype: RecordType) -> ResponseCode {
    let qname = Name::from_ascii(qname).expect("valid name");
    let mut query = Message::new(Header::new_query(0x1234, Opcode::Query, true));
    query
        .questions
        .push(Question::new(qname, qtype, RecordClass::In));
    let ctx = RequestContext::new(
        query,
        ClientId::from_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        Transport::Udp,
        MaxResponseSize::classic(),
        MaxResponseSize::classic(),
        clock.now_monotonic(),
    );
    let response = stage.handle_terminal(&ctx).await.expect("an answer");
    response.message().header.rcode
}

#[tokio::test]
async fn a_conditional_domain_reaches_only_its_forwarder_and_other_names_only_the_main_pool() {
    let upstreams = Upstreams::start().await;
    let clock = Arc::new(SystemClock::new());
    let stage = stage(&upstreams.config(), &clock);

    assert_eq!(
        ask(&stage, &clock, "nas.lan.", RecordType::A).await,
        ResponseCode::NOERROR
    );
    assert_eq!(
        upstreams.counts(),
        [0, 1, 0],
        "nas.lan reaches only the router"
    );

    assert_eq!(
        ask(&stage, &clock, "example.com.", RecordType::A).await,
        ResponseCode::NOERROR
    );
    assert_eq!(
        upstreams.counts(),
        [1, 1, 0],
        "example.com reaches only the main pool"
    );
}

#[tokio::test]
async fn a_configured_reverse_zone_reaches_its_forwarder() {
    let upstreams = Upstreams::start().await;
    // The commandable fake always answers type A; a PTR question needs a scripted zone.
    let reverse_zone = ZoneScript::new().origin("1.168.192.in-addr.arpa.", 60);
    let router = FakeNameServer::start(FakeRole::Authoritative, reverse_zone)
        .await
        .expect("reverse-zone router");
    let clock = Arc::new(SystemClock::new());
    let stage = stage(&upstreams.config_with_router(router.udp_addr()), &clock);

    let rcode = ask(
        &stage,
        &clock,
        "10.1.168.192.in-addr.arpa.",
        RecordType::PTR,
    )
    .await;

    assert_eq!(rcode, ResponseCode::NXDOMAIN, "the router's own answer");
    let asked: Vec<RecordType> = router
        .received_queries()
        .iter()
        .map(|question| question.qtype)
        .collect();
    assert_eq!(asked, vec![RecordType::PTR], "the PTR reached the router");
    assert_eq!(upstreams.main.query_count(), 0);
    assert_eq!(upstreams.hub.query_count(), 0);
}

#[tokio::test]
async fn the_longest_configured_suffix_wins() {
    let upstreams = Upstreams::start().await;
    let clock = Arc::new(SystemClock::new());
    let stage = stage(&upstreams.config(), &clock);

    ask(&stage, &clock, "bulb.iot.lan.", RecordType::A).await;

    assert_eq!(
        upstreams.counts(),
        [0, 0, 1],
        "iot.lan is longer than lan, so the hub answers"
    );
}

#[tokio::test]
async fn a_conditional_answer_is_cached_like_any_other() {
    let upstreams = Upstreams::start().await;
    let clock = Arc::new(SystemClock::new());
    let stage = stage(&upstreams.config(), &clock);

    ask(&stage, &clock, "nas.lan.", RecordType::A).await;
    ask(&stage, &clock, "nas.lan.", RecordType::A).await;

    assert_eq!(
        upstreams.counts(),
        [0, 1, 0],
        "the second question is a cache hit"
    );
}

#[tokio::test]
async fn a_failing_conditional_pool_fails_the_query_without_asking_the_main_pool() {
    let upstreams = Upstreams::start().await;
    upstreams.router.set_behavior(UpstreamBehavior::Servfail);
    let clock = Arc::new(SystemClock::new());
    let stage = stage(&upstreams.config(), &clock);
    let mut query = Message::new(Header::new_query(0x1234, Opcode::Query, true));
    query.questions.push(Question::new(
        Name::from_ascii("nas.lan.").expect("valid name"),
        RecordType::A,
        RecordClass::In,
    ));
    let ctx = RequestContext::new(
        query,
        ClientId::from_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        Transport::Udp,
        MaxResponseSize::classic(),
        MaxResponseSize::classic(),
        clock.now_monotonic(),
    );

    let result = stage.handle_terminal(&ctx).await;

    let rcode = result.err().map(|error| error.response_code());
    assert_eq!(rcode, Some(ResponseCode::SERVFAIL));
    assert_eq!(
        upstreams.counts(),
        [0, 1, 0],
        "the name never falls back to the main pool, which would leak it"
    );
}

#[test]
fn a_conditional_member_slower_than_the_query_deadline_is_rejected() {
    let toml = r#"
query_timeout_secs = 2

[upstream]
strategy = "ordered_failover"

[[upstream.members]]
name = "main"
kind = "forwarder"
addr = "9.9.9.9:53"
udp_timeout_ms = 1000
tcp_timeout_ms = 1000

[[upstream.conditional]]
domains = ["lan"]

[[upstream.conditional.members]]
name = "router"
kind = "forwarder"
addr = "192.168.1.1:53"
udp_timeout_ms = 2000
"#;
    let error = ServerConfig::from_toml_str(toml)
        .err()
        .map(|error| error.to_string());
    assert!(
        error.as_deref().is_some_and(|text| text.contains("router")),
        "{error:?}"
    );
}

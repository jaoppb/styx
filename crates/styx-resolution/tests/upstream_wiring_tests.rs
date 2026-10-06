//! Integration tests for upstream pool wiring, TOML configuration, and global deadline enforcement.

mod harness;

use std::sync::Arc;
use std::time::{Duration, Instant};

use harness::{CommandableUpstream, DnsClient, UpstreamBehavior};
use styx_core::{Clock, SystemClock, UpstreamId};
use styx_proto::{
    Header, Message, Name, Opcode, Question, RData, RecordClass, RecordType, ResponseCode,
};
use styx_resolution::{
    AllowAllFilter, CacheStage, CanaryConfig, ConfiguredStrategy, DiscardObserver, Do53Forwarder,
    NoLocalRecords, Pipeline, PoolError, PoolMember, PoolTerminal, ProbePolicy, Server,
    ServerConfig, ShardedAnswerCache, UpstreamPool,
};

fn make_query(name: &str) -> Message {
    let qname = match Name::from_ascii(name) {
        Ok(q) => q,
        Err(_) => Name::root(),
    };
    let mut header = Header::new_query(0x1234, Opcode::Query, true);
    header.recursion_desired = true;
    let mut msg = Message::new(header);
    msg.questions
        .push(Question::new(qname, RecordType::A, RecordClass::In));
    msg
}

type ConcreteStage = CacheStage<
    ShardedAnswerCache<SystemClock>,
    ConfiguredStrategy,
    Do53Forwarder<SystemClock>,
    SystemClock,
>;
type ConcretePipeline =
    Pipeline<NoLocalRecords, AllowAllFilter, DiscardObserver, SystemClock, ConcreteStage>;

fn build_test_pipeline(
    server_config: &ServerConfig,
    clock: Arc<SystemClock>,
) -> Option<Arc<ConcretePipeline>> {
    let pool_config = server_config.upstream.as_ref()?;

    let mut members = Vec::new();
    for member_cfg in &pool_config.members {
        let id = UpstreamId::new(member_cfg.name.as_str());
        let forwarder = Do53Forwarder::new(
            id.clone(),
            member_cfg.addr,
            member_cfg.edns_buffer,
            member_cfg.timeouts.udp,
            member_cfg.timeouts.tcp,
            clock.clone(),
        );
        let canary = member_cfg
            .canary
            .clone()
            .unwrap_or_else(|| CanaryConfig::for_kind(member_cfg.kind));
        members.push(PoolMember::new(id, forwarder, member_cfg.weight, canary));
    }

    let strategy = ConfiguredStrategy::from_name(pool_config.strategy);
    let pool = Arc::new(UpstreamPool::new(
        members,
        strategy,
        clock.clone(),
        pool_config.circuit.clone(),
        ProbePolicy::new(pool_config.probe.clone()),
    ));

    let cache = Arc::new(ShardedAnswerCache::with_defaults(clock.clone()));
    let cache_stage = Arc::new(CacheStage::new(
        cache,
        pool,
        clock.clone(),
        server_config.query_timeout,
    ));

    Some(Arc::new(
        Pipeline::new(
            Arc::new(NoLocalRecords::new()),
            Arc::new(AllowAllFilter::new()),
            Arc::new(DiscardObserver::new()),
            clock,
        )
        .with_terminal(cache_stage),
    ))
}

#[tokio::test]
async fn test_server_resolves_via_toml_configured_upstream() {
    let upstream = CommandableUpstream::start().await.expect("upstream start");
    let upstream_addr = upstream.udp_addr();

    let toml_content = format!(
        r#"
listen_addrs = ["127.0.0.1:0"]
query_timeout_secs = 5

[upstream]
strategy = "ordered_failover"

[[upstream.members]]
name = "fake-upstream"
addr = "{upstream_addr}"
weight = 1
kind = "forwarder"
"#
    );

    let server_config =
        ServerConfig::from_toml_str(&toml_content).expect("parse valid server config");
    let clock = Arc::new(SystemClock::new());
    let pipeline = build_test_pipeline(&server_config, clock.clone()).expect("build test pipeline");

    let mut server = Server::bind(server_config, pipeline, clock)
        .await
        .expect("bind server");

    let addrs = server.local_addrs();
    let udp_addr = addrs[0];

    let client = DnsClient::new();
    let query = make_query("example.com.");
    let response = client
        .query_udp(udp_addr, &query)
        .await
        .expect("query succeeds");

    assert_eq!(response.header.rcode, ResponseCode::NOERROR);
    assert_eq!(response.answers.len(), 1);
    assert!(matches!(response.answers[0].rdata, RData::A(_)));
    assert_eq!(upstream.query_count(), 1);

    server.shutdown().await.expect("server shutdown");
}

#[tokio::test]
async fn test_pool_terminal_direct_resolution() {
    let upstream = CommandableUpstream::start().await.expect("upstream start");
    let clock = Arc::new(SystemClock::new());
    let id = UpstreamId::new("up-direct");
    let forwarder = Do53Forwarder::new(
        id.clone(),
        upstream.udp_addr(),
        styx_resolution::EdnsBufferSize::default(),
        Duration::from_secs(2),
        Duration::from_secs(3),
        clock.clone(),
    );
    let member = PoolMember::new(
        id,
        forwarder,
        styx_resolution::Weight::new(1),
        CanaryConfig::for_kind(styx_core::UpstreamKind::Forwarder),
    );

    let pool = Arc::new(UpstreamPool::new(
        vec![member],
        ConfiguredStrategy::from_name(styx_resolution::StrategyName::OrderedFailover),
        clock.clone(),
        styx_resolution::CircuitConfig::default(),
        ProbePolicy::new(styx_resolution::ProbeConfig::default()),
    ));

    let terminal = Arc::new(PoolTerminal::new(
        pool,
        clock.clone(),
        Duration::from_secs(2),
    ));

    let pipeline = Arc::new(
        Pipeline::new(
            Arc::new(NoLocalRecords::new()),
            Arc::new(AllowAllFilter::new()),
            Arc::new(DiscardObserver::new()),
            clock.clone(),
        )
        .with_terminal(terminal),
    );

    let server_config = ServerConfig {
        listen_addrs: vec![([127, 0, 0, 1], 0).into()],
        udp_payload_size_default: styx_resolution::MaxResponseSize::classic(),
        tcp_idle_timeout: Duration::from_secs(5),
        query_timeout: Duration::from_secs(2),
        limits: styx_resolution::ConcurrencyLimits::default_limits(),
        supervisor: styx_resolution::SupervisorBackoffPolicy::default(),
        upstream: None,
    };

    let mut server = Server::bind(server_config, pipeline, clock)
        .await
        .expect("bind server with PoolTerminal");

    let client = DnsClient::new();
    let query = make_query("direct.example.");
    let response = client
        .query_udp(server.local_addrs()[0], &query)
        .await
        .expect("direct terminal query succeeds");

    assert_eq!(response.header.rcode, ResponseCode::NOERROR);
    assert_eq!(response.answers.len(), 1);
    server.shutdown().await.expect("server shutdown");
}

#[tokio::test]
async fn test_global_deadline_enforces_budget_across_members() {
    let clock = Arc::new(SystemClock::new());
    let up1 = CommandableUpstream::start().await.expect("up1 start");
    let up2 = CommandableUpstream::start().await.expect("up2 start");

    // up1 hangs indefinitely
    up1.set_behavior(UpstreamBehavior::Timeout);
    // up2 is functional
    up2.set_behavior(UpstreamBehavior::Normal);

    let id1 = UpstreamId::new("up1");
    let forwarder1 = Do53Forwarder::new(
        id1.clone(),
        up1.udp_addr(),
        styx_resolution::EdnsBufferSize::default(),
        Duration::from_secs(5),
        Duration::from_secs(5),
        clock.clone(),
    );

    let id2 = UpstreamId::new("up2");
    let forwarder2 = Do53Forwarder::new(
        id2.clone(),
        up2.udp_addr(),
        styx_resolution::EdnsBufferSize::default(),
        Duration::from_secs(5),
        Duration::from_secs(5),
        clock.clone(),
    );

    let member1 = PoolMember::new(
        id1,
        forwarder1,
        styx_resolution::Weight::new(1),
        CanaryConfig::for_kind(styx_core::UpstreamKind::Forwarder),
    );
    let member2 = PoolMember::new(
        id2,
        forwarder2,
        styx_resolution::Weight::new(1),
        CanaryConfig::for_kind(styx_core::UpstreamKind::Forwarder),
    );

    let pool = UpstreamPool::new(
        vec![member1, member2],
        ConfiguredStrategy::from_name(styx_resolution::StrategyName::OrderedFailover),
        clock.clone(),
        styx_resolution::CircuitConfig::default(),
        ProbePolicy::new(styx_resolution::ProbeConfig::default()),
    );

    let qname = Name::from_ascii("deadline.test.").unwrap();
    let question = Question::new(qname, RecordType::A, RecordClass::In);

    // Global query timeout is 100ms.
    let start = Instant::now();
    let deadline = clock.now_monotonic() + Duration::from_millis(100);

    let result = pool.resolve(&question, deadline).await;
    let elapsed = start.elapsed();

    // Query must fail because up1 times out at deadline and up2 is never tried.
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), PoolError::Exhausted { .. }));

    // Verify time elapsed was around 100ms (not 5s or 10s)
    assert!(elapsed < Duration::from_millis(500));

    // up2 should have NEVER been contacted because deadline expired during up1's attempt
    assert_eq!(up2.query_count(), 0);
}

//! The composition root's own wiring of `[[upstream.conditional]]`: the routes reach the
//! cache stage, and every conditional pool is probed. The resolution crate's tests build
//! their own stage, so only these notice if `main.rs` stops wiring either.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use styx_core::{Clock, SystemClock};
use styx_proto::{Header, Message, Name, Opcode, Question, RecordClass, RecordType, ResponseCode};
use styx_recursion::application::config::RecursionSection;
use styx_resolution::{
    CacheConfig, ClientId, MaxResponseSize, PipelineError, RequestContext, ServerConfig, Transport,
};
use styx_testkit::CommandableUpstream;

use super::{build_cache, build_pipeline, Pools, RecursionWiring};

fn config(main: &CommandableUpstream, router: &CommandableUpstream) -> ServerConfig {
    ServerConfig::from_toml_str(&format!(
        r#"
listen_addrs = ["127.0.0.1:0"]

[upstream]
strategy = "ordered_failover"

[[upstream.members]]
name = "main"
kind = "forwarder"
addr = "{main}"

[[upstream.conditional]]
domains = ["lan"]

[[upstream.conditional.members]]
name = "router"
kind = "forwarder"
addr = "{router}"

[[upstream.conditional]]
domains = ["iot.lan"]

[[upstream.conditional.members]]
name = "hub"
kind = "forwarder"
addr = "{router}"
"#,
        main = main.udp_addr(),
        router = router.udp_addr(),
    ))
    .expect("valid conditional configuration")
}

/// The wiring of a pool with no recursor member: nothing to validate or load.
async fn no_recursors(config: &ServerConfig) -> RecursionWiring {
    let pool_config = config.upstream.as_ref().expect("an [upstream] section");
    RecursionWiring::load(
        RecursionSection::default(),
        pool_config,
        config.query_timeout,
    )
    .await
    .expect("a forwarder-only pool needs no recursion wiring")
}

fn query(qname: &str, clock: &SystemClock) -> RequestContext {
    let mut message = Message::new(Header::new_query(0x1234, Opcode::Query, true));
    message.questions.push(Question::new(
        Name::from_ascii(qname).expect("valid name"),
        RecordType::A,
        RecordClass::In,
    ));
    RequestContext::new(
        message,
        ClientId::from_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        Transport::Udp,
        MaxResponseSize::classic(),
        MaxResponseSize::classic(),
        clock.now_monotonic(),
    )
}

#[tokio::test]
async fn the_built_pipeline_sends_a_conditional_name_to_its_forwarder_only() {
    let main = CommandableUpstream::start().await.expect("main upstream");
    let router = CommandableUpstream::start().await.expect("router upstream");
    let config = config(&main, &router);
    let pool_config = config.upstream.as_ref().expect("an [upstream] section");
    let clock = Arc::new(SystemClock::new());
    let cache_config = CacheConfig::from_toml_str("").expect("default [cache]");
    let recursion = no_recursors(&config).await;
    let pools = Pools::build(pool_config, &recursion, &clock).expect("pools");
    let cache = build_cache(Arc::clone(&clock), &cache_config).expect("cache");
    let pipeline = build_pipeline(pools, Arc::clone(&clock), &config, cache, &cache_config);

    pipeline
        .handle(&query("nas.lan.", &clock))
        .await
        .expect("an answer");

    assert_eq!(router.query_count(), 1, "nas.lan reached the router");
    assert_eq!(
        main.query_count(),
        0,
        "nas.lan did not leak to the main pool"
    );
}

#[tokio::test]
async fn every_conditional_pool_gets_its_own_probe_scheduler() {
    let main = CommandableUpstream::start().await.expect("main upstream");
    let router = CommandableUpstream::start().await.expect("router upstream");
    let config = config(&main, &router);
    let pool_config = config.upstream.as_ref().expect("an [upstream] section");
    let clock = Arc::new(SystemClock::new());
    let recursion = no_recursors(&config).await;
    let pools = Pools::build(pool_config, &recursion, &clock).expect("pools");

    let schedulers = pools.probe_schedulers(&clock, Duration::from_secs(1));

    assert_eq!(
        schedulers.len(),
        3,
        "the main pool and both conditional pools"
    );
}

fn reverse_zone_config(main: &CommandableUpstream, router: &CommandableUpstream) -> ServerConfig {
    ServerConfig::from_toml_str(&format!(
        r#"
listen_addrs = ["127.0.0.1:0"]

[upstream]
strategy = "ordered_failover"

[[upstream.members]]
name = "main"
kind = "forwarder"
addr = "{main}"

[[upstream.conditional]]
domains = ["1.168.192.in-addr.arpa"]

[[upstream.conditional.members]]
name = "router"
kind = "forwarder"
addr = "{router}"
"#,
        main = main.udp_addr(),
        router = router.udp_addr(),
    ))
    .expect("valid conditional configuration")
}

/// Asks for an A record: the fake upstream answers every question with one, and a
/// locally served zone answers by name whatever the type.
async fn reverse_lookup(config: &ServerConfig, qname: &str) -> Result<Message, PipelineError> {
    let pool_config = config.upstream.as_ref().expect("an [upstream] section");
    let clock = Arc::new(SystemClock::new());
    let cache_config = CacheConfig::from_toml_str("").expect("default [cache]");
    let recursion = no_recursors(config).await;
    let pools = Pools::build(pool_config, &recursion, &clock).expect("pools");
    let cache = build_cache(Arc::clone(&clock), &cache_config).expect("cache");
    let pipeline = build_pipeline(pools, Arc::clone(&clock), config, cache, &cache_config);
    pipeline.handle(&query(qname, &clock)).await
}

#[tokio::test]
async fn a_private_reverse_lookup_is_answered_nxdomain_without_asking_anyone() {
    let main = CommandableUpstream::start().await.expect("main upstream");
    let router = CommandableUpstream::start().await.expect("router upstream");
    let config = reverse_zone_config(&main, &router);

    let response = reverse_lookup(&config, "10.2.168.192.in-addr.arpa.")
        .await
        .expect("an answer");

    assert_eq!(response.header.rcode, ResponseCode::NXDOMAIN);
    assert_eq!(main.query_count(), 0, "192.168.2.10 did not leak upstream");
    assert_eq!(
        router.query_count(),
        0,
        "192.168.2.10 is outside the router's zone"
    );
}

#[tokio::test]
async fn a_conditional_reverse_zone_wins_over_the_locally_served_default() {
    let main = CommandableUpstream::start().await.expect("main upstream");
    let router = CommandableUpstream::start().await.expect("router upstream");
    let config = reverse_zone_config(&main, &router);

    reverse_lookup(&config, "10.1.168.192.in-addr.arpa.")
        .await
        .expect("an answer");

    assert_eq!(router.query_count(), 1, "192.168.1.10 reached the router");
    assert_eq!(main.query_count(), 0, "and not the main pool");
}

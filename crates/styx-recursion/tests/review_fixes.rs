//! Regression tests for the code-review findings on the recursor: one scenario per
//! finding, each of which failed before its fix.

mod support;

use std::net::Ipv4Addr;
use std::time::Duration;

use styx_core::{Clock, Upstream, UpstreamError};
use styx_proto::{RecordType, ResponseCode};
use styx_recursion::domain::budget::DescentLimits;
use styx_recursion::domain::error::{BudgetExceeded, RecursionError};
use styx_recursion::domain::ports::InfraCache;
use styx_recursion::domain::topology::NameserverAddr;
use styx_testkit::{HarnessError, ZoneScript};
use support::{a, loopback, question, root_script, Network, ROOT};

const COM: u8 = 3;
const EXAMPLE: u8 = 4;
const NET: u8 = 5;
const DNS_NET: u8 = 6;
const DEAD: u8 = 10;

fn ip(last: u8) -> Ipv4Addr {
    Ipv4Addr::new(127, 0, 0, last)
}

fn root_server() -> NameserverAddr {
    NameserverAddr::new(loopback(ROOT))
}

#[tokio::test]
async fn one_lost_packet_shared_by_several_descents_is_one_failure() {
    let mut network = Network::new().await.expect("network");
    network
        .serve(ROOT, root_script().silent())
        .await
        .expect("serve");
    let recursor = network
        .recursor(DescentLimits::default())
        .expect("recursor");
    let (a_q, b_q, c_q) = (
        question("a.example.com.", RecordType::A),
        question("b.example.com.", RecordType::A),
        question("c.example.com.", RecordType::A),
    );

    let _ = tokio::join!(
        recursor.resolve_iteratively(&a_q, network.deadline()),
        recursor.resolve_iteratively(&b_q, network.deadline()),
        recursor.resolve_iteratively(&c_q, network.deadline()),
    );
    tokio::time::sleep(Duration::from_millis(400)).await;

    let now = network.clock.now_monotonic();
    let failures = network
        .infra
        .metrics(root_server(), now)
        .consecutive_failures();
    assert_eq!(
        failures, 2,
        "one shared exchange plus the priming query, not one per descent"
    );
    assert!(!network.infra.metrics(root_server(), now).in_backoff(now));
}

#[tokio::test]
async fn a_server_that_always_servfails_ends_up_in_backoff() {
    let mut network = Network::new().await.expect("network");
    let root = root_script().rcode("com.", None, ResponseCode::SERVFAIL);
    network.serve(ROOT, root).await.expect("serve");
    let recursor = network
        .recursor(DescentLimits::default())
        .expect("recursor");
    let _ = recursor
        .resolve_iteratively(&question("x.com.", RecordType::A), network.deadline())
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    for _ in 0..3 {
        let outcome = recursor
            .resolve_iteratively(&question("x.com.", RecordType::A), network.deadline())
            .await;
        assert!(outcome.is_err());
    }

    let now = network.clock.now_monotonic();
    assert!(
        network.infra.metrics(root_server(), now).in_backoff(now),
        "SERVFAIL is a failure, not a fast success"
    );
}

#[tokio::test]
async fn a_dead_network_trips_the_breaker_but_a_dead_zone_does_not() {
    let mut silent = Network::new().await.expect("network");
    silent
        .serve(ROOT, root_script().silent())
        .await
        .expect("serve");
    let dead_network = silent.recursor(DescentLimits::default()).expect("recursor");
    let error = dead_network
        .resolve(
            &question("a.example.com.", RecordType::A),
            silent.deadline(),
        )
        .await
        .map(|response| response.message.header.rcode)
        .expect_err("nothing answers");
    assert_eq!(error, UpstreamError::Timeout, "an upstream fault");

    let mut network = with_dead_zone().await.expect("network");
    network.serve(DEAD, ZoneScript::new().silent()).await.ok();
    let recursor = network
        .recursor(DescentLimits::default())
        .expect("recursor");
    recursor
        .resolve(
            &question("a.example.com.", RecordType::A),
            network.deadline(),
        )
        .await
        .expect("the network works");
    let dead_zone = recursor
        .resolve(
            &question("www.dead.com.", RecordType::A),
            network.deadline(),
        )
        .await
        .map(|response| response.message.header.rcode);
    assert_eq!(
        dead_zone,
        Err(UpstreamError::ServerFailure { is_upstream: false }),
        "one dead zone must not take the recursor out of the pool"
    );
}

async fn with_dead_zone() -> Result<Network, HarnessError> {
    let mut network = Network::new().await?;
    network
        .serve(ROOT, root_script().refer("com.", "ns.com.", ip(COM)))
        .await?;
    let com = ZoneScript::new()
        .refer("example.com.", "ns.example.com.", ip(EXAMPLE))
        .refer("dead.com.", "ns.dead.com.", ip(DEAD));
    network.serve(COM, com).await?;
    let example = ZoneScript::new().answer(
        "a.example.com.",
        RecordType::A,
        vec![a("a.example.com.", 60)],
    );
    network.serve(EXAMPLE, example).await?;
    Ok(network)
}

#[tokio::test]
async fn glue_looked_up_once_is_not_looked_up_again() {
    let mut network = Network::new().await.expect("network");
    let root = root_script()
        .refer("com.", "ns.com.", ip(COM))
        .refer("net.", "ns.net.", ip(NET));
    network.serve(ROOT, root).await.expect("serve");
    network
        .serve(
            COM,
            ZoneScript::new().refer_without_glue("example.com.", "ns.dns.net."),
        )
        .await
        .expect("serve");
    network
        .serve(
            NET,
            ZoneScript::new().refer("dns.net.", "ns.dns.net.", ip(DNS_NET)),
        )
        .await
        .expect("serve");
    let dns_net = ZoneScript::new().answer(
        "ns.dns.net.",
        RecordType::A,
        vec![a("ns.dns.net.", EXAMPLE)],
    );
    network.serve(DNS_NET, dns_net).await.expect("serve");
    let example = ZoneScript::new()
        .answer(
            "a.example.com.",
            RecordType::A,
            vec![a("a.example.com.", 60)],
        )
        .answer(
            "b.example.com.",
            RecordType::A,
            vec![a("b.example.com.", 61)],
        );
    network.serve(EXAMPLE, example).await.expect("serve");
    let recursor = network
        .recursor(DescentLimits::default())
        .expect("recursor");

    for qname in ["a.example.com.", "b.example.com."] {
        recursor
            .resolve_iteratively(&question(qname, RecordType::A), network.deadline())
            .await
            .expect("resolved");
    }

    let glue_lookups = network
        .asked(DNS_NET)
        .iter()
        .filter(|asked| asked.as_str() == "ns.dns.net. A")
        .count();
    assert_eq!(
        glue_lookups, 1,
        "the second descent used the remembered glue"
    );
}

#[tokio::test]
async fn an_edns_retry_over_tcp_is_charged_to_the_query_budget() {
    let mut network = Network::new().await.expect("network");
    let root = root_script()
        .answer("com.", RecordType::A, vec![a("com.", 9)])
        .edns_intolerant()
        .truncate_udp();
    network.serve(ROOT, root).await.expect("serve");
    let limits = DescentLimits::new(16, 2, 8, Duration::from_secs(4)).expect("limits");
    let recursor = network.recursor(limits).expect("recursor");

    let error = recursor
        .resolve_iteratively(&question("com.", RecordType::A), network.deadline())
        .await
        .expect_err("EDNS FORMERR, plain UDP and TCP are three packets, over a budget of two");

    assert_eq!(
        error,
        RecursionError::BudgetExceeded(BudgetExceeded::OutboundQueries)
    );
}

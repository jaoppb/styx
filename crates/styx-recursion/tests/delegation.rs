//! Socket-level delegation safety: glue, bailiwick, lameness.

mod support;

use std::net::Ipv4Addr;
use std::time::Instant;

use styx_proto::RecordType;
use styx_recursion::domain::budget::DescentLimits;
use styx_recursion::domain::error::RecursionError;
use styx_recursion::domain::ports::InfraCache;
use styx_recursion::domain::topology::NameserverAddr;
use styx_testkit::{HarnessError, ZoneScript};
use support::{a, loopback, owners, question, root_script, Network, ROOT};

const COM: u8 = 3;
const NET: u8 = 5;
const DNS_NET: u8 = 6;
const EXAMPLE: u8 = 4;
const SPARE: u8 = 7;

fn ip(last: u8) -> Ipv4Addr {
    Ipv4Addr::new(127, 0, 0, last)
}

async fn with_root_and_tlds() -> Result<Network, HarnessError> {
    let mut network = Network::new().await?;
    let root = root_script()
        .refer("com.", "ns.com.", ip(COM))
        .refer("net.", "ns.net.", ip(NET));
    network.serve(ROOT, root).await?;
    Ok(network)
}

#[tokio::test]
async fn a_glueless_delegation_is_resolved_by_a_sub_descent() {
    let mut network = with_root_and_tlds().await.expect("network");
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
    network
        .serve(
            DNS_NET,
            ZoneScript::new().answer(
                "ns.dns.net.",
                RecordType::A,
                vec![a("ns.dns.net.", EXAMPLE)],
            ),
        )
        .await
        .expect("serve");
    network
        .serve(
            EXAMPLE,
            ZoneScript::new().answer(
                "www.example.com.",
                RecordType::A,
                vec![a("www.example.com.", 40)],
            ),
        )
        .await
        .expect("serve");
    let recursor = network
        .recursor(DescentLimits::default())
        .expect("recursor");

    let response = recursor
        .resolve_iteratively(
            &question("www.example.com.", RecordType::A),
            network.deadline(),
        )
        .await
        .expect("resolved");

    assert_eq!(owners(&response.answers), ["www.example.com."]);
    assert_eq!(network.asked(DNS_NET), ["ns.dns.net. A"]);
    assert_eq!(network.asked(EXAMPLE), ["www.example.com. A"]);
}

#[tokio::test]
async fn circular_glue_terminates_without_looping() {
    let mut network = with_root_and_tlds().await.expect("network");
    let com = ZoneScript::new()
        .refer_without_glue("a-zone.com.", "ns.b-zone.com.")
        .refer_without_glue("b-zone.com.", "ns.a-zone.com.");
    network.serve(COM, com).await.expect("serve");
    let recursor = network
        .recursor(DescentLimits::default())
        .expect("recursor");

    let started = Instant::now();
    let error = recursor
        .resolve_iteratively(
            &question("www.a-zone.com.", RecordType::A),
            network.deadline(),
        )
        .await
        .expect_err("no nameserver is reachable");

    assert!(
        matches!(
            error,
            RecursionError::NoReachableNameserver { .. } | RecursionError::BudgetExceeded(_)
        ),
        "{error:?}"
    );
    assert!(started.elapsed().as_secs() < 5, "terminated promptly");
}

#[tokio::test]
async fn out_of_bailiwick_glue_is_discarded_not_used() {
    let mut network = with_root_and_tlds().await.expect("network");
    // com refers example.com to a .net nameserver and offers glue for it. The com
    // servers may not speak for .net names, so that glue must never be used.
    let com = ZoneScript::new().refer("example.com.", "ns.example.net.", ip(EXAMPLE));
    network.serve(COM, com).await.expect("serve");
    network.serve(NET, ZoneScript::new()).await.expect("serve");
    network
        .serve(
            EXAMPLE,
            ZoneScript::new().answer(
                "www.example.com.",
                RecordType::A,
                vec![a("www.example.com.", 66)],
            ),
        )
        .await
        .expect("serve");
    let recursor = network
        .recursor(DescentLimits::default())
        .expect("recursor");

    let outcome = recursor
        .resolve_iteratively(
            &question("www.example.com.", RecordType::A),
            network.deadline(),
        )
        .await;

    assert!(
        outcome.is_err(),
        "the only address offered was poisoned glue"
    );
    assert!(
        network.asked(EXAMPLE).is_empty(),
        "the poisoned address was never contacted"
    );
    assert_eq!(
        network.asked(NET),
        ["example.net. NS"],
        "it was looked up instead"
    );
}

#[tokio::test]
async fn a_lame_server_is_skipped_and_its_sibling_answers() {
    let mut network = with_root_and_tlds().await.expect("network");
    let com = ZoneScript::new()
        .refer("example.com.", "ns1.example.com.", ip(EXAMPLE))
        .refer("example.com.", "ns2.example.com.", ip(SPARE));
    network.serve(COM, com).await.expect("serve");
    network
        .serve(EXAMPLE, ZoneScript::new().lame())
        .await
        .expect("serve");
    network
        .serve(
            SPARE,
            ZoneScript::new().answer(
                "www.example.com.",
                RecordType::A,
                vec![a("www.example.com.", 41)],
            ),
        )
        .await
        .expect("serve");
    let recursor = network
        .recursor(DescentLimits::default())
        .expect("recursor");

    let response = recursor
        .resolve_iteratively(
            &question("www.example.com.", RecordType::A),
            network.deadline(),
        )
        .await
        .expect("the sibling answers");

    assert_eq!(owners(&response.answers), ["www.example.com."]);
    let lame = NameserverAddr::new(loopback(EXAMPLE));
    let now = styx_core::Clock::now_monotonic(network.clock.as_ref());
    assert!(
        network
            .infra
            .metrics(lame, now)
            .is_lame_for(&support::name("example.com."), now),
        "the lame server is remembered, so the next descent skips it"
    );
}

#[tokio::test]
async fn every_server_lame_is_a_lame_delegation() {
    let mut network = with_root_and_tlds().await.expect("network");
    network
        .serve(
            COM,
            ZoneScript::new().refer("example.com.", "ns.example.com.", ip(EXAMPLE)),
        )
        .await
        .expect("serve");
    network
        .serve(EXAMPLE, ZoneScript::new().lame())
        .await
        .expect("serve");
    let recursor = network
        .recursor(DescentLimits::default())
        .expect("recursor");

    let error = recursor
        .resolve_iteratively(
            &question("www.example.com.", RecordType::A),
            network.deadline(),
        )
        .await
        .expect_err("lame");

    assert_eq!(error, RecursionError::LameDelegation);
}

//! Socket-level minimisation behaviour against misbehaving servers.

mod support;

use std::net::Ipv4Addr;

use styx_core::Clock;
use styx_proto::{RecordType, ResponseCode};
use styx_recursion::domain::budget::DescentLimits;
use styx_recursion::domain::metrics::MinimisationVerdict;
use styx_recursion::domain::ports::InfraCache;
use styx_recursion::domain::topology::NameserverAddr;
use styx_testkit::{HarnessError, ZoneScript};
use support::{a, loopback, owners, question, root_script, Network, ROOT};

const COM: u8 = 3;
const SPARE_COM: u8 = 8;
const EXAMPLE: u8 = 4;
const OTHER: u8 = 9;

fn ip(last: u8) -> Ipv4Addr {
    Ipv4Addr::new(127, 0, 0, last)
}

fn example_and_other() -> ZoneScript {
    ZoneScript::new()
        .refer("example.com.", "ns.example.com.", ip(EXAMPLE))
        .refer("other.com.", "ns.other.com.", ip(OTHER))
}

async fn network(com: ZoneScript) -> Result<Network, HarnessError> {
    let mut network = Network::new().await?;
    network
        .serve(ROOT, root_script().refer("com.", "ns.com.", ip(COM)))
        .await?;
    network.serve(COM, com).await?;
    network
        .serve(
            EXAMPLE,
            ZoneScript::new().answer(
                "www.example.com.",
                RecordType::A,
                vec![a("www.example.com.", 50)],
            ),
        )
        .await?;
    network
        .serve(
            OTHER,
            ZoneScript::new().answer("x.other.com.", RecordType::A, vec![a("x.other.com.", 51)]),
        )
        .await?;
    Ok(network)
}

fn verdict(network: &Network, last: u8) -> MinimisationVerdict {
    let now = network.clock.now_monotonic();
    network
        .infra
        .metrics(NameserverAddr::new(loopback(last)), now)
        .minimisation(now)
}

#[tokio::test]
async fn truncation_retries_over_tcp_with_the_same_minimised_question() {
    let network = network(example_and_other().truncate_udp())
        .await
        .expect("network");
    let recursor = network
        .recursor(DescentLimits::default())
        .expect("recursor");

    recursor
        .resolve_iteratively(
            &question("www.example.com.", RecordType::A),
            network.deadline(),
        )
        .await
        .expect("resolved");

    let received = network.server(COM).expect("server").received();
    let seen: Vec<(String, bool)> = received
        .iter()
        .map(|query| (query.question.qname.to_string(), query.via_tcp))
        .collect();
    assert_eq!(
        seen,
        [
            ("example.com.".to_string(), false),
            ("example.com.".to_string(), true)
        ],
        "retrying in full on TC would silently leak"
    );
}

#[tokio::test]
async fn an_edns_intolerant_server_is_answered_without_edns_and_remembered() {
    let mut network = Network::new().await.expect("network");
    network
        .serve(ROOT, root_script().refer("com.", "ns.com.", ip(COM)))
        .await
        .expect("serve");
    network
        .serve(COM, example_and_other())
        .await
        .expect("serve");
    network
        .serve(
            EXAMPLE,
            ZoneScript::new().edns_intolerant().answer(
                "www.example.com.",
                RecordType::A,
                vec![a("www.example.com.", 52)],
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
        .expect("resolved without EDNS");

    assert_eq!(owners(&response.answers), ["www.example.com."]);
    let now = network.clock.now_monotonic();
    let edns = network
        .infra
        .metrics(NameserverAddr::new(loopback(EXAMPLE)), now)
        .edns();
    assert_eq!(
        edns,
        styx_recursion::domain::metrics::EdnsCapability::Intolerant
    );
}

#[tokio::test]
async fn a_server_refusing_minimised_queries_gets_the_full_name_after_proof() {
    let com = example_and_other()
        .rcode("example.com.", Some(RecordType::NS), ResponseCode::REFUSED)
        .rcode("other.com.", Some(RecordType::NS), ResponseCode::REFUSED);
    let network = network(com).await.expect("network");
    let recursor = network
        .recursor(DescentLimits::default())
        .expect("recursor");

    recursor
        .resolve_iteratively(
            &question("www.example.com.", RecordType::A),
            network.deadline(),
        )
        .await
        .expect("resolved after falling back");
    assert!(matches!(
        verdict(&network, COM),
        MinimisationVerdict::MishandlesMinimised(_)
    ));

    recursor
        .resolve_iteratively(&question("x.other.com.", RecordType::A), network.deadline())
        .await
        .expect("resolved");
    assert_eq!(
        network.asked(COM),
        ["example.com. NS", "www.example.com. A", "x.other.com. A"],
        "the proven server is asked in full at once, not refused again"
    );
    let snapshot = network.diagnostics.snapshot().expect("published");
    assert_eq!(snapshot.minimisation_fallbacks, 1);
}

#[tokio::test]
async fn a_timeout_writes_no_verdict_and_the_sibling_answers() {
    let mut network = Network::new().await.expect("network");
    let root =
        root_script()
            .refer("com.", "a.ns.com.", ip(COM))
            .refer("com.", "b.ns.com.", ip(SPARE_COM));
    network.serve(ROOT, root).await.expect("serve");
    network
        .serve(COM, ZoneScript::new().silent())
        .await
        .expect("serve");
    network
        .serve(SPARE_COM, example_and_other())
        .await
        .expect("serve");
    network
        .serve(
            EXAMPLE,
            ZoneScript::new().answer(
                "www.example.com.",
                RecordType::A,
                vec![a("www.example.com.", 53)],
            ),
        )
        .await
        .expect("serve");
    let recursor = network
        .recursor(DescentLimits::default())
        .expect("recursor");

    recursor
        .resolve_iteratively(
            &question("www.example.com.", RecordType::A),
            network.deadline(),
        )
        .await
        .expect("the sibling answers");

    assert_eq!(network.asked(COM), ["example.com. NS"], "asked minimised");
    assert_eq!(verdict(&network, COM), MinimisationVerdict::Unknown);
    assert_eq!(
        network.asked(SPARE_COM),
        ["example.com. NS"],
        "still minimised"
    );
}

#[tokio::test]
async fn servfail_writes_no_verdict() {
    let com = example_and_other().rcode("example.com.", None, ResponseCode::SERVFAIL);
    let network = network(com).await.expect("network");
    let recursor = network
        .recursor(DescentLimits::default())
        .expect("recursor");

    let outcome = recursor
        .resolve_iteratively(
            &question("www.example.com.", RecordType::A),
            network.deadline(),
        )
        .await;

    assert!(outcome.is_err(), "the only com server failed");
    assert_eq!(
        network.asked(COM),
        ["example.com. NS"],
        "never retried in full"
    );
    assert_eq!(verdict(&network, COM), MinimisationVerdict::Unknown);
}

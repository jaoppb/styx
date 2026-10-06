//! Socket-level budgets, priming, coalescing and the `Upstream` boundary.

mod support;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use styx_core::{Upstream, UpstreamError, UpstreamKind};
use styx_proto::RecordType;
use styx_recursion::domain::budget::DescentLimits;
use styx_recursion::domain::diagnostics::ContactOutcome;
use styx_recursion::domain::error::{BudgetExceeded, ConfigError, RecursionError};
use styx_testkit::{FakeNameServer, FakeRole, HarnessError, ZoneScript};
use support::{a, loopback, owners, question, root_script, Network, ROOT};

const COM: u8 = 3;
const SPARE_COM: u8 = 8;
const EXAMPLE: u8 = 4;

fn ip(last: u8) -> Ipv4Addr {
    Ipv4Addr::new(127, 0, 0, last)
}

fn limits(depth: u8, queries: u16, wall_clock: Duration) -> Result<DescentLimits, ConfigError> {
    DescentLimits::new(depth, queries, 8, wall_clock)
}

async fn standard() -> Result<Network, HarnessError> {
    let mut network = Network::new().await?;
    network
        .serve(ROOT, root_script().refer("com.", "ns.com.", ip(COM)))
        .await?;
    network
        .serve(
            COM,
            ZoneScript::new().refer("example.com.", "ns.example.com.", ip(EXAMPLE)),
        )
        .await?;
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
    network.serve(EXAMPLE, example).await?;
    Ok(network)
}

/// Replaces the silent root with a working one on the same address, and adds the
/// rest of the delegation chain.
async fn revive(network: &mut Network) -> Result<FakeNameServer, HarnessError> {
    if let Some(silent) = network.server(ROOT) {
        silent.shutdown();
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    let root = root_script().refer("com.", "ns.com.", ip(COM));
    let address = SocketAddr::new(loopback(ROOT), network.port);
    let revived = FakeNameServer::start_on(address, FakeRole::Root, root).await?;
    let com = ZoneScript::new().refer("example.com.", "ns.example.com.", ip(EXAMPLE));
    network.serve(COM, com).await?;
    let example = ZoneScript::new().answer(
        "a.example.com.",
        RecordType::A,
        vec![a("a.example.com.", 62)],
    );
    network.serve(EXAMPLE, example).await?;
    Ok(revived)
}

/// example.com answers; lame.com is delegated to a server that answers nothing with
/// authority.
async fn with_lame_zone() -> Result<Network, HarnessError> {
    const LAME: u8 = 10;
    let mut network = Network::new().await?;
    network
        .serve(ROOT, root_script().refer("com.", "ns.com.", ip(COM)))
        .await?;
    let com = ZoneScript::new()
        .refer("example.com.", "ns.example.com.", ip(EXAMPLE))
        .refer("lame.com.", "ns.lame.com.", ip(LAME));
    network.serve(COM, com).await?;
    let example = ZoneScript::new().answer(
        "a.example.com.",
        RecordType::A,
        vec![a("a.example.com.", 63)],
    );
    network.serve(EXAMPLE, example).await?;
    network.serve(LAME, ZoneScript::new().lame()).await?;
    Ok(network)
}

#[tokio::test]
async fn the_depth_budget_ends_a_deep_descent() {
    let network = standard().await.expect("network");
    let recursor = network
        .recursor(limits(1, 64, Duration::from_secs(4)).expect("limits"))
        .expect("recursor");

    let error = recursor
        .resolve_iteratively(
            &question("a.example.com.", RecordType::A),
            network.deadline(),
        )
        .await
        .expect_err("too deep");

    assert_eq!(error, RecursionError::BudgetExceeded(BudgetExceeded::Depth));
}

#[tokio::test]
async fn the_query_budget_caps_outbound_traffic() {
    let network = standard().await.expect("network");
    let recursor = network
        .recursor(limits(16, 2, Duration::from_secs(4)).expect("limits"))
        .expect("recursor");

    let error = recursor
        .resolve_iteratively(
            &question("a.example.com.", RecordType::A),
            network.deadline(),
        )
        .await
        .expect_err("too many queries");

    assert_eq!(
        error,
        RecursionError::BudgetExceeded(BudgetExceeded::OutboundQueries)
    );
    assert!(
        network.asked(EXAMPLE).is_empty(),
        "the third query was never sent"
    );
}

#[tokio::test]
async fn the_wall_clock_budget_ends_a_descent_stuck_on_silent_servers() {
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
        .serve(SPARE_COM, ZoneScript::new().silent())
        .await
        .expect("serve");
    let recursor = network
        .recursor(limits(16, 64, Duration::from_secs(2)).expect("limits"))
        .expect("recursor");

    let clock = Arc::clone(&network.clock);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        clock.advance(Duration::from_secs(3));
    });
    let error = recursor
        .resolve_iteratively(
            &question("a.example.com.", RecordType::A),
            network.deadline(),
        )
        .await
        .expect_err("out of time");

    assert_eq!(
        error,
        RecursionError::BudgetExceeded(BudgetExceeded::WallClock)
    );
    assert_eq!(
        network.asked(SPARE_COM),
        Vec::<String>::new(),
        "no query after the clock ran out"
    );
}

#[tokio::test]
async fn priming_failure_falls_back_to_hints_and_recovers_once_a_root_answers() {
    let mut network = Network::new().await.expect("network");
    network
        .serve(ROOT, ZoneScript::new().silent())
        .await
        .expect("serve");
    let recursor = network
        .recursor(DescentLimits::default())
        .expect("recursor");

    let error = recursor
        .resolve_iteratively(
            &question("a.example.com.", RecordType::A),
            network.deadline(),
        )
        .await
        .expect_err("no root reachable");
    assert_eq!(
        error,
        RecursionError::NoReachableNameserver { at_root: true }
    );
    let snapshot = network.diagnostics.snapshot().expect("published");
    assert_eq!(snapshot.last_successful_priming, None);
    assert_eq!(snapshot.roots[0].last_outcome, ContactOutcome::Failed);

    let revived = revive(&mut network).await.expect("revive");
    network.clock.advance(Duration::from_secs(10));

    let response = recursor
        .resolve_iteratively(
            &question("a.example.com.", RecordType::A),
            network.deadline(),
        )
        .await
        .expect("recovered");
    assert_eq!(owners(&response.answers), ["a.example.com."]);
    let primed = revived
        .received_queries()
        .iter()
        .any(|question| question.qname.is_root() && question.qtype == RecordType::NS);
    assert!(primed, "the backoff ended and priming ran again");
    revived.shutdown();
}

#[tokio::test]
async fn concurrent_descents_share_identical_outbound_queries() {
    let network = standard().await.expect("network");
    let recursor = network
        .recursor(DescentLimits::default())
        .expect("recursor");

    let (a_question, b_question) = (
        question("a.example.com.", RecordType::A),
        question("b.example.com.", RecordType::A),
    );
    let (first, second) = tokio::join!(
        recursor.resolve_iteratively(&a_question, network.deadline()),
        recursor.resolve_iteratively(&b_question, network.deadline()),
    );

    assert!(first.is_ok() && second.is_ok());
    assert_eq!(network.asked(ROOT), ["com. NS"], "one root query for both");
    assert_eq!(
        network.asked(COM),
        ["example.com. NS"],
        "one TLD query for both"
    );
    assert_eq!(network.asked(EXAMPLE).len(), 2);
}

#[tokio::test]
async fn the_upstream_port_answers_as_a_recursor_and_maps_failures() {
    let network = with_lame_zone().await.expect("network");
    let recursor = Arc::new(
        network
            .recursor(DescentLimits::default())
            .expect("recursor"),
    );

    let deadline = network.deadline();
    let task = Arc::clone(&recursor);
    let response = tokio::spawn(async move {
        task.resolve(&question("a.example.com.", RecordType::A), deadline)
            .await
    })
    .await
    .expect("the future is Send")
    .expect("resolved");
    assert_eq!(response.kind, UpstreamKind::Recursor);
    assert_eq!(recursor.kind(), UpstreamKind::Recursor);

    let nxdomain = recursor
        .resolve(
            &question("missing.example.com.", RecordType::A),
            network.deadline(),
        )
        .await;
    assert!(
        nxdomain.is_ok(),
        "an NXDOMAIN is an answer, not an upstream failure"
    );

    let lame = recursor
        .resolve(
            &question("www.lame.com.", RecordType::A),
            network.deadline(),
        )
        .await;
    assert_eq!(
        lame.map(|response| response.message.header.rcode),
        Err(UpstreamError::ServerFailure { is_upstream: false }),
        "a name-specific failure must not trip the circuit breaker"
    );
}

#[tokio::test]
async fn diagnostics_report_root_and_tld_contact() {
    let network = standard().await.expect("network");
    let recursor = network
        .recursor(DescentLimits::default())
        .expect("recursor");
    recursor
        .resolve_iteratively(
            &question("a.example.com.", RecordType::A),
            network.deadline(),
        )
        .await
        .expect("resolved");

    let snapshot = network.diagnostics.snapshot().expect("published");
    assert!(snapshot.last_successful_priming.is_some());
    assert_eq!(snapshot.roots.len(), 1);
    assert_eq!(snapshot.roots[0].last_outcome, ContactOutcome::Answered);
    assert!(snapshot.roots[0].last_rtt.is_some());
    assert_eq!(snapshot.tlds.len(), 1);
    assert_eq!(snapshot.tlds[0].tld.to_string(), "com.");
    assert_eq!(snapshot.descents_total, 1);
    assert_eq!(snapshot.descents_failed, 0);
}

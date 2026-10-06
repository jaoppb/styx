//! Socket-level descents against fake root, TLD and authoritative servers.
//!
//! Every test asserts on **the questions the fakes received**, not only on the
//! answer: nothing in an answer reveals whether the full qname leaked to the root.

mod support;

use std::net::Ipv4Addr;

use styx_proto::{RecordType, ResponseCode};
use styx_recursion::domain::budget::DescentLimits;
use styx_recursion::domain::error::RecursionError;
use styx_testkit::{HarnessError, ZoneScript};
use support::{a, cname, owners, question, root_script, Network};

const COM: u8 = 3;
const EXAMPLE: u8 = 4;
const NET: u8 = 5;
const CDN: u8 = 6;

/// root → com → example.com, with `example` as example.com's script.
async fn network(example: ZoneScript) -> Result<Network, HarnessError> {
    let mut network = Network::new().await?;
    let root = root_script()
        .refer("com.", "ns.com.", Ipv4Addr::new(127, 0, 0, COM))
        .refer("net.", "ns.net.", Ipv4Addr::new(127, 0, 0, NET));
    network.serve(support::ROOT, root).await?;
    let com = ZoneScript::new().refer(
        "example.com.",
        "ns.example.com.",
        Ipv4Addr::new(127, 0, 0, EXAMPLE),
    );
    network.serve(COM, com).await?;
    network
        .serve(EXAMPLE, example.origin("example.com.", 60))
        .await?;
    Ok(network)
}

#[tokio::test]
async fn a_cold_descent_tells_each_server_only_what_it_needs() {
    let example = ZoneScript::new().answer(
        "secret.internal.example.com.",
        RecordType::A,
        vec![a("secret.internal.example.com.", 99)],
    );
    let network = network(example).await.expect("network");
    let recursor = network
        .recursor(DescentLimits::default())
        .expect("recursor");

    let response = recursor
        .resolve_iteratively(
            &question("secret.internal.example.com.", RecordType::A),
            network.deadline(),
        )
        .await
        .expect("resolved");

    assert_eq!(owners(&response.answers), ["secret.internal.example.com."]);
    assert_eq!(network.asked(support::ROOT), ["com. NS"]);
    assert_eq!(network.asked(COM), ["example.com. NS"]);
    assert_eq!(
        network.asked(EXAMPLE),
        ["internal.example.com. NS", "secret.internal.example.com. A"],
        "internal.example.com is an empty non-terminal: descend a label, never conclude NODATA"
    );
    assert!(
        network
            .server(COM)
            .expect("server")
            .received()
            .iter()
            .all(|query| query.dnssec_ok),
        "descent queries carry DO=1"
    );
}

#[tokio::test]
async fn a_warm_descent_starts_at_the_cached_cut() {
    let example = ZoneScript::new()
        .answer(
            "www.example.com.",
            RecordType::A,
            vec![a("www.example.com.", 10)],
        )
        .answer(
            "mail.example.com.",
            RecordType::A,
            vec![a("mail.example.com.", 11)],
        );
    let network = network(example).await.expect("network");
    let recursor = network
        .recursor(DescentLimits::default())
        .expect("recursor");

    for qname in ["www.example.com.", "mail.example.com."] {
        recursor
            .resolve_iteratively(&question(qname, RecordType::A), network.deadline())
            .await
            .expect("resolved");
    }

    assert_eq!(network.asked(support::ROOT), ["com. NS"]);
    assert_eq!(network.asked(COM), ["example.com. NS"]);
    assert_eq!(
        network.asked(EXAMPLE),
        ["www.example.com. A", "mail.example.com. A"]
    );
}

#[tokio::test]
async fn an_intermediate_nxdomain_is_trusted_and_the_full_name_never_leaves() {
    let network = network(ZoneScript::new()).await.expect("network");
    let recursor = network
        .recursor(DescentLimits::default())
        .expect("recursor");

    let response = recursor
        .resolve_iteratively(
            &question("tracker-7f3a.ads.missing.com.", RecordType::A),
            network.deadline(),
        )
        .await
        .expect("an NXDOMAIN is an answer");

    assert_eq!(response.header.rcode, ResponseCode::NXDOMAIN);
    assert_eq!(network.asked(COM), ["missing.com. NS"]);
}

#[tokio::test]
async fn a_cname_chain_across_zones_is_followed_and_carried() {
    let example = ZoneScript::new().answer(
        "www.example.com.",
        RecordType::CNAME,
        vec![cname("www.example.com.", "edge.cdn.net.")],
    );
    let mut network = network(example).await.expect("network");
    network
        .serve(
            NET,
            ZoneScript::new().refer("cdn.net.", "ns.cdn.net.", Ipv4Addr::new(127, 0, 0, CDN)),
        )
        .await
        .expect("serve");
    network
        .serve(
            CDN,
            ZoneScript::new().answer("edge.cdn.net.", RecordType::A, vec![a("edge.cdn.net.", 77)]),
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

    assert_eq!(
        owners(&response.answers),
        ["www.example.com.", "edge.cdn.net."]
    );
    assert_eq!(network.asked(NET), ["cdn.net. NS"]);
    assert_eq!(network.asked(CDN), ["edge.cdn.net. A"]);
}

#[tokio::test]
async fn a_cname_within_the_zone_is_followed() {
    let example = ZoneScript::new()
        .answer(
            "www.example.com.",
            RecordType::CNAME,
            vec![cname("www.example.com.", "host.example.com.")],
        )
        .answer(
            "host.example.com.",
            RecordType::A,
            vec![a("host.example.com.", 12)],
        );
    let network = network(example).await.expect("network");
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

    assert_eq!(
        owners(&response.answers),
        ["www.example.com.", "host.example.com."]
    );
}

#[tokio::test]
async fn a_cname_loop_fails_as_a_loop() {
    let example = ZoneScript::new()
        .answer(
            "a.example.com.",
            RecordType::CNAME,
            vec![cname("a.example.com.", "b.example.com.")],
        )
        .answer(
            "b.example.com.",
            RecordType::CNAME,
            vec![cname("b.example.com.", "a.example.com.")],
        );
    let network = network(example).await.expect("network");
    let recursor = network
        .recursor(DescentLimits::default())
        .expect("recursor");

    let error = recursor
        .resolve_iteratively(
            &question("a.example.com.", RecordType::A),
            network.deadline(),
        )
        .await
        .expect_err("loops");

    assert_eq!(error, RecursionError::CnameLoop);
}

#[tokio::test]
async fn a_dname_rewrites_mid_descent() {
    let example = ZoneScript::new()
        .dname("old.example.com.", "example.com.")
        .answer(
            "www.example.com.",
            RecordType::A,
            vec![a("www.example.com.", 13)],
        );
    let network = network(example).await.expect("network");
    let recursor = network
        .recursor(DescentLimits::default())
        .expect("recursor");

    let response = recursor
        .resolve_iteratively(
            &question("www.old.example.com.", RecordType::A),
            network.deadline(),
        )
        .await
        .expect("resolved");

    let types: Vec<RecordType> = response.answers.iter().map(|record| record.rtype).collect();
    assert_eq!(
        types,
        [RecordType::from_u16(39), RecordType::CNAME, RecordType::A],
        "the DNAME, its synthesized CNAME, then the target's address"
    );
}

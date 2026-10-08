use std::net::Ipv4Addr;

use styx_proto::{RecordClass, Ttl, UnknownRdata};

use super::*;

fn name(text: &str) -> Name {
    Name::from_ascii(text).expect("name")
}

fn canonical(text: &str) -> CanonicalName {
    CanonicalName::canonicalize(&name(text))
}

fn cname(owner: &str, target: &str) -> ResourceRecord {
    ResourceRecord::new(
        name(owner),
        RecordType::CNAME,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::Cname(name(target)),
    )
}

fn dname(owner: &str, target: &str) -> ResourceRecord {
    let wire = name(target).as_wire_bytes().to_vec();
    ResourceRecord::new(
        name(owner),
        RecordType::DNAME,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::Unknown(UnknownRdata::new(RecordType::DNAME, wire)),
    )
}

fn address(owner: &str) -> ResourceRecord {
    ResourceRecord::new(
        name(owner),
        RecordType::A,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    )
}

fn scope(zone: &str, qname: &str, answers: &[ResourceRecord]) -> AnswerScope {
    AnswerScope::from_chain(canonical(zone), &canonical(qname), answers)
}

fn permits(scope: &AnswerScope, owner: &str) -> bool {
    scope.permits(&canonical(owner), RecordType::A)
}

#[test]
fn a_cross_zone_chain_permits_each_target() {
    let answers = [
        cname("www.example.com.", "edge.cdn.net."),
        cname("edge.cdn.net.", "pop1.cdn.org."),
        address("pop1.cdn.org."),
    ];
    let scope = scope("www.example.com.", "www.example.com.", &answers);

    assert!(permits(&scope, "www.example.com."));
    assert!(permits(&scope, "edge.cdn.net."));
    assert!(permits(&scope, "pop1.cdn.org."));
}

#[test]
fn a_chain_listed_out_of_order_is_still_followed() {
    let answers = [
        address("pop1.cdn.org."),
        cname("edge.cdn.net.", "pop1.cdn.org."),
        cname("www.example.com.", "edge.cdn.net."),
    ];
    let scope = scope("www.example.com.", "www.example.com.", &answers);

    assert!(permits(&scope, "pop1.cdn.org."));
}

#[test]
fn a_target_is_permitted_exactly_never_its_subtree() {
    let answers = [cname("www.example.com.", "edge.cdn.net.")];
    let scope = scope("www.example.com.", "www.example.com.", &answers);

    assert!(!permits(&scope, "evil.edge.cdn.net."));
    assert!(!permits(&scope, "cdn.net."));
}

#[test]
fn a_cname_owned_outside_the_scope_extends_nothing() {
    let answers = [
        cname("www.example.com.", "edge.cdn.net."),
        cname("unrelated.attacker.example.", "bank.example.org."),
    ];
    let scope = scope("www.example.com.", "www.example.com.", &answers);

    assert!(!permits(&scope, "unrelated.attacker.example."));
    assert!(!permits(&scope, "bank.example.org."));
}

#[test]
fn an_in_zone_cname_off_the_chain_cannot_admit_a_foreign_name() {
    let answers = [
        address("www.example.com."),
        cname("x.example.com.", "www.bank.com."),
        address("www.bank.com."),
    ];
    let scope = scope("example.com.", "www.example.com.", &answers);

    assert!(
        permits(&scope, "x.example.com."),
        "the CNAME itself is in zone"
    );
    assert!(!permits(&scope, "www.bank.com."));
}

#[test]
fn a_cyclic_chain_terminates() {
    let answers = [
        cname("www.example.com.", "a.loop.net."),
        cname("a.loop.net.", "b.loop.net."),
        cname("b.loop.net.", "a.loop.net."),
    ];
    let scope = scope("www.example.com.", "www.example.com.", &answers);

    assert!(permits(&scope, "a.loop.net."));
    assert!(permits(&scope, "b.loop.net."));
}

#[test]
fn a_long_reversed_chain_is_walked_in_one_pass() {
    let mut answers: Vec<ResourceRecord> = (0..2000)
        .map(|index| {
            cname(
                &format!("n{index}.chain.net."),
                &format!("n{}.chain.net.", index + 1),
            )
        })
        .collect();
    answers.reverse();
    answers.push(cname("www.example.com.", "n0.chain.net."));
    let scope = scope("www.example.com.", "www.example.com.", &answers);

    assert!(permits(&scope, "n2000.chain.net."));
}

#[test]
fn without_aliases_the_scope_is_the_zone() {
    let answers = [address("www.example.com."), address("other.example.net.")];
    let scope = scope("example.com.", "www.example.com.", &answers);

    assert!(permits(&scope, "deep.www.example.com."));
    assert!(!permits(&scope, "other.example.net."));
}

#[test]
fn a_dname_is_admitted_with_its_synthesized_cname() {
    let answers = [
        dname("old.example.", "new.example.net."),
        cname("www.old.example.", "www.new.example.net."),
        address("www.new.example.net."),
    ];
    let scope = scope("www.old.example.", "www.old.example.", &answers);

    assert!(scope.permits(&canonical("old.example."), RecordType::DNAME));
    assert!(!scope.permits(&canonical("old.example."), RecordType::A));
    assert!(permits(&scope, "www.new.example.net."));
    assert!(
        !permits(&scope, "other.new.example.net."),
        "never the subtree"
    );
}

#[test]
fn a_dname_whose_cname_says_something_else_is_rejected() {
    let answers = [
        dname("old.example.", "new.example.net."),
        cname("www.old.example.", "www.bank.com."),
    ];
    let scope = scope("www.old.example.", "www.old.example.", &answers);

    assert!(!scope.permits(&canonical("old.example."), RecordType::DNAME));
}

#[test]
fn a_dname_without_a_synthesized_cname_is_rejected() {
    let answers = [dname("old.example.", "new.example.net.")];
    let scope = scope("www.old.example.", "www.old.example.", &answers);

    assert!(!scope.permits(&canonical("old.example."), RecordType::DNAME));
}

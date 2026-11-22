//! Regression tests for DNAME answer chains and RFC 6840 §5.1 canonicalization.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::cmp::Ordering;

use styx_dnssec::domain::canonical::build_canonical_signed_data;
use styx_dnssec::{
    InMemoryChainSource, TrustAnchors, ValidationPolicy, ValidationVerdict, Validator,
    VerdictReason,
};
use styx_proto::application::canonical::canonical_rr_cmp;
use styx_proto::domain::rdata::{RrsigRdata, UnknownRdata};
use styx_proto::{Name, RData, RecordType, ResourceRecord, ResponseCode};
use support::{a_record, clock, name, nsec, query, record, ZoneKey, EXPIRATION, INCEPTION};

fn dname_record(owner: &Name, target: &Name) -> ResourceRecord {
    record(
        owner,
        RecordType::DNAME,
        RData::Unknown(UnknownRdata::new(
            RecordType::DNAME,
            target.as_wire_bytes().to_vec(),
        )),
    )
}

fn dname_fixture() -> (ZoneKey, ZoneKey, ZoneKey, InMemoryChainSource) {
    let root = ZoneKey::generate(&Name::root());
    let old_zone = ZoneKey::generate(&name("old.example."));
    let new_zone = ZoneKey::generate(&name("new.example."));
    let source = InMemoryChainSource::new();
    source.insert_cut(root.apex_cut());
    source.record_not_a_cut(name("example."));
    source.insert_cut(old_zone.signed_cut(&root));
    source.insert_cut(new_zone.signed_cut(&root));
    source.record_not_a_cut(name("www.old.example."));
    source.record_not_a_cut(name("www.new.example."));
    source.record_not_a_cut(name("missing.new.example."));
    (root, old_zone, new_zone, source)
}

#[tokio::test]
async fn test_dname_with_synthesized_cname_and_target_a_is_secure() {
    let (root, old_zone, new_zone, source) = dname_fixture();
    let validator = Validator::new(
        clock(),
        ValidationPolicy::default(),
        TrustAnchors::new(root.anchor()),
    );

    let dname_record = dname_record(&name("old.example."), &name("NeW.ExAmPlE."));
    let synthesized_cname = record(
        &name("www.old.example."),
        RecordType::CNAME,
        RData::Cname(name("www.new.example.")),
    );
    let target_a = a_record(&name("www.new.example."), 42);
    let mut message = query(&name("www.old.example."), RecordType::A);
    message
        .answers
        .push(old_zone.sign(std::slice::from_ref(&dname_record)));
    message.answers.push(dname_record);
    message.answers.push(synthesized_cname);
    message
        .answers
        .push(new_zone.sign(std::slice::from_ref(&target_a)));
    message.answers.push(target_a);

    assert_eq!(
        validator.validate(&message, &source).await.verdict,
        ValidationVerdict::Secure
    );
}

#[tokio::test]
async fn test_dname_forged_synthesized_cname_is_bogus() {
    let (root, old_zone, _new_zone, source) = dname_fixture();
    let validator = Validator::new(
        clock(),
        ValidationPolicy::default(),
        TrustAnchors::new(root.anchor()),
    );

    let dname_record = dname_record(&name("old.example."), &name("new.example."));
    let mut forged = query(&name("www.old.example."), RecordType::A);
    forged
        .answers
        .push(old_zone.sign(std::slice::from_ref(&dname_record)));
    forged.answers.push(dname_record);
    forged.answers.push(record(
        &name("www.old.example."),
        RecordType::CNAME,
        RData::Cname(name("evil.example.")),
    ));

    let outcome = validator.validate(&forged, &source).await;
    assert_eq!(outcome.verdict, ValidationVerdict::Bogus);
    assert_eq!(outcome.reason, VerdictReason::MalformedResponse);
}

#[tokio::test]
async fn test_dname_cname_query_and_unsigned_dname() {
    let (root, old_zone, _new_zone, source) = dname_fixture();
    let validator = Validator::new(
        clock(),
        ValidationPolicy::default(),
        TrustAnchors::new(root.anchor()),
    );

    let dname_record = dname_record(&name("old.example."), &name("new.example."));
    let synthesized_cname = record(
        &name("www.old.example."),
        RecordType::CNAME,
        RData::Cname(name("www.new.example.")),
    );
    let mut cname_query = query(&name("www.old.example."), RecordType::CNAME);
    cname_query
        .answers
        .push(old_zone.sign(std::slice::from_ref(&dname_record)));
    cname_query.answers.push(dname_record.clone());
    cname_query.answers.push(synthesized_cname.clone());
    assert_eq!(
        validator.validate(&cname_query, &source).await.verdict,
        ValidationVerdict::Secure
    );

    let mut unsigned = query(&name("www.old.example."), RecordType::A);
    unsigned.answers.push(dname_record);
    unsigned.answers.push(synthesized_cname);
    assert_eq!(
        validator.validate(&unsigned, &source).await.verdict,
        ValidationVerdict::Bogus
    );
}

#[tokio::test]
async fn test_dname_dangling_target_requires_denial_and_succeeds() {
    let (root, old_zone, new_zone, source) = dname_fixture();
    let validator = Validator::new(
        clock(),
        ValidationPolicy::default(),
        TrustAnchors::new(root.anchor()),
    );

    let dname_record = dname_record(&name("old.example."), &name("new.example."));
    let synthesized_cname = record(
        &name("missing.old.example."),
        RecordType::CNAME,
        RData::Cname(name("missing.new.example.")),
    );
    let denial = nsec(
        &name("new.example."),
        &name("www.new.example."),
        &[
            RecordType::SOA,
            RecordType::NS,
            RecordType::RRSIG,
            RecordType::NSEC,
        ],
    );
    let mut message = query(&name("missing.old.example."), RecordType::A);
    message.header.rcode = ResponseCode::NXDOMAIN;
    message
        .answers
        .push(old_zone.sign(std::slice::from_ref(&dname_record)));
    message.answers.push(dname_record);
    message.answers.push(synthesized_cname);
    message
        .authorities
        .push(new_zone.sign(std::slice::from_ref(&denial)));
    message.authorities.push(denial);

    assert_eq!(
        validator.validate(&message, &source).await.verdict,
        ValidationVerdict::Secure
    );
}

#[tokio::test]
async fn test_nsec_next_domain_preserves_case_in_canonical_and_sorting() {
    let mixed_next = name("WWW.ExAmPlE.");
    let nsec_record = nsec(
        &name("a.example."),
        &mixed_next,
        &[RecordType::A, RecordType::RRSIG, RecordType::NSEC],
    );
    let signature_template = RrsigRdata::new(
        RecordType::NSEC,
        15,
        2,
        300,
        EXPIRATION,
        INCEPTION,
        1,
        name("example."),
        Vec::new(),
    );
    let canonical = build_canonical_signed_data(&signature_template, &[&nsec_record]).unwrap();
    assert!(
        canonical
            .windows(mixed_next.as_wire_bytes().len())
            .any(|window| window == mixed_next.as_wire_bytes()),
        "NSEC next_domain must keep original case per RFC 6840 §5.1"
    );

    let lower_next_nsec = nsec(
        &name("a.example."),
        &name("www.example."),
        &[RecordType::A, RecordType::RRSIG, RecordType::NSEC],
    );
    assert_eq!(
        canonical_rr_cmp(&nsec_record, &lower_next_nsec),
        Ordering::Less
    );

    let root = ZoneKey::generate(&Name::root());
    let source = InMemoryChainSource::new();
    source.insert_cut(root.apex_cut());
    source.record_not_a_cut(name("b."));
    let apex_mixed_nsec = nsec(
        &Name::root(),
        &name("ZZZ."),
        &[
            RecordType::SOA,
            RecordType::NS,
            RecordType::RRSIG,
            RecordType::NSEC,
        ],
    );
    let mut message = query(&name("b."), RecordType::A);
    message.header.rcode = ResponseCode::NXDOMAIN;
    message
        .authorities
        .push(root.sign(std::slice::from_ref(&apex_mixed_nsec)));
    message.authorities.push(apex_mixed_nsec);
    let outcome = Validator::new(
        clock(),
        ValidationPolicy::default(),
        TrustAnchors::new(root.anchor()),
    )
    .validate(&message, &source)
    .await;
    assert_eq!(outcome.verdict, ValidationVerdict::Secure);
}

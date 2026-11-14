//! Integration tests for DNSKEY rollover and algorithm agility.

mod support;

use styx_dnssec::{
    Delegation, InMemoryChainSource, SignedRrset, ValidationPolicy, ValidationVerdict, Validator,
    VerdictReason, ZoneCutMaterial,
};
use styx_proto::{Name, RecordType};
use support::{a_record, clock, query, StaticAnchorSource, ZoneKey};

#[tokio::test]
async fn test_multi_key_rollover_validates_with_any_valid_signature() {
    let root = Name::root();
    let active = ZoneKey::generate(&root);
    let incoming = ZoneKey::generate_with_flags(&root, 256);

    let dnskey_set = vec![active.dnskey_record(), incoming.dnskey_record()];
    let dnskey_signatures = vec![active.sign(&dnskey_set)];
    let source = InMemoryChainSource::new();
    source.insert_cut(ZoneCutMaterial::new(
        root.clone(),
        Delegation::Apex {
            dnskey: SignedRrset::new(dnskey_set, dnskey_signatures),
        },
    ));

    let answer = a_record(&root, 1);
    let mut message = query(&root, RecordType::A);
    message
        .answers
        .push(active.sign(std::slice::from_ref(&answer)));
    message.answers.push(answer);

    let anchors = StaticAnchorSource::new(vec![active.anchor()]);
    let validator = Validator::new(clock(), ValidationPolicy::default());
    let outcome = validator.validate(&message, &source, &anchors).await;

    assert_eq!(outcome.verdict, ValidationVerdict::Secure);
    assert_eq!(outcome.reason, VerdictReason::AnchorMatched);
}

#[tokio::test]
async fn test_unsupported_nsec3_hash_algorithm_yields_insecure() {
    let root = Name::root();
    let active = ZoneKey::generate(&root);
    let source = InMemoryChainSource::new();
    source.insert_cut(ZoneCutMaterial::new(
        root.clone(),
        Delegation::Apex {
            dnskey: active.dnskey_rrset(),
        },
    ));

    let nsec3_rdata = styx_proto::domain::rdata::Nsec3Rdata::new(
        99,
        0,
        1,
        vec![1, 2],
        vec![0; 20],
        styx_proto::domain::rdata::TypeBitmap::new(Vec::new()),
    );
    let nsec3_record = support::record(
        &Name::from_ascii("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.").unwrap(),
        RecordType::NSEC3,
        styx_proto::RData::Nsec3(nsec3_rdata),
    );

    let mut message = query(&support::name("missing.example."), RecordType::A);
    message.header.rcode = styx_proto::ResponseCode::NXDOMAIN;
    message
        .authorities
        .push(active.sign(std::slice::from_ref(&nsec3_record)));
    message.authorities.push(nsec3_record);

    let anchors = StaticAnchorSource::new(vec![active.anchor()]);
    let validator = Validator::new(clock(), ValidationPolicy::default());
    let outcome = validator.validate(&message, &source, &anchors).await;

    assert_eq!(outcome.verdict, ValidationVerdict::Insecure);
    assert_eq!(outcome.reason, VerdictReason::UnsupportedAlgorithm);
}

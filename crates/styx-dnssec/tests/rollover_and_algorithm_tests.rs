//! Integration tests for DNSKEY rollover and algorithm agility.

mod support;

use styx_dnssec::{
    Delegation, InMemoryChainSource, SignedRrset, ValidationPolicy, ValidationVerdict, Validator,
    VerdictReason, ZoneCutMaterial,
};
use styx_proto::domain::rdata::DsRdata;
use styx_proto::{Name, RData, RecordType};
use support::{
    a_record, clock, clock_at, mark_non_cuts, name, query, record, StaticAnchorSource, ZoneKey,
    DIGEST_SHA256, EXPIRATION, INCEPTION,
};

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
    let validator = Validator::new(
        clock(),
        ValidationPolicy::default(),
        anchors.anchors.clone(),
    );
    let outcome = validator.validate(&message, &source).await;

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

    let missing = support::name("missing.example.");
    mark_non_cuts(&source, &missing, &root);
    let mut message = query(&missing, RecordType::A);
    message.header.rcode = styx_proto::ResponseCode::NXDOMAIN;
    message
        .authorities
        .push(active.sign(std::slice::from_ref(&nsec3_record)));
    message.authorities.push(nsec3_record);

    let anchors = StaticAnchorSource::new(vec![active.anchor()]);
    let validator = Validator::new(
        clock(),
        ValidationPolicy::default(),
        anchors.anchors.clone(),
    );
    let outcome = validator.validate(&message, &source).await;

    assert_eq!(outcome.verdict, ValidationVerdict::Insecure);
    assert_eq!(outcome.reason, VerdictReason::UnsupportedAlgorithm);
}

#[tokio::test]
async fn test_mixed_ds_set_validates_through_supported_entry() {
    let root = Name::root();
    let root_key = ZoneKey::generate(&root);
    let example = name("example.");
    let example_key = ZoneKey::generate(&example);

    let unsupported_ds = DsRdata::new(example_key.key_tag(), 200, DIGEST_SHA256, vec![0xAA; 32]);
    let ds_records = vec![
        record(&example, RecordType::DS, RData::Ds(unsupported_ds)),
        example_key.ds_record(),
    ];
    let ds_signatures = vec![root_key.sign(&ds_records)];

    let source = InMemoryChainSource::new();
    source.insert_cut(root_key.apex_cut());
    source.insert_cut(ZoneCutMaterial::new(
        example.clone(),
        Delegation::Signed {
            ds: SignedRrset::new(ds_records, ds_signatures),
            dnskey: example_key.dnskey_rrset(),
        },
    ));
    let www = name("www.example.");
    mark_non_cuts(&source, &www, &example);

    let answer = a_record(&www, 5);
    let mut message = query(&www, RecordType::A);
    message
        .answers
        .push(example_key.sign(std::slice::from_ref(&answer)));
    message.answers.push(answer);

    let anchors = StaticAnchorSource::new(vec![root_key.anchor()]);
    let outcome = Validator::new(clock(), ValidationPolicy::default(), anchors.anchors)
        .validate(&message, &source)
        .await;

    assert_eq!(outcome.verdict, ValidationVerdict::Secure);
    assert_eq!(outcome.reason, VerdictReason::AnchorMatched);
}

#[tokio::test]
async fn test_child_zone_bad_ds_digest_is_bogus() {
    let root = Name::root();
    let root_key = ZoneKey::generate(&root);
    let example = name("example.");
    let example_key = ZoneKey::generate(&example);

    let bad_ds = DsRdata::new(
        example_key.key_tag(),
        example_key.dnskey.algorithm(),
        DIGEST_SHA256,
        vec![0xFF; 32],
    );
    let ds_records = vec![record(&example, RecordType::DS, RData::Ds(bad_ds))];
    let ds_signatures = vec![root_key.sign(&ds_records)];

    let source = InMemoryChainSource::new();
    source.insert_cut(root_key.apex_cut());
    source.insert_cut(ZoneCutMaterial::new(
        example.clone(),
        Delegation::Signed {
            ds: SignedRrset::new(ds_records, ds_signatures),
            dnskey: example_key.dnskey_rrset(),
        },
    ));
    let www = name("www.example.");
    mark_non_cuts(&source, &www, &example);

    let answer = a_record(&www, 5);
    let mut message = query(&www, RecordType::A);
    message
        .answers
        .push(example_key.sign(std::slice::from_ref(&answer)));
    message.answers.push(answer);

    let anchors = StaticAnchorSource::new(vec![root_key.anchor()]);
    let outcome = Validator::new(clock(), ValidationPolicy::default(), anchors.anchors)
        .validate(&message, &source)
        .await;

    assert_eq!(outcome.verdict, ValidationVerdict::Bogus);
    assert_eq!(outcome.reason, VerdictReason::DsDnskeyMismatch);
}

#[tokio::test]
async fn test_inclusive_inception_and_expiration_boundaries() {
    let root_key = ZoneKey::generate(&Name::root());
    let source = InMemoryChainSource::new();
    source.insert_cut(root_key.apex_cut());
    let anchors = StaticAnchorSource::new(vec![root_key.anchor()]);

    let answer = a_record(&Name::root(), 1);
    let mut message = query(&Name::root(), RecordType::A);
    message
        .answers
        .push(root_key.sign(std::slice::from_ref(&answer)));
    message.answers.push(answer);

    for boundary in [u64::from(INCEPTION), u64::from(EXPIRATION)] {
        let outcome = Validator::new(
            clock_at(boundary),
            ValidationPolicy::default(),
            anchors.anchors.clone(),
        )
        .validate(&message, &source)
        .await;
        assert_eq!(outcome.verdict, ValidationVerdict::Secure, "at {boundary}");
    }

    let before = Validator::new(
        clock_at(u64::from(INCEPTION).saturating_sub(1)),
        ValidationPolicy::default(),
        anchors.anchors.clone(),
    )
    .validate(&message, &source)
    .await;
    assert_eq!(before.verdict, ValidationVerdict::Bogus);
    assert_eq!(before.reason, VerdictReason::SignatureNotYetValid);

    let after = Validator::new(
        clock_at(u64::from(EXPIRATION).saturating_add(1)),
        ValidationPolicy::default(),
        anchors.anchors,
    )
    .validate(&message, &source)
    .await;
    assert_eq!(after.verdict, ValidationVerdict::Bogus);
    assert_eq!(after.reason, VerdictReason::SignatureExpired);
}

//! Integration tests for positive chain validation and answer binding (Sub-phase 6a).

mod support;

use styx_dnssec::{
    DigestType, DnssecAlgorithm, InMemoryChainSource, PinnedRootAnchor, TrustAnchor,
    TrustAnchorSource, ValidationPolicy, ValidationVerdict, Validator, VerdictReason,
};
use styx_proto::domain::rdata::{DsRdata, NsecRdata, TypeBitmap};
use styx_proto::{Name, RData, RecordType};
use support::{
    a_record, clock, clock_at, name, query, record, StaticAnchorSource, ZoneKey, DIGEST_SHA256,
};

fn signed_root_answer(root_key: &ZoneKey) -> styx_proto::Message {
    let answer = a_record(&Name::root(), 4);
    let mut message = query(&Name::root(), RecordType::A);
    message
        .answers
        .push(root_key.sign(std::slice::from_ref(&answer)));
    message.answers.push(answer);
    message
}

fn root_source(root_key: &ZoneKey) -> InMemoryChainSource {
    let source = InMemoryChainSource::new();
    source.insert_cut(root_key.apex_cut());
    source
}

#[test]
fn test_pinned_root_anchor_contents() {
    let anchors = PinnedRootAnchor::new().anchors().unwrap();
    assert_eq!(anchors.len(), 2);

    let ksk_2017 = anchors
        .iter()
        .find(|anchor| anchor.key_tag() == 20326)
        .expect("KSK-2017 (tag 20326) must be pinned");
    assert_eq!(ksk_2017.owner(), &Name::root());
    assert_eq!(ksk_2017.algorithm(), DnssecAlgorithm::RSASHA256);
    assert_eq!(ksk_2017.digest_type(), DigestType::SHA256);
    assert_eq!(ksk_2017.digest().len(), 32);

    let ksk_2024 = anchors
        .iter()
        .find(|anchor| anchor.key_tag() == 38696)
        .expect("KSK-2024 (tag 38696) must be pinned for post-Oct-2026 root signing");
    assert_eq!(ksk_2024.owner(), &Name::root());
    assert_eq!(ksk_2024.algorithm(), DnssecAlgorithm::RSASHA256);
    assert_eq!(ksk_2024.digest_type(), DigestType::SHA256);
    assert_eq!(
        ksk_2024.digest(),
        &[
            0x68, 0x3D, 0x2D, 0x0A, 0xCB, 0x8C, 0x9B, 0x71, 0x2A, 0x19, 0x48, 0xB2, 0x7F, 0x74,
            0x12, 0x19, 0x29, 0x8D, 0x0A, 0x45, 0x0D, 0x61, 0x2C, 0x48, 0x3A, 0xF4, 0x44, 0xA4,
            0xC0, 0xFB, 0x2B, 0x16,
        ]
    );
}

#[tokio::test]
async fn test_ed25519_positive_chain_validation() {
    let root_key = ZoneKey::generate(&Name::root());
    let anchors = StaticAnchorSource::new(vec![root_key.anchor()]);

    let validator = Validator::new(clock(), ValidationPolicy::default());
    let outcome = validator
        .validate(
            &signed_root_answer(&root_key),
            &root_source(&root_key),
            &anchors,
        )
        .await;

    assert_eq!(outcome.verdict, ValidationVerdict::Secure);
    assert_eq!(outcome.reason, VerdictReason::AnchorMatched);
}

#[tokio::test]
async fn test_expired_signature_fails() {
    let root_key = ZoneKey::generate(&Name::root());
    let anchors = StaticAnchorSource::new(vec![root_key.anchor()]);

    let validator = Validator::new(clock_at(1_700_000_500), ValidationPolicy::default());
    let outcome = validator
        .validate(
            &signed_root_answer(&root_key),
            &root_source(&root_key),
            &anchors,
        )
        .await;

    assert_eq!(outcome.verdict, ValidationVerdict::Bogus);
}

#[tokio::test]
async fn test_ds_dnskey_mismatch_fails() {
    let root_key = ZoneKey::generate(&Name::root());
    let wrong_digest = TrustAnchor::new(
        Name::root(),
        DsRdata::new(
            root_key.key_tag(),
            root_key.dnskey.algorithm(),
            DIGEST_SHA256,
            vec![0xAA; 32],
        ),
    );
    let anchors = StaticAnchorSource::new(vec![wrong_digest]);

    let validator = Validator::new(clock(), ValidationPolicy::default());
    let outcome = validator
        .validate(
            &signed_root_answer(&root_key),
            &root_source(&root_key),
            &anchors,
        )
        .await;

    assert_eq!(outcome.verdict, ValidationVerdict::Bogus);
    assert_eq!(outcome.reason, VerdictReason::DsDnskeyMismatch);
}

#[tokio::test]
async fn test_future_signature_not_yet_valid_fails() {
    let root_key = ZoneKey::generate(&Name::root());
    let anchors = StaticAnchorSource::new(vec![root_key.anchor()]);

    let validator = Validator::new(clock_at(1_600_000_000), ValidationPolicy::default());
    let outcome = validator
        .validate(
            &signed_root_answer(&root_key),
            &root_source(&root_key),
            &anchors,
        )
        .await;

    assert_eq!(outcome.verdict, ValidationVerdict::Bogus);
}

#[tokio::test]
async fn test_unrelated_signed_answer_is_rejected_as_bogus() {
    let root_key = ZoneKey::generate(&Name::root());
    let example_key = ZoneKey::generate(&name("example."));
    let source = root_source(&root_key);
    source.insert_cut(example_key.signed_cut(&root_key));

    let evil = name("evil.example.");
    let answer = a_record(&evil, 6);
    let mut message = query(&name("www.example."), RecordType::A);
    message
        .answers
        .push(example_key.sign(std::slice::from_ref(&answer)));
    message.answers.push(answer);

    let validator = Validator::new(clock(), ValidationPolicy::default());
    let outcome = validator
        .validate(
            &message,
            &source,
            &StaticAnchorSource::new(vec![root_key.anchor()]),
        )
        .await;

    assert_eq!(outcome.verdict, ValidationVerdict::Bogus);
}

#[tokio::test]
async fn test_wrong_qtype_signed_answer_is_rejected_as_bogus() {
    let root_key = ZoneKey::generate(&Name::root());
    let www = name("www.example.");
    let mut message = query(&www, RecordType::AAAA);
    // Signed A record instead of AAAA for www.example.
    let wrong_type = a_record(&www, 1);
    message
        .answers
        .push(root_key.sign(std::slice::from_ref(&wrong_type)));
    message.answers.push(wrong_type);

    let validator = Validator::new(clock(), ValidationPolicy::default());
    let outcome = validator
        .validate(
            &message,
            &root_source(&root_key),
            &StaticAnchorSource::new(vec![root_key.anchor()]),
        )
        .await;

    assert_eq!(outcome.verdict, ValidationVerdict::Bogus);
}

#[tokio::test]
async fn test_cname_loop_is_rejected_as_bogus() {
    let root_key = ZoneKey::generate(&Name::root());
    let example_key = ZoneKey::generate(&name("example."));
    let source = root_source(&root_key);
    source.insert_cut(example_key.signed_cut(&root_key));

    let www = name("www.example.");
    let alias = name("alias.example.");
    let c1 = record(&www, RecordType::CNAME, RData::Cname(alias.clone()));
    let c2 = record(&alias, RecordType::CNAME, RData::Cname(www.clone()));

    let mut message = query(&www, RecordType::A);
    message
        .answers
        .push(example_key.sign(std::slice::from_ref(&c1)));
    message.answers.push(c1);
    message
        .answers
        .push(example_key.sign(std::slice::from_ref(&c2)));
    message.answers.push(c2);

    let anchors = StaticAnchorSource::new(vec![root_key.anchor()]);
    let outcome = Validator::new(clock(), ValidationPolicy::default())
        .validate(&message, &source, &anchors)
        .await;

    assert_eq!(outcome.verdict, ValidationVerdict::Bogus);
}

#[tokio::test]
async fn test_cname_chain_and_smuggled_record_validation() {
    let root_key = ZoneKey::generate(&Name::root());
    let example_key = ZoneKey::generate(&name("example."));
    let source = root_source(&root_key);
    source.insert_cut(example_key.signed_cut(&root_key));

    let www = name("www.example.");
    let alias = name("alias.example.");
    let cname = record(&www, RecordType::CNAME, RData::Cname(alias.clone()));
    let target_a = a_record(&alias, 9);

    let mut message = query(&www, RecordType::A);
    message
        .answers
        .push(example_key.sign(std::slice::from_ref(&cname)));
    message.answers.push(cname);
    message
        .answers
        .push(example_key.sign(std::slice::from_ref(&target_a)));
    message.answers.push(target_a);

    let anchors = StaticAnchorSource::new(vec![root_key.anchor()]);
    let validator = Validator::new(clock(), ValidationPolicy::default());
    assert_eq!(
        validator
            .validate(&message, &source, &anchors)
            .await
            .verdict,
        ValidationVerdict::Secure
    );

    // Adding an unrelated signed record must make the answer Bogus.
    let smuggled = a_record(&name("evil.example."), 8);
    message
        .answers
        .push(example_key.sign(std::slice::from_ref(&smuggled)));
    message.answers.push(smuggled);
    assert_eq!(
        validator
            .validate(&message, &source, &anchors)
            .await
            .verdict,
        ValidationVerdict::Bogus
    );
}

#[tokio::test]
async fn test_wildcard_answer_requires_signed_denial_proof() {
    let root_key = ZoneKey::generate(&Name::root());
    let example_key = ZoneKey::generate(&name("example."));
    let source = root_source(&root_key);
    source.insert_cut(example_key.signed_cut(&root_key));

    let qname = name("sub.wild.example.");
    let answer = a_record(&qname, 42);
    let mut message = query(&qname, RecordType::A);
    message
        .answers
        .push(example_key.sign_wildcard(std::slice::from_ref(&answer), 1));
    message.answers.push(answer);

    let anchors = StaticAnchorSource::new(vec![root_key.anchor()]);
    let validator = Validator::new(clock(), ValidationPolicy::default());
    // Without authority NSEC proving sub.wild.example. (and wild.example.) do not exist -> Bogus.
    assert_eq!(
        validator
            .validate(&message, &source, &anchors)
            .await
            .verdict,
        ValidationVerdict::Bogus
    );

    // With signed NSEC from example. covering sub.wild.example. and closest encloser example. -> Secure.
    let nsec = record(
        &name("example."),
        RecordType::NSEC,
        RData::Nsec(NsecRdata::new(
            name("z.example."),
            TypeBitmap::new(vec![0x00, 0x01, 0x20]),
        )),
    );
    message
        .authorities
        .push(example_key.sign(std::slice::from_ref(&nsec)));
    message.authorities.push(nsec);

    assert_eq!(
        validator
            .validate(&message, &source, &anchors)
            .await
            .verdict,
        ValidationVerdict::Secure
    );
}

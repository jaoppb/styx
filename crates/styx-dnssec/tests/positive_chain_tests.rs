//! Integration tests for positive chain validation (Sub-phase 6a).

mod support;

use styx_dnssec::{
    PinnedRootAnchor, PullChainSource, TrustAnchor, TrustAnchorSource, ValidationPolicy,
    ValidationVerdict, Validator, VerdictReason,
};
use styx_proto::{Name, RecordType};
use support::{a_record, clock, clock_at, query, StaticAnchorSource, ZoneKey, DIGEST_SHA256};

fn signed_root_answer(root_key: &ZoneKey) -> styx_proto::Message {
    let answer = a_record(&Name::root(), 4);
    let mut message = query(&Name::root(), RecordType::A);
    message
        .answers
        .push(root_key.sign(std::slice::from_ref(&answer)));
    message.answers.push(answer);
    message
}

fn root_source(root_key: &ZoneKey) -> PullChainSource {
    let source = PullChainSource::new();
    source.insert_cut(root_key.apex_cut());
    source
}

#[test]
fn test_pinned_root_anchor_contents() {
    let anchors = PinnedRootAnchor::new().anchors().unwrap();
    assert_eq!(anchors.len(), 1);
    let ksk = anchors.first().unwrap();
    assert_eq!(ksk.owner(), &Name::root());
    assert_eq!(ksk.key_tag(), 20326);
    assert_eq!(ksk.algorithm(), 8);
    assert_eq!(ksk.digest_type(), 2);
}

#[test]
fn test_ed25519_positive_chain_validation() {
    let root_key = ZoneKey::generate(&Name::root());
    let anchors = StaticAnchorSource::new(vec![root_key.anchor()]);

    let validator = Validator::new(clock(), ValidationPolicy::default());
    let outcome = validator.validate(
        &signed_root_answer(&root_key),
        &root_source(&root_key),
        &anchors,
    );

    assert_eq!(outcome.verdict, ValidationVerdict::Secure);
    assert_eq!(outcome.reason, VerdictReason::AnchorMatched);
}

#[test]
fn test_expired_signature_fails() {
    let root_key = ZoneKey::generate(&Name::root());
    let anchors = StaticAnchorSource::new(vec![root_key.anchor()]);

    let validator = Validator::new(clock_at(1_700_000_500), ValidationPolicy::default());
    let outcome = validator.validate(
        &signed_root_answer(&root_key),
        &root_source(&root_key),
        &anchors,
    );

    assert_eq!(outcome.verdict, ValidationVerdict::Bogus);
}

#[test]
fn test_ds_dnskey_mismatch_fails() {
    let root_key = ZoneKey::generate(&Name::root());
    let wrong_digest = TrustAnchor::new(
        Name::root(),
        root_key.key_tag(),
        root_key.dnskey.algorithm(),
        DIGEST_SHA256,
        vec![0xAA; 32],
    );
    let anchors = StaticAnchorSource::new(vec![wrong_digest]);

    let validator = Validator::new(clock(), ValidationPolicy::default());
    let outcome = validator.validate(
        &signed_root_answer(&root_key),
        &root_source(&root_key),
        &anchors,
    );

    assert_eq!(outcome.verdict, ValidationVerdict::Bogus);
    assert_eq!(outcome.reason, VerdictReason::DsDnskeyMismatch);
}

#[test]
fn test_future_signature_not_yet_valid_fails() {
    let root_key = ZoneKey::generate(&Name::root());
    let anchors = StaticAnchorSource::new(vec![root_key.anchor()]);

    let validator = Validator::new(clock_at(1_600_000_000), ValidationPolicy::default());
    let outcome = validator.validate(
        &signed_root_answer(&root_key),
        &root_source(&root_key),
        &anchors,
    );

    assert_eq!(outcome.verdict, ValidationVerdict::Bogus);
}

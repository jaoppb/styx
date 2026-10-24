//! Integration tests for DNSKEY rollover, algorithm agility, and failure modes.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use ring::signature::KeyPair;
use styx_core::test_util::TestClock;
use styx_dnssec::domain::canonical::build_canonical_signed_data;
use styx_dnssec::domain::signature::compute_dnskey_digest;
use styx_dnssec::{
    AlgorithmSet, FailureMode, PullChainSource, TrustAnchor, TrustAnchorSource, ValidationPolicy,
    ValidationVerdict, Validator, VerdictReason, ZoneCutMaterial,
};
use styx_proto::domain::rdata::{DnskeyRdata, RrsigRdata};
use styx_proto::{
    Header, Message, Name, Opcode, Question, RData, RecordClass, RecordType, ResourceRecord, Ttl,
};

fn create_ed25519_keypair() -> Option<(ring::signature::Ed25519KeyPair, Vec<u8>)> {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).ok()?;
    let key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).ok()?;
    let pub_key = key_pair.public_key().as_ref().to_vec();
    Some((key_pair, pub_key))
}

fn sign_rrset(
    key_pair: &ring::signature::Ed25519KeyPair,
    signer: &Name,
    key_tag: u16,
    rrset: &[ResourceRecord],
    type_covered: RecordType,
    inception: u32,
    expiration: u32,
) -> Option<ResourceRecord> {
    let labels_count = u8::try_from(signer.label_count()).ok()?;
    let dummy_sig = RrsigRdata::new(
        type_covered,
        15,
        labels_count,
        300,
        expiration,
        inception,
        key_tag,
        signer.clone(),
        Vec::new(),
    );
    let signed_data = build_canonical_signed_data(&dummy_sig, rrset).ok()?;
    let signature = key_pair.sign(&signed_data);

    let rrsig_rdata = RrsigRdata::new(
        type_covered,
        15,
        labels_count,
        300,
        expiration,
        inception,
        key_tag,
        signer.clone(),
        signature.as_ref().to_vec(),
    );

    let first = rrset.first()?;
    Some(ResourceRecord::new(
        first.owner.clone(),
        RecordType::RRSIG,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::Rrsig(rrsig_rdata),
    ))
}

struct StaticAnchorSource {
    anchors: Vec<TrustAnchor>,
}

impl TrustAnchorSource for StaticAnchorSource {
    fn anchors(&self) -> Result<Vec<TrustAnchor>, styx_dnssec::TrustAnchorError> {
        Ok(self.anchors.clone())
    }
}

struct TwoKeyFixture {
    root: Name,
    dnskey_set: Vec<ResourceRecord>,
    dnskey_sig: ResourceRecord,
    trust_anchor: TrustAnchor,
}

fn setup_two_key_fixture(
    key_pair_a: &ring::signature::Ed25519KeyPair,
    pub_key_a: Vec<u8>,
    pub_key_b: Vec<u8>,
) -> Option<TwoKeyFixture> {
    let root = Name::root();
    let dnskey_a = DnskeyRdata::new(257, 3, 15, pub_key_a);
    let dnskey_b = DnskeyRdata::new(256, 3, 15, pub_key_b);
    let key_tag_a = dnskey_a.key_tag();

    let digest_a = compute_dnskey_digest(&root, &dnskey_a, 2)?;
    let trust_anchor = TrustAnchor::new(root.clone(), key_tag_a, 15, 2, digest_a);

    let dnskey_rr_a = ResourceRecord::new(
        root.clone(),
        RecordType::DNSKEY,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::Dnskey(dnskey_a),
    );
    let dnskey_rr_b = ResourceRecord::new(
        root.clone(),
        RecordType::DNSKEY,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::Dnskey(dnskey_b),
    );

    let dnskey_set = vec![dnskey_rr_a, dnskey_rr_b];
    let dnskey_sig = sign_rrset(
        key_pair_a,
        &root,
        key_tag_a,
        &dnskey_set,
        RecordType::DNSKEY,
        1_700_000_000,
        1_700_000_200,
    )?;

    Some(TwoKeyFixture {
        root,
        dnskey_set,
        dnskey_sig,
        trust_anchor,
    })
}

#[test]
fn test_multi_key_rollover_validates_with_any_valid_signature() {
    let clock = Arc::new(TestClock::new());
    clock.set_utc(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_100));

    let (key_pair_a, pub_key_a) = create_ed25519_keypair().unwrap();
    let (_key_pair_b, pub_key_b) = create_ed25519_keypair().unwrap();

    let fix = setup_two_key_fixture(&key_pair_a, pub_key_a, pub_key_b).unwrap();
    let anchor_source = StaticAnchorSource {
        anchors: vec![fix.trust_anchor.clone()],
    };
    let root_cut = ZoneCutMaterial::new(
        fix.root.clone(),
        None,
        None,
        Some(fix.dnskey_set),
        vec![fix.dnskey_sig],
        styx_dnssec::MaterialOrigin::PulledOnDemand,
    );

    let chain_source = PullChainSource::new();
    chain_source.insert_cut(root_cut);

    let answer_rr = ResourceRecord::new(
        fix.root.clone(),
        RecordType::A,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::A(std::net::Ipv4Addr::new(10, 0, 0, 1)),
    );

    let answer_sig = sign_rrset(
        &key_pair_a,
        &fix.root,
        fix.trust_anchor.key_tag(),
        std::slice::from_ref(&answer_rr),
        RecordType::A,
        1_700_000_000,
        1_700_000_200,
    )
    .unwrap();

    let mut msg = Message::new(Header::new_query(1, Opcode::Query, false));
    msg.questions.push(Question {
        qname: fix.root,
        qtype: RecordType::A,
        qclass: RecordClass::In,
    });
    msg.answers.push(answer_rr);
    msg.answers.push(answer_sig);

    let validator = Validator::new(clock, ValidationPolicy::default());
    let outcome = validator.validate(&msg, &chain_source, &anchor_source);

    assert_eq!(outcome.verdict, ValidationVerdict::Secure);
    assert_eq!(outcome.reason, VerdictReason::AnchorMatched);
}

#[test]
fn test_failure_mode_enforcement_flag() {
    let clock = Arc::new(TestClock::new());

    let warn_policy = ValidationPolicy::new(
        FailureMode::WarnOnly,
        AlgorithmSet::new(),
        styx_dnssec::Nsec3IterationsCap::DEFAULT,
        8,
    );
    let warn_validator = Validator::new(clock.clone(), warn_policy);
    assert!(!warn_validator.is_enforced());

    let hard_policy = ValidationPolicy::default();
    let hard_validator = Validator::new(clock, hard_policy);
    assert!(hard_validator.is_enforced());
}

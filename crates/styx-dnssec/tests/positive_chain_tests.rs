//! Integration tests for positive chain validation (Sub-phase 6a).

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use ring::signature::KeyPair;
use styx_core::test_util::TestClock;
use styx_dnssec::domain::canonical::build_canonical_signed_data;
use styx_dnssec::domain::signature::compute_dnskey_digest;
use styx_dnssec::{
    PinnedRootAnchor, PullChainSource, TrustAnchor, TrustAnchorSource, ValidationPolicy,
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

struct RootFixture {
    root: Name,
    dnskey_rr: ResourceRecord,
    dnskey_sig: ResourceRecord,
    anchor: TrustAnchor,
}

fn build_root_fixture(
    key_pair: &ring::signature::Ed25519KeyPair,
    pub_key: Vec<u8>,
    inception: u32,
    expiration: u32,
) -> Option<RootFixture> {
    let root = Name::root();
    let dnskey_rdata = DnskeyRdata::new(257, 3, 15, pub_key);
    let key_tag = dnskey_rdata.key_tag();

    let digest = compute_dnskey_digest(&root, &dnskey_rdata, 2)?;
    let anchor = TrustAnchor::new(root.clone(), key_tag, 15, 2, digest);

    let dnskey_rr = ResourceRecord::new(
        root.clone(),
        RecordType::DNSKEY,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::Dnskey(dnskey_rdata),
    );

    let dnskey_sig = sign_rrset(
        key_pair,
        &root,
        key_tag,
        std::slice::from_ref(&dnskey_rr),
        RecordType::DNSKEY,
        inception,
        expiration,
    )?;

    Some(RootFixture {
        root,
        dnskey_rr,
        dnskey_sig,
        anchor,
    })
}

#[test]
fn test_pinned_root_anchor_contents() {
    let anchor_source = PinnedRootAnchor::new();
    let anchors = anchor_source.anchors().unwrap();
    assert_eq!(anchors.len(), 1);
    let ksk = anchors.first().unwrap();
    assert_eq!(ksk.owner(), &Name::root());
    assert_eq!(ksk.key_tag(), 20326);
    assert_eq!(ksk.algorithm(), 8);
    assert_eq!(ksk.digest_type(), 2);
}

#[test]
fn test_ed25519_positive_chain_validation() {
    let clock = Arc::new(TestClock::new());
    clock.set_utc(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_100));

    let (key_pair, pub_key) = create_ed25519_keypair().unwrap();
    let fix = build_root_fixture(&key_pair, pub_key, 1_700_000_000, 1_700_000_200).unwrap();

    let anchor_source = StaticAnchorSource {
        anchors: vec![fix.anchor.clone()],
    };
    let root_cut = ZoneCutMaterial::new(
        fix.root.clone(),
        None,
        None,
        Some(vec![fix.dnskey_rr]),
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
        RData::A(std::net::Ipv4Addr::new(1, 2, 3, 4)),
    );

    let answer_sig = sign_rrset(
        &key_pair,
        &fix.root,
        fix.anchor.key_tag(),
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
    assert!(outcome.enforced);
}

#[test]
fn test_expired_signature_fails() {
    let clock = Arc::new(TestClock::new());
    clock.set_utc(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_500));

    let (key_pair, pub_key) = create_ed25519_keypair().unwrap();
    let fix = build_root_fixture(&key_pair, pub_key, 1_700_000_000, 1_700_000_200).unwrap();

    let anchor_source = StaticAnchorSource {
        anchors: vec![fix.anchor],
    };
    let root_cut = ZoneCutMaterial::new(
        fix.root.clone(),
        None,
        None,
        Some(vec![fix.dnskey_rr]),
        vec![fix.dnskey_sig],
        styx_dnssec::MaterialOrigin::PulledOnDemand,
    );

    let chain_source = PullChainSource::new();
    chain_source.insert_cut(root_cut);

    let mut msg = Message::new(Header::new_query(1, Opcode::Query, false));
    msg.questions.push(Question {
        qname: fix.root,
        qtype: RecordType::DNSKEY,
        qclass: RecordClass::In,
    });

    let validator = Validator::new(clock, ValidationPolicy::default());
    let outcome = validator.validate(&msg, &chain_source, &anchor_source);

    assert_eq!(outcome.verdict, ValidationVerdict::Bogus);
}

#[test]
fn test_ds_dnskey_mismatch_fails() {
    let clock = Arc::new(TestClock::new());
    clock.set_utc(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_100));

    let (_key_pair, pub_key) = create_ed25519_keypair().unwrap();
    let root = Name::root();
    let dnskey_rdata = DnskeyRdata::new(257, 3, 15, pub_key);
    let key_tag = dnskey_rdata.key_tag();

    let fake_digest = vec![0xAA; 32];
    let trust_anchor = TrustAnchor::new(root.clone(), key_tag, 15, 2, fake_digest);
    let anchor_source = StaticAnchorSource {
        anchors: vec![trust_anchor],
    };

    let dnskey_rr = ResourceRecord::new(
        root.clone(),
        RecordType::DNSKEY,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::Dnskey(dnskey_rdata),
    );

    let root_cut = ZoneCutMaterial::new(
        root.clone(),
        None,
        None,
        Some(vec![dnskey_rr]),
        Vec::new(),
        styx_dnssec::MaterialOrigin::PulledOnDemand,
    );

    let chain_source = PullChainSource::new();
    chain_source.insert_cut(root_cut);

    let mut msg = Message::new(Header::new_query(1, Opcode::Query, false));
    msg.questions.push(Question {
        qname: root,
        qtype: RecordType::DNSKEY,
        qclass: RecordClass::In,
    });

    let validator = Validator::new(clock, ValidationPolicy::default());
    let outcome = validator.validate(&msg, &chain_source, &anchor_source);

    assert_eq!(outcome.verdict, ValidationVerdict::Bogus);
    assert_eq!(outcome.reason, VerdictReason::DsDnskeyMismatch);
}

#[test]
fn test_future_signature_not_yet_valid_fails() {
    let clock = Arc::new(TestClock::new());
    clock.set_utc(SystemTime::UNIX_EPOCH + Duration::from_secs(1_600_000_000));

    let (key_pair, pub_key) = create_ed25519_keypair().unwrap();
    let fix = build_root_fixture(&key_pair, pub_key, 1_700_000_000, 1_700_000_200).unwrap();

    let anchor_source = StaticAnchorSource {
        anchors: vec![fix.anchor],
    };
    let root_cut = ZoneCutMaterial::new(
        fix.root.clone(),
        None,
        None,
        Some(vec![fix.dnskey_rr]),
        vec![fix.dnskey_sig],
        styx_dnssec::MaterialOrigin::PulledOnDemand,
    );

    let chain_source = PullChainSource::new();
    chain_source.insert_cut(root_cut);

    let mut msg = Message::new(Header::new_query(1, Opcode::Query, false));
    msg.questions.push(Question {
        qname: fix.root,
        qtype: RecordType::DNSKEY,
        qclass: RecordClass::In,
    });

    let validator = Validator::new(clock, ValidationPolicy::default());
    let outcome = validator.validate(&msg, &chain_source, &anchor_source);

    assert_eq!(outcome.verdict, ValidationVerdict::Bogus);
}

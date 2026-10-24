//! Deep verification integration tests covering multi-record RRsets, multi-level descent,
//! non-zone-cut subdomains, NSEC3 NODATA, and unsigned denial rejection.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use ring::signature::KeyPair;
use styx_core::test_util::TestClock;
use styx_dnssec::domain::canonical::build_canonical_signed_data;
use styx_dnssec::domain::nsec3::{base32hex_encode, hash_nsec3_name};
use styx_dnssec::domain::signature::compute_dnskey_digest;
use styx_dnssec::{
    MaterialOrigin, Nsec3IterationsCap, PullChainSource, TrustAnchor, TrustAnchorSource,
    ValidationPolicy, ValidationVerdict, Validator, VerdictReason, ZoneCutMaterial,
};
use styx_proto::domain::rdata::{
    DnskeyRdata, DsRdata, Nsec3Rdata, NsecRdata, RrsigRdata, TypeBitmap,
};
use styx_proto::{
    Header, Message, Name, Opcode, Question, RData, RecordClass, RecordType, ResourceRecord,
    ResponseCode, Ttl,
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

fn make_root_cut(
    key_pair: &ring::signature::Ed25519KeyPair,
    pub_key: Vec<u8>,
) -> Option<(Name, u16, ZoneCutMaterial, TrustAnchor)> {
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
        1_700_000_000,
        1_700_000_200,
    )?;

    let root_cut = ZoneCutMaterial::new(
        root.clone(),
        None,
        None,
        Some(vec![dnskey_rr]),
        vec![dnskey_sig],
        MaterialOrigin::PulledOnDemand,
    );
    Some((root, key_tag, root_cut, anchor))
}

fn make_child_cut(
    child_kp: &ring::signature::Ed25519KeyPair,
    child_pub: Vec<u8>,
    zone: &Name,
) -> Option<(u16, ZoneCutMaterial)> {
    let child_dnskey = DnskeyRdata::new(257, 3, 15, child_pub);
    let child_tag = child_dnskey.key_tag();
    let child_digest = compute_dnskey_digest(zone, &child_dnskey, 2)?;

    let ds_rdata = DsRdata::new(child_tag, 15, 2, child_digest);
    let ds_rr = ResourceRecord::new(
        zone.clone(),
        RecordType::DS,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::Ds(ds_rdata),
    );

    let child_rr = ResourceRecord::new(
        zone.clone(),
        RecordType::DNSKEY,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::Dnskey(child_dnskey),
    );
    let child_sig = sign_rrset(
        child_kp,
        zone,
        child_tag,
        std::slice::from_ref(&child_rr),
        RecordType::DNSKEY,
        1_700_000_000,
        1_700_000_200,
    )?;

    let cut = ZoneCutMaterial::new(
        zone.clone(),
        Some(vec![ds_rr]),
        None,
        Some(vec![child_rr]),
        vec![child_sig],
        MaterialOrigin::PulledOnDemand,
    );
    Some((child_tag, cut))
}

#[test]
fn test_multi_record_rrset_validation_succeeds() {
    let clock = Arc::new(TestClock::new());
    clock.set_utc(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_100));

    let (key_pair, pub_key) = create_ed25519_keypair().unwrap();
    let (root, key_tag, root_cut, anchor) = make_root_cut(&key_pair, pub_key).unwrap();
    let anchor_source = StaticAnchorSource {
        anchors: vec![anchor],
    };
    let chain_source = PullChainSource::new();
    chain_source.insert_cut(root_cut);

    let rr1 = ResourceRecord::new(
        root.clone(),
        RecordType::A,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::A(std::net::Ipv4Addr::new(1, 1, 1, 1)),
    );
    let rr2 = ResourceRecord::new(
        root.clone(),
        RecordType::A,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::A(std::net::Ipv4Addr::new(2, 2, 2, 2)),
    );

    let answer_sig = sign_rrset(
        &key_pair,
        &root,
        key_tag,
        &[rr1.clone(), rr2.clone()],
        RecordType::A,
        1_700_000_000,
        1_700_000_200,
    )
    .unwrap();

    let mut msg = Message::new(Header::new_query(1, Opcode::Query, false));
    msg.questions.push(Question {
        qname: root,
        qtype: RecordType::A,
        qclass: RecordClass::In,
    });
    msg.answers.push(rr1);
    msg.answers.push(rr2);
    msg.answers.push(answer_sig);

    let validator = Validator::new(clock, ValidationPolicy::default());
    let outcome = validator.validate(&msg, &chain_source, &anchor_source);

    assert_eq!(outcome.verdict, ValidationVerdict::Secure);
    assert_eq!(outcome.reason, VerdictReason::AnchorMatched);
}

#[test]
fn test_multi_level_descent_and_subdomain_hostname() {
    let clock = Arc::new(TestClock::new());
    clock.set_utc(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_100));

    let (root_kp, root_pub) = create_ed25519_keypair().unwrap();
    let (_root, _tag, root_cut, anchor) = make_root_cut(&root_kp, root_pub).unwrap();
    let anchor_source = StaticAnchorSource {
        anchors: vec![anchor],
    };

    let example = Name::from_ascii("example.").unwrap();
    let www = Name::from_ascii("www.example.").unwrap();

    let (child_kp, child_pub) = create_ed25519_keypair().unwrap();
    let (child_tag, child_cut) = make_child_cut(&child_kp, child_pub, &example).unwrap();

    let chain_source = PullChainSource::new();
    chain_source.insert_cut(root_cut);
    chain_source.insert_cut(child_cut);

    let www_rr = ResourceRecord::new(
        www.clone(),
        RecordType::A,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::A(std::net::Ipv4Addr::new(9, 9, 9, 9)),
    );
    let www_sig = sign_rrset(
        &child_kp,
        &example,
        child_tag,
        std::slice::from_ref(&www_rr),
        RecordType::A,
        1_700_000_000,
        1_700_000_200,
    )
    .unwrap();

    let mut msg = Message::new(Header::new_query(1, Opcode::Query, false));
    msg.questions.push(Question {
        qname: www,
        qtype: RecordType::A,
        qclass: RecordClass::In,
    });
    msg.answers.push(www_rr);
    msg.answers.push(www_sig);

    let validator = Validator::new(clock, ValidationPolicy::default());
    let outcome = validator.validate(&msg, &chain_source, &anchor_source);

    assert_eq!(outcome.verdict, ValidationVerdict::Secure);
    assert_eq!(outcome.reason, VerdictReason::AnchorMatched);
}

#[test]
fn test_nsec3_nodata_verification() {
    let clock = Arc::new(TestClock::new());
    clock.set_utc(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_100));

    let (key_pair, pub_key) = create_ed25519_keypair().unwrap();
    let (root, key_tag, root_cut, anchor) = make_root_cut(&key_pair, pub_key).unwrap();
    let anchor_source = StaticAnchorSource {
        anchors: vec![anchor],
    };
    let chain_source = PullChainSource::new();
    chain_source.insert_cut(root_cut);

    let cap = Nsec3IterationsCap::DEFAULT;
    let salt = vec![0x12, 0x34];
    let params = styx_dnssec::domain::denial::Nsec3Params::new(
        1,
        styx_dnssec::domain::denial::Nsec3Flags::new(0),
        1,
        salt.clone(),
    );

    let root_hash = hash_nsec3_name(&root, &params, cap).unwrap();
    let root_nsec3_owner = Name::from_ascii(&format!("{}.", base32hex_encode(&root_hash))).unwrap();
    let nsec3_rdata = Nsec3Rdata::new(
        1,
        0,
        1,
        salt,
        root_hash,
        TypeBitmap::new(vec![0x00, 0x01, 0x40]),
    );
    let nsec3_rr = ResourceRecord::new(
        root_nsec3_owner,
        RecordType::NSEC3,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::Nsec3(nsec3_rdata),
    );
    let nsec3_sig = sign_rrset(
        &key_pair,
        &root,
        key_tag,
        std::slice::from_ref(&nsec3_rr),
        RecordType::NSEC3,
        1_700_000_000,
        1_700_000_200,
    )
    .unwrap();

    let mut msg = Message::new(Header::new_query(1, Opcode::Query, false));
    msg.header.rcode = ResponseCode::NOERROR;
    msg.questions.push(Question {
        qname: root,
        qtype: RecordType::AAAA,
        qclass: RecordClass::In,
    });
    msg.authorities.push(nsec3_rr);
    msg.authorities.push(nsec3_sig);

    let validator = Validator::new(clock, ValidationPolicy::default());
    let outcome = validator.validate(&msg, &chain_source, &anchor_source);

    assert_eq!(outcome.verdict, ValidationVerdict::Secure);
    assert_eq!(outcome.reason, VerdictReason::AnchorMatched);
}

#[test]
fn test_unsigned_denial_rejected_as_bogus() {
    let clock = Arc::new(TestClock::new());
    clock.set_utc(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_100));

    let (key_pair, pub_key) = create_ed25519_keypair().unwrap();
    let (root, _tag, root_cut, anchor) = make_root_cut(&key_pair, pub_key).unwrap();
    let anchor_source = StaticAnchorSource {
        anchors: vec![anchor],
    };
    let chain_source = PullChainSource::new();
    chain_source.insert_cut(root_cut);

    let nsec_rr = ResourceRecord::new(
        root.clone(),
        RecordType::NSEC,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::Nsec(NsecRdata::new(root, TypeBitmap::new(Vec::new()))),
    );

    let mut msg = Message::new(Header::new_query(1, Opcode::Query, false));
    msg.header.rcode = ResponseCode::NXDOMAIN;
    msg.questions.push(Question {
        qname: Name::from_ascii("nonexistent.example.").unwrap(),
        qtype: RecordType::A,
        qclass: RecordClass::In,
    });
    msg.authorities.push(nsec_rr);

    let validator = Validator::new(clock, ValidationPolicy::default());
    let outcome = validator.validate(&msg, &chain_source, &anchor_source);

    assert_eq!(outcome.verdict, ValidationVerdict::Bogus);
    assert_eq!(outcome.reason, VerdictReason::NoValidRrsig);
}

#[test]
fn test_sha1_ds_digest_computation() {
    let zone = Name::from_ascii("example.com.").unwrap();
    let dnskey = DnskeyRdata::new(257, 3, 8, vec![0x01, 0x02, 0x03, 0x04]);
    let digest = compute_dnskey_digest(&zone, &dnskey, 1);
    assert!(digest.is_some());
    assert_eq!(digest.unwrap().len(), 20);
}

//! Deep verification integration tests covering multi-record RRsets, multi-level descent,
//! non-zone-cut subdomains, NSEC3 NODATA, and unsigned denial rejection.

mod support;

use styx_dnssec::domain::denial::{Nsec3Flags, Nsec3Params};
use styx_dnssec::domain::nsec3::{base32hex_encode, hash_nsec3_name};
use styx_dnssec::domain::signature::compute_dnskey_digest;
use styx_dnssec::{
    Nsec3IterationsCap, PullChainSource, ValidationPolicy, ValidationVerdict, Validator,
    VerdictReason,
};
use styx_proto::domain::rdata::{DnskeyRdata, Nsec3Rdata, NsecRdata, TypeBitmap};
use styx_proto::{Name, RData, RecordType, ResponseCode};
use support::{a_record, clock, name, query, record, StaticAnchorSource, ZoneKey};

fn root_only(root_key: &ZoneKey) -> PullChainSource {
    let source = PullChainSource::new();
    source.insert_cut(root_key.apex_cut());
    source
}

#[test]
fn test_multi_record_rrset_validation_succeeds() {
    let root_key = ZoneKey::generate(&Name::root());
    let rrset = vec![a_record(&Name::root(), 1), a_record(&Name::root(), 2)];

    let mut message = query(&Name::root(), RecordType::A);
    message.answers.push(root_key.sign(&rrset));
    message.answers.extend(rrset);

    let validator = Validator::new(clock(), ValidationPolicy::default());
    let anchors = StaticAnchorSource::new(vec![root_key.anchor()]);
    let outcome = validator.validate(&message, &root_only(&root_key), &anchors);

    assert_eq!(outcome.verdict, ValidationVerdict::Secure);
    assert_eq!(outcome.reason, VerdictReason::AnchorMatched);
}

#[test]
fn test_multi_level_descent_and_subdomain_hostname() {
    let root_key = ZoneKey::generate(&Name::root());
    let example_key = ZoneKey::generate(&name("example."));
    let source = root_only(&root_key);
    source.insert_cut(example_key.signed_cut(&root_key));

    let www = name("www.example.");
    let answer = a_record(&www, 9);
    let mut message = query(&www, RecordType::A);
    message
        .answers
        .push(example_key.sign(std::slice::from_ref(&answer)));
    message.answers.push(answer);

    let validator = Validator::new(clock(), ValidationPolicy::default());
    let anchors = StaticAnchorSource::new(vec![root_key.anchor()]);
    let outcome = validator.validate(&message, &source, &anchors);

    assert_eq!(outcome.verdict, ValidationVerdict::Secure);
    assert_eq!(outcome.reason, VerdictReason::AnchorMatched);
}

#[test]
fn test_nsec3_nodata_verification() {
    let root = Name::root();
    let root_key = ZoneKey::generate(&root);

    let salt = vec![0x12, 0x34];
    let params = Nsec3Params::new(1, Nsec3Flags::new(0), 1, salt.clone());
    let root_hash = hash_nsec3_name(&root, &params, Nsec3IterationsCap::DEFAULT).unwrap();
    let owner = name(&format!("{}.", base32hex_encode(&root_hash)));
    let a_only = TypeBitmap::new(vec![0x00, 0x01, 0x40]);
    let nsec3 = record(
        &owner,
        RecordType::NSEC3,
        RData::Nsec3(Nsec3Rdata::new(1, 0, 1, salt, root_hash, a_only)),
    );

    let mut message = query(&root, RecordType::AAAA);
    message.header.rcode = ResponseCode::NOERROR;
    message
        .authorities
        .push(root_key.sign(std::slice::from_ref(&nsec3)));
    message.authorities.push(nsec3);

    let validator = Validator::new(clock(), ValidationPolicy::default());
    let anchors = StaticAnchorSource::new(vec![root_key.anchor()]);
    let outcome = validator.validate(&message, &root_only(&root_key), &anchors);

    assert_eq!(outcome.verdict, ValidationVerdict::Secure);
    assert_eq!(outcome.reason, VerdictReason::AnchorMatched);
}

#[test]
fn test_unsigned_denial_rejected_as_bogus() {
    let root = Name::root();
    let root_key = ZoneKey::generate(&root);
    let nsec = record(
        &root,
        RecordType::NSEC,
        RData::Nsec(NsecRdata::new(root.clone(), TypeBitmap::new(Vec::new()))),
    );

    let mut message = query(&name("nonexistent.example."), RecordType::A);
    message.header.rcode = ResponseCode::NXDOMAIN;
    message.authorities.push(nsec);

    let validator = Validator::new(clock(), ValidationPolicy::default());
    let anchors = StaticAnchorSource::new(vec![root_key.anchor()]);
    let outcome = validator.validate(&message, &root_only(&root_key), &anchors);

    assert_eq!(outcome.verdict, ValidationVerdict::Bogus);
    assert_eq!(outcome.reason, VerdictReason::NoValidRrsig);
}

#[test]
fn test_sha1_ds_digest_computation() {
    let zone = name("example.com.");
    let dnskey = DnskeyRdata::new(257, 3, 8, vec![0x01, 0x02, 0x03, 0x04]);
    let digest = compute_dnskey_digest(&zone, &dnskey, 1);
    assert_eq!(digest.map(|digest| digest.len()), Some(20));
}

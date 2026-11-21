//! Unit-level rejection tests for [`verify_rrsig_record`] using single-field mutations
//! over a valid Ed25519-signed RRset.

#![allow(clippy::unwrap_used)]

mod support;

use ring::signature::{Ed25519KeyPair, KeyPair};
use styx_core::test_util::TestClock;
use styx_dnssec::domain::canonical::build_canonical_signed_data;
use styx_dnssec::domain::signature::verify_rrsig_record;
use styx_dnssec::{DnssecAlgorithm, VerdictReason};
use styx_proto::domain::rdata::{DnskeyRdata, RrsigRdata};
use styx_proto::{Name, RData, RecordClass, RecordType, ResourceRecord, Ttl};
use support::clock_at;

fn signed_fixture() -> (Name, DnskeyRdata, ResourceRecord, RrsigRdata, TestClock) {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let signer = Name::from_ascii("example.com.").unwrap();
    let owner = Name::from_ascii("www.example.com.").unwrap();
    let dnskey = DnskeyRdata::new(
        257,
        3,
        DnssecAlgorithm::ED25519.value(),
        pair.public_key().as_ref().to_vec(),
    );
    let record = ResourceRecord::new(
        owner,
        RecordType::A,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::A(std::net::Ipv4Addr::new(192, 0, 2, 1)),
    );
    let mut template = RrsigRdata::new(
        RecordType::A,
        DnssecAlgorithm::ED25519.value(),
        3,
        300,
        1000,
        10,
        dnskey.key_tag(),
        signer.clone(),
        Vec::new(),
    );
    let signed_data = build_canonical_signed_data(&template, &[&record]).unwrap();
    template = RrsigRdata::new(
        RecordType::A,
        DnssecAlgorithm::ED25519.value(),
        3,
        300,
        1000,
        10,
        dnskey.key_tag(),
        signer,
        pair.sign(&signed_data).as_ref().to_vec(),
    );
    (
        Name::from_ascii("example.com.").unwrap(),
        dnskey,
        record,
        template,
        clock_at(100),
    )
}

#[test]
fn verify_rrsig_record_rejects_single_field_mutations() {
    let (signer, dnskey, record, rrsig, clock) = signed_fixture();
    assert_eq!(
        verify_rrsig_record(&rrsig, &[&record], &dnskey, &signer, &clock),
        Ok(())
    );

    let bad_tag = RrsigRdata::new(
        rrsig.type_covered(),
        rrsig.algorithm(),
        rrsig.labels(),
        rrsig.original_ttl(),
        rrsig.signature_expiration(),
        rrsig.signature_inception(),
        rrsig.key_tag().wrapping_add(1),
        rrsig.signer_name().clone(),
        rrsig.signature().to_vec(),
    );
    assert!(verify_rrsig_record(&bad_tag, &[&record], &dnskey, &signer, &clock).is_err());

    let bad_labels = RrsigRdata::new(
        rrsig.type_covered(),
        rrsig.algorithm(),
        2,
        rrsig.original_ttl(),
        rrsig.signature_expiration(),
        rrsig.signature_inception(),
        rrsig.key_tag(),
        rrsig.signer_name().clone(),
        rrsig.signature().to_vec(),
    );
    assert!(verify_rrsig_record(&bad_labels, &[&record], &dnskey, &signer, &clock).is_err());

    let bad_algorithm = RrsigRdata::new(
        rrsig.type_covered(),
        DnssecAlgorithm::ECDSAP256SHA256.value(),
        rrsig.labels(),
        rrsig.original_ttl(),
        rrsig.signature_expiration(),
        rrsig.signature_inception(),
        rrsig.key_tag(),
        rrsig.signer_name().clone(),
        rrsig.signature().to_vec(),
    );
    assert!(verify_rrsig_record(&bad_algorithm, &[&record], &dnskey, &signer, &clock).is_err());

    let mutated_record = ResourceRecord::new(
        record.owner.clone(),
        RecordType::A,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::A(std::net::Ipv4Addr::new(192, 0, 2, 2)),
    );
    assert!(verify_rrsig_record(&rrsig, &[&mutated_record], &dnskey, &signer, &clock).is_err());
}

#[test]
fn verify_rrsig_record_rejects_type_covered_mismatch() {
    let (signer, dnskey, record, rrsig, clock) = signed_fixture();
    let wrong_type = RrsigRdata::new(
        RecordType::AAAA,
        rrsig.algorithm(),
        rrsig.labels(),
        rrsig.original_ttl(),
        rrsig.signature_expiration(),
        rrsig.signature_inception(),
        rrsig.key_tag(),
        rrsig.signer_name().clone(),
        rrsig.signature().to_vec(),
    );
    assert_eq!(
        verify_rrsig_record(&wrong_type, &[&record], &dnskey, &signer, &clock),
        Err(VerdictReason::NoValidRrsig)
    );
}

#[test]
fn verify_rrsig_record_rejects_owner_not_subdomain_of_signer() {
    let (signer, dnskey, _, rrsig, clock) = signed_fixture();
    let other_owner = Name::from_ascii("other.org.").unwrap();
    let record = ResourceRecord::new(
        other_owner,
        RecordType::A,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::A(std::net::Ipv4Addr::new(192, 0, 2, 1)),
    );
    assert_eq!(
        verify_rrsig_record(&rrsig, &[&record], &dnskey, &signer, &clock),
        Err(VerdictReason::NoValidRrsig)
    );
}

#[test]
fn verify_rrsig_record_rejects_signer_name_mismatch_with_dnskey_owner() {
    let (_, dnskey, record, rrsig, clock) = signed_fixture();
    let dnskey_owner = Name::from_ascii("other.com.").unwrap();
    assert_eq!(
        verify_rrsig_record(&rrsig, &[&record], &dnskey, &dnskey_owner, &clock),
        Err(VerdictReason::NoValidRrsig)
    );
}

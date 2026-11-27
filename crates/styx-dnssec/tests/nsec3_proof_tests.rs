//! NSEC3 proofs over a zone's full hash chain rather than a lone record: span coverage,
//! closest-encloser NXDOMAIN, wildcard expansion and wildcard NODATA, with and without
//! Opt-Out (RFC 5155 §7.2, §8, §9.2).

#![allow(clippy::unwrap_used)]

mod support;

use styx_dnssec::domain::denial::{DenialProof, DenialStrength};
use styx_dnssec::domain::error::DenialError;
use styx_dnssec::domain::nsec3::nsec3_covers_hash;
use styx_dnssec::Nsec3Proof;
use styx_proto::domain::rdata::{Nsec3Rdata, TypeBitmap};
use styx_proto::{RData, RecordType, ResourceRecord, ResponseCode};
use support::nsec3_chain::{chain, hash, node, opt_out, Node, APEX_TYPES, CAP, SALT};
use support::{base32hex_encode, name, record};

fn proof(records: &[ResourceRecord]) -> DenialProof {
    let references: Vec<&ResourceRecord> = records.iter().collect();
    DenialProof::from_records(&references).unwrap()
}

#[test]
fn a_normal_span_covers_only_the_hashes_strictly_between_its_ends() {
    let (owner, next) = ([0x10; 20], [0x30; 20]);
    assert!(nsec3_covers_hash(&owner, &next, &[0x20; 20]));
    assert!(!nsec3_covers_hash(&owner, &next, &owner));
    assert!(!nsec3_covers_hash(&owner, &next, &next));
    assert!(!nsec3_covers_hash(&owner, &next, &[0x05; 20]));
    assert!(!nsec3_covers_hash(&owner, &next, &[0x40; 20]));
}

#[test]
fn the_wrapping_span_covers_both_ends_of_the_hash_ring() {
    let (owner, next) = ([0x30; 20], [0x10; 20]);
    assert!(nsec3_covers_hash(&owner, &next, &[0x40; 20]));
    assert!(nsec3_covers_hash(&owner, &next, &[0x05; 20]));
    assert!(!nsec3_covers_hash(&owner, &next, &[0x20; 20]));
    assert!(!nsec3_covers_hash(&owner, &next, &owner));
    assert!(!nsec3_covers_hash(&owner, &next, &next));
}

fn example_zone() -> Vec<Node> {
    vec![
        node("example.", APEX_TYPES),
        node("a.example.", &[RecordType::A, RecordType::RRSIG]),
        node("b.example.", &[RecordType::TXT, RecordType::RRSIG]),
        node("c.example.", &[RecordType::MX, RecordType::RRSIG]),
    ]
}

#[test]
fn nxdomain_is_proven_from_a_chain_of_several_records() {
    let zone = name("example.");
    let records = chain(&zone, &example_zone());
    let qname = name("missing.example.");

    let verdict = proof(&records).verify(&zone, &qname, RecordType::A, ResponseCode::NXDOMAIN, CAP);

    assert_eq!(verdict, Ok(DenialStrength::Proven));
}

#[test]
fn nxdomain_without_the_closest_encloser_record_is_not_proven() {
    let zone = name("example.");
    let apex_hash = hash(&zone);
    let records: Vec<ResourceRecord> =
        chain(&zone, &example_zone())
            .into_iter()
            .filter(|record| match record.rdata {
                RData::Nsec3(_) => !record.owner.labels().next().is_some_and(|label| {
                    label.as_bytes() == base32hex_encode(&apex_hash).as_bytes()
                }),
                _ => true,
            })
            .collect();
    let qname = name("missing.example.");

    let verdict = proof(&records).verify(&zone, &qname, RecordType::A, ResponseCode::NXDOMAIN, CAP);

    assert!(verdict.is_err());
}

fn wildcard_zone(extra: Option<Node>) -> Vec<Node> {
    let mut nodes = vec![
        node("example.", APEX_TYPES),
        node("*.example.", &[RecordType::A, RecordType::RRSIG]),
    ];
    nodes.extend(extra);
    nodes
}

#[test]
fn a_wildcard_expansion_with_a_covered_next_closer_is_proven() {
    let zone = name("example.");
    let records = chain(&zone, &wildcard_zone(None));

    let verdict = proof(&records).verify_wildcard_expansion(&zone, &name("host.example."), 1, CAP);

    assert_eq!(verdict, Ok(DenialStrength::Proven));
}

#[test]
fn a_wildcard_expansion_over_an_opt_out_span_is_only_opt_out() {
    let zone = name("example.");
    let records = chain(&zone, &opt_out(wildcard_zone(None)));

    let verdict = proof(&records).verify_wildcard_expansion(&zone, &name("host.example."), 1, CAP);

    assert_eq!(verdict, Ok(DenialStrength::OptOut));
}

#[test]
fn a_wildcard_expansion_over_a_name_that_exists_is_refused() {
    let zone = name("example.");
    let existing = node("host.example.", &[RecordType::TXT, RecordType::RRSIG]);
    let records = chain(&zone, &wildcard_zone(Some(existing)));

    let verdict = proof(&records).verify_wildcard_expansion(&zone, &name("host.example."), 1, CAP);

    assert_eq!(verdict, Err(DenialError::DenialProofIncomplete));
}

#[test]
fn a_wildcard_expansion_below_a_delegation_or_dname_is_refused() {
    let zone = name("example.");
    for types in [
        &[RecordType::NS][..],
        &[RecordType::DNAME, RecordType::RRSIG][..],
    ] {
        let cut = Node {
            owner: name("sub.example."),
            types,
            opt_out: false,
        };
        let records = chain(&zone, &wildcard_zone(Some(cut)));
        let owner = name("host.sub.example.");

        let verdict = proof(&records).verify_wildcard_expansion(&zone, &owner, 2, CAP);

        assert_eq!(
            verdict,
            Err(DenialError::DenialProofIncomplete),
            "{types:?}"
        );
    }
}

#[test]
fn ds_nodata_over_an_opt_out_span_is_only_opt_out() {
    let zone = name("example.");
    let records = chain(&zone, &opt_out(example_zone()));
    let child = name("unsigned.example.");

    let verdict = proof(&records).verify(&zone, &child, RecordType::DS, ResponseCode::NOERROR, CAP);

    assert_eq!(verdict, Ok(DenialStrength::OptOut));
}

#[test]
fn ds_nodata_over_a_strict_span_without_a_wildcard_is_not_proven() {
    let zone = name("example.");
    let records = chain(&zone, &example_zone());
    let child = name("unsigned.example.");

    let verdict = proof(&records).verify(&zone, &child, RecordType::DS, ResponseCode::NOERROR, CAP);

    assert_eq!(verdict, Err(DenialError::NotCovered));
}

#[test]
fn wildcard_nodata_is_proven_by_the_wildcards_bitmap() {
    let zone = name("example.");
    let records = chain(&zone, &wildcard_zone(None));
    let qname = name("missing.example.");

    let denial = proof(&records);

    assert_eq!(
        denial.verify(&zone, &qname, RecordType::AAAA, ResponseCode::NOERROR, CAP),
        Ok(DenialStrength::Proven)
    );
    assert_eq!(
        denial.verify(&zone, &qname, RecordType::A, ResponseCode::NOERROR, CAP),
        Err(DenialError::NotCovered),
        "the wildcard holds A, so A at the qname is not denied"
    );
}

#[test]
fn wildcard_nodata_over_an_opt_out_span_is_only_opt_out() {
    let zone = name("example.");
    let records = chain(&zone, &opt_out(wildcard_zone(None)));
    let qname = name("missing.example.");

    let verdict =
        proof(&records).verify(&zone, &qname, RecordType::AAAA, ResponseCode::NOERROR, CAP);

    assert_eq!(verdict, Ok(DenialStrength::OptOut));
}

fn sha1_nsec3(owner_hash: &[u8], next: Vec<u8>, hash_algorithm: u8) -> ResourceRecord {
    let owner = name(&format!("{}.example.", base32hex_encode(owner_hash)));
    let rdata = Nsec3Rdata::new(
        hash_algorithm,
        0,
        1,
        SALT.to_vec(),
        next,
        TypeBitmap::new(Vec::new()),
    );
    record(&owner, RecordType::NSEC3, RData::Nsec3(rdata))
}

#[test]
fn an_sha1_nsec3_whose_hashes_are_not_20_octets_is_refused() {
    for (owner_hash, next) in [
        (vec![0x11; 19], vec![0x22; 20]),
        (vec![0x11; 20], vec![0x22; 21]),
    ] {
        let record = sha1_nsec3(&owner_hash, next, 1);

        assert_eq!(
            Nsec3Proof::from_records(&[&record]),
            Err(DenialError::DenialProofIncomplete)
        );
    }
}

#[test]
fn an_unknown_hash_algorithm_is_not_held_to_sha1_lengths() {
    let record = sha1_nsec3(&[0x11; 32], vec![0x22; 32], 2);

    assert!(Nsec3Proof::from_records(&[&record]).is_ok());
}

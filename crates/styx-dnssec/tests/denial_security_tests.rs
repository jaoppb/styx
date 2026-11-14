//! Regression tests for NSEC closest-encloser wildcards, NSEC3 RFC 5155 §8.3/§8.4
//! delegation/DNAME/bailiwick checks, and strict base32hex decoding.

mod support;

use styx_dnssec::domain::denial::{DenialProof, Nsec3Flags, Nsec3Params, Nsec3Proof, NsecProof};
use styx_dnssec::domain::error::DenialError;
use styx_dnssec::domain::nsec3::{base32hex_decode, hash_nsec3_name};
use styx_dnssec::{Nsec3HashAlgorithm, Nsec3IterationsCap};
use styx_proto::domain::rdata::{Nsec3Rdata, NsecRdata, TypeBitmap};
use styx_proto::{Name, RData, RecordClass, RecordType, ResourceRecord, ResponseCode, Ttl};
use support::base32hex_encode;

fn nsec3_record(
    owner: &Name,
    salt: Vec<u8>,
    next_hash: Vec<u8>,
    bitmap: TypeBitmap,
) -> ResourceRecord {
    ResourceRecord::new(
        owner.clone(),
        RecordType::NSEC3,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::Nsec3(Nsec3Rdata::new(1, 0, 1, salt, next_hash, bitmap)),
    )
}

#[test]
fn test_nsec_multilabel_nxdomain_rejects_existing_wildcard_at_closest_encloser() {
    let zone = Name::from_ascii("example.").unwrap();
    let qname = Name::from_ascii("a.b.c.example.").unwrap();
    let wild_owner = Name::from_ascii("*.example.").unwrap();
    let next = Name::from_ascii("d.example.").unwrap();

    // Attacker replays `*.example. NSEC d.example.`, which covers `a.b.c.example.`
    // and `*.b.c.example.`, while `*.example.` actually exists in the zone.
    let replayed = ResourceRecord::new(
        wild_owner,
        RecordType::NSEC,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::Nsec(NsecRdata::new(next, TypeBitmap::new(Vec::new()))),
    );
    let proof = DenialProof::from_records(&[&replayed]).unwrap();
    let err = proof
        .verify(
            &zone,
            &qname,
            RecordType::A,
            ResponseCode::NXDOMAIN,
            Nsec3IterationsCap::DEFAULT,
        )
        .unwrap_err();
    assert_eq!(err, DenialError::DenialProofIncomplete);

    // Meanwhile `example. NSEC d.example.` proves both `a.b.c.example.` and `*.example.` absent.
    let valid_nsec = ResourceRecord::new(
        zone.clone(),
        RecordType::NSEC,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::Nsec(NsecRdata::new(
            Name::from_ascii("d.example.").unwrap(),
            TypeBitmap::new(Vec::new()),
        )),
    );
    let valid_proof = DenialProof::from_records(&[&valid_nsec]).unwrap();
    assert!(valid_proof
        .verify(
            &zone,
            &qname,
            RecordType::A,
            ResponseCode::NXDOMAIN,
            Nsec3IterationsCap::DEFAULT,
        )
        .is_ok());

    assert!(NsecProof::new(vec![valid_nsec])
        .prove_no_wildcard(&zone)
        .is_ok());
}

#[test]
fn test_nsec3_rejects_delegation_and_dname_closest_enclosers() {
    let cap = Nsec3IterationsCap::DEFAULT;
    let salt = vec![0xAA, 0xBB];
    let params = Nsec3Params::new(
        Nsec3HashAlgorithm::SHA1,
        Nsec3Flags::new(0),
        1,
        salt.clone(),
    );

    let zone = Name::from_ascii("example.").unwrap();
    let ce = Name::from_ascii("sub.example.").unwrap();
    let qname = Name::from_ascii("host.sub.example.").unwrap();
    let ce_hash = hash_nsec3_name(&ce, &params, cap).unwrap();
    let ce_owner = Name::from_ascii(&format!("{}.example.", base32hex_encode(&ce_hash))).unwrap();

    // 1. Closest encloser is a delegation cut (NS bit set, SOA bit clear).
    let ns_only = TypeBitmap::new(vec![0x00, 0x01, 0x20]);
    let delegation_rr = nsec3_record(&ce_owner, salt.clone(), ce_hash.clone(), ns_only);
    let delegation_proof = Nsec3Proof::from_records(&[&delegation_rr]).unwrap();
    assert_eq!(
        delegation_proof.prove_name_does_not_exist(&zone, &qname, cap),
        Err(DenialError::DenialProofIncomplete)
    );

    // 2. Closest encloser carries a DNAME bit (type 39: byte 4 bit 0 = 0x01).
    let dname_bitmap = TypeBitmap::new(vec![0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let dname_rr = nsec3_record(&ce_owner, salt, ce_hash, dname_bitmap);
    let dname_proof = Nsec3Proof::from_records(&[&dname_rr]).unwrap();
    assert_eq!(
        dname_proof.prove_name_does_not_exist(&zone, &qname, cap),
        Err(DenialError::DenialProofIncomplete)
    );
}

#[test]
fn test_nsec3_rejects_parent_zone_owner_and_delegation_nodata() {
    let cap = Nsec3IterationsCap::DEFAULT;
    let salt = vec![0x11, 0x22];
    let params = Nsec3Params::new(
        Nsec3HashAlgorithm::SHA1,
        Nsec3Flags::new(0),
        1,
        salt.clone(),
    );

    let parent_zone = Name::from_ascii("example.").unwrap();
    let child_zone = Name::from_ascii("sub.example.").unwrap();
    let qname = Name::from_ascii("host.sub.example.").unwrap();

    // Parent-side NSEC3 for `sub.example.` replayed when validating `sub.example.`.
    let sub_hash = hash_nsec3_name(&child_zone, &params, cap).unwrap();
    let parent_owner =
        Name::from_ascii(&format!("{}.example.", base32hex_encode(&sub_hash))).unwrap();
    let ns_only = TypeBitmap::new(vec![0x00, 0x01, 0x20]);
    let parent_rr = nsec3_record(
        &parent_owner,
        salt.clone(),
        sub_hash.clone(),
        ns_only.clone(),
    );
    let replayed_proof = Nsec3Proof::from_records(&[&parent_rr]).unwrap();
    assert_eq!(
        replayed_proof.prove_name_does_not_exist(&child_zone, &qname, cap),
        Err(DenialError::DenialProofIncomplete)
    );

    // Exact NODATA for A at `sub.example.` using delegation NSEC3 (NS without SOA) in `example.`.
    let nodata_proof = Nsec3Proof::from_records(&[&parent_rr]).unwrap();
    assert_eq!(
        nodata_proof.prove_type_does_not_exist(&parent_zone, &child_zone, RecordType::A, cap),
        Err(DenialError::NotCovered)
    );

    // Sanity check: DS query at delegation cut DOES match NS-without-SOA.
    let a_not_ds = nsec3_record(
        &parent_owner,
        salt,
        sub_hash,
        TypeBitmap::new(vec![0x00, 0x01, 0x20]),
    );
    assert!(Nsec3Proof::from_records(&[&a_not_ds])
        .unwrap()
        .prove_type_does_not_exist(&parent_zone, &child_zone, RecordType::DS, cap)
        .is_ok());
}

#[test]
fn test_base32hex_decode_rejects_invalid_lengths_padding_and_chars() {
    // Valid 32-char SHA-1 NSEC3 hash label (case-insensitive)
    let valid_lower = b"0p9mhaveqvm6t7vbl5lop2u3t2rp3tom";
    let valid_upper = b"0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM";
    assert_eq!(base32hex_decode(valid_lower), base32hex_decode(valid_upper));
    assert_eq!(base32hex_decode(valid_lower).map(|b| b.len()), Some(20));

    // Invalid base32hex lengths (1, 3, 6 chars mod 8 cannot encode whole bytes)
    assert_eq!(base32hex_decode(b"0"), None);
    assert_eq!(base32hex_decode(b"000"), None);
    assert_eq!(base32hex_decode(b"000000"), None);

    // Non-zero trailing padding bits in final 2-char block (`01` has trailing bit set)
    assert_eq!(base32hex_decode(b"01"), None);

    // Invalid characters and padding `=`
    assert_eq!(base32hex_decode(b"0p9mhaveqvm6t7vbl5lop2u3t2rp3toz"), None);
    assert_eq!(base32hex_decode(b"00======"), None);
}

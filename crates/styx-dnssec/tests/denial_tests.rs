//! Integration tests for NSEC and NSEC3 denial-of-existence proofs (Sub-phases 6b and 6c).

// The helpers below sit outside `#[test]` functions, where clippy's allowances stop.
#![allow(clippy::unwrap_used, clippy::panic)]

mod support;

use styx_dnssec::domain::denial::{nsec_covers_name, DenialProof, DenialStrength, Nsec3Params};
use styx_dnssec::domain::error::DenialError;
use styx_dnssec::domain::nsec3::{base32hex_decode, hash_nsec3_name};
use styx_dnssec::{Nsec3HashAlgorithm, Nsec3IterationsCap};
use styx_proto::domain::rdata::{Nsec3Rdata, NsecRdata, TypeBitmap};
use styx_proto::{Name, RData, RecordClass, RecordType, ResourceRecord, ResponseCode, Ttl};
use support::base32hex_encode;

#[test]
fn test_nsec_coverage_normal_span_and_apex_wrap() {
    let a = Name::from_ascii("a.example.com.").unwrap();
    let b = Name::from_ascii("b.example.com.").unwrap();
    let c = Name::from_ascii("c.example.com.").unwrap();
    let z = Name::from_ascii("z.example.com.").unwrap();

    // Normal span: a < b < c
    assert!(nsec_covers_name(&a, &c, &b));
    assert!(!nsec_covers_name(&a, &b, &c));

    // Apex wrap-around: z -> b covers a, but does not cover z itself
    assert!(nsec_covers_name(&z, &b, &a));
    assert!(!nsec_covers_name(&z, &b, &z));
}

fn nsec_rr_next(record: &ResourceRecord) -> &Name {
    match record.rdata {
        RData::Nsec(ref nsec) => nsec.next_domain(),
        _ => panic!("not an NSEC"),
    }
}

#[test]
fn test_nsec_nodata_and_name_error() {
    let owner = Name::from_ascii("host.example.com.").unwrap();
    let next = Name::from_ascii("other.example.com.").unwrap();
    let qname = Name::from_ascii("missing.example.com.").unwrap();

    // Bitmap without AAAA (window 0, len 1, byte with A only)
    let bitmap = TypeBitmap::new(vec![0x00, 0x01, 0x40]); // A record bit set
    let nsec_rdata = NsecRdata::new(next, bitmap);
    let nsec_rr = ResourceRecord::new(
        owner.clone(),
        RecordType::NSEC,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::Nsec(nsec_rdata),
    );

    let zone = Name::from_ascii("example.com.").unwrap();
    let cap = Nsec3IterationsCap::DEFAULT;
    let proof = DenialProof::from_records(&[&nsec_rr]).unwrap();

    // The NSEC spans qname.
    assert!(nsec_covers_name(&owner, nsec_rr_next(&nsec_rr), &qname));

    // Type does not exist for AAAA at host.example.com
    assert!(proof
        .verify(&zone, &owner, RecordType::AAAA, ResponseCode::NOERROR, cap)
        .is_ok());

    // Type A exists at host.example.com -> fails NODATA proof
    assert_eq!(
        proof.verify(&zone, &owner, RecordType::A, ResponseCode::NOERROR, cap),
        Err(DenialError::NotCovered)
    );
}

#[test]
fn test_nsec3_iterations_cap_enforced() {
    let params = Nsec3Params::new(
        Nsec3HashAlgorithm::SHA1,
        150, // exceeds cap of 100
        vec![0xAA, 0xBB],
    );

    let cap = Nsec3IterationsCap::DEFAULT; // 100
    let name = Name::from_ascii("test.example.com.").unwrap();

    let err = hash_nsec3_name(&name, &params, cap).unwrap_err();
    assert_eq!(err, DenialError::Nsec3IterationsExceeded);
}

#[test]
fn test_nsec3_hash_and_base32hex_roundtrip() {
    let params = Nsec3Params::new(Nsec3HashAlgorithm::SHA1, 1, vec![0x12, 0x34]);
    let cap = Nsec3IterationsCap::DEFAULT;
    let name = Name::from_ascii("example.com.").unwrap();

    let digest = hash_nsec3_name(&name, &params, cap).unwrap();
    assert_eq!(digest.len(), 20); // SHA-1 is 20 bytes

    let encoded = base32hex_encode(&digest);
    let decoded = base32hex_decode(encoded.as_bytes()).unwrap();
    assert_eq!(digest, decoded);
}

#[test]
fn test_nsec3_nxdomain_three_part_proof() {
    let cap = Nsec3IterationsCap::DEFAULT;
    let salt = vec![0xAB, 0xCD];
    let params = Nsec3Params::new(Nsec3HashAlgorithm::SHA1, 1, salt.clone());

    let zone = Name::from_ascii("example.com.").unwrap();
    let qname = Name::from_ascii("missing.example.com.").unwrap();

    // 1. Closest encloser is example.com.
    let ce_hash = hash_nsec3_name(&zone, &params, cap).unwrap();
    let ce_owner =
        Name::from_ascii(&format!("{}.example.com.", base32hex_encode(&ce_hash))).unwrap();

    // Single NSEC3 in zone (owner == next) covers all other hashes in the zone (RFC 5155 §7.2.1)
    let nsec3_cover = Nsec3Rdata::new(1, 0, 1, salt, ce_hash, TypeBitmap::new(Vec::new()));

    let rr1 = ResourceRecord::new(
        ce_owner,
        RecordType::NSEC3,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::Nsec3(nsec3_cover),
    );

    let proof = DenialProof::from_records(&[&rr1]).unwrap();
    let result = proof.verify(&zone, &qname, RecordType::A, ResponseCode::NXDOMAIN, cap);

    assert!(result.is_ok());
}

#[test]
fn test_nsec3_opt_out_unsigned_delegation() {
    let cap = Nsec3IterationsCap::DEFAULT;
    let salt = vec![0x11, 0x22];
    let zone = Name::from_ascii("example.com.").unwrap();
    let child = Name::from_ascii("unsigned.example.com.").unwrap();

    let opt_out_hash = vec![0x00; 20];
    let opt_out_rdata = Nsec3Rdata::new(
        1,
        1, // opt-out flag set
        1,
        salt,
        opt_out_hash.clone(), // single NSEC3 in zone covers all other hashes
        TypeBitmap::new(Vec::new()),
    );

    let owner_name =
        Name::from_ascii(&format!("{}.example.com.", base32hex_encode(&opt_out_hash))).unwrap();
    let rr = ResourceRecord::new(
        owner_name,
        RecordType::NSEC3,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::Nsec3(opt_out_rdata),
    );

    let proof = DenialProof::from_records(&[&rr]).unwrap();

    // An opt-out span alone is not a DS-absence proof: RFC 5155 §8.6 also needs the
    // closest provable encloser, and nothing here matches one.
    assert!(proof.prove_ds_absence(&zone, &child, cap).is_err());
}

/// The apex NSEC3 alone in the zone: it matches the apex and, as the only NSEC3, covers
/// every other hash, with `flags` as given.
fn lone_apex_nsec3(zone: &Name, salt: &[u8], flags: u8) -> ResourceRecord {
    let params = Nsec3Params::new(Nsec3HashAlgorithm::SHA1, 1, salt.to_vec());
    let apex_hash = hash_nsec3_name(zone, &params, Nsec3IterationsCap::DEFAULT).unwrap();
    let owner = Name::from_ascii(&format!("{}.{zone}", base32hex_encode(&apex_hash))).unwrap();
    ResourceRecord::new(
        owner,
        RecordType::NSEC3,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::Nsec3(Nsec3Rdata::new(
            1,
            flags,
            1,
            salt.to_vec(),
            apex_hash,
            // NS and SOA: the apex, not a delegation.
            TypeBitmap::new(vec![0x00, 0x01, 0x22]),
        )),
    )
}

#[test]
fn test_nsec3_opt_out_ds_absence_needs_the_closest_encloser_and_an_opt_out_cover() {
    let cap = Nsec3IterationsCap::DEFAULT;
    let salt = [0x11, 0x22];
    let zone = Name::from_ascii("example.com.").unwrap();
    let child = Name::from_ascii("unsigned.example.com.").unwrap();

    let opt_out = lone_apex_nsec3(&zone, &salt, 1);
    let proof = DenialProof::from_records(&[&opt_out]).unwrap();
    assert!(proof.prove_ds_absence(&zone, &child, cap).is_ok());

    let strict = lone_apex_nsec3(&zone, &salt, 0);
    let proof = DenialProof::from_records(&[&strict]).unwrap();
    assert_eq!(
        proof.prove_ds_absence(&zone, &child, cap),
        Err(DenialError::NotCovered),
        "without Opt-Out the covered next closer proves no delegation exists"
    );
}

#[test]
fn test_nsec3_nxdomain_over_an_opt_out_span_is_not_proven() {
    let cap = Nsec3IterationsCap::DEFAULT;
    let salt = [0x11, 0x22];
    let zone = Name::from_ascii("example.com.").unwrap();
    let qname = Name::from_ascii("missing.example.com.").unwrap();

    let strict = DenialProof::from_records(&[&lone_apex_nsec3(&zone, &salt, 0)]).unwrap();
    assert_eq!(
        strict.verify(&zone, &qname, RecordType::A, ResponseCode::NXDOMAIN, cap),
        Ok(DenialStrength::Proven)
    );

    // RFC 5155 §9.2: the next closer name may be an unsigned delegation, so no AD.
    let opt_out = DenialProof::from_records(&[&lone_apex_nsec3(&zone, &salt, 1)]).unwrap();
    assert_eq!(
        opt_out.verify(&zone, &qname, RecordType::A, ResponseCode::NXDOMAIN, cap),
        Ok(DenialStrength::OptOut)
    );
}

#[test]
fn test_denial_proof_from_records_and_verify() {
    use styx_dnssec::domain::denial::DenialProof;
    use styx_proto::ResponseCode;

    let zone = Name::from_ascii("example.com.").unwrap();
    let owner = Name::from_ascii("host.example.com.").unwrap();
    let next = Name::from_ascii("other.example.com.").unwrap();
    let qname = Name::from_ascii("missing.example.com.").unwrap();

    let bitmap = TypeBitmap::new(vec![0x00, 0x01, 0x40]); // A only
    let nsec_rr = ResourceRecord::new(
        owner,
        RecordType::NSEC,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::Nsec(NsecRdata::new(next, bitmap)),
    );

    let proof = DenialProof::from_records(&[&nsec_rr]).unwrap();
    assert_eq!(proof.records().len(), 1);

    // NODATA for AAAA at host.example.com.
    let host = Name::from_ascii("host.example.com.").unwrap();
    let result = proof.verify(
        &zone,
        &host,
        RecordType::AAAA,
        ResponseCode::NOERROR,
        Nsec3IterationsCap::DEFAULT,
    );
    assert!(result.is_ok());

    // NXDOMAIN requires wildcard coverage, which single nsec doesn't have
    let nx_result = proof.verify(
        &zone,
        &qname,
        RecordType::A,
        ResponseCode::NXDOMAIN,
        Nsec3IterationsCap::DEFAULT,
    );
    assert!(nx_result.is_err());
}

#[test]
fn test_from_records_rejects_mixed_nsec_and_nsec3() {
    use styx_dnssec::domain::denial::DenialProof;

    let owner = Name::from_ascii("host.example.com.").unwrap();
    let next = Name::from_ascii("other.example.com.").unwrap();
    let nsec_rr = ResourceRecord::new(
        owner.clone(),
        RecordType::NSEC,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::Nsec(NsecRdata::new(
            next,
            TypeBitmap::new(vec![0x00, 0x01, 0x40]),
        )),
    );

    let nsec3_rr = ResourceRecord::new(
        owner,
        RecordType::NSEC3,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::Nsec3(Nsec3Rdata::new(
            1,
            0,
            1,
            vec![1, 2],
            vec![0; 20],
            TypeBitmap::new(Vec::new()),
        )),
    );

    let err = DenialProof::from_records(&[&nsec_rr, &nsec3_rr]).unwrap_err();
    assert_eq!(err, DenialError::DenialProofIncomplete);
}

#[test]
fn test_from_records_rejects_conflicting_nsec3_parameters() {
    use styx_dnssec::domain::denial::DenialProof;

    let owner = Name::from_ascii("host.example.com.").unwrap();
    let nsec3_first = ResourceRecord::new(
        owner.clone(),
        RecordType::NSEC3,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::Nsec3(Nsec3Rdata::new(
            1,
            0,
            1,
            vec![1, 2],
            vec![0; 20],
            TypeBitmap::new(Vec::new()),
        )),
    );
    let nsec3_conflicting = ResourceRecord::new(
        owner,
        RecordType::NSEC3,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::Nsec3(Nsec3Rdata::new(
            1,
            0,
            50, // conflicting iteration count
            vec![1, 2],
            vec![0; 20],
            TypeBitmap::new(Vec::new()),
        )),
    );

    let err = DenialProof::from_records(&[&nsec3_first, &nsec3_conflicting]).unwrap_err();
    assert_eq!(err, DenialError::DenialProofIncomplete);
}

/// Whether the lone NSEC `record` proves no DS at its owner, under the owner's parent.
fn ds_absence(record: &ResourceRecord) -> Result<(), DenialError> {
    let zone = &record.owner;
    DenialProof::from_records(&[record])
        .unwrap()
        .prove_ds_absence(&zone.parent().unwrap(), zone, Nsec3IterationsCap::DEFAULT)
}

#[test]
fn test_nsec_prove_ds_absence_requires_ns_and_forbids_ds_and_soa() {
    let zone = Name::from_ascii("child.example.com.").unwrap();
    let next = Name::from_ascii("other.example.com.").unwrap();

    // 1. Only A record, missing NS bit
    let a_only = ResourceRecord::new(
        zone.clone(),
        RecordType::NSEC,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::Nsec(NsecRdata::new(
            next.clone(),
            TypeBitmap::new(vec![0x00, 0x01, 0x40]),
        )),
    );
    assert_eq!(ds_absence(&a_only), Err(DenialError::NotCovered));

    // 2. NS bit set (0x20 in byte 0), but also SOA set (0x02 in byte 0) -> zone apex, not cut
    let ns_and_soa = ResourceRecord::new(
        zone.clone(),
        RecordType::NSEC,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::Nsec(NsecRdata::new(
            next.clone(),
            TypeBitmap::new(vec![0x00, 0x01, 0x22]),
        )),
    );
    assert_eq!(ds_absence(&ns_and_soa), Err(DenialError::NotCovered));

    // 3. NS bit set (0x20) and DS bit set (type 43: byte 5, bit 3 = 0x10)
    let ns_and_ds = vec![0x00, 0x06, 0x20, 0x00, 0x00, 0x00, 0x00, 0x10];
    let ns_and_ds_rr = ResourceRecord::new(
        zone.clone(),
        RecordType::NSEC,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::Nsec(NsecRdata::new(next.clone(), TypeBitmap::new(ns_and_ds))),
    );
    assert_eq!(ds_absence(&ns_and_ds_rr), Err(DenialError::NotCovered));

    // 4. Proper delegation: NS bit set, no DS, no SOA
    let delegation_nsec = ResourceRecord::new(
        zone.clone(),
        RecordType::NSEC,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::Nsec(NsecRdata::new(
            next,
            TypeBitmap::new(vec![0x00, 0x01, 0x20]),
        )),
    );
    assert!(ds_absence(&delegation_nsec).is_ok());
}

#[test]
fn test_nsec3_exact_prove_ds_absence_accepts_delegation() {
    let cap = Nsec3IterationsCap::DEFAULT;
    let salt = vec![0x33, 0x44];
    let params = Nsec3Params::new(Nsec3HashAlgorithm::SHA1, 1, salt.clone());
    let parent = Name::from_ascii("example.com.").unwrap();
    let zone = Name::from_ascii("delegated.example.com.").unwrap();
    let zone_hash = hash_nsec3_name(&zone, &params, cap).unwrap();
    let owner =
        Name::from_ascii(&format!("{}.example.com.", base32hex_encode(&zone_hash))).unwrap();

    let ns_only_rdata = Nsec3Rdata::new(
        1,
        0,
        1,
        salt,
        vec![0; 20],
        TypeBitmap::new(vec![0x00, 0x01, 0x20]),
    );
    let ns_rr = ResourceRecord::new(
        owner,
        RecordType::NSEC3,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::Nsec3(ns_only_rdata),
    );
    let proof = DenialProof::from_records(&[&ns_rr]).unwrap();
    assert!(proof.prove_ds_absence(&parent, &zone, cap).is_ok());
}

#[test]
fn test_nsec3_exact_prove_ds_absence_rejects_missing_ns_or_apex_soa() {
    let cap = Nsec3IterationsCap::DEFAULT;
    let salt = vec![0x33, 0x44];
    let params = Nsec3Params::new(Nsec3HashAlgorithm::SHA1, 1, salt.clone());
    let parent = Name::from_ascii("example.com.").unwrap();
    let zone = Name::from_ascii("delegated.example.com.").unwrap();
    let zone_hash = hash_nsec3_name(&zone, &params, cap).unwrap();
    let owner =
        Name::from_ascii(&format!("{}.example.com.", base32hex_encode(&zone_hash))).unwrap();

    // 1. Exact match missing NS bit (e.g. only A) -> fails
    let a_only_rdata = Nsec3Rdata::new(
        1,
        0,
        1,
        salt.clone(),
        vec![0; 20],
        TypeBitmap::new(vec![0x00, 0x01, 0x40]),
    );
    let a_rr = ResourceRecord::new(
        owner.clone(),
        RecordType::NSEC3,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::Nsec3(a_only_rdata),
    );
    let proof_a = DenialProof::from_records(&[&a_rr]).unwrap();
    assert_eq!(
        proof_a.prove_ds_absence(&parent, &zone, cap),
        Err(DenialError::NotCovered)
    );

    // 2. Exact match with NS and SOA -> fails (apex, not delegation)
    let soa_rdata = Nsec3Rdata::new(
        1,
        0,
        1,
        salt,
        vec![0; 20],
        TypeBitmap::new(vec![0x00, 0x01, 0x22]),
    );
    let soa_rr = ResourceRecord::new(
        owner,
        RecordType::NSEC3,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::Nsec3(soa_rdata),
    );
    let proof_soa = DenialProof::from_records(&[&soa_rr]).unwrap();
    assert_eq!(
        proof_soa.prove_ds_absence(&parent, &zone, cap),
        Err(DenialError::NotCovered)
    );
}

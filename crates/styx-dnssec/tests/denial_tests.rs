//! Integration tests for NSEC and NSEC3 denial-of-existence proofs (Sub-phases 6b and 6c).

use styx_dnssec::domain::denial::{
    nsec_covers_name, Nsec3Flags, Nsec3Params, Nsec3Proof, NsecProof,
};
use styx_dnssec::domain::error::DenialError;
use styx_dnssec::domain::nsec3::{
    base32hex_decode, base32hex_encode, hash_nsec3_name, verify_nsec3_ds_absence,
    verify_nsec3_nxdomain,
};
use styx_dnssec::Nsec3IterationsCap;
use styx_proto::domain::rdata::{Nsec3Rdata, NsecRdata, TypeBitmap};
use styx_proto::{Name, RData, RecordClass, RecordType, ResourceRecord, Ttl};

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

    let proof = NsecProof::new(vec![nsec_rr]);

    // Name does not exist covers qname
    assert!(proof.prove_name_does_not_exist(&qname).is_ok());

    // Type does not exist for AAAA at host.example.com
    assert!(proof
        .prove_type_does_not_exist(&owner, RecordType::AAAA)
        .is_ok());

    // Type A exists at host.example.com -> fails NODATA proof
    assert_eq!(
        proof.prove_type_does_not_exist(&owner, RecordType::A),
        Err(DenialError::NotCovered)
    );
}

#[test]
fn test_nsec3_iterations_cap_enforced() {
    let params = Nsec3Params::new(
        1, // SHA-1
        Nsec3Flags::new(0),
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
    let params = Nsec3Params::new(1, Nsec3Flags::new(0), 1, vec![0x12, 0x34]);
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
    let params = Nsec3Params::new(1, Nsec3Flags::new(0), 1, salt.clone());

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

    let proof = Nsec3Proof::new(params, vec![rr1]);
    let result = verify_nsec3_nxdomain(&proof, &qname, cap);

    assert!(result.is_ok());
}

#[test]
fn test_nsec3_opt_out_unsigned_delegation() {
    let cap = Nsec3IterationsCap::DEFAULT;
    let salt = vec![0x11, 0x22];
    // Opt-out flag = 1
    let params = Nsec3Params::new(1, Nsec3Flags::new(1), 1, salt.clone());

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

    let proof = Nsec3Proof::new(params, vec![rr]);
    assert!(proof.opt_out_applies());

    // DS absence is verified under opt-out span
    let res = verify_nsec3_ds_absence(&proof, &child, cap);
    assert!(res.is_ok());
}

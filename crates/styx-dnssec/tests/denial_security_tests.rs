//! Regression tests for NSEC closest-encloser wildcards, NSEC3 RFC 5155 §8.3/§8.4
//! delegation/DNAME/bailiwick checks, and strict base32hex decoding.

mod support;

use styx_dnssec::domain::denial::{DenialProof, Nsec3Params};
use styx_dnssec::domain::error::DenialError;
use styx_dnssec::domain::nsec3::{base32hex_decode, hash_nsec3_name};
use styx_dnssec::{
    Delegation, InMemoryChainSource, Nsec3HashAlgorithm, Nsec3IterationsCap, TrustAnchorSource,
    ValidationPolicy, ValidationVerdict, Validator, VerdictReason, ZoneCutMaterial,
};
use styx_proto::domain::rdata::{Nsec3Rdata, NsecRdata, TypeBitmap};
use styx_proto::{Name, RData, RecordClass, RecordType, ResourceRecord, ResponseCode, Ttl};
use support::{base32hex_encode, clock, mark_non_cuts, query, StaticAnchorSource, ZoneKey};

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
}

#[test]
fn test_nsec3_rejects_delegation_and_dname_closest_enclosers() {
    let cap = Nsec3IterationsCap::DEFAULT;
    let salt = vec![0xAA, 0xBB];
    let params = Nsec3Params::new(Nsec3HashAlgorithm::SHA1, 1, salt.clone());

    let zone = Name::from_ascii("example.").unwrap();
    let ce = Name::from_ascii("sub.example.").unwrap();
    let qname = Name::from_ascii("host.sub.example.").unwrap();
    let ce_hash = hash_nsec3_name(&ce, &params, cap).unwrap();
    let ce_owner = Name::from_ascii(&format!("{}.example.", base32hex_encode(&ce_hash))).unwrap();

    // 1. Closest encloser is a delegation cut (NS bit set, SOA bit clear).
    let ns_only = TypeBitmap::new(vec![0x00, 0x01, 0x20]);
    let delegation_rr = nsec3_record(&ce_owner, salt.clone(), ce_hash.clone(), ns_only);
    let delegation_proof = DenialProof::from_records(&[&delegation_rr]).unwrap();
    assert_eq!(
        delegation_proof.verify(&zone, &qname, RecordType::A, ResponseCode::NXDOMAIN, cap),
        Err(DenialError::DenialProofIncomplete)
    );

    // 2. Closest encloser carries a DNAME bit (type 39: byte 4 bit 0 = 0x01).
    let dname_bitmap = TypeBitmap::new(vec![0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x01]);
    let dname_rr = nsec3_record(&ce_owner, salt, ce_hash, dname_bitmap);
    let dname_proof = DenialProof::from_records(&[&dname_rr]).unwrap();
    assert_eq!(
        dname_proof.verify(&zone, &qname, RecordType::A, ResponseCode::NXDOMAIN, cap),
        Err(DenialError::DenialProofIncomplete)
    );
}

#[test]
fn test_nsec3_rejects_parent_zone_owner_and_delegation_nodata() {
    let cap = Nsec3IterationsCap::DEFAULT;
    let salt = vec![0x11, 0x22];
    let params = Nsec3Params::new(Nsec3HashAlgorithm::SHA1, 1, salt.clone());

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
    let replayed_proof = DenialProof::from_records(&[&parent_rr]).unwrap();
    assert_eq!(
        replayed_proof.verify(
            &child_zone,
            &qname,
            RecordType::A,
            ResponseCode::NXDOMAIN,
            cap
        ),
        Err(DenialError::DenialProofIncomplete)
    );

    // Exact NODATA for A at `sub.example.` using delegation NSEC3 (NS without SOA) in `example.`.
    let nodata_proof = DenialProof::from_records(&[&parent_rr]).unwrap();
    assert_eq!(
        nodata_proof.verify(
            &parent_zone,
            &child_zone,
            RecordType::A,
            ResponseCode::NOERROR,
            cap,
        ),
        Err(DenialError::NotCovered)
    );

    // Sanity check: DS query at delegation cut DOES match NS-without-SOA.
    let a_not_ds = nsec3_record(
        &parent_owner,
        salt,
        sub_hash,
        TypeBitmap::new(vec![0x00, 0x01, 0x20]),
    );
    assert!(DenialProof::from_records(&[&a_not_ds])
        .unwrap()
        .verify(
            &parent_zone,
            &child_zone,
            RecordType::DS,
            ResponseCode::NOERROR,
            cap,
        )
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

#[test]
fn test_nsec3_iterations_cap_boundaries_and_custom_cap() {
    let name = Name::from_ascii("test.example.com.").unwrap();
    let default_cap = Nsec3IterationsCap::DEFAULT;

    let at_cap = Nsec3Params::new(Nsec3HashAlgorithm::SHA1, 100, vec![0xAA, 0xBB]);
    assert!(hash_nsec3_name(&name, &at_cap, default_cap).is_ok());

    let over_cap = Nsec3Params::new(Nsec3HashAlgorithm::SHA1, 101, vec![0xAA, 0xBB]);
    assert_eq!(
        hash_nsec3_name(&name, &over_cap, default_cap),
        Err(DenialError::Nsec3IterationsExceeded)
    );

    let custom_cap = Nsec3IterationsCap::new(5);
    let at_custom = Nsec3Params::new(Nsec3HashAlgorithm::SHA1, 5, vec![0xAA, 0xBB]);
    let over_custom = Nsec3Params::new(Nsec3HashAlgorithm::SHA1, 6, vec![0xAA, 0xBB]);
    assert!(hash_nsec3_name(&name, &at_custom, custom_cap).is_ok());
    assert_eq!(
        hash_nsec3_name(&name, &over_custom, custom_cap),
        Err(DenialError::Nsec3IterationsExceeded)
    );
}

#[tokio::test]
async fn test_validator_returns_bogus_for_over_cap_nsec3_proof() {
    let root = Name::root();
    let root_key = ZoneKey::generate(&root);
    let source = InMemoryChainSource::new();
    source.insert_cut(ZoneCutMaterial::new(
        root.clone(),
        Delegation::Apex {
            dnskey: root_key.dnskey_rrset(),
        },
    ));

    let qname = Name::from_ascii("missing.example.").unwrap();
    mark_non_cuts(&source, &qname, &root);

    let owner_hash = vec![0x11; 20];
    let nsec3_owner = Name::from_ascii(&format!("{}.", base32hex_encode(&owner_hash))).unwrap();
    source.record_not_a_cut(nsec3_owner.clone());

    let nsec3 = nsec3_record(
        &nsec3_owner,
        vec![0xAB],
        owner_hash,
        TypeBitmap::new(vec![0x00, 0x01, 0x22]),
    );
    let over_cap_nsec3 = ResourceRecord::new(
        nsec3.owner,
        RecordType::NSEC3,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::Nsec3(Nsec3Rdata::new(
            1,
            0,
            101,
            vec![0xAB],
            vec![0x11; 20],
            TypeBitmap::new(vec![0x00, 0x01, 0x22]),
        )),
    );

    let mut message = query(&qname, RecordType::A);
    message.header.rcode = ResponseCode::NXDOMAIN;
    message
        .authorities
        .push(root_key.sign(std::slice::from_ref(&over_cap_nsec3)));
    message.authorities.push(over_cap_nsec3);

    let anchors = StaticAnchorSource::new(vec![root_key.anchor()]);
    let outcome = Validator::new(clock(), ValidationPolicy::default(), anchors.anchors())
        .validate(&message, &source)
        .await;

    assert_eq!(outcome.verdict, ValidationVerdict::Bogus);
    assert_eq!(outcome.reason, VerdictReason::Nsec3IterationsExceeded);
}

#[tokio::test]
async fn test_any_query_with_non_empty_nsec_bitmap_is_bogus() {
    let root_key = ZoneKey::generate(&Name::root());
    let example_key = ZoneKey::generate(&support::name("example."));
    let source = InMemoryChainSource::new();
    source.insert_cut(root_key.apex_cut());
    source.insert_cut(example_key.signed_cut(&root_key));

    let www = support::name("www.example.");
    source.record_not_a_cut(www.clone());
    let nsec = support::nsec(
        &www,
        &support::name("z.example."),
        &[RecordType::A, RecordType::RRSIG, RecordType::NSEC],
    );
    let mut message = query(&www, RecordType::ANY);
    message
        .authorities
        .push(example_key.sign(std::slice::from_ref(&nsec)));
    message.authorities.push(nsec);

    let anchors = StaticAnchorSource::new(vec![root_key.anchor()]);
    let outcome = Validator::new(clock(), ValidationPolicy::default(), anchors.anchors())
        .validate(&message, &source)
        .await;

    assert_eq!(outcome.verdict, ValidationVerdict::Bogus);
    assert_eq!(outcome.reason, VerdictReason::DenialProofIncomplete);
}

#[tokio::test]
async fn test_any_query_at_nsec3_empty_non_terminal_is_secure() {
    let root_key = ZoneKey::generate(&Name::root());
    let example = support::name("example.");
    let example_key = ZoneKey::generate(&example);
    let source = InMemoryChainSource::new();
    source.insert_cut(root_key.apex_cut());
    source.insert_cut(example_key.signed_cut(&root_key));

    let ent = support::name("ent.example.");
    source.record_not_a_cut(ent.clone());
    let salt = vec![0xAA];
    let params = Nsec3Params::new(Nsec3HashAlgorithm::SHA1, 0, salt.clone());
    let ent_hash = hash_nsec3_name(&ent, &params, Nsec3IterationsCap::DEFAULT).unwrap();
    let nsec3_owner = support::name(&format!("{}.example.", base32hex_encode(&ent_hash)));
    source.record_not_a_cut(nsec3_owner.clone());
    let nsec3 = ResourceRecord::new(
        nsec3_owner,
        RecordType::NSEC3,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::Nsec3(Nsec3Rdata::new(
            1,
            0,
            0,
            salt,
            ent_hash,
            TypeBitmap::new(Vec::new()),
        )),
    );
    let mut message = query(&ent, RecordType::ANY);
    message
        .authorities
        .push(example_key.sign(std::slice::from_ref(&nsec3)));
    message.authorities.push(nsec3);

    let anchors = StaticAnchorSource::new(vec![root_key.anchor()]);
    let outcome = Validator::new(clock(), ValidationPolicy::default(), anchors.anchors())
        .validate(&message, &source)
        .await;

    assert_eq!(outcome.verdict, ValidationVerdict::Secure);
    assert_eq!(outcome.reason, VerdictReason::ProvenDenialOfExistence);
}

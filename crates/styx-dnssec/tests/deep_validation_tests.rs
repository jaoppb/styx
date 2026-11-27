//! Deep verification integration tests covering multi-record RRsets, multi-level descent,
//! non-zone-cut subdomains, NSEC3 NODATA, and unsigned denial rejection.

mod support;

use styx_dnssec::domain::denial::Nsec3Params;
use styx_dnssec::domain::nsec3::hash_nsec3_name;
use styx_dnssec::domain::signature::compute_dnskey_digest;
use styx_dnssec::{
    Delegation, DigestType, InMemoryChainSource, Nsec3HashAlgorithm, Nsec3IterationsCap,
    SignedRrset, ValidationPolicy, ValidationVerdict, Validator, VerdictReason, ZoneCutMaterial,
};
use styx_proto::domain::rdata::{DnskeyRdata, Nsec3Rdata, NsecRdata, TypeBitmap};
use styx_proto::{Name, RData, RecordClass, RecordType, ResourceRecord, ResponseCode};
use support::{
    a_record, base32hex_encode, clock, mark_non_cuts, name, query, record, StaticAnchorSource,
    ZoneKey,
};

fn root_only(root_key: &ZoneKey) -> InMemoryChainSource {
    let source = InMemoryChainSource::new();
    source.insert_cut(root_key.apex_cut());
    source
}

#[tokio::test]
async fn test_multi_record_rrset_validation_succeeds() {
    let root_key = ZoneKey::generate(&Name::root());
    let rrset = vec![a_record(&Name::root(), 1), a_record(&Name::root(), 2)];

    let mut message = query(&Name::root(), RecordType::A);
    message.answers.push(root_key.sign(&rrset));
    message.answers.extend(rrset);
    let anchors = StaticAnchorSource::new(vec![root_key.anchor()]);

    let validator = Validator::new(
        clock(),
        ValidationPolicy::default(),
        anchors.anchors.clone(),
    );
    let source = root_only(&root_key);
    let outcome = validator.validate(&message, &source).await;

    assert_eq!(outcome.verdict, ValidationVerdict::Secure);
    assert_eq!(outcome.reason, VerdictReason::AnchorMatched);
}

#[tokio::test]
async fn test_multi_level_descent_and_subdomain_hostname() {
    let root_key = ZoneKey::generate(&Name::root());
    let example_key = ZoneKey::generate(&name("example."));
    let source = root_only(&root_key);
    source.insert_cut(example_key.signed_cut(&root_key));

    let www = name("www.example.");
    mark_non_cuts(&source, &www, &name("example."));
    let answer = a_record(&www, 9);
    let mut message = query(&www, RecordType::A);
    message
        .answers
        .push(example_key.sign(std::slice::from_ref(&answer)));
    message.answers.push(answer);
    let anchors = StaticAnchorSource::new(vec![root_key.anchor()]);

    let validator = Validator::new(
        clock(),
        ValidationPolicy::default(),
        anchors.anchors.clone(),
    );
    let outcome = validator.validate(&message, &source).await;

    assert_eq!(outcome.verdict, ValidationVerdict::Secure);
    assert_eq!(outcome.reason, VerdictReason::AnchorMatched);
}

#[tokio::test]
async fn test_nsec3_nodata_verification() {
    let root = Name::root();
    let root_key = ZoneKey::generate(&root);

    let salt = vec![0x12, 0x34];
    let params = Nsec3Params::new(Nsec3HashAlgorithm::SHA1, 1, salt.clone());
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
    let anchors = StaticAnchorSource::new(vec![root_key.anchor()]);

    let validator = Validator::new(
        clock(),
        ValidationPolicy::default(),
        anchors.anchors.clone(),
    );
    let source = root_only(&root_key);
    source.record_not_a_cut(owner);
    let outcome = validator.validate(&message, &source).await;

    assert_eq!(outcome.verdict, ValidationVerdict::Secure);
    assert_eq!(outcome.reason, VerdictReason::ProvenDenialOfExistence);
}

#[tokio::test]
async fn test_unsigned_denial_rejected_as_bogus() {
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
    let anchors = StaticAnchorSource::new(vec![root_key.anchor()]);

    let validator = Validator::new(
        clock(),
        ValidationPolicy::default(),
        anchors.anchors.clone(),
    );
    let source = root_only(&root_key);
    mark_non_cuts(&source, &name("nonexistent.example."), &root);
    let outcome = validator.validate(&message, &source).await;

    assert_eq!(outcome.verdict, ValidationVerdict::Bogus);
    assert_eq!(outcome.reason, VerdictReason::NoValidRrsig);
}

#[test]
fn test_sha1_ds_digest_computation() {
    let zone = name("example.com.");
    let dnskey = DnskeyRdata::new(257, 3, 8, vec![0x01, 0x02, 0x03, 0x04]);
    let digest = compute_dnskey_digest(&zone, &dnskey, DigestType::SHA1);
    assert_eq!(digest.map(|digest| digest.len()), Some(20));
}

#[tokio::test]
async fn test_signed_delegation_without_zone_ds_is_bogus_without_spending_budget() {
    let root_key = ZoneKey::generate(&Name::root());
    let example_key = ZoneKey::generate(&name("example."));
    let sibling_key = ZoneKey::generate(&name("sibling."));
    let www = name("www.example.");
    let answer = a_record(&www, 9);
    let mut message = query(&www, RecordType::A);
    message
        .answers
        .push(example_key.sign(std::slice::from_ref(&answer)));
    message.answers.push(answer);
    let anchors = StaticAnchorSource::new(vec![root_key.anchor()]);

    // Parent-signed sibling DS only (no DS for `example.`) -> Bogus(DsDnskeyMismatch),
    // not Insecure(UnsupportedAlgorithm), even when budget has only 1 verification for root.
    let sibling_ds = vec![sibling_key.ds_record()];
    let sibling_sig = vec![root_key.sign(&sibling_ds)];
    for ds_set in [
        SignedRrset::new(Vec::new(), Vec::new()),
        SignedRrset::new(sibling_ds, sibling_sig),
    ] {
        let source = root_only(&root_key);
        source.insert_cut(ZoneCutMaterial::new(
            name("example."),
            Delegation::Signed {
                ds: ds_set,
                dnskey: example_key.dnskey_rrset(),
            },
        ));
        mark_non_cuts(&source, &www, &name("example."));
        let policy = ValidationPolicy {
            max_signature_verifications: 1,
            ..ValidationPolicy::default()
        };
        let outcome = Validator::new(clock(), policy, anchors.anchors.clone())
            .validate(&message, &source)
            .await;
        assert_eq!(outcome.verdict, ValidationVerdict::Bogus);
        assert_eq!(outcome.reason, VerdictReason::DsDnskeyMismatch);
    }
}

#[tokio::test]
async fn test_signed_delegation_with_unrelated_records_ignores_them_for_budget() {
    let root_key = ZoneKey::generate(&Name::root());
    let example_key = ZoneKey::generate(&name("example."));
    let www = name("www.example.");
    let answer = a_record(&www, 9);
    let mut message = query(&www, RecordType::A);
    message
        .answers
        .push(example_key.sign(std::slice::from_ref(&answer)));
    message.answers.push(answer);
    let anchors = StaticAnchorSource::new(vec![root_key.anchor()]);

    // Valid `(example., DS)` alongside an unrelated record does not spend budget on it.
    let source = root_only(&root_key);
    let ds = vec![example_key.ds_record()];
    let ds_sig = root_key.sign(&ds);
    let unrelated = record(
        &Name::root(),
        RecordType::A,
        RData::A(std::net::Ipv4Addr::LOCALHOST),
    );
    let mut ds_records = ds;
    ds_records.push(unrelated);
    source.insert_cut(ZoneCutMaterial::new(
        name("example."),
        Delegation::Signed {
            ds: SignedRrset::new(ds_records, vec![ds_sig]),
            dnskey: example_key.dnskey_rrset(),
        },
    ));
    mark_non_cuts(&source, &www, &name("example."));
    let tight = ValidationPolicy {
        max_signature_verifications: 4,
        ..ValidationPolicy::default()
    };
    let outcome = Validator::new(clock(), tight, anchors.anchors.clone())
        .validate(&message, &source)
        .await;
    assert_eq!(outcome.verdict, ValidationVerdict::Secure);
}

#[tokio::test]
async fn test_multi_rrset_cname_and_authority_nsec_exceeding_per_tag_limit_succeed() {
    let root_key = ZoneKey::generate(&Name::root());
    let example_key = ZoneKey::generate(&name("example."));
    let source = root_only(&root_key);
    source.insert_cut(example_key.signed_cut(&root_key));

    let mut message = query(&name("c0.example."), RecordType::A);
    for idx in 0u8..6 {
        let owner = name(&format!("c{idx}.example."));
        let next = name(&format!("c{}.example.", idx.saturating_add(1)));
        source.record_not_a_cut(owner.clone());
        let cname = record(&owner, RecordType::CNAME, RData::Cname(next));
        message
            .answers
            .push(example_key.sign(std::slice::from_ref(&cname)));
        message.answers.push(cname);
    }
    let final_owner = name("c6.example.");
    source.record_not_a_cut(final_owner.clone());
    let answer = a_record(&final_owner, 7);
    message
        .answers
        .push(example_key.sign(std::slice::from_ref(&answer)));
    message.answers.push(answer);

    for idx in 0u8..6 {
        let owner = name(&format!("n{idx}.example."));
        let next = name(&format!("n{}.example.", idx.saturating_add(1)));
        source.record_not_a_cut(owner.clone());
        let nsec = support::nsec(
            &owner,
            &next,
            &[RecordType::A, RecordType::RRSIG, RecordType::NSEC],
        );
        message
            .authorities
            .push(example_key.sign(std::slice::from_ref(&nsec)));
        message.authorities.push(nsec);
    }

    let anchors = StaticAnchorSource::new(vec![root_key.anchor()]);
    let outcome = Validator::new(
        clock(),
        ValidationPolicy::default(),
        anchors.anchors.clone(),
    )
    .validate(&message, &source)
    .await;
    assert_eq!(outcome.verdict, ValidationVerdict::Secure);
}

#[tokio::test]
async fn test_delegation_ds_rrsig_with_mismatched_owner_or_class_is_bogus() {
    let root_key = ZoneKey::generate(&Name::root());
    let example_key = ZoneKey::generate(&name("example."));
    let ds = vec![example_key.ds_record()];
    let valid_sig = root_key.sign(&ds);
    let wrong_owner_sig = ResourceRecord::new(
        name("other."),
        valid_sig.rtype,
        valid_sig.rclass,
        valid_sig.ttl,
        valid_sig.rdata.clone(),
    );
    let wrong_class_sig = ResourceRecord::new(
        valid_sig.owner.clone(),
        valid_sig.rtype,
        RecordClass::Ch,
        valid_sig.ttl,
        valid_sig.rdata,
    );
    let www = name("www.example.");
    let answer = a_record(&www, 5);
    let mut message = query(&www, RecordType::A);
    message
        .answers
        .push(example_key.sign(std::slice::from_ref(&answer)));
    message.answers.push(answer);
    let anchors = StaticAnchorSource::new(vec![root_key.anchor()]);

    for bad_sig in [wrong_owner_sig, wrong_class_sig] {
        let source = root_only(&root_key);
        source.insert_cut(ZoneCutMaterial::new(
            name("example."),
            Delegation::Signed {
                ds: SignedRrset::new(ds.clone(), vec![bad_sig]),
                dnskey: example_key.dnskey_rrset(),
            },
        ));
        mark_non_cuts(&source, &www, &name("example."));
        let outcome = Validator::new(
            clock(),
            ValidationPolicy::default(),
            anchors.anchors.clone(),
        )
        .validate(&message, &source)
        .await;
        assert_eq!(outcome.verdict, ValidationVerdict::Bogus);
        assert_eq!(outcome.reason, VerdictReason::NoValidRrsig);
    }
}

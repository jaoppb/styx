//! Security hardening tests: KeyTrap bounds, memoisation, Indeterminate HardFail mapping,
//! authority-section validation, multi-zone denials, and probe bounds.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::sync::atomic::{AtomicUsize, Ordering};

use styx_dnssec::domain::denial::DenialProof;
use styx_dnssec::domain::error::DenialError;
use styx_dnssec::{
    ChainSource, ChainSourceError, Delegation, FailureMode, InMemoryChainSource, SignedRrset,
    TrustAnchors, ValidationOutcome, ValidationPolicy, ValidationVerdict, Validator, VerdictReason,
    ZoneCutMaterial,
};
use styx_proto::{
    Message, Name, RData, RecordClass, RecordType, ResourceRecord, ResponseCode, Ttl,
};
use support::{a_record, clock, mark_non_cuts, name, nsec, query, record, ZoneKey};

struct CountingSource {
    inner: InMemoryChainSource,
    calls: AtomicUsize,
}

impl CountingSource {
    fn new(inner: InMemoryChainSource) -> Self {
        Self {
            inner,
            calls: AtomicUsize::new(0),
        }
    }
}

impl ChainSource for CountingSource {
    async fn material_for(&self, zone: &Name) -> Result<ZoneCutMaterial, ChainSourceError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.inner.material_for(zone).await
    }
}

#[test]
fn test_default_failure_mode_is_warn_only() {
    assert_eq!(FailureMode::default(), FailureMode::WarnOnly);
    assert_eq!(
        ValidationPolicy::default().failure_mode,
        FailureMode::WarnOnly
    );
}

#[tokio::test]
async fn test_keytrap_budget_stops_colliding_keys_and_signatures() {
    let root = Name::root();
    let signing_key = ZoneKey::generate(&root);
    let keys = vec![signing_key.dnskey_record(); 8];
    let dnskey_sig = signing_key.sign(&keys);
    let source = InMemoryChainSource::new();
    source.insert_cut(ZoneCutMaterial::new(
        root,
        Delegation::Apex {
            dnskey: SignedRrset::new(keys, vec![dnskey_sig]),
        },
    ));
    let host = name("host.");
    source.record_not_a_cut(host.clone());
    let answer = a_record(&host, 1);

    let mut bad_sig = signing_key.sign(std::slice::from_ref(&answer));
    if let RData::Rrsig(ref rrsig) = bad_sig.rdata {
        bad_sig.rdata = RData::Rrsig(styx_proto::domain::rdata::RrsigRdata::new(
            rrsig.type_covered(),
            rrsig.algorithm(),
            rrsig.labels(),
            rrsig.original_ttl(),
            rrsig.signature_expiration(),
            rrsig.signature_inception(),
            rrsig.key_tag(),
            rrsig.signer_name().clone(),
            vec![0xAA; 64],
        ));
    }

    let mut message = query(&host, RecordType::A);
    message.answers.extend(std::iter::repeat_n(bad_sig, 5));
    message.answers.push(answer);

    for (max_verif, max_fail, max_keys) in [(5, 2, 2), (1, 16, 4)] {
        let policy = ValidationPolicy {
            max_signature_verifications: max_verif,
            max_signature_failures: max_fail,
            max_keys_per_tag_algorithm: max_keys,
            ..ValidationPolicy::default()
        };
        let outcome = Validator::new(clock(), policy, TrustAnchors::new(signing_key.anchor()))
            .validate(&message, &source)
            .await;
        assert_eq!(outcome.verdict, ValidationVerdict::Bogus);
        assert_eq!(outcome.reason, VerdictReason::SignatureBudgetExceeded);
    }
}

#[tokio::test]
async fn test_validator_memoises_zone_descent_across_cname_chain() {
    let root = ZoneKey::generate(&Name::root());
    let example = ZoneKey::generate(&name("example."));
    let inner = InMemoryChainSource::new();
    inner.insert_cut(root.apex_cut());
    inner.insert_cut(example.signed_cut(&root));
    for label in ["a.example.", "b.example.", "c.example."] {
        inner.record_not_a_cut(name(label));
    }

    let c1 = record(
        &name("a.example."),
        RecordType::CNAME,
        RData::Cname(name("b.example.")),
    );
    let c2 = record(
        &name("b.example."),
        RecordType::CNAME,
        RData::Cname(name("c.example.")),
    );
    let a = a_record(&name("c.example."), 7);
    let mut message = query(&name("a.example."), RecordType::A);
    message
        .answers
        .push(example.sign(std::slice::from_ref(&c1)));
    message.answers.push(c1);
    message
        .answers
        .push(example.sign(std::slice::from_ref(&c2)));
    message.answers.push(c2);
    message.answers.push(example.sign(std::slice::from_ref(&a)));
    message.answers.push(a);

    let counting = CountingSource::new(inner);
    let outcome = Validator::new(
        clock(),
        ValidationPolicy::default(),
        TrustAnchors::new(root.anchor()),
    )
    .validate(&message, &counting)
    .await;

    assert_eq!(outcome.verdict, ValidationVerdict::Secure);
    // Only 5 unique names fetched across 3 CNAME links: `.`, `example.`, `a.example.`,
    // `b.example.`, and `c.example.` (root and `example.` are memoised after link 1).
    assert_eq!(counting.calls.load(Ordering::Relaxed), 5);
}

#[test]
fn test_indeterminate_below_anchor_servfails_under_hard_fail_except_no_path_to_anchor() {
    for reason in [
        VerdictReason::ChainMaterialUnavailable,
        VerdictReason::UnexpectedZoneApex,
        VerdictReason::MaxZoneCutsExceeded,
    ] {
        let mut msg = query(&name("www.example."), RecordType::A);
        msg.answers.push(a_record(&name("www.example."), 1));
        ValidationOutcome::indeterminate(reason).apply_to_message(&mut msg, FailureMode::HardFail);
        assert_eq!(msg.header.rcode, ResponseCode::SERVFAIL, "{reason:?}");
        assert!(msg.answers.is_empty());
        assert!(!msg.header.authentic_data);
    }

    let mut no_anchor_msg = query(&name("www.example."), RecordType::A);
    no_anchor_msg.header.authentic_data = true;
    no_anchor_msg
        .answers
        .push(a_record(&name("www.example."), 1));
    ValidationOutcome::indeterminate(VerdictReason::NoPathToAnchor)
        .apply_to_message(&mut no_anchor_msg, FailureMode::HardFail);
    assert_eq!(no_anchor_msg.header.rcode, ResponseCode::NOERROR);
    assert_eq!(no_anchor_msg.answers.len(), 1);
    assert!(!no_anchor_msg.header.authentic_data);
}

#[tokio::test]
async fn test_authority_section_forged_rrset_and_off_class_records_rejected() {
    let root = ZoneKey::generate(&Name::root());
    let source = InMemoryChainSource::new();
    source.insert_cut(root.apex_cut());
    let host = name("host.");
    source.record_not_a_cut(host.clone());
    let answer = a_record(&host, 1);

    // 1. Unsigned forged NS in authority section must never return Secure.
    let mut forged_auth = query(&host, RecordType::A);
    forged_auth
        .answers
        .push(root.sign(std::slice::from_ref(&answer)));
    forged_auth.answers.push(answer.clone());
    forged_auth.authorities.push(record(
        &Name::root(),
        RecordType::NS,
        RData::Ns(name("evil-ns.")),
    ));
    let validator = Validator::new(
        clock(),
        ValidationPolicy::default(),
        TrustAnchors::new(root.anchor()),
    );
    assert_eq!(
        validator.validate(&forged_auth, &source).await.verdict,
        ValidationVerdict::Bogus
    );

    // 2. Signed NS in authority section returns Secure.
    let ns_rr = record(&Name::root(), RecordType::NS, RData::Ns(name("ns1.")));
    let mut signed_auth = query(&host, RecordType::A);
    signed_auth
        .answers
        .push(root.sign(std::slice::from_ref(&answer)));
    signed_auth.answers.push(answer.clone());
    signed_auth
        .authorities
        .push(root.sign(std::slice::from_ref(&ns_rr)));
    signed_auth.authorities.push(ns_rr);
    assert_eq!(
        validator.validate(&signed_auth, &source).await.verdict,
        ValidationVerdict::Secure
    );

    // 3. Off-class answer record yields Bogus(MalformedResponse).
    let mut off_class = query(&host, RecordType::A);
    off_class
        .answers
        .push(root.sign(std::slice::from_ref(&answer)));
    off_class.answers.push(answer);
    off_class.answers.push(ResourceRecord::new(
        host,
        RecordType::A,
        RecordClass::Ch,
        Ttl::from_secs(60),
        RData::A(std::net::Ipv4Addr::new(10, 0, 0, 1)),
    ));
    let outcome = validator.validate(&off_class, &source).await;
    assert_eq!(outcome.verdict, ValidationVerdict::Bogus);
    assert_eq!(outcome.reason, VerdictReason::MalformedResponse);
}

#[tokio::test]
async fn test_multi_zone_denials_in_authority_and_missing_question() {
    let root = ZoneKey::generate(&Name::root());
    let zone_a = ZoneKey::generate(&name("a."));
    let zone_b = ZoneKey::generate(&name("b."));
    let source = InMemoryChainSource::new();
    source.insert_cut(root.apex_cut());
    source.insert_cut(zone_a.signed_cut(&root));
    source.insert_cut(zone_b.signed_cut(&root));
    source.record_not_a_cut(name("sub.wild.a."));
    source.record_not_a_cut(name("wild.a."));
    source.record_not_a_cut(name("missing.b."));

    // Wildcard-expanded CNAME in `a.` pointing to NXDOMAIN `missing.b.` in `b.`.
    let qname = name("sub.wild.a.");
    let cname = record(&qname, RecordType::CNAME, RData::Cname(name("missing.b.")));
    let nsec_a = nsec(
        &name("a."),
        &name("z.a."),
        &[RecordType::SOA, RecordType::NS],
    );
    let nsec_b = nsec(
        &name("b."),
        &name("z.b."),
        &[RecordType::SOA, RecordType::NS],
    );

    let mut message = query(&qname, RecordType::A);
    message.header.rcode = ResponseCode::NXDOMAIN;
    message
        .answers
        .push(zone_a.sign_wildcard(std::slice::from_ref(&cname), 1));
    message.answers.push(cname);
    message
        .authorities
        .push(zone_a.sign(std::slice::from_ref(&nsec_a)));
    message.authorities.push(nsec_a);
    message
        .authorities
        .push(zone_b.sign(std::slice::from_ref(&nsec_b)));
    message.authorities.push(nsec_b);

    let validator = Validator::new(
        clock(),
        ValidationPolicy::default(),
        TrustAnchors::new(root.anchor()),
    );
    assert_eq!(
        validator.validate(&message, &source).await.verdict,
        ValidationVerdict::Secure
    );

    let empty = Message::new(styx_proto::Header::new_query(
        1,
        styx_proto::Opcode::Query,
        false,
    ));
    let no_q = validator.validate(&empty, &source).await;
    assert_eq!(no_q.verdict, ValidationVerdict::Indeterminate);
    assert_eq!(no_q.reason, VerdictReason::MalformedResponse);
}

#[test]
fn test_nsec_wildcard_expansion_requires_exact_encloser_label_count() {
    let zone = name(".");
    let owner = name("a.b.example.");
    let covering = nsec(&name("."), &name("z."), &[RecordType::SOA, RecordType::NS]);
    let proof = DenialProof::from_records(&[&covering]).unwrap();
    // Closest encloser of `a.b.example.` covered by `.` -> `z.` is `.` (0 labels),
    // which must NOT satisfy a wildcard RRSIG with `signature_labels = 1` (`*.example.`).
    assert_eq!(
        proof.verify_wildcard_expansion(&zone, &owner, 1, styx_dnssec::Nsec3IterationsCap::DEFAULT),
        Err(DenialError::DenialProofIncomplete)
    );
}

#[tokio::test]
async fn test_descent_not_a_cut_probe_bound() {
    let root = ZoneKey::generate(&Name::root());
    let source = InMemoryChainSource::new();
    source.insert_cut(root.apex_cut());

    let mut deep = String::new();
    for i in 0..35 {
        deep.push_str(&format!("l{i}."));
    }
    let deep_name = name(&deep);
    mark_non_cuts(&source, &deep_name, &Name::root());

    let answer = a_record(&deep_name, 1);
    let mut message = query(&deep_name, RecordType::A);
    message
        .answers
        .push(root.sign(std::slice::from_ref(&answer)));
    message.answers.push(answer);

    let outcome = Validator::new(
        clock(),
        ValidationPolicy::default(),
        TrustAnchors::new(root.anchor()),
    )
    .validate(&message, &source)
    .await;

    assert_eq!(outcome.verdict, ValidationVerdict::Indeterminate);
    assert_eq!(outcome.reason, VerdictReason::MaxZoneCutsExceeded);
}

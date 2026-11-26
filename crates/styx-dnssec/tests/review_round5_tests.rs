//! Responses the 2026-11-24 review of PR #131 showed the validator judging wrongly. Each
//! test names the verdict RFC 4035 requires.

#![allow(clippy::unwrap_used)]

mod support;

use styx_dnssec::{
    ChainSource, Delegation, InMemoryChainSource, SignedRrset, TrustAnchor, TrustAnchors,
    ValidationPolicy, ValidationVerdict, Validator, VerdictReason, ZoneCutMaterial,
};
use styx_proto::{Message, Name, RData, RecordClass, RecordType, ResourceRecord, ResponseCode};
use support::nsec3_chain::{chain, node, opt_out, Node, APEX_TYPES};
use support::{a_record, clock, name, query, record, ZoneKey, DIGEST_SHA1, DIGEST_SHA256};

/// The root and `example.` signed under it.
struct Signed {
    root: ZoneKey,
    example: ZoneKey,
    source: InMemoryChainSource,
}

impl Signed {
    fn new() -> Self {
        let root = ZoneKey::generate(&Name::root());
        let example = ZoneKey::generate(&name("example."));
        let source = InMemoryChainSource::new();
        source.insert_cut(root.apex_cut());
        source.insert_cut(example.signed_cut(&root));
        source.record_not_a_cut(name("www.example."));
        source.record_not_a_cut(name("host.example."));
        Self {
            root,
            example,
            source,
        }
    }

    async fn validate(&self, message: &Message) -> (ValidationVerdict, VerdictReason) {
        validate(message, &self.source, vec![self.root.anchor()]).await
    }
}

async fn validate<S: ChainSource>(
    message: &Message,
    source: &S,
    anchors: Vec<TrustAnchor>,
) -> (ValidationVerdict, VerdictReason) {
    let anchors = TrustAnchors::from_vec(anchors).unwrap();
    let outcome = Validator::new(clock(), ValidationPolicy::default(), anchors)
        .validate(message, source)
        .await;
    (outcome.verdict, outcome.reason)
}

fn signed_answer(message: &mut Message, key: &ZoneKey, rrset: Vec<ResourceRecord>) {
    message.answers.push(key.sign(&rrset));
    message.answers.extend(rrset);
}

/// An `ANY` answer at a zone apex carries the child's own data and the DS the parent
/// signs. A DS the child signed itself must not pass on the strength of the child's keys.
#[tokio::test]
async fn an_any_answer_at_an_apex_does_not_let_the_child_sign_its_own_ds() {
    let zone = Signed::new();
    let apex = name("example.");
    let forged = ZoneKey::generate(&apex);
    let mut message = query(&apex, RecordType::ANY);
    signed_answer(&mut message, &zone.example, vec![a_record(&apex, 1)]);
    signed_answer(&mut message, &zone.example, vec![forged.ds_record()]);

    let verdict = zone.validate(&message).await;

    assert_eq!(verdict.0, ValidationVerdict::Bogus);
}

/// The same `ANY` answer with the DS signed by the parent is Secure: each RRset is checked
/// in the zone that signs it.
#[tokio::test]
async fn an_any_answer_at_an_apex_checks_the_ds_in_the_parent_zone() {
    let zone = Signed::new();
    let apex = name("example.");
    let mut message = query(&apex, RecordType::ANY);
    signed_answer(&mut message, &zone.example, vec![a_record(&apex, 1)]);
    signed_answer(&mut message, &zone.root, vec![zone.example.ds_record()]);

    let verdict = zone.validate(&message).await;

    assert_eq!(verdict.0, ValidationVerdict::Secure);
}

/// The RCODE is not signed: signed data at the end of the chain under NXDOMAIN is a
/// rewritten header, not a Secure NXDOMAIN.
#[tokio::test]
async fn signed_data_under_a_non_noerror_rcode_is_malformed() {
    for rcode in [
        ResponseCode::NXDOMAIN,
        ResponseCode::SERVFAIL,
        ResponseCode::REFUSED,
    ] {
        let zone = Signed::new();
        let www = name("www.example.");
        let mut message = query(&www, RecordType::A);
        signed_answer(&mut message, &zone.example, vec![a_record(&www, 1)]);
        message.header.rcode = rcode;

        let verdict = zone.validate(&message).await;

        assert_eq!(
            verdict,
            (ValidationVerdict::Bogus, VerdictReason::MalformedResponse),
            "{rcode:?}"
        );
    }
}

/// A DS or anchor vouches for the DNSKEY RRset at its own zone. A key whose digest matches
/// but whose record sits at another owner is not that zone's key.
#[tokio::test]
async fn a_dnskey_rrset_owned_by_another_name_is_not_the_zones_keys() {
    let evil = ZoneKey::generate(&name("evil."));
    let root_digest = styx_dnssec::domain::signature::compute_dnskey_digest(
        &Name::root(),
        &evil.dnskey,
        styx_dnssec::DigestType::SHA256,
    )
    .unwrap();
    let anchor = TrustAnchor::new(
        Name::root(),
        styx_proto::domain::rdata::DsRdata::new(evil.key_tag(), 15, DIGEST_SHA256, root_digest),
    );
    let source = InMemoryChainSource::new();
    source.insert_cut(ZoneCutMaterial::new(
        Name::root(),
        Delegation::Apex {
            dnskey: evil.dnskey_rrset(),
        },
    ));
    let host = name("a.evil.");
    source.record_not_a_cut(name("evil."));
    source.record_not_a_cut(host.clone());
    let mut message = query(&host, RecordType::A);
    signed_answer(&mut message, &evil, vec![a_record(&host, 1)]);

    let verdict = validate(&message, &source, vec![anchor]).await;

    assert_eq!(
        verdict,
        (ValidationVerdict::Bogus, VerdictReason::DsDnskeyMismatch)
    );
}

/// A DNSKEY RRset whose only signature is a wildcard expansion is not self-signed at the
/// apex, whatever the key it verifies with.
#[tokio::test]
async fn a_dnskey_rrset_signed_only_through_a_wildcard_is_bogus() {
    let example = ZoneKey::generate(&name("example."));
    let keys = vec![example.dnskey_record()];
    let signatures = vec![example.sign_wildcard(&keys, 0)];
    let source = InMemoryChainSource::new();
    source.insert_cut(ZoneCutMaterial::new(
        name("example."),
        Delegation::Apex {
            dnskey: SignedRrset::new(keys, signatures),
        },
    ));
    let www = name("www.example.");
    source.record_not_a_cut(www.clone());
    let mut message = query(&www, RecordType::A);
    signed_answer(&mut message, &example, vec![a_record(&www, 1)]);

    let verdict = validate(&message, &source, vec![example.anchor()]).await;

    assert_eq!(
        verdict,
        (ValidationVerdict::Bogus, VerdictReason::NoValidRrsig)
    );
}

/// RFC 4509 §3: a SHA-1 DS is ignored. With a SHA-256 DS for the real key beside it, a
/// SHA-1 DS naming another key vouches for nothing, so that key cannot sign the zone.
#[tokio::test]
async fn a_sha1_ds_beside_a_sha256_ds_vouches_for_nothing() {
    let root = ZoneKey::generate(&Name::root());
    let example = ZoneKey::generate(&name("example."));
    let other = ZoneKey::generate(&name("example."));
    let ds = vec![
        example.ds_record(),
        record(
            &name("example."),
            RecordType::DS,
            RData::Ds(other.ds(DIGEST_SHA1)),
        ),
    ];
    let ds_signatures = vec![root.sign(&ds)];
    let keys = vec![example.dnskey_record(), other.dnskey_record()];
    let key_signatures = vec![other.sign(&keys)];
    let source = InMemoryChainSource::new();
    source.insert_cut(root.apex_cut());
    source.insert_cut(ZoneCutMaterial::new(
        name("example."),
        Delegation::Signed {
            ds: SignedRrset::new(ds, ds_signatures),
            dnskey: SignedRrset::new(keys, key_signatures),
        },
    ));
    let www = name("www.example.");
    source.record_not_a_cut(www.clone());
    let mut message = query(&www, RecordType::A);
    signed_answer(&mut message, &other, vec![a_record(&www, 1)]);

    let verdict = validate(&message, &source, vec![root.anchor()]).await;

    assert_eq!(verdict.0, ValidationVerdict::Bogus);
}

/// Every authority record must be in the question's class before anything is Secure.
#[tokio::test]
async fn an_off_class_authority_record_is_malformed() {
    let zone = Signed::new();
    let www = name("www.example.");
    let mut message = query(&www, RecordType::A);
    signed_answer(&mut message, &zone.example, vec![a_record(&www, 1)]);
    let mut off_class = a_record(&www, 2);
    off_class.rclass = RecordClass::Ch;
    message.authorities.push(off_class);

    let verdict = zone.validate(&message).await;

    assert_eq!(
        verdict,
        (ValidationVerdict::Bogus, VerdictReason::MalformedResponse)
    );
}

fn wildcard_nodes() -> Vec<Node> {
    vec![
        node("example.", APEX_TYPES),
        node("*.example.", &[RecordType::A, RecordType::RRSIG]),
    ]
}

/// `host.example. A` expanded from `*.example.`, with every NSEC3 of the zone's chain in
/// the authority section, each signed as its own RRset.
fn nsec3_wildcard_answer(zone: &Signed, nodes: &[Node]) -> Message {
    let host = name("host.example.");
    let mut message = query(&host, RecordType::A);
    let answer = vec![a_record(&host, 1)];
    message.answers.push(zone.example.sign_wildcard(&answer, 1));
    message.answers.extend(answer);
    for nsec3 in chain(&name("example."), nodes) {
        let rrset = vec![nsec3];
        message.authorities.push(zone.example.sign(&rrset));
        message.authorities.extend(rrset);
    }
    message
}

#[tokio::test]
async fn an_nsec3_proven_wildcard_expansion_is_secure() {
    let zone = Signed::new();
    let message = nsec3_wildcard_answer(&zone, &wildcard_nodes());

    let verdict = zone.validate(&message).await;

    assert_eq!(verdict.0, ValidationVerdict::Secure);
}

#[tokio::test]
async fn an_nsec3_wildcard_expansion_over_an_opt_out_span_is_insecure() {
    let zone = Signed::new();
    let message = nsec3_wildcard_answer(&zone, &opt_out(wildcard_nodes()));

    let verdict = zone.validate(&message).await;

    assert_eq!(
        verdict,
        (ValidationVerdict::Insecure, VerdictReason::Nsec3OptOut)
    );
}

/// The expansion is forged when the qname exists: no NSEC3 span covers it.
#[tokio::test]
async fn an_nsec3_wildcard_expansion_over_an_existing_name_is_bogus() {
    let zone = Signed::new();
    let mut nodes = wildcard_nodes();
    nodes.push(node("host.example.", &[RecordType::TXT, RecordType::RRSIG]));
    let message = nsec3_wildcard_answer(&zone, &nodes);

    let verdict = zone.validate(&message).await;

    assert_eq!(verdict.0, ValidationVerdict::Bogus);
}

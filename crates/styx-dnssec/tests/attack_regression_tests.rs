//! Responses an attacker, a rollover or an ordinary zone layout can produce, each of which
//! an earlier version of the validator judged wrongly (PR #131 review, blockers B1-B5 and
//! the material findings). Each test names the verdict RFC 4035, 5155 or 6840 requires.

#![allow(clippy::unwrap_used)]

mod support;

use styx_dnssec::{
    ChainSource, ChainSourceError, Delegation, InMemoryChainSource, SignedRrset, TrustAnchor,
    TrustAnchors, ValidationPolicy, ValidationVerdict, Validator, VerdictReason, ZoneCutMaterial,
};
use styx_proto::{Message, Name, RData, RecordType, ResourceRecord, ResponseCode};
use support::{a_record, clock, name, nsec, query, record, ZoneKey};

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

fn signed_authority(message: &mut Message, key: &ZoneKey, rrset: Vec<ResourceRecord>) {
    message.authorities.push(key.sign(&rrset));
    message.authorities.extend(rrset);
}

fn cname(owner: &str, target: &str) -> ResourceRecord {
    record(&name(owner), RecordType::CNAME, RData::Cname(name(target)))
}

/// B1: since the 2026 root rollover the root DNSKEY RRset carries a published KSK that no
/// longer signs. Both are anchored; whichever is listed first, the signing one must count.
#[tokio::test]
async fn a_rollover_key_that_does_not_sign_does_not_hide_the_one_that_does() {
    let published = ZoneKey::generate(&Name::root());
    let signing = ZoneKey::generate(&Name::root());
    let keys = vec![published.dnskey_record(), signing.dnskey_record()];
    let signatures = vec![signing.sign(&keys)];
    let source = InMemoryChainSource::new();
    source.insert_cut(ZoneCutMaterial::new(
        Name::root(),
        Delegation::Apex {
            dnskey: SignedRrset::new(keys, signatures),
        },
    ));
    let host = name("host.");
    let mut message = query(&host, RecordType::A);
    signed_answer(&mut message, &signing, vec![a_record(&host, 1)]);

    let verdict = validate(
        &message,
        &source,
        vec![published.anchor(), signing.anchor()],
    )
    .await;

    assert_eq!(verdict.0, ValidationVerdict::Secure);
}

/// B2: the RRSIG over `*.example. NSEC` still verifies when the NSEC is moved to another
/// owner, because the canonical owner of a wildcard RRSIG is rebuilt from its label count.
/// A denial built from such a record is forged (RFC 4035 §5.3.4, §5.4).
#[tokio::test]
async fn a_wildcard_nsec_moved_to_the_qname_is_not_a_denial() {
    let zone = Signed::new();
    let www = name("www.example.");
    let types = [RecordType::TXT, RecordType::RRSIG, RecordType::NSEC];
    let wildcard_nsec = nsec(&name("*.example."), &name("a.example."), &types);
    let signature = zone
        .example
        .sign_wildcard(std::slice::from_ref(&wildcard_nsec), 1);
    let mut moved = wildcard_nsec;
    moved.owner = www.clone();
    let mut message = query(&www, RecordType::A);
    message.authorities.push(signature);
    message.authorities.push(moved);

    let verdict = zone.validate(&message).await;

    assert_eq!(verdict.0, ValidationVerdict::Bogus);
}

/// The B2 fix keeps RFC 4035 §5.3.2's exception: a record whose owner literally is the
/// wildcard is not an expansion of it.
#[tokio::test]
async fn a_literal_wildcard_nsec_still_proves_nodata_at_the_wildcard() {
    let zone = Signed::new();
    let wildcard = name("*.example.");
    let types = [RecordType::TXT, RecordType::RRSIG, RecordType::NSEC];
    let mut message = query(&wildcard, RecordType::A);
    let wildcard_nsec = nsec(&wildcard, &name("a.example."), &types);
    message.authorities.push(
        zone.example
            .sign_wildcard(std::slice::from_ref(&wildcard_nsec), 1),
    );
    message.authorities.push(wildcard_nsec);

    let verdict = zone.validate(&message).await;

    assert_eq!(
        verdict,
        (
            ValidationVerdict::Secure,
            VerdictReason::ProvenDenialOfExistence
        )
    );
}

/// B3: keep the signed CNAME, strip its target's data, claim NXDOMAIN. Without a denial
/// for the target that is a forged answer, not a Secure one (RFC 6840 §4.3).
#[tokio::test]
async fn a_cname_whose_target_has_no_data_and_no_denial_is_bogus() {
    let zone = Signed::new();
    let www = name("www.example.");
    let mut message = query(&www, RecordType::A);
    signed_answer(
        &mut message,
        &zone.example,
        vec![cname("www.example.", "alias.example.")],
    );
    message.header.rcode = ResponseCode::NXDOMAIN;

    let verdict = zone.validate(&message).await;

    assert_eq!(verdict.0, ValidationVerdict::Bogus);
}

#[tokio::test]
async fn a_cname_whose_target_is_proven_absent_is_secure() {
    let zone = Signed::new();
    let www = name("www.example.");
    let mut message = query(&www, RecordType::A);
    signed_answer(
        &mut message,
        &zone.example,
        vec![cname("www.example.", "alias.example.")],
    );
    message.header.rcode = ResponseCode::NXDOMAIN;
    let apex_types = [RecordType::NS, RecordType::SOA, RecordType::NSEC];
    signed_authority(
        &mut message,
        &zone.example,
        vec![nsec(&name("example."), &name("z.example."), &apex_types)],
    );

    let verdict = zone.validate(&message).await;

    assert_eq!(
        verdict,
        (
            ValidationVerdict::Secure,
            VerdictReason::ProvenDenialOfExistence
        )
    );
}

/// A CNAME into another signed zone: each RRset is checked with its own zone's keys
/// (RFC 4035 §5.3.1), not the question zone's.
#[tokio::test]
async fn a_cname_into_another_signed_zone_is_validated_there() {
    let zone = Signed::new();
    let other = ZoneKey::generate(&name("other."));
    zone.source.insert_cut(other.signed_cut(&zone.root));
    let www = name("www.example.");
    let cdn = name("cdn.other.");
    let mut message = query(&www, RecordType::A);
    signed_answer(
        &mut message,
        &zone.example,
        vec![cname("www.example.", "cdn.other.")],
    );
    signed_answer(&mut message, &other, vec![a_record(&cdn, 9)]);

    let verdict = zone.validate(&message).await;

    assert_eq!(verdict.0, ValidationVerdict::Secure);
}

/// A CNAME from a signed zone into a provably unsigned one: the chain is Insecure, never
/// Bogus.
#[tokio::test]
async fn a_cname_into_an_unsigned_zone_is_insecure() {
    let zone = Signed::new();
    let unsigned = name("unsigned.");
    let ns_only = nsec(&unsigned, &name("v."), &[RecordType::NS]);
    let ds_denial = styx_dnssec::DenialProof::from_records(&[&ns_only]).unwrap();
    zone.source.insert_cut(ZoneCutMaterial::new(
        unsigned.clone(),
        Delegation::Unsigned {
            ds_denial,
            signatures: vec![zone.root.sign(std::slice::from_ref(&ns_only))],
        },
    ));
    let www = name("www.example.");
    let target = name("cdn.unsigned.");
    let mut message = query(&www, RecordType::A);
    signed_answer(
        &mut message,
        &zone.example,
        vec![cname("www.example.", "cdn.unsigned.")],
    );
    message.answers.push(a_record(&target, 9));

    let verdict = zone.validate(&message).await;

    assert_eq!(verdict.0, ValidationVerdict::Insecure);
}

/// B4: DS is parent-side data. A genuine DS answer is signed by the parent and must be
/// checked with the parent's keys (RFC 4035 §2.4, §5.2).
#[tokio::test]
async fn a_ds_answer_is_validated_with_the_parent_zone_keys() {
    let zone = Signed::new();
    let mut message = query(&name("example."), RecordType::DS);
    signed_answer(&mut message, &zone.root, vec![zone.example.ds_record()]);

    let verdict = zone.validate(&message).await;

    assert_eq!(verdict.0, ValidationVerdict::Secure);
}

/// B4: the child's own apex NSEC lists no DS. Replayed against a DS question it must not
/// prove DS absent: only the parent can (RFC 4035 §3.1.4.1).
#[tokio::test]
async fn the_child_apex_nsec_does_not_prove_its_ds_absent() {
    let zone = Signed::new();
    let example = name("example.");
    let mut message = query(&example, RecordType::DS);
    let apex_types = [
        RecordType::NS,
        RecordType::SOA,
        RecordType::DNSKEY,
        RecordType::RRSIG,
        RecordType::NSEC,
    ];
    signed_authority(
        &mut message,
        &zone.example,
        vec![nsec(&example, &name("z.example."), &apex_types)],
    );

    let verdict = zone.validate(&message).await;

    assert_ne!(verdict.0, ValidationVerdict::Secure);
}

/// A chain source that answers a question about one name with material for another.
struct MisdirectedSource {
    inner: InMemoryChainSource,
    asked: Name,
    answered_with: ZoneCutMaterial,
}

impl ChainSource for MisdirectedSource {
    async fn material_for(&self, zone: &Name) -> Result<ZoneCutMaterial, ChainSourceError> {
        if zone == &self.asked {
            return Ok(self.answered_with.clone());
        }
        self.inner.material_for(zone).await
    }
}

/// Material describing another name than the one asked for is never applied to it.
#[tokio::test]
async fn material_for_another_name_is_indeterminate() {
    let zone = Signed::new();
    let decoy = ZoneKey::generate(&name("decoy."));
    let source = MisdirectedSource {
        inner: zone.source,
        asked: name("example."),
        answered_with: decoy.signed_cut(&zone.root),
    };
    let mut message = query(&name("www.example."), RecordType::A);
    signed_answer(
        &mut message,
        &zone.example,
        vec![a_record(&name("www.example."), 7)],
    );

    let verdict = validate(&message, &source, vec![zone.root.anchor()]).await;

    assert_eq!(
        verdict,
        (
            ValidationVerdict::Indeterminate,
            VerdictReason::ChainMaterialUnavailable
        )
    );
}

/// A revoked key, or one without the Zone Key flag, verifies nothing even when a DS or
/// anchor matches it (RFC 4035 §5.3.1, RFC 5011 §2.1).
#[tokio::test]
async fn a_revoked_key_or_a_non_zone_key_verifies_nothing() {
    for flags in [257 | 0x0080, 1] {
        let root = ZoneKey::generate_with_flags(&Name::root(), flags);
        let source = InMemoryChainSource::new();
        source.insert_cut(root.apex_cut());
        let host = name("host.");
        let mut message = query(&host, RecordType::A);
        signed_answer(&mut message, &root, vec![a_record(&host, 1)]);

        let verdict = validate(&message, &source, vec![root.anchor()]).await;

        assert_eq!(verdict.0, ValidationVerdict::Bogus, "flags {flags:#06x}");
    }
}

/// NSEC NODATA at an empty non-terminal: no NSEC owns it, but the covering NSEC's next
/// name lies below it (RFC 4035 §3.1.3.1, RFC 7129 §3.2).
#[tokio::test]
async fn an_nsec_nodata_at_an_empty_non_terminal_is_secure() {
    let zone = Signed::new();
    let ent = name("ent.example.");
    let mut message = query(&ent, RecordType::A);
    let types = [RecordType::A, RecordType::RRSIG, RecordType::NSEC];
    signed_authority(
        &mut message,
        &zone.example,
        vec![nsec(&name("a.example."), &name("x.ent.example."), &types)],
    );

    let verdict = zone.validate(&message).await;

    assert_eq!(verdict.0, ValidationVerdict::Secure);
}

/// NSEC wildcard NODATA: the qname is covered, and the wildcard at its closest encloser
/// exists without the asked type (RFC 4035 §3.1.3.4).
#[tokio::test]
async fn an_nsec_wildcard_nodata_is_secure() {
    let zone = Signed::new();
    let host = name("host.example.");
    let mut message = query(&host, RecordType::TXT);
    let wildcard = name("*.example.");
    let types = [RecordType::A, RecordType::RRSIG, RecordType::NSEC];
    let wildcard_nsec = nsec(&wildcard, &name("z.example."), &types);
    message.authorities.push(
        zone.example
            .sign_wildcard(std::slice::from_ref(&wildcard_nsec), 1),
    );
    message.authorities.push(wildcard_nsec);

    let verdict = zone.validate(&message).await;

    assert_eq!(verdict.0, ValidationVerdict::Secure);
}

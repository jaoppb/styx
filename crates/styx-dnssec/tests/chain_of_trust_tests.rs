//! Chain-of-trust holes found in review: each test feeds the validator material a
//! hostile or broken chain source could supply, and asserts it is not trusted.

mod support;

use styx_dnssec::domain::denial::{DenialProof, NsecProof};
use styx_dnssec::{
    ChainRequest, ChainSource, ChainSourceError, Delegation, MaterialOrigin, PullChainSource,
    SignedRrset, ValidationPolicy, ValidationVerdict, Validator, VerdictReason, ZoneCutMaterial,
};
use styx_proto::domain::rdata::{DsRdata, Nsec3Rdata, NsecRdata, RrsigRdata, TypeBitmap};
use styx_proto::{Message, Name, RData, RecordType, ResourceRecord, ResponseCode};
use support::{
    a_record, clock, name, query, record, StaticAnchorSource, ZoneKey, DIGEST_SHA1, EXPIRATION,
    INCEPTION,
};

const NS_ONLY: [u8; 3] = [0x00, 0x01, 0x20];

struct Chain {
    root: ZoneKey,
    example: ZoneKey,
    source: PullChainSource,
}

impl Chain {
    fn new() -> Self {
        let root = ZoneKey::generate(&Name::root());
        let example = ZoneKey::generate(&name("example."));
        let source = PullChainSource::new();
        source.insert_cut(root.apex_cut());
        Self {
            root,
            example,
            source,
        }
    }

    fn www_answer(&self) -> Message {
        let www = name("www.example.");
        let answer = a_record(&www, 7);
        let mut message = query(&www, RecordType::A);
        message
            .answers
            .push(self.example.sign(std::slice::from_ref(&answer)));
        message.answers.push(answer);
        message
    }

    fn validate<S: ChainSource>(
        &self,
        message: &Message,
        source: &S,
    ) -> (ValidationVerdict, VerdictReason) {
        let anchors = StaticAnchorSource::new(vec![self.root.anchor()]);
        let outcome = Validator::new(clock(), ValidationPolicy::default())
            .validate(message, source, &anchors);
        (outcome.verdict, outcome.reason)
    }
}

fn delegation_cut(zone: &Name, delegation: Delegation) -> ZoneCutMaterial {
    ZoneCutMaterial::new(zone.clone(), delegation, MaterialOrigin::PulledOnDemand)
}

fn ds_absence_proof(zone: &Name) -> (DenialProof, Vec<ResourceRecord>) {
    let nsec = record(
        zone,
        RecordType::NSEC,
        RData::Nsec(NsecRdata::new(
            name("f."),
            TypeBitmap::new(NS_ONLY.to_vec()),
        )),
    );
    (
        DenialProof::Nsec(NsecProof::new(vec![nsec.clone()])),
        vec![nsec],
    )
}

#[test]
fn a_ds_rrset_signed_by_a_key_outside_the_parent_is_bogus() {
    let chain = Chain::new();
    let impostor = ZoneKey::generate(&Name::root());
    chain.source.insert_cut(chain.example.signed_cut(&impostor));

    let verdict = chain.validate(&chain.www_answer(), &chain.source);

    assert_eq!(
        verdict,
        (ValidationVerdict::Bogus, VerdictReason::NoValidRrsig)
    );
}

#[test]
fn an_unsigned_ds_rrset_is_bogus() {
    let chain = Chain::new();
    let zone = name("example.");
    chain.source.insert_cut(delegation_cut(
        &zone,
        Delegation::Signed {
            ds: SignedRrset::new(vec![chain.example.ds_record()], Vec::new()),
            dnskey: chain.example.dnskey_rrset(),
        },
    ));

    let verdict = chain.validate(&chain.www_answer(), &chain.source);

    assert_eq!(
        verdict,
        (ValidationVerdict::Bogus, VerdictReason::NoValidRrsig)
    );
}

#[test]
fn an_unsigned_proof_of_ds_absence_cannot_downgrade_to_insecure() {
    let chain = Chain::new();
    let zone = name("example.");
    let (ds_denial, _) = ds_absence_proof(&zone);
    chain.source.insert_cut(delegation_cut(
        &zone,
        Delegation::Unsigned {
            ds_denial,
            signatures: Vec::new(),
        },
    ));

    let verdict = chain.validate(&chain.www_answer(), &chain.source);

    assert_eq!(
        verdict,
        (ValidationVerdict::Bogus, VerdictReason::NoValidRrsig)
    );
}

#[test]
fn a_parent_signed_proof_of_ds_absence_is_insecure() {
    let chain = Chain::new();
    let zone = name("example.");
    let (ds_denial, records) = ds_absence_proof(&zone);
    chain.source.insert_cut(delegation_cut(
        &zone,
        Delegation::Unsigned {
            ds_denial,
            signatures: vec![chain.root.sign(&records)],
        },
    ));

    let verdict = chain.validate(&chain.www_answer(), &chain.source);

    assert_eq!(
        verdict,
        (
            ValidationVerdict::Insecure,
            VerdictReason::ProvenUnsignedDelegation
        )
    );
}

struct FailingAt {
    inner: PullChainSource,
    zone: Name,
}

impl ChainSource for FailingAt {
    fn material_for(
        &self,
        zone: &Name,
        context: &ChainRequest,
    ) -> Result<ZoneCutMaterial, ChainSourceError> {
        if zone == &self.zone {
            return Err(ChainSourceError::Unavailable(zone.clone()));
        }
        self.inner.material_for(zone, context)
    }
}

#[test]
fn a_failed_fetch_is_indeterminate_rather_than_no_cut() {
    let mut chain = Chain::new();
    chain
        .source
        .insert_cut(chain.example.signed_cut(&chain.root));
    let failing = FailingAt {
        inner: std::mem::take(&mut chain.source),
        zone: name("example."),
    };

    let verdict = chain.validate(&chain.www_answer(), &failing);

    assert_eq!(
        verdict,
        (
            ValidationVerdict::Indeterminate,
            VerdictReason::ChainMaterialUnavailable
        )
    );
}

#[test]
fn a_trust_anchor_below_the_root_starts_the_descent() {
    let chain = Chain::new();
    let source = PullChainSource::new();
    source.insert_cut(chain.example.signed_cut(&chain.root));
    let anchors = StaticAnchorSource::new(vec![chain.example.anchor()]);

    let outcome = Validator::new(clock(), ValidationPolicy::default()).validate(
        &chain.www_answer(),
        &source,
        &anchors,
    );

    assert_eq!(outcome.verdict, ValidationVerdict::Secure);
    assert_eq!(outcome.reason, VerdictReason::AnchorMatched);
}

#[test]
fn unsigned_nsec3_records_beside_a_signed_nsec_proof_are_bogus() {
    let chain = Chain::new();
    let root = Name::root();
    let nsec = record(
        &root,
        RecordType::NSEC,
        RData::Nsec(NsecRdata::new(
            root.clone(),
            TypeBitmap::new(NS_ONLY.to_vec()),
        )),
    );
    let nsec3 = record(
        &name("0p9mhaveqvm6t7vbl5lop2u3t2rp3tom."),
        RecordType::NSEC3,
        RData::Nsec3(Nsec3Rdata::new(
            1,
            0,
            0,
            Vec::new(),
            vec![0; 20],
            TypeBitmap::new(Vec::new()),
        )),
    );
    let mut message = query(&name("missing.example."), RecordType::A);
    message.header.rcode = ResponseCode::NXDOMAIN;
    message
        .authorities
        .push(chain.root.sign(std::slice::from_ref(&nsec)));
    message.authorities.push(nsec);
    message.authorities.push(nsec3);

    let verdict = chain.validate(&message, &chain.source);

    assert_eq!(
        verdict,
        (ValidationVerdict::Bogus, VerdictReason::NoValidRrsig)
    );
}

fn cut_with_ds(chain: &Chain, ds: DsRdata) -> ZoneCutMaterial {
    let zone = name("example.");
    let ds_records = vec![record(&zone, RecordType::DS, RData::Ds(ds))];
    let ds_signatures = vec![chain.root.sign(&ds_records)];
    delegation_cut(
        &zone,
        Delegation::Signed {
            ds: SignedRrset::new(ds_records, ds_signatures),
            dnskey: chain.example.dnskey_rrset(),
        },
    )
}

#[test]
fn a_ds_rrset_using_only_unknown_algorithms_is_insecure() {
    let chain = Chain::new();
    let real = chain.example.ds(support::DIGEST_SHA256);
    let unknown = DsRdata::new(
        real.key_tag(),
        200,
        real.digest_type(),
        real.digest().to_vec(),
    );
    chain.source.insert_cut(cut_with_ds(&chain, unknown));

    let verdict = chain.validate(&chain.www_answer(), &chain.source);

    assert_eq!(
        verdict,
        (
            ValidationVerdict::Insecure,
            VerdictReason::UnsupportedAlgorithm
        )
    );
}

#[test]
fn a_ds_rrset_using_only_the_refused_sha1_digest_is_bogus() {
    let chain = Chain::new();
    chain
        .source
        .insert_cut(cut_with_ds(&chain, chain.example.ds(DIGEST_SHA1)));

    let verdict = chain.validate(&chain.www_answer(), &chain.source);

    assert_eq!(
        verdict,
        (ValidationVerdict::Bogus, VerdictReason::DsDnskeyMismatch)
    );
}

#[test]
fn an_answer_signature_with_an_unknown_algorithm_cannot_downgrade_to_insecure() {
    let chain = Chain::new();
    chain
        .source
        .insert_cut(chain.example.signed_cut(&chain.root));
    let www = name("www.example.");
    let unknown_signature = RrsigRdata::new(
        RecordType::A,
        200,
        2,
        300,
        EXPIRATION,
        INCEPTION,
        chain.example.key_tag(),
        name("example."),
        vec![0; 64],
    );
    let mut message = query(&www, RecordType::A);
    message.answers.push(a_record(&www, 7));
    message.answers.push(record(
        &www,
        RecordType::RRSIG,
        RData::Rrsig(unknown_signature),
    ));

    let verdict = chain.validate(&message, &chain.source);

    assert_eq!(
        verdict,
        (ValidationVerdict::Bogus, VerdictReason::NoValidRrsig)
    );
}

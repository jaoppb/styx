//! Integration tests for DNSKEY rollover and algorithm agility.

mod support;

use styx_dnssec::{
    Delegation, MaterialOrigin, PullChainSource, SignedRrset, ValidationPolicy, ValidationVerdict,
    Validator, VerdictReason, ZoneCutMaterial,
};
use styx_proto::{Name, RecordType};
use support::{a_record, clock, query, StaticAnchorSource, ZoneKey};

#[test]
fn test_multi_key_rollover_validates_with_any_valid_signature() {
    let root = Name::root();
    let active = ZoneKey::generate(&root);
    let incoming = ZoneKey::generate_with_flags(&root, 256);

    let dnskey_set = vec![active.dnskey_record(), incoming.dnskey_record()];
    let dnskey_signatures = vec![active.sign(&dnskey_set)];
    let source = PullChainSource::new();
    source.insert_cut(ZoneCutMaterial::new(
        root.clone(),
        Delegation::Apex {
            dnskey: SignedRrset::new(dnskey_set, dnskey_signatures),
        },
        MaterialOrigin::PulledOnDemand,
    ));

    let answer = a_record(&root, 1);
    let mut message = query(&root, RecordType::A);
    message
        .answers
        .push(active.sign(std::slice::from_ref(&answer)));
    message.answers.push(answer);

    let anchors = StaticAnchorSource::new(vec![active.anchor()]);
    let validator = Validator::new(clock(), ValidationPolicy::default());
    let outcome = validator.validate(&message, &source, &anchors);

    assert_eq!(outcome.verdict, ValidationVerdict::Secure);
    assert_eq!(outcome.reason, VerdictReason::AnchorMatched);
}

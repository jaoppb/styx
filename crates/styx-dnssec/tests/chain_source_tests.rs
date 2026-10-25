//! Integration tests for ChainSource strategies and wire response outcome application (Sub-phase 6d).

use styx_dnssec::{
    ChainRequest, ChainSource, Delegation, FailureMode, MaterialOrigin, PullChainSource,
    PushedChainSource, ValidationOutcome, ValidationVerdict, VerdictReason, ZoneCutMaterial,
};
use styx_proto::{
    Header, Message, Name, Opcode, RData, RecordClass, RecordType, ResourceRecord, ResponseCode,
    Ttl,
};

#[test]
fn test_pushed_chain_source_accumulation() {
    let source = PushedChainSource::new();
    let zone = Name::from_ascii("example.com.").unwrap();
    let request = ChainRequest::new(zone.clone());

    source.record_referral(zone.clone(), Delegation::NotACut);

    let cut = source.material_for(&zone, &request).unwrap();
    assert_eq!(cut.zone, zone);
    assert_eq!(cut.origin, MaterialOrigin::PushedFromDescent);
}

#[test]
fn test_pull_chain_source_on_demand() {
    let source = PullChainSource::new();
    let zone = Name::from_ascii("example.com.").unwrap();
    let other_zone = Name::from_ascii("other.com.").unwrap();
    let request = ChainRequest::new(zone.clone());

    source.insert_cut(ZoneCutMaterial::new(
        zone.clone(),
        Delegation::NotACut,
        MaterialOrigin::PulledOnDemand,
    ));

    let retrieved_cut = source.material_for(&zone, &request).unwrap();
    assert_eq!(retrieved_cut.origin, MaterialOrigin::PulledOnDemand);

    let unknown = source.material_for(&other_zone, &request).unwrap();
    assert_eq!(unknown.zone, other_zone);
    assert_eq!(unknown.delegation, Delegation::NotACut);
}

#[test]
fn test_wire_mapping_secure_sets_ad_bit() {
    let mut msg = Message::new(Header::new_query(1, Opcode::Query, false));
    let outcome = ValidationOutcome::new(ValidationVerdict::Secure, VerdictReason::AnchorMatched);

    outcome.apply_to_message(&mut msg, FailureMode::HardFail);

    assert!(msg.header.authentic_data);
    assert_eq!(msg.header.rcode, ResponseCode::NOERROR);
}

#[test]
fn test_wire_mapping_insecure_clears_ad_bit() {
    let mut msg = Message::new(Header::new_query(1, Opcode::Query, false));
    msg.header.authentic_data = true; // start with true to test clearing

    let outcome = ValidationOutcome::new(
        ValidationVerdict::Insecure,
        VerdictReason::ProvenUnsignedDelegation,
    );

    outcome.apply_to_message(&mut msg, FailureMode::HardFail);

    assert!(!msg.header.authentic_data);
    assert_eq!(msg.header.rcode, ResponseCode::NOERROR);
}

#[test]
fn test_wire_mapping_bogus_warn_only_preserves_response() {
    let mut msg = Message::new(Header::new_query(1, Opcode::Query, false));
    msg.header.authentic_data = true;
    let answer = ResourceRecord::new(
        Name::root(),
        RecordType::A,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::A(std::net::Ipv4Addr::new(1, 1, 1, 1)),
    );
    msg.answers.push(answer);

    let outcome = ValidationOutcome::new(ValidationVerdict::Bogus, VerdictReason::NoValidRrsig);

    outcome.apply_to_message(&mut msg, FailureMode::WarnOnly);

    assert!(!msg.header.authentic_data);
    assert_eq!(msg.header.rcode, ResponseCode::NOERROR);
    assert_eq!(msg.answers.len(), 1); // answers preserved
}

#[test]
fn test_wire_mapping_bogus_hard_fail_returns_servfail() {
    let mut msg = Message::new(Header::new_query(1, Opcode::Query, false));
    msg.header.authentic_data = true;
    let answer = ResourceRecord::new(
        Name::root(),
        RecordType::A,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::A(std::net::Ipv4Addr::new(1, 1, 1, 1)),
    );
    msg.answers.push(answer);

    let outcome = ValidationOutcome::new(ValidationVerdict::Bogus, VerdictReason::NoValidRrsig);

    outcome.apply_to_message(&mut msg, FailureMode::HardFail);

    assert!(!msg.header.authentic_data);
    assert_eq!(msg.header.rcode, ResponseCode::SERVFAIL);
    assert!(msg.answers.is_empty()); // answers cleared
}

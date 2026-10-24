//! Integration tests for ChainSource strategies and wire response outcome application (Sub-phase 6d).

use styx_dnssec::{
    ChainRequest, ChainSource, ChainSourceError, MaterialOrigin, PullChainSource,
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

    let request = ChainRequest::new(Some(zone.clone()));

    // Record a referral observed during descent
    source.record_referral(zone.clone(), None, None, None, Vec::new());

    let material = source.material_for(&zone, &request).unwrap();
    let cut = material.cut_for(&zone).unwrap();

    assert_eq!(cut.zone, zone);
    assert_eq!(cut.origin, MaterialOrigin::PushedFromDescent);
}

#[test]
fn test_pull_chain_source_on_demand() {
    let source = PullChainSource::new();
    let zone = Name::from_ascii("example.com.").unwrap();
    let other_zone = Name::from_ascii("other.com.").unwrap();

    let cut = ZoneCutMaterial::new(
        zone.clone(),
        None,
        None,
        None,
        Vec::new(),
        MaterialOrigin::PulledOnDemand,
    );
    source.insert_cut(cut);

    let request = ChainRequest::new(Some(zone.clone()));

    // Existing zone succeeds
    let material = source.material_for(&zone, &request).unwrap();
    let retrieved_cut = material.cut_for(&zone).unwrap();
    assert_eq!(retrieved_cut.origin, MaterialOrigin::PulledOnDemand);

    // Unregistered zone returns ChainSourceError::Unavailable
    let err = source.material_for(&other_zone, &request).unwrap_err();
    match err {
        ChainSourceError::Unavailable(z) => assert_eq!(z, other_zone),
        _ => panic!("expected Unavailable error"),
    }
}

#[test]
fn test_wire_mapping_secure_sets_ad_bit() {
    let mut msg = Message::new(Header::new_query(1, Opcode::Query, false));
    let outcome = ValidationOutcome::new(
        ValidationVerdict::Secure,
        VerdictReason::AnchorMatched,
        true,
    );

    outcome.apply_to_message(&mut msg);

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
        true,
    );

    outcome.apply_to_message(&mut msg);

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

    // Warn-only (enforced: false)
    let outcome =
        ValidationOutcome::new(ValidationVerdict::Bogus, VerdictReason::NoValidRrsig, false);

    outcome.apply_to_message(&mut msg);

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

    // Hard-fail (enforced: true)
    let outcome =
        ValidationOutcome::new(ValidationVerdict::Bogus, VerdictReason::NoValidRrsig, true);

    outcome.apply_to_message(&mut msg);

    assert!(!msg.header.authentic_data);
    assert_eq!(msg.header.rcode, ResponseCode::SERVFAIL);
    assert!(msg.answers.is_empty()); // answers cleared
}

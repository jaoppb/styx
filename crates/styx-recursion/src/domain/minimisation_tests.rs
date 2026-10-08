use std::time::{Duration, Instant};

use super::*;

fn name(text: &str) -> Name {
    Name::from_ascii(text).unwrap()
}

fn state(target: &str, qtype: RecordType) -> MinimisationState {
    MinimisationState::new(name(target), qtype, &Name::root())
}

fn ask(state: &mut MinimisationState, cut: &str) -> (String, RecordType) {
    let question = state.next_question(&name(cut), MinimisationVerdict::Unknown);
    (question.qname.to_string(), question.qtype)
}

#[test]
fn each_cut_is_asked_one_more_label_as_ns_and_only_the_last_gets_the_qtype() {
    let mut minimisation = state("secret.internal.example.com.", RecordType::A);
    assert_eq!(ask(&mut minimisation, "."), ("com.".into(), RecordType::NS));
    minimisation.enter_cut(&name("com."));
    assert_eq!(
        ask(&mut minimisation, "com."),
        ("example.com.".into(), RecordType::NS)
    );
    minimisation.enter_cut(&name("example.com."));
    assert_eq!(
        ask(&mut minimisation, "example.com."),
        ("internal.example.com.".into(), RecordType::NS)
    );
    minimisation.advance_past_empty_non_terminal();
    assert_eq!(
        ask(&mut minimisation, "example.com."),
        ("secret.internal.example.com.".into(), RecordType::A)
    );
    assert_eq!(minimisation.minimised_steps(), 3);
}

#[test]
fn a_server_proven_to_mishandle_minimisation_gets_the_full_qname() {
    let mut minimisation = state("www.example.com.", RecordType::AAAA);
    let verdict =
        MinimisationVerdict::MishandlesMinimised(Instant::now() + Duration::from_secs(60));
    let question = minimisation.next_question(&Name::root(), verdict);
    assert_eq!(question.qname, name("www.example.com."));
    assert_eq!(question.qtype, RecordType::AAAA);
}

#[test]
fn a_refused_minimised_query_retries_in_full_and_success_proves_mishandling() {
    let mut minimisation = state("www.example.com.", RecordType::A);
    let sent = minimisation.next_question(&Name::root(), MinimisationVerdict::Unknown);
    assert_eq!(
        minimisation.on_bad_response(BadResponse::Refused, &sent),
        FallbackDecision::RetryFullQnameSameServer
    );
    assert_eq!(minimisation.mode(), MinimisationMode::FellBackFullQname);
    let (qname, qtype) = ask(&mut minimisation, ".");
    assert_eq!((qname.as_str(), qtype), ("www.example.com.", RecordType::A));
    assert!(minimisation.fallback_proved_mishandling(true));
    assert!(
        !minimisation.fallback_proved_mishandling(true),
        "proof is one-shot"
    );
}

#[test]
fn a_refused_retry_that_also_fails_proves_nothing() {
    let mut minimisation = state("www.example.com.", RecordType::A);
    let sent = minimisation.next_question(&Name::root(), MinimisationVerdict::Unknown);
    minimisation.on_bad_response(BadResponse::Refused, &sent);
    let full = minimisation.next_question(&Name::root(), MinimisationVerdict::Unknown);
    assert_eq!(
        minimisation.on_bad_response(BadResponse::Refused, &full),
        FallbackDecision::TryNextServer
    );
    assert!(!minimisation.fallback_proved_mishandling(true));
}

#[test]
fn servfail_is_health_never_a_fallback() {
    let mut minimisation = state("www.example.com.", RecordType::A);
    let sent = minimisation.next_question(&Name::root(), MinimisationVerdict::Unknown);
    assert_eq!(
        minimisation.on_bad_response(BadResponse::ServerFailure, &sent),
        FallbackDecision::TryNextServer
    );
    assert_eq!(minimisation.mode(), MinimisationMode::Relaxed);
    assert!(!minimisation.fallback_proved_mishandling(true));
}

#[test]
fn an_intermediate_nxdomain_is_trusted() {
    let mut minimisation = state("a.b.nonexistent.com.", RecordType::A);
    minimisation.enter_cut(&name("com."));
    let sent = minimisation.next_question(&name("com."), MinimisationVerdict::Unknown);
    assert!(minimisation.is_intermediate(&sent));
    assert_eq!(
        minimisation.on_bad_response(BadResponse::NameError, &sent),
        FallbackDecision::AcceptAsGenuine
    );
    assert_eq!(minimisation.mode(), MinimisationMode::Relaxed);
}

#[test]
fn a_one_label_target_is_asked_in_full_from_the_root() {
    let mut minimisation = state("com.", RecordType::SOA);
    assert_eq!(
        ask(&mut minimisation, "."),
        ("com.".into(), RecordType::SOA)
    );
}

#[test]
fn a_ds_question_reaches_the_parent_zone_and_is_asked_there_in_full() {
    let mut minimisation = state("example.com.", RecordType::DS);
    assert_eq!(ask(&mut minimisation, "."), ("com.".into(), RecordType::NS));
    minimisation.enter_cut(&name("com."));
    assert_eq!(
        ask(&mut minimisation, "com."),
        ("example.com.".into(), RecordType::DS)
    );
}

#[test]
fn a_fallback_lasts_for_one_zone_cut_and_an_alias_minimises_again() {
    let mut minimisation = state("www.example.com.", RecordType::A);
    let sent = minimisation.next_question(&Name::root(), MinimisationVerdict::Unknown);
    minimisation.on_bad_response(BadResponse::Refused, &sent);
    assert_eq!(minimisation.mode(), MinimisationMode::FellBackFullQname);

    minimisation.retarget(name("secret.tracker.net."), &Name::root());

    assert_eq!(minimisation.mode(), MinimisationMode::Relaxed);
    let (qname, qtype) = ask(&mut minimisation, ".");
    assert_eq!((qname.as_str(), qtype), ("net.", RecordType::NS));
}

#[test]
fn entering_a_new_cut_ends_a_fallback() {
    let mut minimisation = state("www.example.com.", RecordType::A);
    let sent = minimisation.next_question(&Name::root(), MinimisationVerdict::Unknown);
    minimisation.on_bad_response(BadResponse::Refused, &sent);

    minimisation.enter_cut(&name("com."));

    assert_eq!(minimisation.mode(), MinimisationMode::Relaxed);
}

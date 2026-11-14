//! Admission refuses a response that does not echo the client's question (issue #116).

mod harness;

use std::net::Ipv4Addr;
use std::sync::Arc;

use harness::TestClock;
use styx_core::Clock;
use styx_proto::{
    Message, Name, Question, RData, RecordClass, RecordType, ResourceRecord, ResponseCode,
    SoaRdata, Ttl,
};
use styx_resolution::{
    Admission, AdmissionOutcome, AdmissionRequest, AnswerCache, AnswerSource, CacheCapacity,
    CacheError, CacheKey, Lookup, RejectReason, ShardedAnswerCache, TtlPolicy,
};

fn name(text: &str) -> Name {
    Name::from_ascii(text).unwrap_or_else(|_| Name::root())
}

fn ask(text: &str, qtype: RecordType) -> Question {
    Question::new(name(text), qtype, RecordClass::In)
}

fn record(owner: &str, rdata: RData) -> ResourceRecord {
    ResourceRecord::new(
        name(owner),
        rdata.rtype(),
        RecordClass::In,
        Ttl::from_secs(300),
        rdata,
    )
}

fn soa() -> RData {
    RData::Soa(SoaRdata::new(
        name("ns.example.com."),
        name("hostmaster.example.com."),
        1,
        2,
        3,
        4,
        60,
    ))
}

/// An address answer for `answered`, echoing `echoed` as its question section.
fn address_answer(answered: &Question, echoed: Vec<Question>) -> Message {
    let mut message = Message::response_to(0x1000, answered.clone());
    message.questions = echoed;
    message.answers.push(record(
        "www.example.com.",
        RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    ));
    message
}

fn denial(rcode: ResponseCode, echoed: Vec<Question>) -> Message {
    let mut message = Message::response_to(0x1000, ask("www.example.com.", RecordType::A));
    message.header.rcode = rcode;
    message.questions = echoed;
    message.authorities.push(record("example.com.", soa()));
    message
}

fn evaluate(client: &Question, message: &Message) -> Result<AdmissionOutcome, CacheError> {
    let clock = TestClock::new();
    let request = AdmissionRequest::new(
        client,
        message,
        AnswerSource::Upstream,
        clock.now_monotonic(),
    )?;
    Ok(Admission::new(TtlPolicy::default()).evaluate(request))
}

fn assert_refused_whole(outcome: &AdmissionOutcome, reason: RejectReason) {
    assert!(outcome.admitted().is_empty(), "{:?}", outcome.admitted());
    assert_eq!(outcome.refusal_reason(), Some(reason));
    assert!(!outcome.rejected().is_empty());
    assert!(outcome.rejected().iter().all(|r| r.reason == reason));
}

#[test]
fn test_an_echoed_other_name_is_refused_whole() {
    let client = ask("www.example.com.", RecordType::A);
    let message = address_answer(&client, vec![ask("evil.example.net.", RecordType::A)]);
    assert_refused_whole(
        &evaluate(&client, &message).expect("request"),
        RejectReason::QuestionMismatch,
    );
}

#[test]
fn test_an_echoed_other_type_is_refused_whole() {
    let client = ask("www.example.com.", RecordType::A);
    let message = address_answer(&client, vec![ask("www.example.com.", RecordType::AAAA)]);
    assert_refused_whole(
        &evaluate(&client, &message).expect("request"),
        RejectReason::QuestionMismatch,
    );
}

#[test]
fn test_an_echoed_other_class_is_refused_whole() {
    let client = ask("www.example.com.", RecordType::A);
    let other_class = Question::new(name("www.example.com."), RecordType::A, RecordClass::Ch);
    let message = address_answer(&client, vec![other_class]);
    assert_refused_whole(
        &evaluate(&client, &message).expect("request"),
        RejectReason::QuestionMismatch,
    );
}

#[test]
fn test_an_echoed_name_differing_only_in_case_is_admitted() {
    let client = ask("www.example.com.", RecordType::A);
    let message = address_answer(&client, vec![ask("WwW.ExAmPlE.CoM.", RecordType::A)]);
    let outcome = evaluate(&client, &message).expect("request");
    assert_eq!(outcome.refusal_reason(), None);
    assert_eq!(outcome.admitted().len(), 1);
}

#[test]
fn test_a_judged_response_echoing_no_question_is_refused() {
    let client = ask("www.example.com.", RecordType::A);
    let messages = [
        address_answer(&client, Vec::new()),
        denial(ResponseCode::NOERROR, Vec::new()),
        denial(ResponseCode::NXDOMAIN, Vec::new()),
    ];
    for message in &messages {
        let outcome = evaluate(&client, message).expect("request");
        assert_eq!(
            outcome.refusal_reason(),
            Some(RejectReason::QuestionMismatch),
            "{:?}",
            message.header.rcode
        );
        assert!(outcome.admitted().is_empty());
    }
}

#[test]
fn test_an_error_response_admits_nothing_and_is_recorded_as_one() {
    let client = ask("www.example.com.", RecordType::A);
    let echoes = [Vec::new(), vec![ask("evil.example.net.", RecordType::A)]];
    for rcode in [
        ResponseCode::SERVFAIL,
        ResponseCode::REFUSED,
        ResponseCode::FORMERR,
    ] {
        for echoed in &echoes {
            let mut message = address_answer(&client, echoed.clone());
            message.header.rcode = rcode;
            let outcome = evaluate(&client, &message).expect("request");
            assert!(
                outcome.admitted().is_empty(),
                "{rcode:?}: {:?}",
                outcome.admitted()
            );
            assert_eq!(outcome.refusal(), None, "{rcode:?}");
            assert_eq!(outcome.rejected().len(), 1, "{rcode:?}");
            assert!(
                outcome
                    .rejected()
                    .iter()
                    .all(|r| r.reason == RejectReason::ErrorResponse),
                "{rcode:?}: {:?}",
                outcome.rejected()
            );
        }
    }
}

#[test]
fn test_a_response_echoing_two_questions_is_refused_even_if_the_first_matches() {
    let client = ask("www.example.com.", RecordType::A);
    let message = address_answer(
        &client,
        vec![client.clone(), ask("evil.example.net.", RecordType::A)],
    );
    assert_refused_whole(
        &evaluate(&client, &message).expect("request"),
        RejectReason::MultipleQuestions,
    );
}

#[test]
fn test_a_denial_echoing_another_question_is_not_stored_under_the_clients_key() {
    let client = ask("www.example.com.", RecordType::A);
    let message = denial(
        ResponseCode::NXDOMAIN,
        vec![ask("other.example.com.", RecordType::A)],
    );
    assert_refused_whole(
        &evaluate(&client, &message).expect("request"),
        RejectReason::QuestionMismatch,
    );
}

#[test]
fn test_a_meta_type_question_cannot_become_a_key_or_a_request() {
    let clock = TestClock::new();
    for qtype in [
        RecordType::ANY,
        RecordType::AXFR,
        RecordType::IXFR,
        RecordType::OPT,
    ] {
        let client = ask("www.example.com.", qtype);
        let message = address_answer(&client, vec![client.clone()]);
        assert!(matches!(
            CacheKey::from_question(&client),
            Err(CacheError::UncacheableQuestion(_))
        ));
        let built = AdmissionRequest::new(
            &client,
            &message,
            AnswerSource::Upstream,
            clock.now_monotonic(),
        );
        assert!(matches!(built, Err(CacheError::UncacheableQuestion(_))));
    }
}

#[test]
fn test_a_mismatch_is_counted_once_per_answer_and_stores_nothing() {
    let clock = Arc::new(TestClock::new());
    let cache = ShardedAnswerCache::new(
        Arc::clone(&clock),
        CacheCapacity::default(),
        TtlPolicy::default(),
        1,
    )
    .expect("cache");
    let client = ask("www.example.com.", RecordType::A);
    let mut message = address_answer(&client, vec![ask("evil.example.net.", RecordType::A)]);
    message.answers.push(record(
        "www.example.com.",
        RData::A(Ipv4Addr::new(192, 0, 2, 2)),
    ));
    let request = AdmissionRequest::new(
        &client,
        &message,
        AnswerSource::Upstream,
        clock.now_monotonic(),
    )
    .expect("request");

    let admitted = cache
        .admit(Admission::new(TtlPolicy::default()).evaluate(request))
        .expect("admit");

    assert_eq!(admitted.count(), 0);
    assert_eq!(cache.stats().rejected_question_mismatch, 1);
    assert_eq!(cache.stats().rejected_incomplete_chain, 0);
    let key = CacheKey::from_question(&client).expect("key");
    assert_eq!(cache.lookup(&key), Lookup::Miss);
}

#[test]
fn test_an_outcome_carries_the_key_it_was_judged_for() {
    let client = ask("www.example.com.", RecordType::A);
    let message = address_answer(&client, vec![client.clone()]);
    let outcome = evaluate(&client, &message).expect("request");
    assert_eq!(Ok(outcome.key().clone()), CacheKey::from_question(&client));
}

#[test]
fn test_an_ineligible_source_is_refused_whole_and_not_as_a_mismatch() {
    let client = ask("www.example.com.", RecordType::A);
    let message = address_answer(&client, vec![client.clone()]);
    let clock = TestClock::new();
    let expected = [
        (AnswerSource::LocalRecord, RejectReason::ForgedAnswer),
        (AnswerSource::Blocked, RejectReason::ForgedAnswer),
        (AnswerSource::AaaaFiltered, RejectReason::ForgedAnswer),
        (AnswerSource::CacheHit, RejectReason::InadmissibleSource),
        (AnswerSource::Error, RejectReason::InadmissibleSource),
    ];
    for (source, reason) in expected {
        let request = AdmissionRequest::new(&client, &message, source, clock.now_monotonic())
            .expect("request");
        let outcome = Admission::new(TtlPolicy::default()).evaluate(request);
        assert_refused_whole(&outcome, reason);
    }
}

#[test]
fn test_an_answer_echoing_two_questions_is_counted_once_and_stores_nothing() {
    let clock = Arc::new(TestClock::new());
    let cache = ShardedAnswerCache::new(
        Arc::clone(&clock),
        CacheCapacity::default(),
        TtlPolicy::default(),
        1,
    )
    .expect("cache");
    let client = ask("www.example.com.", RecordType::A);
    let message = address_answer(
        &client,
        vec![client.clone(), ask("evil.example.net.", RecordType::A)],
    );
    let request = AdmissionRequest::new(
        &client,
        &message,
        AnswerSource::Upstream,
        clock.now_monotonic(),
    )
    .expect("request");

    let admitted = cache
        .admit(Admission::new(TtlPolicy::default()).evaluate(request))
        .expect("admit");

    assert_eq!(admitted.count(), 0);
    assert_eq!(cache.stats().rejected_multiple_questions, 1);
    assert_eq!(cache.stats().rejected_question_mismatch, 0);
}

#[test]
fn test_a_refusal_names_the_questions_the_response_echoed() {
    let client = ask("www.example.com.", RecordType::A);
    let echoed = vec![ask("evil.example.net.", RecordType::A)];
    let message = address_answer(&client, echoed.clone());
    let outcome = evaluate(&client, &message).expect("request");
    let refusal = outcome.refusal().expect("refused");
    assert_eq!(refusal.reason(), RejectReason::QuestionMismatch);
    assert_eq!(refusal.echoed(), echoed.as_slice());

    let matching = address_answer(&client, vec![client.clone()]);
    let admitted = evaluate(&client, &matching).expect("request");
    assert_eq!(admitted.refusal(), None);
}

/// Issue #116: a NODATA with an SOA and an empty question section was admitted under the
/// client's key, because the denial path never looked at the echoed question.
#[test]
fn test_a_nodata_with_an_soa_and_no_question_is_not_admitted_under_the_clients_key() {
    let client = ask("www.example.com.", RecordType::A);
    let message = denial(ResponseCode::NOERROR, Vec::new());
    let outcome = evaluate(&client, &message).expect("request");

    assert_refused_whole(&outcome, RejectReason::QuestionMismatch);

    let clock = Arc::new(TestClock::new());
    let cache = ShardedAnswerCache::with_defaults(clock);
    let stored = cache.admit(outcome).expect("admit");
    assert_eq!(stored.count(), 0);
    let key = CacheKey::from_question(&client).expect("key");
    assert_eq!(cache.lookup(&key), Lookup::Miss);
}

//! Socket-level contract tests for Do53 forwarder validation and anti-spoofing.

mod harness;

use std::sync::Arc;
use std::time::Duration;

use harness::{CommandableUpstream, TestClock, UpstreamBehavior};
use styx_core::{Clock, Upstream, UpstreamError, UpstreamId};
use styx_proto::{Name, Question, RecordClass, RecordType};
use styx_resolution::{Do53Forwarder, EdnsBufferSize};

fn make_test_question(qname: &str) -> Question {
    let name = match Name::from_ascii(qname) {
        Ok(n) => n,
        Err(_) => Name::root(),
    };
    Question::new(name, RecordType::A, RecordClass::In)
}

fn create_forwarder(
    id_str: &str,
    upstream: &CommandableUpstream,
    clock: Arc<TestClock>,
    timeout: Duration,
) -> Do53Forwarder<TestClock> {
    Do53Forwarder::new(
        UpstreamId::new(id_str),
        upstream.udp_addr(),
        EdnsBufferSize::default(),
        timeout,
        timeout,
        clock,
    )
}

#[tokio::test]
async fn test_forwarder_discards_mismatched_id_and_accepts_valid() {
    let clock = Arc::new(TestClock::new());
    let upstream = CommandableUpstream::start()
        .await
        .expect("start commandable upstream");
    upstream.set_behavior(UpstreamBehavior::MismatchedIdThenNormal);

    let forwarder = create_forwarder("fwd", &upstream, clock.clone(), Duration::from_millis(500));
    let query = make_test_question("id.discard.test.");
    let deadline = clock.now_monotonic() + Duration::from_secs(1);

    let resp = forwarder
        .resolve(&query, deadline)
        .await
        .expect("valid answer accepted");
    let first_q = resp.message.questions.first().expect("first question");
    assert_eq!(first_q.qname, query.qname);
}

#[tokio::test]
async fn test_forwarder_discards_mismatched_question_and_accepts_valid() {
    let clock = Arc::new(TestClock::new());
    let upstream = CommandableUpstream::start()
        .await
        .expect("start commandable upstream");
    upstream.set_behavior(UpstreamBehavior::MismatchedQuestionThenNormal);

    let forwarder = create_forwarder("fwd", &upstream, clock.clone(), Duration::from_millis(500));
    let query = make_test_question("question.discard.test.");
    let deadline = clock.now_monotonic() + Duration::from_secs(1);

    let resp = forwarder
        .resolve(&query, deadline)
        .await
        .expect("valid answer accepted");
    let first_q = resp.message.questions.first().expect("first question");
    assert_eq!(first_q.qname, query.qname);
}

#[tokio::test]
async fn test_forwarder_times_out_on_exclusive_mismatched_id() {
    let clock = Arc::new(TestClock::new());
    let upstream = CommandableUpstream::start()
        .await
        .expect("start commandable upstream");
    upstream.set_behavior(UpstreamBehavior::MismatchedId);

    let forwarder = create_forwarder("fwd", &upstream, clock.clone(), Duration::from_millis(100));
    let query = make_test_question("timeout.id.test.");
    let deadline = clock.now_monotonic() + Duration::from_millis(100);

    let err = forwarder
        .resolve(&query, deadline)
        .await
        .expect_err("should time out on mismatched id");
    assert!(matches!(err, UpstreamError::Timeout));
}

#[tokio::test]
async fn test_forwarder_times_out_on_exclusive_mismatched_question() {
    let clock = Arc::new(TestClock::new());
    let upstream = CommandableUpstream::start()
        .await
        .expect("start commandable upstream");
    upstream.set_behavior(UpstreamBehavior::MismatchedQuestion);

    let forwarder = create_forwarder("fwd", &upstream, clock.clone(), Duration::from_millis(100));
    let query = make_test_question("timeout.question.test.");
    let deadline = clock.now_monotonic() + Duration::from_millis(100);

    let err = forwarder
        .resolve(&query, deadline)
        .await
        .expect_err("should time out on mismatched question");
    assert!(matches!(err, UpstreamError::Timeout));
}

#[tokio::test]
async fn test_txid_is_randomized_across_queries() {
    let clock = Arc::new(TestClock::new());
    let upstream = CommandableUpstream::start()
        .await
        .expect("start commandable upstream");
    let forwarder = create_forwarder("fwd", &upstream, clock.clone(), Duration::from_millis(300));
    let query = make_test_question("random.txid.test.");

    let mut txids = Vec::with_capacity(100);
    for _ in 0..100 {
        let deadline = clock.now_monotonic() + Duration::from_millis(300);
        let resp = forwarder
            .resolve(&query, deadline)
            .await
            .expect("query response");
        txids.push(resp.message.header.id);
    }

    let sequential_pairs = txids
        .windows(2)
        .filter(|pair| match pair {
            [a, b] => b.wrapping_sub(*a) == 1,
            _ => false,
        })
        .count();

    // In a random uniform 16-bit draw, sequential pairs have probability ~1/65536.
    // 100 sequential queries in AtomicU16 would yield 99 sequential pairs.
    assert!(sequential_pairs < 2, "TXIDs appeared sequential: {txids:?}");
}

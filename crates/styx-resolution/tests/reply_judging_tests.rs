//! The pool judges every reply against the question asked, so a member whose reply does not
//! answer it fails over, counts against its health and cannot be reinstated by a probe
//! (issue #118).

mod harness;

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use harness::TestClock;
use styx_core::{
    Clock, ReplyFault, Upstream, UpstreamError, UpstreamId, UpstreamKind, UpstreamResponse,
};
use styx_proto::{Message, Name, Question, RData, RecordClass, RecordType, ResourceRecord, Ttl};
use styx_resolution::{
    CanaryConfig, CircuitConfig, CircuitState, OrderedFailover, PoolError, PoolMember, ProbeConfig,
    ProbePolicy, ProbeScheduler, RaceAll, SelectionStrategy, UpstreamPool, Weight,
};

fn name(text: &str) -> Name {
    Name::from_ascii(text).unwrap_or_else(|_| Name::root())
}

fn ask(text: &str, qtype: RecordType) -> Question {
    Question::new(name(text), qtype, RecordClass::In)
}

/// An address answer for `answered`, echoing `echoed` as its question section.
fn address_reply(answered: &Question, echoed: Vec<Question>) -> Message {
    let mut message = Message::response_to(0x1000, answered.clone());
    message.questions = echoed;
    message.answers.push(ResourceRecord::new(
        name("www.example.com."),
        RecordType::A,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::A(Ipv4Addr::new(192, 0, 2, 1)),
    ));
    message
}

/// A reply that echoes another question.
fn rewritten(answered: &Question) -> Message {
    address_reply(answered, vec![ask("evil.example.net.", RecordType::A)])
}

/// A reply that echoes the question it was asked.
fn faithful(answered: &Question) -> Message {
    address_reply(answered, vec![answered.clone()])
}

/// An upstream that answers every query with one canned message, after an optional delay.
#[derive(Clone)]
struct ScriptedUpstream {
    id: UpstreamId,
    reply: Message,
    delay: Duration,
}

impl ScriptedUpstream {
    fn new(id: &str, reply: Message) -> Self {
        Self {
            id: UpstreamId::new(id),
            reply,
            delay: Duration::ZERO,
        }
    }

    fn after(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }
}

impl Upstream for ScriptedUpstream {
    fn id(&self) -> UpstreamId {
        self.id.clone()
    }

    fn kind(&self) -> UpstreamKind {
        UpstreamKind::Forwarder
    }

    fn resolve(
        &self,
        _query: &Question,
        _deadline: Instant,
    ) -> impl std::future::Future<Output = Result<UpstreamResponse, UpstreamError>> + Send {
        let message = self.reply.clone();
        let answered_by = self.id.clone();
        let delay = self.delay;
        async move {
            tokio::time::sleep(delay).await;
            Ok(UpstreamResponse {
                message,
                answered_by,
                kind: UpstreamKind::Forwarder,
                elapsed: Duration::ZERO,
                via_tcp: false,
                raced_count: 1,
            })
        }
    }
}

fn member(upstream: ScriptedUpstream) -> PoolMember<ScriptedUpstream> {
    PoolMember::new(
        upstream.id(),
        upstream,
        Weight::new(1),
        CanaryConfig {
            qname: name("canary.check."),
            qtype: RecordType::A,
            timeout: Duration::from_millis(500),
        },
    )
}

fn pool<S: SelectionStrategy>(
    strategy: S,
    clock: &Arc<TestClock>,
    members: Vec<ScriptedUpstream>,
) -> UpstreamPool<S, ScriptedUpstream, TestClock> {
    UpstreamPool::new(
        members.into_iter().map(member).collect(),
        strategy,
        Arc::clone(clock),
        CircuitConfig {
            failure_threshold: 3,
            open_cooldown: Duration::from_secs(30),
            half_open_successes: 1,
        },
        ProbePolicy::new(ProbeConfig::default()),
    )
}

fn deadline(clock: &TestClock) -> Instant {
    let now = clock.now_monotonic();
    now.checked_add(Duration::from_secs(5)).unwrap_or(now)
}

#[tokio::test]
async fn test_a_rewriting_member_fails_over_to_the_next_one() {
    let clock = Arc::new(TestClock::new());
    let asked = ask("www.example.com.", RecordType::A);
    let pool = pool(
        OrderedFailover::new(),
        &clock,
        vec![
            ScriptedUpstream::new("rewriter", rewritten(&asked)),
            ScriptedUpstream::new("honest", faithful(&asked)),
        ],
    );

    let reply = pool
        .resolve(&asked, deadline(&clock))
        .await
        .expect("failover");

    assert_eq!(reply.answered_by, UpstreamId::new("honest"));
    let views = pool.snapshot();
    let rewriter = views.first().expect("rewriter view");
    assert_eq!(
        rewriter.refused_replies.count(ReplyFault::QuestionMismatch),
        1
    );
    assert_eq!(
        rewriter.srtt, None,
        "a refused reply is not a latency sample"
    );
}

#[tokio::test]
async fn test_repeated_bad_replies_open_the_circuit_instead_of_alternating_with_successes() {
    let clock = Arc::new(TestClock::new());
    let asked = ask("www.example.com.", RecordType::A);
    let pool = pool(
        OrderedFailover::new(),
        &clock,
        vec![
            ScriptedUpstream::new("rewriter", rewritten(&asked)),
            ScriptedUpstream::new("honest", faithful(&asked)),
        ],
    );

    for _ in 0..3 {
        pool.resolve(&asked, deadline(&clock))
            .await
            .expect("served");
    }

    let views = pool.snapshot();
    let rewriter = views.first().expect("rewriter view");
    assert!(matches!(rewriter.circuit, CircuitState::Open { .. }));
    assert!(!rewriter.available);
}

#[tokio::test]
async fn test_every_member_rewriting_is_exhausted_with_the_untrusted_reply() {
    let clock = Arc::new(TestClock::new());
    let asked = ask("www.example.com.", RecordType::A);
    let two_questions = address_reply(&asked, vec![asked.clone(), asked.clone()]);
    let pool = pool(
        OrderedFailover::new(),
        &clock,
        vec![
            ScriptedUpstream::new("first", rewritten(&asked)),
            ScriptedUpstream::new("second", two_questions),
        ],
    );

    let error = pool
        .resolve(&asked, deadline(&clock))
        .await
        .expect_err("nothing to serve");

    assert!(matches!(
        error,
        PoolError::Exhausted {
            last_error: Some(UpstreamError::UntrustedReply(ReplyFault::MultipleQuestions))
        }
    ));
    let views = pool.snapshot();
    let first = views.first().expect("first view");
    let second = views.get(1).expect("second view");
    assert_eq!(first.refused_replies.count(ReplyFault::QuestionMismatch), 1);
    assert_eq!(
        second.refused_replies.count(ReplyFault::MultipleQuestions),
        1
    );
}

#[tokio::test]
async fn test_a_fast_bad_reply_loses_a_race_to_a_slower_good_one() {
    let clock = Arc::new(TestClock::new());
    let asked = ask("www.example.com.", RecordType::A);
    let pool = pool(
        RaceAll::new(),
        &clock,
        vec![
            ScriptedUpstream::new("rewriter", rewritten(&asked)),
            ScriptedUpstream::new("honest", faithful(&asked)).after(Duration::from_millis(30)),
        ],
    );

    let reply = pool
        .resolve(&asked, deadline(&clock))
        .await
        .expect("race won");

    assert_eq!(reply.answered_by, UpstreamId::new("honest"));
    let views = pool.snapshot();
    let rewriter = views.first().expect("rewriter view");
    assert_eq!(
        rewriter.refused_replies.count(ReplyFault::QuestionMismatch),
        1
    );
}

#[tokio::test]
async fn test_a_meta_type_question_is_judged_on_the_pool_path_too() {
    let clock = Arc::new(TestClock::new());
    let asked = ask("www.example.com.", RecordType::ANY);
    let pool = pool(
        OrderedFailover::new(),
        &clock,
        vec![ScriptedUpstream::new("rewriter", rewritten(&asked))],
    );

    let error = pool
        .resolve(&asked, deadline(&clock))
        .await
        .expect_err("refused");

    assert!(matches!(
        error,
        PoolError::Exhausted {
            last_error: Some(UpstreamError::UntrustedReply(ReplyFault::QuestionMismatch))
        }
    ));
}

#[tokio::test]
async fn test_a_probe_does_not_reinstate_a_member_whose_replies_are_refused() {
    let clock = Arc::new(TestClock::new());
    let asked = ask("www.example.com.", RecordType::A);
    let pool = Arc::new(pool(
        OrderedFailover::new(),
        &clock,
        vec![ScriptedUpstream::new("rewriter", rewritten(&asked))],
    ));
    for _ in 0..3 {
        let _ = pool.resolve(&asked, deadline(&clock)).await;
    }
    let opened = pool.snapshot();
    assert!(matches!(
        opened.first().expect("view").circuit,
        CircuitState::Open { .. }
    ));

    let scheduler = ProbeScheduler::new(
        Arc::clone(&pool),
        Arc::clone(&clock),
        Duration::from_secs(1),
    );
    scheduler.probe_once(&UpstreamId::new("rewriter")).await;

    let views = pool.snapshot();
    let rewriter = views.first().expect("view");
    assert!(matches!(rewriter.circuit, CircuitState::Open { .. }));
    assert_eq!(
        rewriter.refused_replies.count(ReplyFault::QuestionMismatch),
        4,
        "the probe's refused reply is tallied too"
    );
}

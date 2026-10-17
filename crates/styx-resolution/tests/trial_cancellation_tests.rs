//! A half-open trial that is dropped before it reports must give its slot back.
//!
//! Covers the three ways a trial is cancelled without recording an outcome: a race
//! loser aborted by the winner, the global query deadline, and a cancelled probe.

mod harness;

use std::sync::Arc;
use std::time::Duration;

use harness::{CommandableUpstream, TestClock, UpstreamBehavior};
use styx_core::{Clock, UpstreamId};
use styx_proto::{Name, Question, RecordClass, RecordType};
use styx_resolution::{
    CanaryConfig, CircuitConfig, CircuitState, Do53Forwarder, EdnsBufferSize, OrderedFailover,
    PoolMember, ProbeConfig, ProbePolicy, ProbeScheduler, RaceAll, UpstreamPool,
};

const COOLDOWN: Duration = Duration::from_secs(30);
const PAST_COOLDOWN: Duration = Duration::from_secs(35);
const TRIAL_DELAY: Duration = Duration::from_millis(250);
const CANCEL_AFTER: Duration = Duration::from_millis(50);

fn question() -> Question {
    let name = Name::from_ascii("trial.test.").unwrap_or_else(|_| Name::root());
    Question::new(name, RecordType::A, RecordClass::In)
}

fn member(
    id: &str,
    upstream: &CommandableUpstream,
    clock: &Arc<TestClock>,
) -> PoolMember<Do53Forwarder<TestClock>> {
    let id = UpstreamId::new(id);
    let forwarder = Do53Forwarder::new(
        id.clone(),
        upstream.udp_addr(),
        EdnsBufferSize::default(),
        Duration::from_millis(500),
        Duration::from_millis(500),
        clock.clone(),
    );
    let canary = CanaryConfig {
        qname: Name::from_ascii("canary.check.").unwrap_or_else(|_| Name::root()),
        qtype: RecordType::A,
        timeout: Duration::from_millis(500),
    };
    PoolMember::new(id, forwarder, styx_resolution::Weight::new(1), canary)
}

fn trip_after_one_fault() -> CircuitConfig {
    CircuitConfig {
        failure_threshold: 1,
        open_cooldown: COOLDOWN,
        half_open_successes: 1,
    }
}

fn deadline(clock: &TestClock) -> std::time::Instant {
    let now = clock.now_monotonic();
    now.checked_add(Duration::from_secs(5)).unwrap_or(now)
}

fn available(
    pool: &UpstreamPool<
        impl styx_resolution::SelectionStrategy,
        Do53Forwarder<TestClock>,
        TestClock,
    >,
    index: usize,
) -> bool {
    let views = pool.snapshot();
    views.get(index).is_some_and(|view| view.available)
}

#[tokio::test]
async fn race_loser_aborted_half_open_is_probed_again_once_the_winner_fails() {
    let clock = Arc::new(TestClock::new());
    let fast = CommandableUpstream::start().await.expect("fast start");
    let slow = CommandableUpstream::start().await.expect("slow start");
    let pool = UpstreamPool::new(
        vec![member("fast", &fast, &clock), member("slow", &slow, &clock)],
        RaceAll::new(),
        clock.clone(),
        trip_after_one_fault(),
        ProbePolicy::new(ProbeConfig::default()),
    );

    // `slow` refuses once while `fast` is still answering: it trips Open.
    fast.set_behavior(UpstreamBehavior::Delay(Duration::from_millis(150)));
    slow.set_behavior(UpstreamBehavior::Refused);
    pool.resolve(&question(), deadline(&clock))
        .await
        .expect("fast answers");
    assert!(matches!(
        pool.snapshot()[1].circuit,
        CircuitState::Open { .. }
    ));

    // Past the cool-down `slow` is admitted as a trial, but `fast` wins and aborts it.
    clock.advance(PAST_COOLDOWN);
    fast.set_behavior(UpstreamBehavior::Normal);
    slow.set_behavior(UpstreamBehavior::Delay(TRIAL_DELAY));
    let winner = pool
        .resolve(&question(), deadline(&clock))
        .await
        .expect("fast wins");
    assert_eq!(winner.answered_by, UpstreamId::new("fast"));
    assert!(
        available(&pool, 1),
        "the aborted trial must not lock `slow` out"
    );

    // `fast` starts failing: `slow` has to be tried and answer.
    fast.set_behavior(UpstreamBehavior::Refused);
    slow.set_behavior(UpstreamBehavior::Normal);
    let answer = pool
        .resolve(&question(), deadline(&clock))
        .await
        .expect("slow answers");
    assert_eq!(answer.answered_by, UpstreamId::new("slow"));
}

#[tokio::test]
async fn deadline_cancelled_trial_frees_the_member_and_is_not_a_fault() {
    let clock = Arc::new(TestClock::new());
    let upstream = CommandableUpstream::start().await.expect("upstream start");
    let pool = UpstreamPool::new(
        vec![member("only", &upstream, &clock)],
        OrderedFailover::new(),
        clock.clone(),
        trip_after_one_fault(),
        ProbePolicy::new(ProbeConfig::default()),
    );

    upstream.set_behavior(UpstreamBehavior::Refused);
    let _ = pool.resolve(&question(), deadline(&clock)).await;
    clock.advance(PAST_COOLDOWN);
    let before = pool.members()[0].health.read().expect("health").clone();

    // The pipeline's global deadline drops the whole resolution mid-trial.
    upstream.set_behavior(UpstreamBehavior::Delay(TRIAL_DELAY));
    let cancelled =
        tokio::time::timeout(CANCEL_AFTER, pool.resolve(&question(), deadline(&clock))).await;
    assert!(
        cancelled.is_err(),
        "the trial must still be running when cancelled"
    );

    assert!(
        available(&pool, 0),
        "a cancelled trial must not lock the member out"
    );
    let after = pool.members()[0].health.read().expect("health").clone();
    assert!(!matches!(after.circuit(), CircuitState::Open { .. }));
    assert_eq!(after.consecutive_failures(), before.consecutive_failures());
    assert_eq!(after.refused_replies(), before.refused_replies());
    assert_eq!(after.srtt(), before.srtt());
}

#[tokio::test]
async fn cancelled_probe_frees_the_member() {
    let clock = Arc::new(TestClock::new());
    let upstream = CommandableUpstream::start().await.expect("upstream start");
    let pool = Arc::new(UpstreamPool::new(
        vec![member("only", &upstream, &clock)],
        OrderedFailover::new(),
        clock.clone(),
        trip_after_one_fault(),
        ProbePolicy::new(ProbeConfig::default()),
    ));

    upstream.set_behavior(UpstreamBehavior::Refused);
    let _ = pool.resolve(&question(), deadline(&clock)).await;
    assert!(!available(&pool, 0));

    upstream.set_behavior(UpstreamBehavior::Delay(TRIAL_DELAY));
    let scheduler = ProbeScheduler::new(pool.clone(), clock.clone(), CANCEL_AFTER);
    let cancelled =
        tokio::time::timeout(CANCEL_AFTER, scheduler.probe_once(&UpstreamId::new("only"))).await;
    assert!(
        cancelled.is_err(),
        "the probe must still be running when cancelled"
    );

    assert!(
        matches!(pool.snapshot()[0].circuit, CircuitState::HalfOpen { .. }),
        "the probe moved the circuit to HalfOpen"
    );
    assert!(
        available(&pool, 0),
        "a cancelled probe must not lock the member out"
    );
}

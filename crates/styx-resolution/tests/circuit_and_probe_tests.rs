//! Socket-level integration tests for circuit breakers, probing, and Do53 transports.

mod harness;

use std::sync::Arc;
use std::time::Duration;

use harness::{CommandableUpstream, TestClock, UpstreamBehavior};
use styx_proto::{Name, Question, RecordClass, RecordType};
use styx_resolution::{
    CanaryConfig, CircuitConfig, CircuitState, Do53Forwarder, EdnsBufferSize, OrderedFailover,
    PoolError, PoolMember, ProbeConfig, ProbePolicy, ProbeScheduler, UpstreamId, UpstreamPool,
};

use tokio_util::sync::CancellationToken;

fn make_test_question(qname: &str) -> Question {
    let name = match Name::from_ascii(qname) {
        Ok(n) => n,
        Err(_) => Name::root(),
    };
    Question::new(name, RecordType::A, RecordClass::In)
}

fn create_member(
    id_str: &str,
    upstream: &CommandableUpstream,
    clock: Arc<TestClock>,
) -> PoolMember<Do53Forwarder<TestClock>> {
    let id = UpstreamId::new(id_str);
    let forwarder = Do53Forwarder::new(
        id.clone(),
        upstream.udp_addr(),
        EdnsBufferSize::default(),
        Duration::from_millis(300),
        Duration::from_millis(300),
        clock,
    );
    let canary_qname = match Name::from_ascii("canary.check.") {
        Ok(n) => n,
        Err(_) => Name::root(),
    };
    PoolMember::new(
        id,
        forwarder,
        styx_resolution::Weight::new(1),
        CanaryConfig {
            qname: canary_qname,
            qtype: RecordType::A,
            timeout: Duration::from_millis(300),
        },
    )
}

#[tokio::test]
async fn test_circuit_tripping_and_clock_advancement_recovery() {
    let clock = Arc::new(TestClock::new());
    let up1 = CommandableUpstream::start().await.expect("up1 start");

    let member1 = create_member("up1", &up1, clock.clone());
    let pool = UpstreamPool::new(
        vec![member1],
        OrderedFailover::new(),
        clock.clone(),
        CircuitConfig {
            failure_threshold: 2,
            open_cooldown: Duration::from_secs(30),
            half_open_successes: 1,
        },
        ProbePolicy::new(ProbeConfig::default()),
    );

    let query = make_test_question("circuit.test.");

    // Trip circuit with 2 consecutive failures
    up1.set_behavior(UpstreamBehavior::Timeout);
    let _ = pool.resolve(&query).await;
    let _ = pool.resolve(&query).await;

    // Check circuit tripped to Open
    let views = pool.snapshot();
    assert!(!views[0].available);
    assert!(matches!(views[0].circuit, CircuitState::Open { .. }));

    // Subsequent query fails immediately with AllUpstreamsDown
    let err = pool.resolve(&query).await.unwrap_err();
    assert!(matches!(err, PoolError::AllUpstreamsDown));

    // Fast-forward clock past open_cooldown
    clock.advance(Duration::from_secs(35));

    // Upstream recovers
    up1.set_behavior(UpstreamBehavior::Normal);

    // Available for half-open trial, succeeds and closes circuit
    let resp = pool.resolve(&query).await.expect("recovery query success");
    assert_eq!(resp.answered_by, UpstreamId::new("up1"));

    let views = pool.snapshot();
    assert!(views[0].available);
    assert_eq!(views[0].circuit, CircuitState::Closed);
}

#[tokio::test]
async fn test_probe_silence_on_healthy_upstream() {
    let clock = Arc::new(TestClock::new());
    let up = CommandableUpstream::start().await.expect("up start");
    let member = create_member("up", &up, clock.clone());

    let pool = Arc::new(UpstreamPool::new(
        vec![member],
        OrderedFailover::new(),
        clock.clone(),
        CircuitConfig::default(),
        ProbePolicy::new(ProbeConfig {
            idle_window: Duration::from_secs(60),
            down_retry_interval: Duration::from_secs(10),
            tick: Duration::from_millis(50),
        }),
    ));

    let scheduler = ProbeScheduler::new(pool.clone(), clock.clone(), Duration::from_millis(50));
    let shutdown = CancellationToken::new();
    let s_cancel = shutdown.clone();

    tokio::spawn(async move {
        scheduler.run(s_cancel).await;
    });

    let query = make_test_question("active.example.");
    // Send real queries periodically so member is never idle beyond 60s
    for _ in 0..5 {
        let _ = pool.resolve(&query).await.expect("query success");
        clock.advance(Duration::from_secs(5));
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    shutdown.cancel();

    // Exactly 5 real queries, ZERO probe queries generated!
    assert_eq!(up.query_count(), 5);
}

#[tokio::test]
async fn test_standby_probe_after_idle_window() {
    let clock = Arc::new(TestClock::new());
    let up1 = CommandableUpstream::start().await.expect("up1 start");
    let up2 = CommandableUpstream::start().await.expect("up2 start");

    let member1 = create_member("up1", &up1, clock.clone());
    let member2 = create_member("up2", &up2, clock.clone());

    let pool = Arc::new(UpstreamPool::new(
        vec![member1, member2],
        OrderedFailover::new(),
        clock.clone(),
        CircuitConfig::default(),
        ProbePolicy::new(ProbeConfig {
            idle_window: Duration::from_secs(60),
            down_retry_interval: Duration::from_secs(10),
            tick: Duration::from_millis(50),
        }),
    ));

    let scheduler = ProbeScheduler::new(pool.clone(), clock.clone(), Duration::from_millis(50));
    let query = make_test_question("primary.example.");

    // Serve queries only to primary
    let _ = pool.resolve(&query).await.expect("query success");
    assert_eq!(up1.query_count(), 1);
    assert_eq!(up2.query_count(), 0);

    // Advance clock past idle window for secondary
    clock.advance(Duration::from_secs(65));

    // Secondary is now due for probe
    let due = pool.due_for_probe();
    assert!(due.contains(&UpstreamId::new("up2")));

    // Probe secondary
    scheduler.probe_once(&UpstreamId::new("up2")).await;
    assert_eq!(up2.query_count(), 1);
}

#[tokio::test]
async fn test_tcp_fallback_on_truncation() {
    let clock = Arc::new(TestClock::new());
    let up = CommandableUpstream::start().await.expect("up start");
    up.set_behavior(UpstreamBehavior::TruncateUdp);

    let member = create_member("up", &up, clock.clone());
    let pool = UpstreamPool::new(
        vec![member],
        OrderedFailover::new(),
        clock.clone(),
        CircuitConfig::default(),
        ProbePolicy::new(ProbeConfig::default()),
    );

    let query = make_test_question("truncated.test.");
    let resp = pool.resolve(&query).await.expect("fallback success");

    // Proves TCP fallback happened seamlessly
    assert!(resp.via_tcp);
    assert_eq!(resp.answered_by, UpstreamId::new("up"));
}

#[tokio::test]
async fn test_answer_fault_does_not_open_circuit() {
    let clock = Arc::new(TestClock::new());
    let up = CommandableUpstream::start().await.expect("up start");
    let member = create_member("up", &up, clock.clone());

    let pool = UpstreamPool::new(
        vec![member],
        OrderedFailover::new(),
        clock.clone(),
        CircuitConfig {
            failure_threshold: 2,
            open_cooldown: Duration::from_secs(30),
            half_open_successes: 1,
        },
        ProbePolicy::new(ProbeConfig::default()),
    );

    // Record 5 answer faults directly (e.g. SERVFAIL for bad name / NXDOMAIN)
    for _ in 0..5 {
        pool.record(
            &UpstreamId::new("up"),
            styx_resolution::Outcome::Failure {
                class: styx_resolution::FailureClass::AnswerFault,
                was_probe: false,
            },
        );
    }

    // Circuit must remain CLOSED
    let views = pool.snapshot();
    assert_eq!(views[0].circuit, CircuitState::Closed);
    assert!(views[0].available);
}

#[tokio::test]
async fn test_all_down_returns_definite_error() {
    let clock = Arc::new(TestClock::new());
    let up = CommandableUpstream::start().await.expect("up start");
    up.set_behavior(UpstreamBehavior::DropAll);

    let member = create_member("up", &up, clock.clone());
    let pool = UpstreamPool::new(
        vec![member],
        OrderedFailover::new(),
        clock.clone(),
        CircuitConfig::default(),
        ProbePolicy::new(ProbeConfig::default()),
    );

    let query = make_test_question("alldown.test.");
    let err = pool.resolve(&query).await.unwrap_err();
    assert!(matches!(err, PoolError::Exhausted { .. }));
}

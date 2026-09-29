//! Socket-level integration tests for upstream pool selection strategies.

mod harness;

use std::sync::Arc;
use std::time::Duration;

use harness::{CommandableUpstream, TestClock, UpstreamBehavior};
use styx_core::UpstreamId;
use styx_proto::{Name, Question, RecordClass, RecordType};
use styx_resolution::{
    CanaryConfig, CircuitConfig, Do53Forwarder, EdnsBufferSize, OrderedFailover, PoolMember,
    ProbeConfig, ProbePolicy, RaceAll, RoundRobin, UpstreamPool, Weighted,
};

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
    weight: u32,
    clock: Arc<TestClock>,
) -> PoolMember<Do53Forwarder<TestClock>> {
    let id = UpstreamId::new(id_str);
    let forwarder = Do53Forwarder::new(
        id.clone(),
        upstream.udp_addr(),
        EdnsBufferSize::default(),
        Duration::from_millis(500),
        Duration::from_millis(500),
        clock,
    );
    let canary_qname = match Name::from_ascii("canary.test.") {
        Ok(n) => n,
        Err(_) => Name::root(),
    };
    PoolMember::new(
        id,
        forwarder,
        styx_resolution::Weight::new(weight),
        CanaryConfig {
            qname: canary_qname,
            qtype: RecordType::A,
            timeout: Duration::from_millis(500),
        },
    )
}

#[tokio::test]
async fn test_ordered_failover_recovery_and_selection() {
    let clock = Arc::new(TestClock::new());
    let up1 = CommandableUpstream::start().await.expect("up1 start");
    let up2 = CommandableUpstream::start().await.expect("up2 start");

    let member1 = create_member("up1", &up1, 10, clock.clone());
    let member2 = create_member("up2", &up2, 10, clock.clone());

    let pool = UpstreamPool::new(
        vec![member1, member2],
        OrderedFailover::new(),
        clock.clone(),
        CircuitConfig {
            failure_threshold: 2,
            open_cooldown: Duration::from_secs(10),
            half_open_successes: 1,
        },
        ProbePolicy::new(ProbeConfig::default()),
    );

    let query = make_test_question("example.com.");

    // Initial query: primary serves
    let resp = pool.resolve(&query).await.expect("query success");
    assert_eq!(resp.answered_by, UpstreamId::new("up1"));
    assert_eq!(up1.query_count(), 1);
    assert_eq!(up2.query_count(), 0);

    // Primary fails: secondary answers
    up1.set_behavior(UpstreamBehavior::Timeout);
    let resp2 = pool.resolve(&query).await.expect("query failover");
    assert_eq!(resp2.answered_by, UpstreamId::new("up2"));
    assert_eq!(up2.query_count(), 1);

    // Primary recovers: traffic returns to primary
    up1.set_behavior(UpstreamBehavior::Normal);
    let resp3 = pool.resolve(&query).await.expect("query recovered");
    assert_eq!(resp3.answered_by, UpstreamId::new("up1"));
}

#[tokio::test]
async fn test_round_robin_distribution_and_concurrency() {
    let clock = Arc::new(TestClock::new());
    let up1 = CommandableUpstream::start().await.expect("up1 start");
    let up2 = CommandableUpstream::start().await.expect("up2 start");

    let member1 = create_member("up1", &up1, 1, clock.clone());
    let member2 = create_member("up2", &up2, 1, clock.clone());

    let pool = Arc::new(UpstreamPool::new(
        vec![member1, member2],
        RoundRobin::new(),
        clock.clone(),
        CircuitConfig::default(),
        ProbePolicy::new(ProbeConfig::default()),
    ));

    let query = make_test_question("example.org.");

    // Sequential alternating distribution
    for _ in 0..10 {
        let _ = pool.resolve(&query).await.expect("query success");
    }
    assert_eq!(up1.query_count(), 5);
    assert_eq!(up2.query_count(), 5);

    // Concurrent dispatch fairness
    let mut handles = Vec::new();
    for _ in 0..20 {
        let p = pool.clone();
        let q = query.clone();
        handles.push(tokio::spawn(async move { p.resolve(&q).await }));
    }

    for h in handles {
        let res = h.await.expect("join handle");
        assert!(res.is_ok());
    }

    assert_eq!(up1.query_count(), 15);
    assert_eq!(up2.query_count(), 15);
}

#[tokio::test]
async fn test_weighted_distribution_and_degenerate_cases() {
    let clock = Arc::new(TestClock::new());
    let up1 = CommandableUpstream::start().await.expect("up1 start");
    let up2 = CommandableUpstream::start().await.expect("up2 start");

    // Proportional weights 3:1
    let member1 = create_member("up1", &up1, 3, clock.clone());
    let member2 = create_member("up2", &up2, 1, clock.clone());

    let pool = UpstreamPool::new(
        vec![member1, member2],
        Weighted::new(),
        clock.clone(),
        CircuitConfig::default(),
        ProbePolicy::new(ProbeConfig::default()),
    );

    let query = make_test_question("weighted.test.");
    for _ in 0..40 {
        let _ = pool.resolve(&query).await.expect("query success");
    }

    assert_eq!(up1.query_count(), 30);
    assert_eq!(up2.query_count(), 10);

    // Degenerate case: single member
    let up3 = CommandableUpstream::start().await.expect("up3 start");
    let single_pool = UpstreamPool::new(
        vec![create_member("up3", &up3, 10, clock.clone())],
        Weighted::new(),
        clock.clone(),
        CircuitConfig::default(),
        ProbePolicy::new(ProbeConfig::default()),
    );
    let resp = single_pool.resolve(&query).await.expect("single success");
    assert_eq!(resp.answered_by, UpstreamId::new("up3"));

    // Degenerate case: zero total weight degrades to round-robin
    let up4 = CommandableUpstream::start().await.expect("up4 start");
    let up5 = CommandableUpstream::start().await.expect("up5 start");
    let zero_pool = UpstreamPool::new(
        vec![
            create_member("up4", &up4, 0, clock.clone()),
            create_member("up5", &up5, 0, clock.clone()),
        ],
        Weighted::new(),
        clock.clone(),
        CircuitConfig::default(),
        ProbePolicy::new(ProbeConfig::default()),
    );
    for _ in 0..4 {
        let _ = zero_pool
            .resolve(&query)
            .await
            .expect("zero weight success");
    }
    assert_eq!(up4.query_count(), 2);
    assert_eq!(up5.query_count(), 2);
}

#[tokio::test]
async fn test_race_fanout_and_attribution() {
    let clock = Arc::new(TestClock::new());
    let up1 = CommandableUpstream::start().await.expect("up1 start");
    let up2 = CommandableUpstream::start().await.expect("up2 start");
    let up3 = CommandableUpstream::start().await.expect("up3 start");

    // up1 delays 200ms, up2 delays 20ms (winner), up3 delays 300ms
    up1.set_behavior(UpstreamBehavior::Delay(Duration::from_millis(200)));
    up2.set_behavior(UpstreamBehavior::Delay(Duration::from_millis(20)));
    up3.set_behavior(UpstreamBehavior::Delay(Duration::from_millis(300)));

    let member1 = create_member("up1", &up1, 1, clock.clone());
    let member2 = create_member("up2", &up2, 1, clock.clone());
    let member3 = create_member("up3", &up3, 1, clock.clone());

    let pool = UpstreamPool::new(
        vec![member1, member2, member3],
        RaceAll::new(),
        clock.clone(),
        CircuitConfig::default(),
        ProbePolicy::new(ProbeConfig::default()),
    );

    let query = make_test_question("race.test.");
    let resp = pool.resolve(&query).await.expect("race resolution");

    assert_eq!(resp.answered_by, UpstreamId::new("up2"));
    assert_eq!(resp.raced_count, 3);

    // Give background tasks a brief moment to reach fakes
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Privacy hazard assertion: fanout reaches all 3 members!
    assert!(up1.query_count() >= 1);
    assert!(up2.query_count() >= 1);
    assert!(up3.query_count() >= 1);
}

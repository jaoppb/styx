use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use styx_proto::{Header, Message, Name, Opcode, RecordClass, RecordType};

use super::*;
use crate::domain::ports::EdnsObservation;

fn key() -> OutboundKey {
    OutboundKey {
        server: NameserverAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
        as_sent: Question::new(
            Name::from_ascii("com.").unwrap(),
            RecordType::NS,
            RecordClass::In,
        ),
    }
}

fn reply() -> Outcome {
    Ok(TransportReply {
        message: Message::new(Header::new_query(1, Opcode::Query, false)),
        via_tcp: false,
        edns: EdnsObservation::Inconclusive,
        wire_exchanges: 1,
    })
}

fn after(millis: u64) -> Instant {
    let now = Instant::now();
    now.checked_add(Duration::from_millis(millis))
        .unwrap_or(now)
}

async fn slow_reply(sent: Arc<AtomicUsize>, millis: u64) -> Outcome {
    sent.fetch_add(1, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(millis)).await;
    reply()
}

#[tokio::test]
async fn concurrent_callers_share_one_send() {
    let flights = InFlight::new();
    let sent = Arc::new(AtomicUsize::new(0));
    let call = || {
        let sent = Arc::clone(&sent);
        flights.exchange(key(), after(2000), move || slow_reply(sent, 50))
    };

    let (first, second, third) = tokio::join!(call(), call(), call());

    assert_eq!(sent.load(Ordering::SeqCst), 1);
    assert_eq!(first.role, FlightRole::Leader);
    assert_eq!(second.role, FlightRole::Follower);
    assert_eq!(third.role, FlightRole::Follower);
    assert!(first.outcome.is_ok() && second.outcome.is_ok() && third.outcome.is_ok());
}

#[tokio::test]
async fn a_follower_is_not_cut_short_by_the_leaders_deadline() {
    let flights = InFlight::new();
    let sent = Arc::new(AtomicUsize::new(0));
    let leader_sent = Arc::clone(&sent);
    let follower = async {
        tokio::time::sleep(Duration::from_millis(10)).await;
        flights
            .exchange(key(), after(2000), || async { unreachable_send() })
            .await
    };
    let leader = flights.exchange(key(), after(30), move || slow_reply(leader_sent, 150));

    let (leader, follower) = tokio::join!(leader, follower);

    assert_eq!(
        leader.outcome.map_err(|failed| failed.error),
        Err(TransportError::Timeout),
        "the leader's own deadline passed"
    );
    assert_eq!(follower.role, FlightRole::Follower);
    assert!(
        follower.outcome.is_ok(),
        "the follower waited for the reply"
    );
    assert_eq!(sent.load(Ordering::SeqCst), 1);
}

fn unreachable_send() -> Outcome {
    Err(failure(TransportError::Malformed))
}

#[tokio::test]
async fn a_cancelled_leader_neither_strands_followers_nor_leaks_its_entry() {
    let flights = Arc::new(InFlight::new());
    let sent = Arc::new(AtomicUsize::new(0));
    let leader_sent = Arc::clone(&sent);
    let leading = flights.exchange(key(), after(2000), move || slow_reply(leader_sent, 80));
    let leader = tokio::time::timeout(Duration::from_millis(10), leading).await;
    assert!(leader.is_err(), "the leader was cancelled mid-flight");
    assert_eq!(flights.len(), 1, "the exchange outlives its caller");

    let follower = flights
        .exchange(key(), after(2000), || async { unreachable_send() })
        .await;

    assert_eq!(follower.role, FlightRole::Follower);
    assert!(follower.outcome.is_ok());
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(flights.is_empty());
}

#[tokio::test]
async fn the_entry_is_gone_once_the_exchange_completes() {
    let flights = InFlight::new();
    let sent = Arc::new(AtomicUsize::new(0));
    let result = flights
        .exchange(key(), after(2000), || slow_reply(sent, 5))
        .await;
    assert!(result.outcome.is_ok());
    assert!(flights.is_empty());
}

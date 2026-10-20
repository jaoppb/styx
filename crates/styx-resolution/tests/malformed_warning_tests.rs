//! A flood of undecodable queries costs the log one warning plus one summary per interval,
//! while every query is still answered FORMERR (issue #88).

mod harness;

use std::net::SocketAddr;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use harness::{DnsClient, HarnessError, TestServer};
use styx_proto::{Message, ResponseCode};
use tokio::net::UdpSocket;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::Layer;

const FLOOD: usize = 10_000;
const FLOOD_SUPPRESSED: u64 = 9_999;
const TCP_QUERIES: u16 = 50;
const TCP_SUPPRESSED: u64 = 49;
const SHUTDOWN_QUERIES: usize = 5;
const SHUTDOWN_SUPPRESSED: u64 = 4;
const BATCH: usize = 100;
const INTERVAL: Duration = Duration::from_secs(1);
const REPLY_TIMEOUT: Duration = Duration::from_secs(3);
const POLL: Duration = Duration::from_millis(20);
const POLLS_BEFORE_GIVING_UP: u32 = 150;
const QUIET_PERIOD: Duration = Duration::from_millis(200);

/// One `warn` raised for malformed queries.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Warning {
    addr: String,
    suppressed: u64,
}

static WARNINGS: Mutex<Vec<Warning>> = Mutex::new(Vec::new());

#[derive(Default)]
struct WarningFields {
    addr: String,
    suppressed: u64,
    message: String,
}

impl Visit for WarningFields {
    fn record_u64(&mut self, field: &Field, value: u64) {
        if field.name() == "suppressed" {
            self.suppressed = value;
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        match field.name() {
            "addr" => self.addr = format!("{value:?}"),
            "message" => self.message = format!("{value:?}"),
            _ => {}
        }
    }
}

struct CaptureWarnings;

impl<S: Subscriber> Layer<S> for CaptureWarnings {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut fields = WarningFields::default();
        event.record(&mut fields);
        if !fields.message.starts_with("malformed") {
            return;
        }
        if let Ok(mut warnings) = WARNINGS.lock() {
            warnings.push(Warning {
                addr: fields.addr,
                suppressed: fields.suppressed,
            });
        }
    }
}

fn capture_warnings() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        let warnings_only = CaptureWarnings.with_filter(LevelFilter::from_level(Level::WARN));
        let subscriber = tracing_subscriber::registry().with(warnings_only);
        tracing::subscriber::set_global_default(subscriber).ok();
    });
}

/// The malformed-query warnings raised by the listener bound to `addr`.
fn warnings_from(addr: SocketAddr) -> Vec<Warning> {
    let addr = addr.to_string();
    WARNINGS
        .lock()
        .map(|warnings| {
            warnings
                .iter()
                .filter(|warning| warning.addr == addr)
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

fn suppressed_counts(warnings: &[Warning]) -> Vec<u64> {
    warnings.iter().map(|warning| warning.suppressed).collect()
}

/// A query header claiming one question, followed by a label length that is not valid.
fn undecodable_query(id: u16) -> Vec<u8> {
    let [id_high, id_low] = id.to_be_bytes();
    let mut bytes = vec![id_high, id_low, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    bytes.extend_from_slice(&[0xff; 8]);
    bytes
}

fn check_formerr(raw: &[u8], id: u16) -> Result<(), HarnessError> {
    let reply = Message::decode(raw)?;
    if reply.header.id != id || reply.header.rcode != ResponseCode::FORMERR {
        return Err(HarnessError::Protocol(format!(
            "expected FORMERR for {id:#06x}, got {:?} for {:#06x}",
            reply.header.rcode, reply.header.id
        )));
    }
    Ok(())
}

/// Sends `count` undecodable datagrams in batches, awaiting one FORMERR per datagram.
async fn flood_udp(target: SocketAddr, count: usize) -> Result<(), HarnessError> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let mut buf = [0u8; 512];
    for start in (0..count).step_by(BATCH) {
        let batch = BATCH.min(count.saturating_sub(start));
        for offset in 0..batch {
            let id = u16::try_from(start.saturating_add(offset) % 65_535).unwrap_or(0);
            socket.send_to(&undecodable_query(id), target).await?;
        }
        for _ in 0..batch {
            let received = tokio::time::timeout(REPLY_TIMEOUT, socket.recv_from(&mut buf))
                .await
                .map_err(|_| HarnessError::Timeout("a datagram went unanswered".into()))??;
            let reply = buf
                .get(..received.0)
                .ok_or_else(|| HarnessError::Protocol("reply length out of bounds".into()))?;
            let reply = Message::decode(reply)?;
            if reply.header.rcode != ResponseCode::FORMERR {
                return Err(HarnessError::Protocol(format!(
                    "expected FORMERR, got {:?}",
                    reply.header.rcode
                )));
            }
        }
    }
    Ok(())
}

/// Advances the server's clock one interval at a time until `done` holds or the polls run out.
async fn advance_until(
    server: &TestServer,
    addr: SocketAddr,
    done: impl Fn(&[Warning]) -> bool,
) -> Vec<Warning> {
    for _ in 0..POLLS_BEFORE_GIVING_UP {
        let warnings = warnings_from(addr);
        if done(&warnings) {
            return warnings;
        }
        server.clock().advance(INTERVAL);
        tokio::time::sleep(POLL).await;
    }
    warnings_from(addr)
}

#[tokio::test]
async fn test_udp_flood_logs_two_warnings_and_answers_every_datagram() {
    capture_warnings();
    let mut server = TestServer::boot_ephemeral().await.expect("boot server");
    let addr = server.udp_addr();

    flood_udp(addr, FLOOD)
        .await
        .expect("every datagram is answered");
    let warnings = advance_until(&server, addr, |lines| lines.len() >= 2).await;
    server.clock().advance(INTERVAL.saturating_mul(10));
    tokio::time::sleep(QUIET_PERIOD).await;

    assert_eq!(suppressed_counts(&warnings), [0, FLOOD_SUPPRESSED]);
    assert_eq!(warnings_from(addr), warnings, "a third warning appeared");
    server.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn test_shutdown_reports_a_pending_count_without_waiting_out_the_interval() {
    capture_warnings();
    let mut server = TestServer::boot_ephemeral().await.expect("boot server");
    let addr = server.udp_addr();

    flood_udp(addr, SHUTDOWN_QUERIES)
        .await
        .expect("every datagram is answered");
    server.shutdown().await.expect("shutdown");

    assert_eq!(
        suppressed_counts(&warnings_from(addr)),
        [0, SHUTDOWN_SUPPRESSED]
    );
    assert_eq!(server.active_tasks(), 0);
}

#[tokio::test]
async fn test_tcp_flood_logs_two_warnings_and_answers_every_query() {
    capture_warnings();
    let mut server = TestServer::boot_ephemeral().await.expect("boot server");
    let addr = server.tcp_addr();
    let client = DnsClient::new();

    for id in 0..TCP_QUERIES {
        let raw = client
            .query_raw_tcp(addr, &undecodable_query(id))
            .await
            .expect("every undecodable query is answered");
        check_formerr(&raw, id).expect("FORMERR reply");
    }
    let warnings = advance_until(&server, addr, |lines| lines.len() >= 2).await;

    assert_eq!(suppressed_counts(&warnings), [0, TCP_SUPPRESSED]);
    server.shutdown().await.expect("shutdown");
}

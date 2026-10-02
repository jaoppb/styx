//! Concurrent query processing in the UDP and TCP listeners (issue 64).

mod harness;

use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use harness::{DnsClient, HarnessError, ServerSettings, TestServer};
use styx_proto::application::Encoder;
use styx_proto::{Header, Message, Name, Opcode, Question, RecordClass, RecordType, ResponseCode};
use styx_resolution::{
    AllowAllFilter, ClientId, ConcurrencyLimits, ConfigError, NoLocalRecords, PipelineError,
    PoolConfig, QueryDetail, QueryObserver, RequestContext, ResolutionOutcome, ResolutionResponse,
    ServerConfig, TerminalHandler,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Answers REFUSED, after `delay` for any name starting with `slow`.
struct DelayTerminal {
    delay: Duration,
}

impl TerminalHandler for DelayTerminal {
    async fn handle_terminal(
        &self,
        ctx: &RequestContext,
    ) -> Result<ResolutionResponse, PipelineError> {
        let question = ctx
            .query
            .questions
            .first()
            .cloned()
            .ok_or(PipelineError::MalformedQuery)?;
        if question.qname.to_string().starts_with("slow") {
            tokio::time::sleep(self.delay).await;
        }
        let mut response = Message::response_to(ctx.query.header.id, question);
        response.header.rcode = ResponseCode::REFUSED;
        let outcome = ResolutionOutcome::Error {
            rcode: ResponseCode::REFUSED,
        };
        Ok(ResolutionResponse::new(response, outcome))
    }
}

#[derive(Default)]
struct RecordingObserver {
    outcomes: Mutex<Vec<ResolutionOutcome>>,
}

impl QueryObserver for RecordingObserver {
    fn record_outcome(&self, _: &ClientId, _: &Question, outcome: &ResolutionOutcome) {
        if let Ok(mut outcomes) = self.outcomes.lock() {
            outcomes.push(outcome.clone());
        }
    }

    fn offer_detail(&self, _detail: QueryDetail) {}

    fn dropped_detail(&self) -> u64 {
        0
    }
}

fn query(id: u16, name: &str) -> Message {
    let mut msg = Message::new(Header::new_query(id, Opcode::Query, true));
    let qname = Name::from_ascii(name).unwrap_or_else(|_| Name::root());
    msg.questions
        .push(Question::new(qname, RecordType::A, RecordClass::In));
    msg
}

fn framed(message: &Message) -> Result<Vec<u8>, HarnessError> {
    let mut encoder = Encoder::new(65535);
    encoder.encode_message(message)?;
    Ok(styx_proto::frame_tcp(&encoder.buf)?)
}

async fn read_response(stream: &mut TcpStream) -> Result<Message, HarnessError> {
    let mut prefix = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut prefix))
        .await
        .map_err(|_| HarnessError::Timeout("TCP response prefix timed out".into()))??;
    let mut body = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
    stream.read_exact(&mut body).await?;
    Ok(Message::decode(&body)?)
}

/// Returns `true` once the server has closed `stream` (EOF or reset) within `within`.
async fn closed_within(stream: &mut TcpStream, within: Duration) -> bool {
    let mut byte = [0u8; 1];
    matches!(
        tokio::time::timeout(within, stream.read(&mut byte)).await,
        Ok(Ok(0) | Err(_))
    )
}

type BootedServer = TestServer<
    NoLocalRecords,
    AllowAllFilter,
    RecordingObserver,
    harness::TestClock,
    DelayTerminal,
>;

fn settings_with(limits: ConcurrencyLimits) -> ServerSettings {
    ServerSettings {
        limits,
        ..ServerSettings::default()
    }
}

fn limits(connections: usize, per_connection: usize) -> Option<ConcurrencyLimits> {
    let defaults = ConcurrencyLimits::default_limits();
    Some(ConcurrencyLimits::new(
        defaults.max_in_flight_queries(),
        NonZeroUsize::new(connections)?,
        NonZeroUsize::new(per_connection)?,
        NonZeroUsize::MIN,
        defaults.tcp_write_timeout(),
    ))
}

async fn boot(delay: Duration, settings: ServerSettings) -> Result<BootedServer, HarnessError> {
    boot_observed(delay, settings, Arc::new(RecordingObserver::default())).await
}

async fn boot_observed(
    delay: Duration,
    settings: ServerSettings,
    observer: Arc<RecordingObserver>,
) -> Result<BootedServer, HarnessError> {
    TestServer::boot_with_limits(
        Arc::new(NoLocalRecords::new()),
        Arc::new(AllowAllFilter::new()),
        observer,
        Arc::new(DelayTerminal { delay }),
        settings,
    )
    .await
}

#[tokio::test]
async fn udp_fast_query_is_not_blocked_by_a_slow_one() {
    let mut server = boot(Duration::from_secs(1), ServerSettings::default())
        .await
        .unwrap();
    let addr = server.udp_addr();

    let slow = tokio::spawn(async move {
        DnsClient::new()
            .query_udp(addr, &query(1, "slow.test."))
            .await
    });
    tokio::time::sleep(Duration::from_millis(10)).await;

    let started = Instant::now();
    let fast = DnsClient::new()
        .query_udp(addr, &query(2, "fast.test."))
        .await
        .unwrap();
    assert_eq!(fast.header.id, 2);
    assert!(
        started.elapsed() < Duration::from_millis(50),
        "{:?}",
        started.elapsed()
    );

    assert_eq!(slow.await.unwrap().unwrap().header.id, 1);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn tcp_pipelined_queries_are_answered_out_of_order() {
    let mut server = boot(Duration::from_secs(1), ServerSettings::default())
        .await
        .unwrap();
    let mut stream = TcpStream::connect(server.tcp_addr()).await.unwrap();

    stream
        .write_all(&framed(&query(1, "slow.test.")).unwrap())
        .await
        .unwrap();
    stream
        .write_all(&framed(&query(2, "fast.test.")).unwrap())
        .await
        .unwrap();

    assert_eq!(read_response(&mut stream).await.unwrap().header.id, 2);
    assert_eq!(read_response(&mut stream).await.unwrap().header.id, 1);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn tcp_connection_beyond_the_cap_is_closed() {
    let mut server = boot(Duration::ZERO, settings_with(limits(2, 32).unwrap()))
        .await
        .unwrap();
    let addr = server.tcp_addr();

    let mut first = TcpStream::connect(addr).await.unwrap();
    let mut second = TcpStream::connect(addr).await.unwrap();
    for (id, stream) in [(1, &mut first), (2, &mut second)] {
        stream
            .write_all(&framed(&query(id, "fast.test.")).unwrap())
            .await
            .unwrap();
        assert_eq!(read_response(stream).await.unwrap().header.id, id);
    }

    let mut third = TcpStream::connect(addr).await.unwrap();
    assert!(closed_within(&mut third, Duration::from_secs(1)).await);

    first
        .write_all(&framed(&query(3, "fast.test.")).unwrap())
        .await
        .unwrap();
    assert_eq!(read_response(&mut first).await.unwrap().header.id, 3);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn per_connection_cap_holds_back_the_next_query() {
    let mut server = boot(
        Duration::from_millis(300),
        settings_with(limits(256, 1).unwrap()),
    )
    .await
    .unwrap();
    let mut stream = TcpStream::connect(server.tcp_addr()).await.unwrap();

    stream
        .write_all(&framed(&query(1, "slow.test.")).unwrap())
        .await
        .unwrap();
    stream
        .write_all(&framed(&query(2, "fast.test.")).unwrap())
        .await
        .unwrap();

    assert_eq!(read_response(&mut stream).await.unwrap().header.id, 1);
    assert_eq!(read_response(&mut stream).await.unwrap().header.id, 2);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn expired_deadline_answers_servfail_and_records_once() {
    let observer = Arc::new(RecordingObserver::default());
    let settings = ServerSettings {
        query_timeout: Duration::from_millis(200),
        ..ServerSettings::default()
    };
    let mut server = boot_observed(Duration::from_secs(1), settings, Arc::clone(&observer))
        .await
        .unwrap();

    let started = Instant::now();
    let response = DnsClient::new()
        .query_udp(server.udp_addr(), &query(7, "slow.test."))
        .await
        .unwrap();
    assert_eq!(response.header.rcode, ResponseCode::SERVFAIL);
    assert!(
        started.elapsed() < Duration::from_millis(400),
        "{:?}",
        started.elapsed()
    );

    let outcomes = observer.outcomes.lock().unwrap().clone();
    assert_eq!(
        outcomes,
        vec![ResolutionOutcome::Error {
            rcode: ResponseCode::SERVFAIL
        }]
    );
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn idle_timer_waits_for_in_flight_queries() {
    let settings = ServerSettings {
        tcp_idle_timeout: Duration::from_millis(100),
        ..ServerSettings::default()
    };
    let mut server = boot(Duration::from_millis(300), settings).await.unwrap();
    let mut stream = TcpStream::connect(server.tcp_addr()).await.unwrap();

    stream
        .write_all(&framed(&query(1, "slow.test.")).unwrap())
        .await
        .unwrap();
    assert_eq!(read_response(&mut stream).await.unwrap().header.id, 1);
    assert!(closed_within(&mut stream, Duration::from_millis(500)).await);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_tcp_client_that_never_reads_does_not_starve_udp() {
    let mut server = boot(Duration::ZERO, settings_with(limits(256, 2).unwrap()))
        .await
        .unwrap();
    let mut stream = TcpStream::connect(server.tcp_addr()).await.unwrap();

    let mut burst = Vec::new();
    for id in 0..2000u16 {
        burst.extend(framed(&query(id, "fast.test.")).unwrap());
    }
    let writer = tokio::spawn(async move {
        let _ = stream.write_all(&burst).await;
        stream
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let response = DnsClient::new()
        .query_udp(server.udp_addr(), &query(9, "fast.test."))
        .await
        .unwrap();
    assert_eq!(response.header.id, 9);
    writer.abort();
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn shutdown_drains_in_flight_work_and_leaves_no_task() {
    let mut server = boot(Duration::from_millis(300), ServerSettings::default())
        .await
        .unwrap();
    let addr = server.udp_addr();
    let slow = tokio::spawn(async move {
        DnsClient::new()
            .query_udp(addr, &query(5, "slow.test."))
            .await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let started = Instant::now();
    server.shutdown().await.unwrap();
    assert!(
        started.elapsed() < Duration::from_millis(2500),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(server.active_tasks(), 0);
    assert_eq!(slow.await.unwrap().unwrap().header.id, 5);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn reuseport_group_answers_queries_from_many_ports() {
    let four = NonZeroUsize::new(4).unwrap();
    let settings =
        settings_with(ConcurrencyLimits::default_limits().with_udp_sockets_per_addr(four));
    let mut server = boot(Duration::ZERO, settings).await.unwrap();
    let addr: SocketAddr = server.udp_addr();

    let mut clients = Vec::new();
    for id in 0..32u16 {
        clients.push(tokio::spawn(async move {
            DnsClient::new()
                .query_udp(addr, &query(id, "fast.test."))
                .await
        }));
    }
    for (id, client) in (0..32u16).zip(clients) {
        assert_eq!(client.await.unwrap().unwrap().header.id, id);
    }
    server.shutdown().await.unwrap();
}

#[test]
fn zero_caps_are_rejected() {
    for key in ["max_in_flight_queries", "max_tcp_connections"] {
        let result = ServerConfig::from_toml_str(&format!("{key} = 0"));
        assert!(matches!(result, Err(ConfigError::Invalid(_))), "{key}");
    }
    let parsed = ServerConfig::from_toml_str("max_in_flight_queries = 8").unwrap();
    assert_eq!(parsed.limits.max_in_flight_queries().get(), 8);
    assert_eq!(parsed.limits.max_tcp_connections().get(), 256);
}

#[test]
fn deadline_must_exceed_every_member_timeout() {
    let pool = PoolConfig::from_toml_str(
        r#"
            strategy = "round_robin"
            [[members]]
            name = "cf"
            kind = "forwarder"
            addr = "1.1.1.1:53"
            udp_timeout_ms = 1000
            tcp_timeout_ms = 2000
        "#,
    )
    .unwrap();
    let equal = ServerConfig::from_toml_str("query_timeout_secs = 2").unwrap();
    assert!(matches!(
        equal.check_deadline_covers(&pool),
        Err(ConfigError::Invalid(_))
    ));
    let longer = ServerConfig::from_toml_str("query_timeout_secs = 3").unwrap();
    assert!(longer.check_deadline_covers(&pool).is_ok());
}

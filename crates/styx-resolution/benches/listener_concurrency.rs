#![allow(missing_docs, clippy::expect_used, clippy::too_many_lines)]

//! Listener concurrency bench (issue 64).
//!
//! Pass criterion on the reference machine (i5-12600K, Linux x86_64, `--release`,
//! loopback): `udp_throughput/clients/8` ≥ 2 × `udp_throughput/clients/1`, and
//! `head_of_line` under 50 ms. Run by hand — it is machine-dependent and not gated:
//! `cargo bench -p styx-resolution --bench listener_concurrency`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use styx_core::SystemClock;
use styx_proto::application::Encoder;
use styx_proto::{Header, Message, Name, Opcode, Question, RecordClass, RecordType, ResponseCode};
use styx_resolution::{
    default_socket_count, AllowAllFilter, ConcurrencyLimits, DiscardObserver, MaxResponseSize,
    NoLocalRecords, Pipeline, PipelineError, RequestContext, ResolutionOutcome, ResolutionResponse,
    Server, ServerConfig, TerminalHandler,
};
use tokio::net::UdpSocket;
use tokio::runtime::Runtime;

/// Queries each client keeps in flight before reading the replies back.
const WINDOW: usize = 32;

/// Windows each client sends per iteration.
const ROUNDS: usize = 4;

/// Queries each client sends per iteration.
const QUERIES_PER_CLIENT: u64 = 128;

/// Answers REFUSED, after one second for any name starting with `slow`.
struct DelayTerminal;

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
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        let mut response = Message::response_to(ctx.query.header.id, question);
        response.header.rcode = ResponseCode::REFUSED;
        let outcome = ResolutionOutcome::Error {
            rcode: ResponseCode::REFUSED,
        };
        Ok(ResolutionResponse::new(response, outcome))
    }
}

fn encoded_query(name: &str) -> Vec<u8> {
    let mut message = Message::new(Header::new_query(0x4242, Opcode::Query, true));
    message.questions.push(Question::new(
        Name::from_ascii(name).expect("valid name"),
        RecordType::A,
        RecordClass::In,
    ));
    let mut encoder = Encoder::new(512);
    encoder
        .encode_message(&message)
        .expect("query encodes within 512 octets");
    encoder.buf
}

fn config() -> ServerConfig {
    ServerConfig {
        listen_addrs: vec![SocketAddr::from(([127, 0, 0, 1], 0))],
        udp_payload_size_default: MaxResponseSize::classic(),
        tcp_idle_timeout: Duration::from_secs(5),
        query_timeout: Duration::from_secs(2),
        limits: ConcurrencyLimits::default_limits()
            .with_udp_sockets_per_addr(default_socket_count()),
    }
}

async fn client_socket() -> Arc<UdpSocket> {
    Arc::new(
        UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind client socket"),
    )
}

/// Sends `ROUNDS` windows of `WINDOW` queries and reads every reply back.
async fn drive_client(socket: Arc<UdpSocket>, server: SocketAddr, query: Arc<Vec<u8>>) {
    let mut buf = [0u8; 512];
    for _ in 0..ROUNDS {
        for _ in 0..WINDOW {
            socket.send_to(&query, server).await.expect("send query");
        }
        for _ in 0..WINDOW {
            let reply = tokio::time::timeout(Duration::from_secs(1), socket.recv_from(&mut buf));
            if reply.await.is_err() {
                // A datagram lost on loopback under load; the round still completes.
                break;
            }
        }
    }
}

fn bench_udp_throughput(c: &mut Criterion, runtime: &Runtime) {
    let server = runtime.block_on(async {
        let clock = Arc::new(SystemClock::new());
        let pipeline = Arc::new(Pipeline::new(
            Arc::new(NoLocalRecords::new()),
            Arc::new(AllowAllFilter::new()),
            Arc::new(DiscardObserver::new()),
            Arc::clone(&clock),
        ));
        Server::bind(config(), pipeline, clock)
            .await
            .expect("bind server")
    });
    let addr = *server.local_addrs().first().expect("UDP address");
    let query = Arc::new(encoded_query("bench.example."));

    let mut group = c.benchmark_group("udp_throughput");
    for clients in [1usize, 8] {
        let sockets: Vec<Arc<UdpSocket>> =
            runtime.block_on(async { client_sockets(clients).await });
        let total = u64::try_from(clients)
            .unwrap_or(1)
            .saturating_mul(QUERIES_PER_CLIENT);
        group.throughput(Throughput::Elements(total));
        group.bench_with_input(
            BenchmarkId::new("clients", clients),
            &sockets,
            |b, sockets| {
                b.to_async(runtime)
                    .iter(|| drive_clients(sockets.clone(), addr, Arc::clone(&query)));
            },
        );
    }
    group.finish();
    drop(server);
}

/// Runs every client concurrently, each on its own task, and waits for all of them.
async fn drive_clients(sockets: Vec<Arc<UdpSocket>>, server: SocketAddr, query: Arc<Vec<u8>>) {
    let handles: Vec<_> = sockets
        .into_iter()
        .map(|socket| tokio::spawn(drive_client(socket, server, Arc::clone(&query))))
        .collect();
    for handle in handles {
        handle.await.expect("client task");
    }
}

/// Times `iterations` fast queries, each sent while a fresh slow query is in flight.
async fn time_fast_behind_slow(
    iterations: u64,
    sockets: (Arc<UdpSocket>, Arc<UdpSocket>),
    server: SocketAddr,
    queries: (Arc<Vec<u8>>, Arc<Vec<u8>>),
) -> Duration {
    let (slow_socket, fast_socket) = sockets;
    let (slow, fast) = queries;
    let mut total = Duration::ZERO;
    let mut buf = [0u8; 512];
    for _ in 0..iterations {
        slow_socket.send_to(&slow, server).await.expect("send slow");
        let started = Instant::now();
        fast_socket.send_to(&fast, server).await.expect("send fast");
        fast_socket.recv_from(&mut buf).await.expect("fast reply");
        total = total.saturating_add(started.elapsed());
    }
    total
}

async fn client_sockets(clients: usize) -> Vec<Arc<UdpSocket>> {
    let mut sockets = Vec::with_capacity(clients);
    for _ in 0..clients {
        sockets.push(client_socket().await);
    }
    sockets
}

fn bench_head_of_line(c: &mut Criterion, runtime: &Runtime) {
    let server = runtime.block_on(async {
        let clock = Arc::new(SystemClock::new());
        let pipeline = Arc::new(
            Pipeline::new(
                Arc::new(NoLocalRecords::new()),
                Arc::new(AllowAllFilter::new()),
                Arc::new(DiscardObserver::new()),
                Arc::clone(&clock),
            )
            .with_terminal(Arc::new(DelayTerminal)),
        );
        Server::bind(config(), pipeline, clock)
            .await
            .expect("bind server")
    });
    let addr = *server.local_addrs().first().expect("UDP address");
    let slow = Arc::new(encoded_query("slow.example."));
    let fast = Arc::new(encoded_query("fast.example."));
    let (slow_socket, fast_socket) =
        runtime.block_on(async { (client_socket().await, client_socket().await) });

    let mut group = c.benchmark_group("head_of_line");
    group.bench_function("fast_behind_slow", |b| {
        b.to_async(runtime).iter_custom(|iterations| {
            time_fast_behind_slow(
                iterations,
                (Arc::clone(&slow_socket), Arc::clone(&fast_socket)),
                addr,
                (Arc::clone(&slow), Arc::clone(&fast)),
            )
        });
    });
    group.finish();
    drop(server);
}

fn bench_listener_concurrency(c: &mut Criterion) {
    let runtime = Runtime::new().expect("tokio runtime");
    bench_udp_throughput(c, &runtime);
    bench_head_of_line(c, &runtime);
}

criterion_group!(benches, bench_listener_concurrency);
criterion_main!(benches);

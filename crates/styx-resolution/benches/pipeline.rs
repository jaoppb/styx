#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::too_many_lines
)]

use std::alloc::System;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use stats_alloc::{Region, StatsAlloc};
use styx_core::{SystemClock, Upstream, UpstreamId};
use styx_proto::{
    Header, Message, Name, Opcode, Question, RData, RecordClass, RecordType, ResourceRecord,
    ResponseCode, Ttl,
};
use styx_resolution::infrastructure::tcp_frame::write_framed;
use styx_resolution::{
    AllowAllFilter, ClientId, DiscardObserver, Do53Forwarder, EdnsBufferSize, FilterPolicy,
    FilterVerdict, LocalRecords, MaxResponseSize, NoLocalRecords, Pipeline, RequestContext,
    ResponseWriter, Transport,
};

#[global_allocator]
static GLOBAL: StatsAlloc<System> = StatsAlloc::system();

struct StaticLocalRecords {
    target_qname: Name,
    ip: Ipv4Addr,
}

impl LocalRecords for StaticLocalRecords {
    fn lookup(&self, question: &Question) -> Option<Vec<ResourceRecord>> {
        if question.qname == self.target_qname {
            Some(vec![ResourceRecord::new(
                question.qname.clone(),
                RecordType::A,
                RecordClass::In,
                Ttl::from_secs(60),
                RData::A(self.ip),
            )])
        } else {
            None
        }
    }
}

struct BlockFilter;

impl FilterPolicy for BlockFilter {
    fn evaluate(&self, _client: &ClientId, _question: &Question) -> FilterVerdict {
        FilterVerdict::Block
    }
}

fn build_query(qname_str: &str) -> Message {
    let qname = Name::from_ascii(qname_str).expect("valid qname");
    let header = Header::new_query(0x1234, Opcode::Query, true);
    let mut msg = Message::new(header);
    msg.questions
        .push(Question::new(qname, RecordType::A, RecordClass::In));
    msg
}

fn build_answer(qname_str: &str, num_records: usize) -> Message {
    let qname = Name::from_ascii(qname_str).expect("valid qname");
    let mut header = Header::new_query(0x1234, Opcode::Query, false);
    header.kind = styx_proto::MessageKind::Response;
    header.rcode = ResponseCode::NOERROR;
    let mut msg = Message::new(header);
    msg.questions
        .push(Question::new(qname.clone(), RecordType::A, RecordClass::In));

    for i in 0..num_records {
        let octet = u8::try_from(i % 250).unwrap_or(0);
        msg.answers.push(ResourceRecord::new(
            qname.clone(),
            RecordType::A,
            RecordClass::In,
            Ttl::from_secs(300),
            RData::A(Ipv4Addr::new(192, 0, 2, octet)),
        ));
    }
    msg
}

fn make_context(query: Message, transport: Transport, max_size: MaxResponseSize) -> RequestContext {
    let client = ClientId::from_socket_addr(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        12345,
    ));
    RequestContext::new(query, client, transport, max_size, Instant::now())
}

fn report_alloc(label: &str, mut f: impl FnMut()) {
    let reg = Region::new(&GLOBAL);
    f();
    let change = reg.change();
    println!(
        "ALLOC_PROFILE: {:<32} {:>4} allocs, {:>6} bytes",
        label, change.allocations, change.bytes_allocated
    );
}

fn bench_pipeline(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");

    let clock = Arc::new(SystemClock::new());
    let observer = Arc::new(DiscardObserver::new());
    let no_local = Arc::new(NoLocalRecords::new());
    let allow_filter = Arc::new(AllowAllFilter::new());

    let pipeline_refused = Pipeline::new(
        no_local.clone(),
        allow_filter.clone(),
        observer.clone(),
        clock.clone(),
    );

    let local_qname = Name::from_ascii("local.example.org.").expect("valid qname");
    let static_local = Arc::new(StaticLocalRecords {
        target_qname: local_qname,
        ip: Ipv4Addr::new(10, 0, 0, 1),
    });
    let pipeline_local = Pipeline::new(static_local, allow_filter, observer.clone(), clock.clone());

    let block_filter = Arc::new(BlockFilter);
    let pipeline_filtered = Pipeline::new(no_local, block_filter, observer, clock);

    let query_refused = build_query("refused.example.org.");
    let ctx_refused = make_context(
        query_refused,
        Transport::Udp,
        MaxResponseSize::from_edns_advertised(1232),
    );

    let query_local = build_query("local.example.org.");
    let ctx_local = make_context(
        query_local,
        Transport::Udp,
        MaxResponseSize::from_edns_advertised(1232),
    );

    let query_filtered = build_query("blocked.example.org.");
    let ctx_filtered = make_context(
        query_filtered,
        Transport::Udp,
        MaxResponseSize::from_edns_advertised(1232),
    );

    let writer = ResponseWriter::new();
    let small_answer = build_answer("small.example.org.", 1);
    let large_answer = build_answer("large.example.org.", 35);
    let ctx_udp_classic = make_context(
        build_query("small.example.org."),
        Transport::Udp,
        MaxResponseSize::classic(),
    );
    let ctx_tcp = make_context(
        build_query("small.example.org."),
        Transport::Tcp,
        MaxResponseSize::tcp_ceiling(),
    );

    let responder = rt
        .block_on(tokio::net::UdpSocket::bind("127.0.0.1:0"))
        .expect("bind responder");
    let responder_addr = responder.local_addr().expect("responder address");
    rt.spawn(async move {
        let mut buf = [0u8; 4096];
        while let Ok((n, peer)) = responder.recv_from(&mut buf).await {
            if let Some(flags) = buf.get_mut(2) {
                *flags |= 0x80;
            }
            let Some(reply) = buf.get(..n) else { continue };
            let _ = responder.send_to(reply, peer).await;
        }
    });
    let forwarder = Do53Forwarder::new(
        UpstreamId::new("bench"),
        responder_addr,
        EdnsBufferSize::default(),
        std::time::Duration::from_secs(1),
        std::time::Duration::from_secs(1),
        Arc::new(SystemClock::new()),
    );
    let forward_question = build_query("forward.example.org.")
        .questions
        .first()
        .expect("question")
        .clone();
    let tcp_body = writer
        .write(small_answer.clone(), &ctx_tcp)
        .expect("tcp body");
    let resolve_once = || {
        let deadline = Instant::now()
            .checked_add(std::time::Duration::from_secs(5))
            .unwrap_or_else(Instant::now);
        rt.block_on(forwarder.resolve(&forward_question, deadline))
    };
    let write_once = || rt.block_on(write_framed(&mut tokio::io::sink(), &tcp_body));

    println!("\n=== styx-resolution allocation profile ===");
    report_alloc("do53_resolve_udp_loopback", || {
        let _ = resolve_once();
    });
    report_alloc("tcp_write_framed", || {
        let _ = write_once();
    });
    report_alloc("response_writer_udp_fits", || {
        let _ = writer.write(small_answer.clone(), &ctx_udp_classic);
    });
    report_alloc("response_writer_udp_truncate", || {
        let _ = writer.write(large_answer.clone(), &ctx_udp_classic);
    });
    report_alloc("response_writer_tcp", || {
        let _ = writer.write(small_answer.clone(), &ctx_tcp);
    });
    report_alloc("pipeline_handle_refused", || {
        let _ = rt.block_on(pipeline_refused.handle(&ctx_refused));
    });
    report_alloc("pipeline_handle_local_hit", || {
        let _ = rt.block_on(pipeline_local.handle(&ctx_local));
    });
    report_alloc("pipeline_handle_filtered", || {
        let _ = rt.block_on(pipeline_filtered.handle(&ctx_filtered));
    });
    println!("==========================================\n");

    let mut group = c.benchmark_group("pipeline");

    group.bench_function("response_writer_udp_fits", |b| {
        b.iter_batched(
            || small_answer.clone(),
            |msg| writer.write(black_box(msg), black_box(&ctx_udp_classic)),
            BatchSize::SmallInput,
        );
    });

    group.bench_function("response_writer_udp_truncate", |b| {
        b.iter_batched(
            || large_answer.clone(),
            |msg| writer.write(black_box(msg), black_box(&ctx_udp_classic)),
            BatchSize::SmallInput,
        );
    });

    group.bench_function("response_writer_tcp", |b| {
        b.iter_batched(
            || small_answer.clone(),
            |msg| writer.write(black_box(msg), black_box(&ctx_tcp)),
            BatchSize::SmallInput,
        );
    });

    group.bench_function("do53_resolve_udp_loopback", |b| b.iter(resolve_once));

    group.bench_function("tcp_write_framed", |b| b.iter(write_once));

    group.bench_function("pipeline_handle_refused", |b| {
        b.iter(|| rt.block_on(pipeline_refused.handle(black_box(&ctx_refused))));
    });

    group.bench_function("pipeline_handle_local_hit", |b| {
        b.iter(|| rt.block_on(pipeline_local.handle(black_box(&ctx_local))));
    });

    group.bench_function("pipeline_handle_filtered", |b| {
        b.iter(|| rt.block_on(pipeline_filtered.handle(black_box(&ctx_filtered))));
    });

    group.finish();
}

criterion_group!(benches, bench_pipeline);
criterion_main!(benches);

#![allow(
    missing_docs,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::too_many_lines
)]

use std::alloc::System;
use std::net::Ipv4Addr;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use stats_alloc::{Region, StatsAlloc};
use styx_proto::application::{Decoder, Encoder};
use styx_proto::{
    Header, Message, Name, Opcode, Question, RData, RecordClass, RecordType, ResourceRecord,
    ResponseCode, Ttl,
};

#[global_allocator]
static GLOBAL: StatsAlloc<System> = StatsAlloc::system();

fn build_query() -> Message {
    let qname = Name::from_ascii("www.example.com.").expect("valid qname");
    let header = Header::new_query(0x1234, Opcode::Query, true);
    let mut msg = Message::new(header);
    msg.questions
        .push(Question::new(qname, RecordType::A, RecordClass::In));
    msg
}

fn build_cname_4a() -> Message {
    let qname = Name::from_ascii("www.example.com.").expect("valid qname");
    let cname_target = Name::from_ascii("cdn.example.com.").expect("valid target");
    let mut header = Header::new_query(0x1234, Opcode::Query, false);
    header.kind = styx_proto::MessageKind::Response;
    header.rcode = ResponseCode::NOERROR;
    let mut msg = Message::new(header);
    msg.questions
        .push(Question::new(qname.clone(), RecordType::A, RecordClass::In));

    msg.answers.push(ResourceRecord::new(
        qname,
        RecordType::CNAME,
        RecordClass::In,
        Ttl::from_secs(300),
        RData::Cname(cname_target.clone()),
    ));

    for octet in 34..38 {
        msg.answers.push(ResourceRecord::new(
            cname_target.clone(),
            RecordType::A,
            RecordClass::In,
            Ttl::from_secs(300),
            RData::A(Ipv4Addr::new(93, 184, 216, octet)),
        ));
    }
    msg
}

fn build_40_records() -> Message {
    let qname = Name::from_ascii("cluster.example.org.").expect("valid qname");
    let mut header = Header::new_query(0x1234, Opcode::Query, false);
    header.kind = styx_proto::MessageKind::Response;
    header.rcode = ResponseCode::NOERROR;
    let mut msg = Message::new(header);
    msg.questions
        .push(Question::new(qname, RecordType::A, RecordClass::In));

    for i in 0..40u8 {
        let node_name = format!("node{i}.cluster.example.org.");
        let rname = Name::from_ascii(&node_name).expect("valid node name");
        msg.answers.push(ResourceRecord::new(
            rname,
            RecordType::A,
            RecordClass::In,
            Ttl::from_secs(60),
            RData::A(Ipv4Addr::new(10, 0, i, 1)),
        ));
    }
    msg
}

fn encode_msg(msg: &Message) -> Vec<u8> {
    let mut encoder = Encoder::new(4096);
    encoder.encode_message(msg).expect("encoding succeeds");
    encoder.buf
}

fn decode_msg(bytes: &[u8]) -> Message {
    let mut decoder = Decoder::new(bytes);
    decoder.decode_message().expect("decoding succeeds")
}

fn report_alloc(label: &str, mut f: impl FnMut()) {
    let reg = Region::new(&GLOBAL);
    f();
    let change = reg.change();
    println!(
        "ALLOC_PROFILE: {:<28} {:>4} allocs, {:>6} bytes",
        label, change.allocations, change.bytes_allocated
    );
}

fn bench_codec(c: &mut Criterion) {
    let query_msg = build_query();
    let query_bytes = encode_msg(&query_msg);

    let cname_msg = build_cname_4a();
    let cname_bytes = encode_msg(&cname_msg);

    let rec40_msg = build_40_records();
    let rec40_bytes = encode_msg(&rec40_msg);

    println!("\n=== styx-proto allocation profile ===");
    report_alloc("decode_query_small", || {
        let _ = decode_msg(&query_bytes);
    });
    report_alloc("encode_query_small", || {
        let _ = encode_msg(&query_msg);
    });
    report_alloc("decode_cname_4a", || {
        let _ = decode_msg(&cname_bytes);
    });
    report_alloc("encode_cname_4a", || {
        let _ = encode_msg(&cname_msg);
    });
    report_alloc("decode_large_40_records", || {
        let _ = decode_msg(&rec40_bytes);
    });
    report_alloc("encode_large_40_records", || {
        let _ = encode_msg(&rec40_msg);
    });
    println!("=====================================\n");

    let mut group = c.benchmark_group("codec");

    group.bench_function("decode_query_small", |b| {
        b.iter(|| decode_msg(black_box(&query_bytes)));
    });
    group.bench_function("encode_query_small", |b| {
        b.iter(|| encode_msg(black_box(&query_msg)));
    });
    group.bench_function("decode_cname_4a", |b| {
        b.iter(|| decode_msg(black_box(&cname_bytes)));
    });
    group.bench_function("encode_cname_4a", |b| {
        b.iter(|| encode_msg(black_box(&cname_msg)));
    });
    group.bench_function("decode_large_40_records", |b| {
        b.iter(|| decode_msg(black_box(&rec40_bytes)));
    });
    group.bench_function("encode_large_40_records", |b| {
        b.iter(|| encode_msg(black_box(&rec40_msg)));
    });

    group.finish();
}

criterion_group!(benches, bench_codec);
criterion_main!(benches);

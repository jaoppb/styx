//! Transport and truncation integration tests.

mod harness;

use std::sync::Arc;

use harness::{DnsClient, TestServer};
use styx_proto::domain::rdata::basic::TxtRdata;
use styx_proto::domain::rdata::CharacterString;
use styx_proto::{
    Header, Message, MessageKind, Name, Opcode, Opt, Question, RData, RecordClass, RecordType,
    ResourceRecord, ResponseCode, Ttl,
};
use styx_resolution::{
    PipelineError, RequestContext, ResolutionOutcome, ResolvedSource, TerminalHandler,
};

fn make_query(name: &str, rtype: RecordType) -> Message {
    let qname = match Name::from_ascii(name) {
        Ok(q) => q,
        Err(_) => Name::root(),
    };
    let mut header = Header::new_query(0x1000, Opcode::Query, true);
    header.recursion_desired = true;
    let mut msg = Message::new(header);
    msg.questions
        .push(Question::new(qname, rtype, RecordClass::In));
    msg
}

struct LargeAnswerTerminal;

impl TerminalHandler for LargeAnswerTerminal {
    async fn handle_terminal(
        &self,
        ctx: &RequestContext,
    ) -> Result<(Message, ResolutionOutcome), PipelineError> {
        let question = ctx
            .query
            .questions
            .first()
            .cloned()
            .ok_or(PipelineError::MalformedQuery)?;
        let mut response = Message::response_to(ctx.query.header.id, question.clone());
        response.header.opcode = ctx.query.header.opcode;
        response.header.rcode = ResponseCode::NOERROR;

        let count = if question.qname.to_string().starts_with("medium") {
            5
        } else {
            25
        };

        // Generate TXT records to exceed desired limit
        for i in 0..count {
            let txt = CharacterString::new(
                format!("this is a large payload record number {i}").into_bytes(),
            );
            let rr = ResourceRecord::new(
                question.qname.clone(),
                RecordType::TXT,
                RecordClass::In,
                Ttl::from_secs(300),
                RData::Txt(TxtRdata::new(vec![txt])),
            );
            response.answers.push(rr);
        }

        if let Some(opt) = &ctx.query.opt {
            let resp_opt = Opt::new(opt.udp_payload_size(), 0, 0, false, Vec::new());
            response.opt = Some(resp_opt);
        }

        let outcome = ResolutionOutcome::Resolved {
            source: ResolvedSource::Upstream,
            rcode: ResponseCode::NOERROR,
            cacheable: false,
            authentic_data: false,
        };

        Ok((response, outcome))
    }
}

#[tokio::test]
async fn test_udp_roundtrip() {
    let mut server = TestServer::boot_ephemeral().await.expect("boot server");
    let client = DnsClient::new();
    let query = make_query("example.com.", RecordType::A);

    let response = client
        .query_udp(server.udp_addr(), &query)
        .await
        .expect("query");
    assert_eq!(response.header.id, 0x1000);
    assert_eq!(response.header.kind, MessageKind::Response);
    assert_eq!(response.header.rcode, ResponseCode::REFUSED);
    assert_eq!(response.questions.len(), 1);

    server.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn test_tcp_roundtrip_without_prior_udp() {
    let mut server = TestServer::boot_ephemeral().await.expect("boot server");
    let client = DnsClient::new();
    let query = make_query("example.com.", RecordType::A);

    let response = client
        .query_tcp(server.tcp_addr(), &query)
        .await
        .expect("query");
    assert_eq!(response.header.id, 0x1000);
    assert_eq!(response.header.kind, MessageKind::Response);
    assert_eq!(response.header.rcode, ResponseCode::REFUSED);

    server.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn test_tcp_multiple_queries_single_connection() {
    let mut server = TestServer::boot_ephemeral().await.expect("boot server");
    let mut stream = tokio::net::TcpStream::connect(server.tcp_addr())
        .await
        .expect("connect");

    for id in 1..=5 {
        let mut query = make_query("example.com.", RecordType::A);
        query.header.id = id;
        let mut encoder = styx_proto::application::Encoder::new(4096);
        encoder.encode_message(&query).expect("encode");
        let framed = styx_proto::frame_tcp(&encoder.buf).expect("frame");

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stream.write_all(&framed).await.expect("write");

        let mut len_prefix = [0u8; 2];
        stream.read_exact(&mut len_prefix).await.expect("read len");
        let len = usize::from(u16::from_be_bytes(len_prefix));
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await.expect("read payload");

        let response = Message::decode(&buf).expect("decode");
        assert_eq!(response.header.id, id);
        assert_eq!(response.header.rcode, ResponseCode::REFUSED);
    }

    server.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn test_udp_truncation_and_tcp_fallback() {
    let mut server = TestServer::boot_with_terminal(
        Arc::new(styx_resolution::NoLocalRecords::new()),
        Arc::new(styx_resolution::AllowAllFilter::new()),
        Arc::new(styx_resolution::DiscardObserver::new()),
        Arc::new(LargeAnswerTerminal),
    )
    .await
    .expect("boot server");

    let client = DnsClient::new();
    let query = make_query("large.example.com.", RecordType::TXT);

    // 1. Without EDNS on UDP: exceeds 512 bytes, TC flag set
    let udp_resp = client
        .query_udp(server.udp_addr(), &query)
        .await
        .expect("udp query");
    assert!(
        udp_resp.header.truncated,
        "TC bit must be set on UDP overflow"
    );

    // 2. Over TCP: returns full response untruncated
    let tcp_resp = client
        .query_tcp(server.tcp_addr(), &query)
        .await
        .expect("tcp query");
    assert!(!tcp_resp.header.truncated, "TCP must not truncate");
    assert!(!tcp_resp.answers.is_empty(), "TCP delivers full answers");

    // 3. UDP with advertised EDNS buffer size 4096: fits without TC
    let mut edns_query = query.clone();
    edns_query.opt = Some(Opt::new(4096, 0, 0, false, Vec::new()));
    let edns_resp = client
        .query_udp(server.udp_addr(), &edns_query)
        .await
        .expect("edns query");
    assert!(!edns_resp.header.truncated, "EDNS(0) 4096 must avoid TC");
    assert!(!edns_resp.answers.is_empty());

    // 4. UDP with advertised EDNS buffer size below 512 (e.g. 100):
    // Per RFC 6891 Section 6.2.3, values below 512 are clamped to 512.
    // 4a. A response exceeding 512 bytes still sets TC.
    let mut small_edns_query = query.clone();
    small_edns_query.opt = Some(Opt::new(100, 0, 0, false, Vec::new()));
    let small_edns_resp = client
        .query_udp(server.udp_addr(), &small_edns_query)
        .await
        .expect("small edns query");
    assert!(
        small_edns_resp.header.truncated,
        "Small advertised EDNS clamped to 512 still forces TC when payload > 512"
    );

    // 4b. A response of ~390 bytes (> 100 but < 512) is NOT truncated because 100 is clamped to 512.
    let mut medium_edns_query = make_query("medium.example.com.", RecordType::TXT);
    medium_edns_query.opt = Some(Opt::new(100, 0, 0, false, Vec::new()));
    let medium_edns_resp = client
        .query_udp(server.udp_addr(), &medium_edns_query)
        .await
        .expect("medium edns query");
    assert!(
        !medium_edns_resp.header.truncated,
        "EDNS buffer size 100 must be clamped to 512, avoiding TC for 390-byte answer"
    );
    assert!(!medium_edns_resp.answers.is_empty());

    server.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn test_malformed_inputs_yield_explicit_rcodes() {
    let mut server = TestServer::boot_ephemeral().await.expect("boot server");
    let client = DnsClient::new();

    // QDCOUNT = 0 -> FORMERR
    let mut no_q = make_query("example.com.", RecordType::A);
    no_q.questions.clear();
    let resp = client
        .query_udp(server.udp_addr(), &no_q)
        .await
        .expect("query");
    assert_eq!(resp.header.rcode, ResponseCode::FORMERR);

    // QDCOUNT = 2 -> FORMERR
    let mut multi_q = make_query("example.com.", RecordType::A);
    let second_name = match Name::from_ascii("second.com.") {
        Ok(n) => n,
        Err(_) => Name::root(),
    };
    multi_q
        .questions
        .push(Question::new(second_name, RecordType::A, RecordClass::In));
    let resp = client
        .query_udp(server.udp_addr(), &multi_q)
        .await
        .expect("query");
    assert_eq!(resp.header.rcode, ResponseCode::FORMERR);

    // Unsupported Opcode -> NOTIMP
    let mut unsupp_op = make_query("example.com.", RecordType::A);
    unsupp_op.header.opcode = Opcode::Status;
    let resp = client
        .query_udp(server.udp_addr(), &unsupp_op)
        .await
        .expect("query");
    assert_eq!(resp.header.rcode, ResponseCode::NOTIMP);

    // Unsupported Class -> NOTIMP
    let mut unsupp_class = make_query("example.com.", RecordType::A);
    if let Some(q) = unsupp_class.questions.first_mut() {
        q.qclass = RecordClass::Ch;
    }
    let resp = client
        .query_udp(server.udp_addr(), &unsupp_class)
        .await
        .expect("query");
    assert_eq!(resp.header.rcode, ResponseCode::NOTIMP);

    // Verify server remains fully functional after invalid queries
    let valid_q = make_query("example.com.", RecordType::A);
    let valid_resp = client
        .query_udp(server.udp_addr(), &valid_q)
        .await
        .expect("query");
    assert_eq!(valid_resp.header.rcode, ResponseCode::REFUSED);

    server.shutdown().await.expect("shutdown");
}

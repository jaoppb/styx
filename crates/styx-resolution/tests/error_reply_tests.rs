//! A reply the pipeline could not produce still answers the client's query: the listeners
//! shape it like any other reply, over UDP and over TCP (issue #81).

mod harness;

use std::sync::Arc;

use harness::{DnsClient, TestClock, TestServer};
use styx_proto::{
    Header, Message, MessageKind, Name, Opcode, Question, RecordClass, RecordType, ResponseCode,
};
use styx_resolution::{
    AllowAllFilter, DiscardObserver, NoLocalRecords, PipelineError, RequestContext,
    ResolutionResponse, TerminalHandler,
};

const MIXED_CASE: &str = "WwW.ExAmPlE.CoM.";

struct FailingTerminal;

impl TerminalHandler for FailingTerminal {
    async fn handle_terminal(
        &self,
        _ctx: &RequestContext,
    ) -> Result<ResolutionResponse, PipelineError> {
        Err(PipelineError::Internal("upstream unavailable".into()))
    }
}

fn query() -> Message {
    let qname = Name::from_ascii(MIXED_CASE).unwrap_or_else(|_| Name::root());
    let mut header = Header::new_query(0x2468, Opcode::Query, true);
    header.checking_disabled = true;
    let mut message = Message::new(header);
    message
        .questions
        .push(Question::new(qname, RecordType::A, RecordClass::In));
    message
}

async fn failing_server(
) -> Option<TestServer<NoLocalRecords, AllowAllFilter, DiscardObserver, TestClock, FailingTerminal>>
{
    TestServer::boot_with_terminal(
        Arc::new(NoLocalRecords::new()),
        Arc::new(AllowAllFilter::new()),
        Arc::new(DiscardObserver::new()),
        Arc::new(FailingTerminal),
    )
    .await
    .ok()
}

fn assert_shaped_error(reply: &Message) {
    assert_eq!(reply.header.id, 0x2468);
    assert_eq!(reply.header.kind, MessageKind::Response);
    assert_eq!(reply.header.rcode, ResponseCode::SERVFAIL);
    assert!(reply.header.recursion_desired);
    assert!(reply.header.checking_disabled);
    assert!(reply.header.recursion_available);
    assert!(!reply.header.authoritative);
    let asked: Vec<String> = reply
        .questions
        .iter()
        .map(|question| question.qname.to_string())
        .collect();
    assert_eq!(asked, vec![MIXED_CASE.to_string()]);
}

#[tokio::test]
async fn test_a_udp_error_reply_is_shaped_for_the_client() {
    let mut server = failing_server().await.expect("boot server");

    let reply = DnsClient::new()
        .query_udp(server.udp_addr(), &query())
        .await
        .expect("query");

    assert_shaped_error(&reply);
    server.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn test_a_tcp_error_reply_is_shaped_for_the_client() {
    let mut server = failing_server().await.expect("boot server");

    let reply = DnsClient::new()
        .query_tcp(server.tcp_addr(), &query())
        .await
        .expect("query");

    assert_shaped_error(&reply);
    server.shutdown().await.expect("shutdown");
}

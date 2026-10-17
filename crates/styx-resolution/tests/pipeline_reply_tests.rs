//! Every reply the pipeline returns is shaped by the query it answers, whichever exit produced
//! it: a local record, a blocked name or the default refusal (issue #81).

mod harness;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use harness::TestClock;
use styx_core::Clock;
use styx_proto::{
    Header, Message, Name, Opcode, Question, RData, RecordClass, RecordType, ResourceRecord,
    ResponseCode, Ttl,
};
use styx_resolution::{
    AllowAllFilter, ClientId, DiscardObserver, FilterPolicy, FilterVerdict, LocalRecords,
    MaxResponseSize, NoLocalRecords, Pipeline, RequestContext, Transport,
};

const MIXED_CASE: &str = "WwW.ExAmPlE.CoM.";

struct OneLocalRecord;

impl LocalRecords for OneLocalRecord {
    fn lookup(&self, question: &Question) -> Option<Vec<ResourceRecord>> {
        Some(vec![ResourceRecord::new(
            question.qname.clone(),
            RecordType::A,
            RecordClass::In,
            Ttl::from_secs(60),
            RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        )])
    }
}

struct BlockEverything;

impl FilterPolicy for BlockEverything {
    fn evaluate(&self, _client: &ClientId, _question: &Question) -> FilterVerdict {
        FilterVerdict::Block
    }
}

/// An RD=0, CD=1 query for a mixed-case name, which no exit may answer with its own defaults.
fn context(clock: &TestClock) -> RequestContext {
    let name = Name::from_ascii(MIXED_CASE).unwrap_or_else(|_| Name::root());
    let mut header = Header::new_query(0x1234, Opcode::Query, false);
    header.checking_disabled = true;
    let mut query = Message::new(header);
    query
        .questions
        .push(Question::new(name, RecordType::A, RecordClass::In));
    RequestContext::new(
        query,
        ClientId::from_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        Transport::Udp,
        MaxResponseSize::classic(),
        MaxResponseSize::classic(),
        clock.now_monotonic(),
    )
}

fn assert_shaped_for_the_client(reply: &Message) {
    assert_eq!(reply.header.id, 0x1234);
    assert!(!reply.header.recursion_desired);
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
async fn test_a_local_record_answer_is_shaped_for_the_client() {
    let clock = Arc::new(TestClock::new());
    let pipeline = Pipeline::new(
        Arc::new(OneLocalRecord),
        Arc::new(AllowAllFilter::new()),
        Arc::new(DiscardObserver::new()),
        Arc::clone(&clock),
    );

    let reply = pipeline.handle(&context(&clock)).await.expect("answer");

    assert_eq!(reply.answers.len(), 1);
    assert_shaped_for_the_client(&reply);
}

#[tokio::test]
async fn test_a_blocked_answer_is_shaped_for_the_client() {
    let clock = Arc::new(TestClock::new());
    let pipeline = Pipeline::new(
        Arc::new(NoLocalRecords::new()),
        Arc::new(BlockEverything),
        Arc::new(DiscardObserver::new()),
        Arc::clone(&clock),
    );

    let reply = pipeline.handle(&context(&clock)).await.expect("answer");

    assert_eq!(reply.header.rcode, ResponseCode::NXDOMAIN);
    assert_shaped_for_the_client(&reply);
}

#[tokio::test]
async fn test_the_default_refusal_is_shaped_for_the_client() {
    let clock = Arc::new(TestClock::new());
    let pipeline = Pipeline::new(
        Arc::new(NoLocalRecords::new()),
        Arc::new(AllowAllFilter::new()),
        Arc::new(DiscardObserver::new()),
        Arc::clone(&clock),
    );

    let reply = pipeline.handle(&context(&clock)).await.expect("answer");

    assert_eq!(reply.header.rcode, ResponseCode::REFUSED);
    assert_shaped_for_the_client(&reply);
}

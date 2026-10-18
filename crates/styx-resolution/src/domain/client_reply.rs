//! Shapes a response so it answers the client's query, whichever path produced it.
//!
//! The pipeline runs this once, on the way out, for every reply it returns: a cached answer,
//! a live one, a forged one and a refusal all pass the same step, so they cannot drift apart.
//! A failure the pipeline reports as an error is answered by [`error_reply`], which decides the
//! same header fields through the same rule. Those two are the only places they are decided:
//! the ID, the question as the client spelled it (ADR 0007), RD and CD come from the query, RA is
//! set because styx recurses, and AA is clear because styx is never authoritative for the zone it
//! answers about.
//!
//! RA describes styx, not the upstream behind it: it is 1 even when a forwarder answered RA=0
//! or REFUSED, because styx offers recursion to its clients whatever one pool member does.

use styx_proto::{Header, Message, MessageKind, ResponseCode};

/// Rewrites the header and question of `response` to answer `query`.
///
/// The question section becomes the query's first question with its casing intact, which a
/// 0x20-randomising client compares against what it sent.
pub fn conform_to_query(response: &mut Message, query: &Message) {
    conform_header(&mut response.header, &query.header);
    response.questions.clear();
    if let Some(question) = query.questions.first() {
        response.questions.push(question.clone());
    }
}

/// Builds the reply to a query the pipeline could not answer, carrying `rcode`.
///
/// The header follows the same rule as [`conform_to_query`]. The question section echoes every
/// question of the query, so the client sees exactly what was rejected, a multi-question query
/// included.
#[must_use]
pub fn error_reply(query: &Message, rcode: ResponseCode) -> Message {
    let mut reply = Message::new(Header::new_query(
        query.header.id,
        query.header.opcode,
        false,
    ));
    reply.header.kind = MessageKind::Response;
    reply.header.rcode = rcode;
    conform_header(&mut reply.header, &query.header);
    reply.questions = query.questions.clone();
    reply
}

fn conform_header(response: &mut Header, query: &Header) {
    response.id = query.id;
    response.recursion_desired = query.recursion_desired;
    response.checking_disabled = query.checking_disabled;
    response.recursion_available = true;
    response.authoritative = false;
}

#[cfg(test)]
mod tests {
    use styx_proto::{Name, Opcode, Question, RecordClass, RecordType};

    use super::*;

    fn question(text: &str) -> Question {
        let name = Name::from_ascii(text).unwrap_or_else(|_| Name::root());
        Question::new(name, RecordType::A, RecordClass::In)
    }

    fn query(recursion_desired: bool, checking_disabled: bool) -> Message {
        let mut header = Header::new_query(0x4321, Opcode::Query, recursion_desired);
        header.checking_disabled = checking_disabled;
        let mut message = Message::new(header);
        message.questions.push(question("WwW.ExAmPlE.CoM."));
        message
    }

    fn upstream_reply() -> Message {
        let mut reply = Message::response_to(0x1000, question("www.example.com."));
        reply.header.authoritative = true;
        reply.header.recursion_desired = true;
        reply.header.recursion_available = false;
        reply
    }

    #[test]
    fn test_the_response_takes_id_rd_cd_and_question_from_the_query() {
        let mut response = upstream_reply();

        conform_to_query(&mut response, &query(false, true));

        assert_eq!(response.header.id, 0x4321);
        assert!(!response.header.recursion_desired);
        assert!(response.header.checking_disabled);
        let asked: Vec<String> = response
            .questions
            .iter()
            .map(|question| question.qname.to_string())
            .collect();
        assert_eq!(asked, vec!["WwW.ExAmPlE.CoM.".to_string()]);
    }

    #[test]
    fn test_the_response_is_recursion_available_and_never_authoritative() {
        let mut response = upstream_reply();

        conform_to_query(&mut response, &query(true, false));

        assert!(response.header.recursion_available);
        assert!(!response.header.authoritative);
    }

    #[test]
    fn test_a_query_without_a_question_leaves_the_response_without_one() {
        let mut response = upstream_reply();
        let mut bare = query(true, false);
        bare.questions.clear();

        conform_to_query(&mut response, &bare);

        assert!(response.questions.is_empty());
    }

    #[test]
    fn test_an_error_reply_takes_its_header_from_the_query() {
        let reply = error_reply(&query(false, true), ResponseCode::SERVFAIL);

        assert_eq!(reply.header.id, 0x4321);
        assert_eq!(reply.header.kind, MessageKind::Response);
        assert_eq!(reply.header.rcode, ResponseCode::SERVFAIL);
        assert!(!reply.header.recursion_desired);
        assert!(reply.header.checking_disabled);
        assert!(reply.header.recursion_available);
        assert!(!reply.header.authoritative);
    }

    #[test]
    fn test_an_error_reply_keeps_the_opcode_and_echoes_every_question() {
        let mut asked = query(true, false);
        asked.header.opcode = Opcode::Notify;
        asked.questions.push(question("other.example."));

        let reply = error_reply(&asked, ResponseCode::NOTIMP);

        assert_eq!(reply.header.opcode, Opcode::Notify);
        let names: Vec<String> = reply
            .questions
            .iter()
            .map(|question| question.qname.to_string())
            .collect();
        assert_eq!(
            names,
            vec!["WwW.ExAmPlE.CoM.".to_string(), "other.example.".to_string()]
        );
    }
}

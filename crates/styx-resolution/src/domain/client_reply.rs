//! Shapes a response so it answers the client's query, whichever path produced it.
//!
//! A cached answer and a live one reach the client through the same step, so the two cannot
//! drift apart: the ID, the question as the client spelled it (ADR 0007), RD and CD come from
//! the query, RA is set because styx recurses, and AA is clear because styx is never
//! authoritative for the zone it answers about.

use styx_proto::Message;

/// Rewrites the header and question of `response` to answer `query`.
///
/// The question section becomes the query's first question with its casing intact, which a
/// 0x20-randomising client compares against what it sent.
pub fn conform_to_query(response: &mut Message, query: &Message) {
    response.header.id = query.header.id;
    response.header.recursion_desired = query.header.recursion_desired;
    response.header.checking_disabled = query.header.checking_disabled;
    response.header.recursion_available = true;
    response.header.authoritative = false;
    response.questions = query.questions.first().cloned().into_iter().collect();
}

#[cfg(test)]
mod tests {
    use styx_proto::{Header, Name, Opcode, Question, RecordClass, RecordType};

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
}

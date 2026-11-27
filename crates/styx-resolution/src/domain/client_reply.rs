//! Shapes a response so it answers the client's query, whichever path produced it.
//!
//! The pipeline runs this once, on the way out, for every reply it returns: a cached answer,
//! a live one, a forged one and a refusal all pass the same step, so they cannot drift apart.
//! A failure the pipeline reports as an error is answered by [`error_reply`], which decides the
//! same header fields through the same rule, and so do the FORMERR and BADVERS replies the
//! listeners send before the pipeline, through [`conform_header`]. That is the only place the
//! header fields are decided: the ID, RD and CD come from the query, RA is set because styx
//! recurses (RFC 1035 §4.1.1 makes it a property of the server, not of the RCODE), and AA is
//! clear because styx is never authoritative for the zone it answers about. The question as the
//! client spelled it (ADR 0007) is copied by [`conform_to_query`] and [`error_reply`].
//!
//! RA describes styx, not the upstream behind it: it is 1 even when a forwarder answered RA=0
//! or REFUSED, because styx offers recursion to its clients whatever one pool member does.
//!
//! AD survives only for a query that set DO or AD (RFC 6840 §5.8), whichever path built the
//! reply: the cache keeps the verdict, the client's bits decide whether it is shown.
//!
//! Every upstream query asks for DNSSEC records (RFC 4035 §3.2.1), so a reply carries
//! RRSIG, NSEC and NSEC3 records whatever the client asked. A client that did not set DO gets
//! them stripped here, except the type its question names.

use styx_proto::{Header, Message, MessageKind, RecordType, ResourceRecord, ResponseCode};

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
    // RFC 6840 §5.8: AD only for a client that showed it understands it, with DO or AD.
    response.header.authentic_data &= query.header.authentic_data || asks_for_dnssec(query);
    if !asks_for_dnssec(query) {
        strip_unrequested_dnssec(response);
    }
}

/// Whether the query set the DO bit, asking for DNSSEC records in the reply.
#[must_use]
pub fn asks_for_dnssec(query: &Message) -> bool {
    query.opt.as_ref().is_some_and(styx_proto::Opt::dnssec_ok)
}

/// Removes the RRSIG, NSEC and NSEC3 records a DO=0 client did not ask for (RFC 4035
/// §3.2.1): every one of them, except those of the type the response's question names.
fn strip_unrequested_dnssec(response: &mut Message) {
    let asked = response.questions.first().map(|question| question.qtype);
    let keep = |record: &ResourceRecord| !is_authenticating(record) || Some(record.rtype) == asked;
    response.answers.retain(keep);
    response.authorities.retain(keep);
    response.additionals.retain(keep);
}

fn is_authenticating(record: &ResourceRecord) -> bool {
    matches!(
        record.rtype,
        RecordType::RRSIG | RecordType::NSEC | RecordType::NSEC3
    )
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

/// Sets the header fields of `response` that styx decides, whichever path built the reply.
///
/// Replies built before the pipeline, such as FORMERR and BADVERS, call this directly: they have
/// a query header but no question to conform, so [`conform_to_query`] does not apply to them.
pub fn conform_header(response: &mut Header, query: &Header) {
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

    fn signed_reply(qtype: RecordType) -> Message {
        use std::net::Ipv4Addr;
        use styx_proto::{NsecRdata, RData, ResourceRecord, RrsigRdata, Ttl, TypeBitmap};

        let owner = Name::from_ascii("www.example.com.").unwrap_or_else(|_| Name::root());
        let record = |rtype, rdata| {
            ResourceRecord::new(
                owner.clone(),
                rtype,
                RecordClass::In,
                Ttl::from_secs(60),
                rdata,
            )
        };
        let rrsig = RrsigRdata::new(RecordType::A, 13, 3, 60, 0, 0, 1, Name::root(), vec![1]);
        let nsec = NsecRdata::new(owner.clone(), TypeBitmap::new(Vec::new()));
        let mut reply =
            Message::response_to(0x1000, Question::new(owner.clone(), qtype, RecordClass::In));
        reply
            .answers
            .push(record(RecordType::A, RData::A(Ipv4Addr::LOCALHOST)));
        reply
            .answers
            .push(record(RecordType::RRSIG, RData::Rrsig(rrsig)));
        reply
            .authorities
            .push(record(RecordType::NSEC, RData::Nsec(nsec)));
        reply
    }

    fn with_do(mut query: Message, dnssec_ok: bool) -> Message {
        query.opt = Some(styx_proto::Opt::new(1232, 0, dnssec_ok, Vec::new()));
        query
    }

    fn types_of(message: &Message) -> Vec<RecordType> {
        message
            .answers
            .iter()
            .chain(&message.authorities)
            .chain(&message.additionals)
            .map(|record| record.rtype)
            .collect()
    }

    #[test]
    fn test_a_do0_client_gets_no_rrsig_or_nsec_records() {
        for asked in [query(true, false), with_do(query(true, false), false)] {
            let mut response = signed_reply(RecordType::A);

            conform_to_query(&mut response, &asked);

            assert_eq!(types_of(&response), vec![RecordType::A]);
        }
    }

    #[test]
    fn test_a_do1_client_keeps_every_dnssec_record() {
        let mut response = signed_reply(RecordType::A);

        conform_to_query(&mut response, &with_do(query(true, false), true));

        assert_eq!(
            types_of(&response),
            vec![RecordType::A, RecordType::RRSIG, RecordType::NSEC]
        );
    }

    /// RFC 4035 §3.2.1: the stripping never removes the type the query asked for.
    #[test]
    fn test_a_do0_client_still_gets_the_dnssec_type_it_asked_for() {
        let mut asked = query(true, false);
        if let Some(question) = asked.questions.first_mut() {
            question.qtype = RecordType::RRSIG;
        }
        let mut response = signed_reply(RecordType::RRSIG);

        conform_to_query(&mut response, &asked);

        assert_eq!(types_of(&response), vec![RecordType::A, RecordType::RRSIG]);
    }

    fn authenticated_reply() -> Message {
        let mut reply = upstream_reply();
        reply.header.authentic_data = true;
        reply
    }

    #[test]
    fn test_ad_is_cleared_for_a_query_with_neither_do_nor_ad() {
        for asked in [query(true, false), with_do(query(true, false), false)] {
            let mut response = authenticated_reply();

            conform_to_query(&mut response, &asked);

            assert!(!response.header.authentic_data);
        }
    }

    #[test]
    fn test_ad_is_kept_for_a_query_with_do_or_ad() {
        let mut with_ad = query(true, false);
        with_ad.header.authentic_data = true;
        for asked in [with_do(query(true, false), true), with_ad] {
            let mut response = authenticated_reply();

            conform_to_query(&mut response, &asked);

            assert!(response.header.authentic_data);
        }
    }

    #[test]
    fn test_ad_is_never_set_by_the_query_alone() {
        let mut asked = with_do(query(true, false), true);
        asked.header.authentic_data = true;
        let mut response = upstream_reply();

        conform_to_query(&mut response, &asked);

        assert!(!response.header.authentic_data);
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

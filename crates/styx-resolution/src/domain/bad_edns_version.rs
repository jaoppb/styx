//! The reply to a query that asks for an EDNS version this server does not implement.

use styx_proto::{Header, Message, MessageKind, ResponseCode, UnsupportedEdns};

/// Builds the BADVERS reply RFC 6891 §6.1.3 requires.
///
/// It echoes the query's ID, opcode, RD bit and question, and carries the extended RCODE 16.
/// The OPT record advertising version 0 is attached by the response writer, which owns the
/// server's payload size.
#[must_use]
pub fn bad_edns_version_response(rejected: &UnsupportedEdns) -> Message {
    let query = rejected.header();
    let mut response = Message::new(Header::new_query(
        query.id,
        query.opcode,
        query.recursion_desired,
    ));
    response.header.kind = MessageKind::Response;
    response.header.rcode = ResponseCode::BADVERS_OR_BADSIG;
    response.questions = rejected.questions().to_vec();
    response
}

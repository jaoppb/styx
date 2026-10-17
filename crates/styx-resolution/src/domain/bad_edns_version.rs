//! The reply to a query that asks for an EDNS version this server does not implement.

use styx_proto::{Header, Message, MessageKind, Opt, ResponseCode, UnsupportedEdns};

/// Builds the BADVERS reply RFC 6891 §6.1.3 requires.
///
/// It echoes the query's ID, opcode, RD bit and question, and carries the extended RCODE 16.
/// It also carries an OPT advertising version 0, which marks the sender as an EDNS client: the
/// response writer would otherwise answer SERVFAIL, since an extended RCODE cannot go to a
/// client without one. The writer sets the OPT's payload size, which it owns.
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
    response.opt = Some(Opt::new(0, 0, false, Vec::new()));
    response
}

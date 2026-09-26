//! Top-level DNS message representation.
//!
//! A [`Message`] represents a complete DNS datagram (RFC 1035 §4.1) consisting
//! of a header and four sections: Questions, Answers, Authorities, and Additionals.
//! If an EDNS(0) OPT pseudo-record is present in the additional section, it is
//! lifted into the [`opt`](Message::opt) field.

use crate::domain::edns::Opt;
use crate::domain::header::{Header, MessageKind, Opcode, ResponseCode};
use crate::domain::question::Question;
use crate::domain::record::ResourceRecord;

/// A complete DNS message datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// The 12-octet DNS message header.
    pub header: Header,
    /// Questions section (QDCOUNT records).
    pub questions: Vec<Question>,
    /// Answers section (ANCOUNT records).
    pub answers: Vec<ResourceRecord>,
    /// Authority nameservers section (NSCOUNT records).
    pub authorities: Vec<ResourceRecord>,
    /// Additional records section (ARCOUNT records, excluding lifted OPT).
    pub additionals: Vec<ResourceRecord>,
    /// Lifted EDNS(0) OPT pseudo-record, if present.
    pub opt: Option<Opt>,
}

impl Message {
    /// Creates a new empty message with the provided header.
    #[must_use]
    pub fn new(header: Header) -> Self {
        Self {
            header,
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
            opt: None,
        }
    }

    /// Constructs a standard response skeleton to a question with the given header ID.
    #[must_use]
    pub fn response_to(id: u16, question: Question) -> Self {
        let mut header = Header::new_query(id, Opcode::Query, false);
        header.kind = MessageKind::Response;
        header.rcode = ResponseCode::NOERROR;
        Self {
            header,
            questions: vec![question],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
            opt: None,
        }
    }
}

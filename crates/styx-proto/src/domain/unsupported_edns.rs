//! A query rejected for asking for an EDNS version this codec does not implement.

use crate::domain::header::Header;
use crate::domain::question::Question;

/// What the decoder had parsed of a query when it met an OPT record with a version other
/// than 0 (RFC 6891 §6.1.3).
///
/// A responder MUST answer such a query with BADVERS, so this carries the header and the
/// question section the reply needs to echo. Nothing after the OPT record is validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedEdns {
    version: u8,
    header: Header,
    questions: Vec<Question>,
}

impl UnsupportedEdns {
    pub(crate) fn new(version: u8, header: Header, questions: Vec<Question>) -> Self {
        Self {
            version,
            header,
            questions,
        }
    }

    /// The EDNS version the sender asked for.
    #[must_use]
    pub fn version(&self) -> u8 {
        self.version
    }

    /// The header of the rejected message.
    #[must_use]
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// The question section of the rejected message.
    #[must_use]
    pub fn questions(&self) -> &[Question] {
        &self.questions
    }
}

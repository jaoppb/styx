//! DNS Question section representation.
//!
//! A [`Question`] represents a query tuple `(qname, qtype, qclass)` as
//! defined in RFC 1035 §4.1.2. Because [`Question`] serves as the primary
//! key for the answer cache (Phase 4), its equality and hash semantics are
//! case-insensitive by construction.

use crate::domain::name::Name;
use crate::domain::record::{RecordClass, RecordType};

/// A question in a DNS query or response.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Question {
    /// Domain name being queried.
    pub qname: Name,
    /// Record type requested (e.g. A, AAAA, MX, ANY).
    pub qtype: RecordType,
    /// Record class requested (typically IN).
    pub qclass: RecordClass,
}

impl Question {
    /// Creates a new question tuple.
    #[must_use]
    pub fn new(qname: Name, qtype: RecordType, qclass: RecordClass) -> Self {
        Self {
            qname,
            qtype,
            qclass,
        }
    }
}

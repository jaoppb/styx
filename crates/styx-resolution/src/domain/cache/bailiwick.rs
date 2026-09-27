//! Bailiwick zone scoping and cache-poisoning prevention.
//!
//! A responding server only holds authority over names within its assigned bailiwick zone.
//! Permitting arbitrary records into the answer cache without bailiwick verification
//! creates a classic cache-poisoning vulnerability.

use styx_proto::{Message, Question, RecordType};

use crate::domain::cache::key::CanonicalName;

/// The authoritative zone scope defining cache admission boundaries for a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bailiwick {
    zone: CanonicalName,
}

impl Bailiwick {
    /// Creates a new `Bailiwick` enclosing the given zone.
    #[must_use]
    pub const fn new(zone: CanonicalName) -> Self {
        Self { zone }
    }

    /// Derives the bailiwick zone of authority from a query question and its response message.
    ///
    /// Determination order:
    /// 1. SOA record in the authority section (its owner is the authoritative zone).
    /// 2. Deepest NS record in the authority section whose owner is at or above the qname.
    /// 3. The query name itself as fallback.
    #[must_use]
    pub fn of_response(question: &Question, message: &Message) -> Self {
        let qname_canon = CanonicalName::canonicalize(&question.qname);

        if let Some(zone) = Self::find_soa_zone(&qname_canon, message) {
            return Self { zone };
        }

        if let Some(zone) = Self::find_deepest_ns_zone(&qname_canon, message) {
            return Self { zone };
        }

        Self { zone: qname_canon }
    }

    fn find_soa_zone(qname: &CanonicalName, message: &Message) -> Option<CanonicalName> {
        for rr in &message.authorities {
            if rr.rtype != RecordType::SOA {
                continue;
            }
            let zone = CanonicalName::canonicalize(&rr.owner);
            if qname.is_subdomain_of(&zone) {
                return Some(zone);
            }
        }
        None
    }

    fn find_deepest_ns_zone(qname: &CanonicalName, message: &Message) -> Option<CanonicalName> {
        let mut deepest: Option<CanonicalName> = None;
        for rr in &message.authorities {
            if rr.rtype != RecordType::NS {
                continue;
            }
            let candidate = CanonicalName::canonicalize(&rr.owner);
            if !qname.is_subdomain_of(&candidate) {
                continue;
            }
            let is_deeper = deepest
                .as_ref()
                .is_none_or(|cur| candidate.label_count() > cur.label_count());
            if is_deeper {
                deepest = Some(candidate);
            }
        }
        deepest
    }

    /// Returns `true` if `owner` falls within this bailiwick zone.
    ///
    /// An owner name is permitted if it is equal to or a subdomain of the bailiwick zone.
    #[must_use]
    pub fn permits(&self, owner: &CanonicalName) -> bool {
        owner.is_subdomain_of(&self.zone)
    }

    /// Returns the enclosing zone of authority.
    #[must_use]
    pub const fn zone(&self) -> &CanonicalName {
        &self.zone
    }
}

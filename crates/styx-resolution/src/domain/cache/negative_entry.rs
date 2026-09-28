//! Negative cache entry representation (RFC 2308).

use std::time::Instant;

use styx_proto::{Header, Message, MessageKind, Opcode, Question, ResponseCode};

use crate::domain::cache::bytes::HeapBytes;
use crate::domain::cache::dnssec::DnssecMetadata;
use crate::domain::cache::entry::SecurityStatus;
use crate::domain::cache::error::CacheError;
use crate::domain::cache::key::CacheKey;
use crate::domain::cache::positive_entry::CachedRRset;
use crate::domain::cache::ttl::Deadline;

/// The specific variety of negative DNS denial (RFC 2308).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DenialKind {
    /// Non-Existent Domain (RCODE NXDOMAIN).
    NxDomain,
    /// Name exists, but contains no records of the requested type (RCODE NOERROR).
    NoData,
}

/// A cached negative response (RFC 2308), timed and validated by an authority SOA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegativeEntry {
    kind: DenialKind,
    soa: CachedRRset,
    deadline: Deadline,
    dnssec: DnssecMetadata,
}

impl NegativeEntry {
    /// Creates a new `NegativeEntry`.
    #[must_use]
    pub const fn new(
        kind: DenialKind,
        soa: CachedRRset,
        deadline: Deadline,
        dnssec: DnssecMetadata,
    ) -> Self {
        Self {
            kind,
            soa,
            deadline,
            dnssec,
        }
    }

    /// The denial variety (NXDOMAIN vs NODATA).
    #[must_use]
    pub const fn kind(&self) -> DenialKind {
        self.kind
    }

    /// The SOA record proving and timing this negative response.
    #[must_use]
    pub const fn soa(&self) -> &CachedRRset {
        &self.soa
    }

    /// Absolute expiration deadline computed from SOA TTL and MINIMUM.
    #[must_use]
    pub const fn deadline(&self) -> Deadline {
        self.deadline
    }

    /// Accessor for the DNSSEC metadata.
    #[must_use]
    pub const fn dnssec(&self) -> &DnssecMetadata {
        &self.dnssec
    }

    /// DNSSEC security status of the denial proof.
    #[must_use]
    pub fn security(&self) -> SecurityStatus {
        self.dnssec.status()
    }

    /// Assembles an outgoing DNS response [`Message`] representing this negative answer.
    ///
    /// # Errors
    /// Returns [`CacheError`] if SOA TTL calculation fails.
    pub fn to_response(&self, key: &CacheKey, now: Instant) -> Result<Message, CacheError> {
        let rcode = match self.kind {
            DenialKind::NxDomain => ResponseCode::NXDOMAIN,
            DenialKind::NoData => ResponseCode::NOERROR,
        };

        let mut header = Header::new_query(0, Opcode::Query, false);
        header.kind = MessageKind::Response;
        header.rcode = rcode;
        header.authoritative = true;
        header.authentic_data = self.security() == SecurityStatus::Secure;
        header.recursion_available = true;

        let mut msg = Message::new(header);
        msg.questions.push(Question::new(
            key.qname().inner().clone(),
            key.qtype(),
            key.qclass(),
        ));
        msg.authorities = self.soa.to_resource_records(now)?;

        Ok(msg)
    }

    /// Returns the estimated heap size consumed by this negative entry.
    #[must_use]
    pub fn heap_size(&self) -> HeapBytes {
        let base = std::mem::size_of::<Self>();
        let soa_bytes = self.soa.heap_size().get();
        let dnssec_bytes = self.dnssec.heap_size().get();
        HeapBytes::new(base.saturating_add(soa_bytes).saturating_add(dnssec_bytes))
    }
}

#[cfg(test)]
mod tests {
    use styx_proto::{Name, Question, RData, RecordClass, RecordType, SoaRdata, Ttl};

    use super::*;
    use crate::domain::cache::key::CanonicalName;
    use crate::domain::cache::rrset::RRset;

    #[test]
    fn test_negative_entry_accessors_and_response() {
        let name = CanonicalName::canonicalize(&Name::root());
        let soa_rdata = RData::Soa(SoaRdata::new(
            Name::root(),
            Name::root(),
            1,
            3600,
            600,
            86400,
            300,
        ));
        let rrset = RRset::new(name, RecordType::SOA, RecordClass::In, vec![soa_rdata])
            .expect("valid soa rrset");

        let now = Instant::now();
        let deadline = Deadline::from_ttl(now, Ttl::from_secs(300)).expect("valid deadline");
        let soa = CachedRRset::new(rrset, Ttl::from_secs(300), deadline);

        let entry = NegativeEntry::new(
            DenialKind::NxDomain,
            soa,
            deadline,
            DnssecMetadata::Indeterminate,
        );
        assert_eq!(entry.kind(), DenialKind::NxDomain);
        assert_eq!(entry.deadline(), deadline);
        assert_eq!(entry.dnssec(), &DnssecMetadata::Indeterminate);
        assert_eq!(entry.security(), SecurityStatus::Indeterminate);

        let question = Question::new(Name::root(), RecordType::A, RecordClass::In);
        let key = CacheKey::from_question(&question).expect("valid key");
        let resp = entry.to_response(&key, now).expect("valid response");
        assert_eq!(resp.header.rcode, ResponseCode::NXDOMAIN);
        assert_eq!(resp.authorities.len(), 1);
    }
}

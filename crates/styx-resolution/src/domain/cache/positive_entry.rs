//! Positive cache entry representations (single RRsets and composite messages).

use std::time::Instant;

use styx_proto::{
    Header, Message, MessageKind, Opcode, Question, RData, RecordClass, RecordType, ResourceRecord,
    ResponseCode, RrsigRdata, Ttl,
};

use crate::domain::cache::bytes::HeapBytes;
use crate::domain::cache::dnssec::DnssecMetadata;
use crate::domain::cache::entry::SecurityStatus;
use crate::domain::cache::error::CacheError;
use crate::domain::cache::key::{CacheKey, CanonicalName};
use crate::domain::cache::rrset::RRset;
use crate::domain::cache::ttl::Deadline;

/// Header flags preserved for a cached DNS response message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MessageFlags {
    /// Authoritative Answer (AA) flag.
    pub authoritative: bool,
    /// Authentic Data (AD) flag.
    pub authentic_data: bool,
}

/// A cached Resource Record Set (RRset) envelope combining record data, TTL, and DNSSEC state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedRRset {
    rrset: RRset,
    original_ttl: Ttl,
    deadline: Deadline,
    dnssec: DnssecMetadata,
}

impl CachedRRset {
    /// Creates a new `CachedRRset` with default (indeterminate) DNSSEC status.
    #[must_use]
    pub const fn new(rrset: RRset, original_ttl: Ttl, deadline: Deadline) -> Self {
        Self {
            rrset,
            original_ttl,
            deadline,
            dnssec: DnssecMetadata::Indeterminate,
        }
    }

    /// Creates a new `CachedRRset` with explicit DNSSEC metadata.
    #[must_use]
    pub const fn with_dnssec(
        rrset: RRset,
        original_ttl: Ttl,
        deadline: Deadline,
        dnssec: DnssecMetadata,
    ) -> Self {
        Self {
            rrset,
            original_ttl,
            deadline,
            dnssec,
        }
    }

    /// Accessor for the underlying RRset.
    #[must_use]
    pub const fn rrset(&self) -> &RRset {
        &self.rrset
    }

    /// Owner domain name in canonical form.
    #[must_use]
    pub const fn owner(&self) -> &CanonicalName {
        self.rrset.owner()
    }

    /// DNS record type.
    #[must_use]
    pub const fn rtype(&self) -> RecordType {
        self.rrset.rtype()
    }

    /// DNS record class.
    #[must_use]
    pub const fn rclass(&self) -> RecordClass {
        self.rrset.rclass()
    }

    /// Accessor for the RRset's RDATA collection.
    #[must_use]
    pub fn rdata(&self) -> &[RData] {
        self.rrset.rdata()
    }

    /// Accessor for the original TTL.
    #[must_use]
    pub const fn original_ttl(&self) -> Ttl {
        self.original_ttl
    }

    /// Absolute expiration deadline.
    #[must_use]
    pub const fn deadline(&self) -> Deadline {
        self.deadline
    }

    /// Accessor for the DNSSEC metadata.
    #[must_use]
    pub const fn dnssec(&self) -> &DnssecMetadata {
        &self.dnssec
    }

    /// DNSSEC security verdict.
    #[must_use]
    pub fn security(&self) -> SecurityStatus {
        self.dnssec.status()
    }

    /// Attached RRSIG signatures.
    #[must_use]
    pub fn signatures(&self) -> Option<&[RrsigRdata]> {
        self.dnssec.signatures()
    }

    /// Computes the remaining time-to-live for this RRset relative to `now`.
    ///
    /// # Errors
    /// Returns [`CacheError`] on calculation overflow.
    pub fn remaining_ttl(&self, now: Instant) -> Result<Ttl, CacheError> {
        self.deadline.remaining(now)
    }

    /// Converts this cached RRset into wire [`ResourceRecord`] items with recomputed TTLs.
    ///
    /// # Errors
    /// Returns [`CacheError`] if TTL recomputation fails.
    pub fn to_resource_records(&self, now: Instant) -> Result<Vec<ResourceRecord>, CacheError> {
        let ttl = self.remaining_ttl(now)?;
        Ok(self.rrset.to_resource_records(ttl))
    }

    /// Returns the estimated heap size consumed by this RRset.
    #[must_use]
    pub fn heap_size(&self) -> HeapBytes {
        let base = std::mem::size_of::<Self>();
        let rrset_heap = self.rrset.heap_size().get();
        let dnssec_heap = self.dnssec.heap_size().get();
        let total = base.saturating_add(rrset_heap).saturating_add(dnssec_heap);
        HeapBytes::new(total)
    }
}

/// A cached composite DNS message (used for CNAME chains or multi-section answers).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedMessage {
    rcode: ResponseCode,
    flags: MessageFlags,
    answer: Vec<CachedRRset>,
    authority: Vec<CachedRRset>,
    additional: Vec<CachedRRset>,
    deadline: Deadline,
}

impl CachedMessage {
    /// Creates a new `CachedMessage`.
    #[must_use]
    pub fn new(
        rcode: ResponseCode,
        flags: MessageFlags,
        answer: Vec<CachedRRset>,
        authority: Vec<CachedRRset>,
        additional: Vec<CachedRRset>,
        deadline: Deadline,
    ) -> Self {
        Self {
            rcode,
            flags,
            answer,
            authority,
            additional,
            deadline,
        }
    }

    /// Response status code.
    #[must_use]
    pub const fn rcode(&self) -> ResponseCode {
        self.rcode
    }

    /// Preserved header flags.
    #[must_use]
    pub const fn flags(&self) -> MessageFlags {
        self.flags
    }

    /// Answer section RRsets.
    #[must_use]
    pub fn answer(&self) -> &[CachedRRset] {
        &self.answer
    }

    /// Authority section RRsets.
    #[must_use]
    pub fn authority(&self) -> &[CachedRRset] {
        &self.authority
    }

    /// Additional section RRsets.
    #[must_use]
    pub fn additional(&self) -> &[CachedRRset] {
        &self.additional
    }

    /// Overall entry deadline (earliest deadline among all contained RRsets).
    #[must_use]
    pub const fn deadline(&self) -> Deadline {
        self.deadline
    }

    /// Assembles an outgoing DNS [`Message`] with recomputed remaining TTLs.
    ///
    /// # Errors
    /// Returns [`CacheError`] if TTL calculation fails.
    pub fn to_response(&self, key: &CacheKey, now: Instant) -> Result<Message, CacheError> {
        let mut header = Header::new_query(0, Opcode::Query, false);
        header.kind = MessageKind::Response;
        header.rcode = self.rcode;
        header.authoritative = self.flags.authoritative;
        header.authentic_data = self.flags.authentic_data;
        header.recursion_available = true;

        let mut msg = Message::new(header);
        msg.questions.push(Question::new(
            key.qname().inner().clone(),
            key.qtype(),
            key.qclass(),
        ));

        for rrset in &self.answer {
            msg.answers.extend(rrset.to_resource_records(now)?);
        }
        for rrset in &self.authority {
            msg.authorities.extend(rrset.to_resource_records(now)?);
        }
        for rrset in &self.additional {
            msg.additionals.extend(rrset.to_resource_records(now)?);
        }

        Ok(msg)
    }

    /// Returns the estimated heap size consumed by this cached message.
    #[must_use]
    pub fn heap_size(&self) -> HeapBytes {
        let mut total = std::mem::size_of::<Self>();
        for rr in &self.answer {
            total = total.saturating_add(rr.heap_size().get());
        }
        for rr in &self.authority {
            total = total.saturating_add(rr.heap_size().get());
        }
        for rr in &self.additional {
            total = total.saturating_add(rr.heap_size().get());
        }
        HeapBytes::new(total)
    }
}

/// A positive cache entry, holding either a single RRset or a composite message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PositiveEntry {
    /// A single RRset matching the queried name, type, and class.
    RRset(CachedRRset),
    /// A composite response with multiple sections or CNAME chains.
    Message(CachedMessage),
}

impl PositiveEntry {
    /// Returns the expiration deadline for this positive entry.
    #[must_use]
    pub fn deadline(&self) -> Deadline {
        match self {
            Self::RRset(rrset) => rrset.deadline(),
            Self::Message(msg) => msg.deadline(),
        }
    }

    /// Returns the estimated heap size consumed by this positive entry.
    #[must_use]
    pub fn heap_size(&self) -> HeapBytes {
        match self {
            Self::RRset(rrset) => rrset.heap_size(),
            Self::Message(msg) => msg.heap_size(),
        }
    }

    /// Synthesizes an outgoing DNS response [`Message`] from this entry.
    ///
    /// # Errors
    /// Returns [`CacheError`] if response construction fails.
    pub fn to_response(&self, key: &CacheKey, now: Instant) -> Result<Message, CacheError> {
        match self {
            Self::RRset(rrset) => {
                let mut header = Header::new_query(0, Opcode::Query, false);
                header.kind = MessageKind::Response;
                header.rcode = ResponseCode::NOERROR;
                header.recursion_available = true;
                header.authentic_data = rrset.security() == SecurityStatus::Secure;

                let mut msg = Message::new(header);
                msg.questions.push(Question::new(
                    key.qname().inner().clone(),
                    key.qtype(),
                    key.qclass(),
                ));
                msg.answers = rrset.to_resource_records(now)?;
                Ok(msg)
            }
            Self::Message(msg) => msg.to_response(key, now),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use styx_proto::Name;

    use super::*;

    #[test]
    fn test_cached_rrset_and_forwarding_accessors() {
        let name = CanonicalName::canonicalize(&Name::root());
        let ip = RData::A(Ipv4Addr::new(1, 1, 1, 1));
        let rrset = RRset::new(
            name.clone(),
            RecordType::A,
            RecordClass::In,
            vec![ip.clone()],
        )
        .expect("valid rrset");

        let now = Instant::now();
        let deadline = Deadline::from_ttl(now, Ttl::from_secs(300)).expect("valid deadline");
        let cached = CachedRRset::new(rrset.clone(), Ttl::from_secs(300), deadline);

        assert_eq!(cached.rrset(), &rrset);
        assert_eq!(cached.owner(), &name);
        assert_eq!(cached.rtype(), RecordType::A);
        assert_eq!(cached.rclass(), RecordClass::In);
        assert_eq!(cached.rdata(), &[ip]);
        assert_eq!(cached.original_ttl(), Ttl::from_secs(300));
        assert_eq!(cached.deadline(), deadline);
        assert_eq!(cached.dnssec(), &DnssecMetadata::Indeterminate);
        assert_eq!(cached.security(), SecurityStatus::Indeterminate);
        assert_eq!(cached.signatures(), None);

        let records = cached.to_resource_records(now).expect("records valid");
        assert_eq!(records.len(), 1);

        let secure_cached = CachedRRset::with_dnssec(
            rrset,
            Ttl::from_secs(300),
            deadline,
            DnssecMetadata::Secure { signatures: vec![] },
        );
        assert_eq!(secure_cached.security(), SecurityStatus::Secure);
        assert!(secure_cached.dnssec().is_secure());
    }
}

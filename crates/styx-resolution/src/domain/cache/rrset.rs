//! Canonical DNS Resource Record Set (RRset) representation.

use styx_proto::{RData, RecordClass, RecordType, ResourceRecord, Ttl};

use crate::domain::cache::bytes::HeapBytes;
use crate::domain::cache::error::CacheError;
use crate::domain::cache::key::CanonicalName;

/// An RFC 2181 Resource Record Set (RRset) sharing owner, type, and class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RRset {
    owner: CanonicalName,
    rtype: RecordType,
    rclass: RecordClass,
    rdata: Vec<RData>,
}

impl RRset {
    /// Creates a new `RRset` with the given owner, type, class, and RDATA set.
    ///
    /// # Errors
    /// Returns [`CacheError::EmptyRRset`] if `rdata` is empty.
    ///
    /// # Invariants
    /// Duplicate RDATA entries are filtered out while preserving first-seen order.
    pub fn new(
        owner: CanonicalName,
        rtype: RecordType,
        rclass: RecordClass,
        rdata: Vec<RData>,
    ) -> Result<Self, CacheError> {
        if rdata.is_empty() {
            return Err(CacheError::EmptyRRset);
        }
        let mut deduped = Vec::with_capacity(rdata.len());
        for item in rdata {
            if !deduped.contains(&item) {
                deduped.push(item);
            }
        }
        Ok(Self {
            owner,
            rtype,
            rclass,
            rdata: deduped,
        })
    }

    /// Owner domain name in canonical form.
    #[must_use]
    pub const fn owner(&self) -> &CanonicalName {
        &self.owner
    }

    /// DNS record type.
    #[must_use]
    pub const fn rtype(&self) -> RecordType {
        self.rtype
    }

    /// DNS record class.
    #[must_use]
    pub const fn rclass(&self) -> RecordClass {
        self.rclass
    }

    /// Accessor for the RRset's RDATA collection.
    #[must_use]
    pub fn rdata(&self) -> &[RData] {
        &self.rdata
    }

    /// Converts this RRset into wire [`ResourceRecord`] items with the specified TTL.
    #[must_use]
    pub fn to_resource_records(&self, ttl: Ttl) -> Vec<ResourceRecord> {
        let name = self.owner.inner().clone();
        self.rdata
            .iter()
            .map(|rd| ResourceRecord::new(name.clone(), self.rtype, self.rclass, ttl, rd.clone()))
            .collect()
    }

    /// Returns the estimated heap size consumed by this RRset.
    #[must_use]
    pub fn heap_size(&self) -> HeapBytes {
        let base = std::mem::size_of::<Self>();
        let name_bytes = self.owner.inner().wire_len();
        let rdata_bytes = self.rdata.len().saturating_mul(16);
        let total = base.saturating_add(name_bytes).saturating_add(rdata_bytes);
        HeapBytes::new(total)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use styx_proto::Name;

    use super::*;

    #[test]
    fn test_rrset_empty_rdata_fails() {
        let name = CanonicalName::canonicalize(&Name::root());
        let result = RRset::new(name, RecordType::A, RecordClass::In, vec![]);
        assert!(matches!(result, Err(CacheError::EmptyRRset)));
    }

    #[test]
    fn test_rrset_dedup_and_accessors() {
        let name = CanonicalName::canonicalize(&Name::root());
        let ip1 = RData::A(Ipv4Addr::new(192, 0, 2, 1));
        let ip2 = RData::A(Ipv4Addr::new(192, 0, 2, 2));
        let rdata = vec![ip1.clone(), ip2.clone(), ip1.clone()];

        let rrset = RRset::new(name.clone(), RecordType::A, RecordClass::In, rdata)
            .expect("valid non-empty rdata");
        assert_eq!(rrset.owner(), &name);
        assert_eq!(rrset.rtype(), RecordType::A);
        assert_eq!(rrset.rclass(), RecordClass::In);
        assert_eq!(rrset.rdata(), &[ip1, ip2]);
        assert_eq!(rrset.to_resource_records(Ttl::from_secs(300)).len(), 2);
    }
}

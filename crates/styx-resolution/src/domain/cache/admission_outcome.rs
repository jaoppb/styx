//! What admission decided about a response: the entries it let in, and the records
//! and answers it refused, each with the reason.

use styx_proto::RecordType;

use crate::domain::cache::entry::CacheEntry;
use crate::domain::cache::key::CanonicalName;

/// The reason a record or response was refused admission into the answer cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RejectReason {
    /// Record owner violates bailiwick boundaries of the responding authority.
    OutOfBailiwick,
    /// Response was synthesized locally (local record or block policy) and must not be cached.
    ForgedAnswer,
    /// Query asked for an uncacheable meta-qtype.
    UncacheableQtype,
    /// Record TTL is zero (served once, never stored).
    ZeroTtl,
    /// Denial response was structurally malformed.
    MalformedDenial,
    /// Negative response (NXDOMAIN or NODATA) lacked an authoritative SOA record.
    NoSoaInDenial,
    /// Positive answer whose alias chain ends in neither the asked type nor a denial,
    /// whether it looked that way as received or became so when a link was not stored.
    IncompleteChain,
    /// Response carried data but echoed no question, so it cannot be shown to answer anything.
    MalformedResponse,
    /// Record could not be represented in the cache (TTL deadline overflow or invalid RRset).
    Unstorable,
    /// Provenance source is inadmissible for caching (e.g. cache hit or error).
    InadmissibleSource,
}

/// A record rejected during cache admission evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedRecord {
    /// Owner name of the rejected record.
    pub owner: CanonicalName,
    /// Record type of the rejected record.
    pub rtype: RecordType,
    /// Why the record was rejected.
    pub reason: RejectReason,
}

impl RejectedRecord {
    pub(crate) const fn new(owner: CanonicalName, rtype: RecordType, reason: RejectReason) -> Self {
        Self {
            owner,
            rtype,
            reason,
        }
    }
}

/// The outcome of evaluating a response for cache admission.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AdmissionOutcome {
    /// Admitted entries ready for storage in the answer cache.
    pub admitted: Vec<CacheEntry>,
    /// Records rejected during admission evaluation.
    pub rejected: Vec<RejectedRecord>,
    /// Set when the response was refused as a whole answer rather than record by
    /// record: the reason it was refused for. Counted once per answer, whatever
    /// the number of records it carried.
    pub refusal: Option<RejectReason>,
}

impl AdmissionOutcome {
    /// Refuses the whole answer for `reason`, recording each of its `records`.
    pub(crate) fn refuse(&mut self, reason: RejectReason, records: Vec<RejectedRecord>) {
        self.refusal = Some(reason);
        self.rejected.extend(records);
    }
}

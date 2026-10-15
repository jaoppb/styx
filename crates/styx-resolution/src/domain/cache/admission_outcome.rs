//! What admission decided about a response: the entries it let in, and the records
//! and answers it refused, each with the reason.

use styx_proto::RecordType;

use crate::domain::cache::entry::CacheEntry;
use crate::domain::cache::key::{CacheKey, CanonicalName};
use crate::domain::cache::refusal::Refusal;

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
    /// Response carried more than one question, which RFC 9619 makes an incorrectly
    /// formatted message.
    MultipleQuestions,
    /// Response echoed no question, or one other than the client's, so it cannot be shown
    /// to answer the key it would be stored under.
    QuestionMismatch,
    /// Record could not be represented in the cache (TTL deadline overflow or invalid RRset).
    Unstorable,
    /// Provenance source is inadmissible for caching (e.g. cache hit or error).
    InadmissibleSource,
    /// Response carried an error rcode (SERVFAIL, REFUSED, FORMERR, ...), which speaks
    /// for no question and caches nothing.
    ErrorResponse,
}

impl RejectReason {
    /// Whether the response was refused for the question it echoed, which no client
    /// should be handed an answer for.
    #[must_use]
    pub const fn concerns_question(self) -> bool {
        matches!(self, Self::QuestionMismatch | Self::MultipleQuestions)
    }
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

/// What admission has admitted and refused so far, before it is bound to a key.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Tally {
    admitted: Vec<CacheEntry>,
    rejected: Vec<RejectedRecord>,
    refusal: Option<Refusal>,
}

impl Tally {
    pub(crate) fn admit_entry(&mut self, entry: CacheEntry) {
        self.admitted.push(entry);
    }

    pub(crate) fn reject(&mut self, record: RejectedRecord) {
        self.rejected.push(record);
    }

    /// Refuses the whole answer, recording each of its `records`.
    pub(crate) fn refuse(&mut self, refusal: Refusal, records: Vec<RejectedRecord>) {
        self.refusal = Some(refusal);
        self.rejected.extend(records);
    }
}

/// The outcome of evaluating a response for cache admission.
///
/// Every field is private: the key is fixed when the outcome is built from the request it
/// was judged for, so the outcome cannot be stored under another key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionOutcome {
    key: CacheKey,
    tally: Tally,
}

/// What a cache stores from an outcome: the key it was judged for and its entries.
pub(crate) struct AdmittedEntries {
    pub(crate) key: CacheKey,
    pub(crate) entries: Vec<CacheEntry>,
}

impl AdmissionOutcome {
    /// Binds what was admitted and refused to the `key` it was judged for.
    pub(crate) const fn new(key: CacheKey, tally: Tally) -> Self {
        Self { key, tally }
    }

    /// The key the response was judged for, and the one its entries are stored under.
    #[must_use]
    pub const fn key(&self) -> &CacheKey {
        &self.key
    }

    /// Admitted entries ready for storage in the answer cache.
    #[must_use]
    pub fn admitted(&self) -> &[CacheEntry] {
        &self.tally.admitted
    }

    /// Records rejected during admission evaluation.
    #[must_use]
    pub fn rejected(&self) -> &[RejectedRecord] {
        &self.tally.rejected
    }

    /// Set when the response was refused as a whole answer rather than record by
    /// record. Counted once per answer, whatever the number of records it carried.
    #[must_use]
    pub const fn refusal(&self) -> Option<&Refusal> {
        self.tally.refusal.as_ref()
    }

    /// The reason the response was refused as a whole answer, if it was.
    #[must_use]
    pub fn refusal_reason(&self) -> Option<RejectReason> {
        self.tally.refusal.as_ref().map(Refusal::reason)
    }

    /// Gives up the entries together with the key they were judged for.
    pub(crate) fn into_admitted(self) -> AdmittedEntries {
        AdmittedEntries {
            key: self.key,
            entries: self.tally.admitted,
        }
    }
}

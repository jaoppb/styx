//! Admission control, bailiwick enforcement, and cache entry ingestion.

use std::time::Instant;

use styx_proto::{Message, RData, RecordClass, RecordType, ResourceRecord, ResponseCode, Ttl};

use crate::domain::answer::AnswerSource;
use crate::domain::cache::bailiwick::Bailiwick;
use crate::domain::cache::dnssec::DnssecMetadata;
use crate::domain::cache::entry::CacheEntry;
use crate::domain::cache::key::CanonicalName;
use crate::domain::cache::negative_entry::{DenialKind, NegativeEntry};
use crate::domain::cache::positive_entry::{
    CachedMessage, CachedRRset, MessageFlags, PositiveEntry,
};
use crate::domain::cache::rrset::RRset;
use crate::domain::cache::ttl::{Deadline, TtlPolicy};

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

/// The outcome of evaluating a response for cache admission.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AdmissionOutcome {
    /// Admitted entries ready for storage in the answer cache.
    pub admitted: Vec<CacheEntry>,
    /// Records rejected during admission evaluation.
    pub rejected: Vec<RejectedRecord>,
}

/// Gatekeeper deciding what may enter the answer cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admission {
    ttl: TtlPolicy,
}

struct RawRRset {
    owner: CanonicalName,
    rtype: RecordType,
    rclass: RecordClass,
    ttl: Ttl,
    rdata: Vec<RData>,
}

impl Admission {
    /// Creates a new `Admission` controller with the given TTL policy.
    #[must_use]
    pub const fn new(ttl: TtlPolicy) -> Self {
        Self { ttl }
    }

    /// Returns the configured TTL policy.
    #[must_use]
    pub const fn ttl(&self) -> &TtlPolicy {
        &self.ttl
    }

    /// Evaluates a DNS message and its provenance source for cache admission.
    #[must_use]
    pub fn evaluate(
        &self,
        bailiwick: &Bailiwick,
        message: &Message,
        source: AnswerSource,
        now: Instant,
    ) -> AdmissionOutcome {
        let mut outcome = AdmissionOutcome::default();

        if let Some(reason) = self.check_source_eligibility(source) {
            self.reject_all_records(message, reason, &mut outcome.rejected);
            return outcome;
        }

        // Check for RFC 2308 negative response (NXDOMAIN or NODATA)
        let is_nxdomain = message.header.rcode == ResponseCode::NXDOMAIN;
        let is_nodata = message.header.rcode == ResponseCode::NOERROR && message.answers.is_empty();

        if is_nxdomain || is_nodata {
            let kind = if is_nxdomain {
                DenialKind::NxDomain
            } else {
                DenialKind::NoData
            };
            self.evaluate_denial(kind, message, now, &mut outcome);
            return outcome;
        }

        // Positive response processing
        self.evaluate_positive(bailiwick, message, now, &mut outcome);
        outcome
    }

    fn check_source_eligibility(&self, source: AnswerSource) -> Option<RejectReason> {
        match source {
            AnswerSource::LocalRecord | AnswerSource::Blocked => Some(RejectReason::ForgedAnswer),
            AnswerSource::CacheHit | AnswerSource::Error => Some(RejectReason::InadmissibleSource),
            AnswerSource::Upstream | AnswerSource::Recursion => None,
        }
    }

    fn reject_all_records(
        &self,
        message: &Message,
        reason: RejectReason,
        rejected: &mut Vec<RejectedRecord>,
    ) {
        for rr in message
            .answers
            .iter()
            .chain(&message.authorities)
            .chain(&message.additionals)
        {
            rejected.push(RejectedRecord {
                owner: CanonicalName::canonicalize(&rr.owner),
                rtype: rr.rtype,
                reason,
            });
        }
    }

    fn group_records(&self, records: &[ResourceRecord]) -> Vec<RawRRset> {
        let mut groups: Vec<RawRRset> = Vec::new();
        for rr in records {
            let owner = CanonicalName::canonicalize(&rr.owner);
            match groups
                .iter_mut()
                .find(|g| g.owner == owner && g.rtype == rr.rtype && g.rclass == rr.rclass)
            {
                Some(existing) => Self::merge_record_into_group(existing, rr),
                None => groups.push(RawRRset {
                    owner,
                    rtype: rr.rtype,
                    rclass: rr.rclass,
                    ttl: rr.ttl,
                    rdata: vec![rr.rdata.clone()],
                }),
            }
        }
        groups
    }

    fn merge_record_into_group(existing: &mut RawRRset, rr: &ResourceRecord) {
        if !existing.rdata.contains(&rr.rdata) {
            existing.rdata.push(rr.rdata.clone());
        }
        existing.ttl = existing.ttl.min(rr.ttl);
    }

    fn evaluate_denial(
        &self,
        kind: DenialKind,
        message: &Message,
        now: Instant,
        outcome: &mut AdmissionOutcome,
    ) {
        let soa_record = message
            .authorities
            .iter()
            .find(|rr| rr.rtype == RecordType::SOA);
        let Some(rr) = soa_record else {
            outcome.rejected.push(RejectedRecord {
                owner: CanonicalName::canonicalize(
                    &message
                        .questions
                        .first()
                        .map_or_else(styx_proto::Name::root, |q| q.qname.clone()),
                ),
                rtype: RecordType::SOA,
                reason: RejectReason::NoSoaInDenial,
            });
            return;
        };

        let RData::Soa(soa_rdata) = &rr.rdata else {
            return;
        };

        if rr.ttl == Ttl::ZERO {
            outcome.rejected.push(RejectedRecord {
                owner: CanonicalName::canonicalize(&rr.owner),
                rtype: RecordType::SOA,
                reason: RejectReason::ZeroTtl,
            });
            return;
        }

        let effective_ttl = self
            .ttl
            .effective_negative_ttl_raw(rr.ttl, soa_rdata.minimum());
        let Ok(deadline) = Deadline::from_ttl(now, effective_ttl) else {
            return;
        };

        let Ok(rrset) = RRset::new(
            CanonicalName::canonicalize(&rr.owner),
            RecordType::SOA,
            rr.rclass,
            vec![rr.rdata.clone()],
        ) else {
            return;
        };

        let soa_rrset = CachedRRset::new(rrset, rr.ttl, deadline);

        let negative_entry =
            NegativeEntry::new(kind, soa_rrset, deadline, DnssecMetadata::Indeterminate);

        outcome.admitted.push(CacheEntry::Negative(negative_entry));
    }

    fn evaluate_positive(
        &self,
        bailiwick: &Bailiwick,
        message: &Message,
        now: Instant,
        outcome: &mut AdmissionOutcome,
    ) {
        let mut answer_rrsets = self.admit_answers(bailiwick, message, now, outcome);
        if answer_rrsets.is_empty() {
            return;
        }

        let authority_rrsets = self.admit_authorities(bailiwick, message, now, outcome);
        let additional_rrsets = self.admit_additionals(message, &authority_rrsets, now, outcome);

        if answer_rrsets.len() == 1 && authority_rrsets.is_empty() && additional_rrsets.is_empty() {
            if let Some(rrset) = answer_rrsets.pop() {
                outcome
                    .admitted
                    .push(CacheEntry::Positive(PositiveEntry::RRset(rrset)));
                return;
            }
        }

        let fallback_deadline = match Deadline::from_ttl(now, Ttl::from_secs(60)) {
            Ok(d) => d,
            Err(_) => match Deadline::from_ttl(now, Ttl::ZERO) {
                Ok(d) => d,
                Err(_) => return,
            },
        };

        let earliest_deadline = answer_rrsets
            .iter()
            .chain(&authority_rrsets)
            .chain(&additional_rrsets)
            .map(|r| r.deadline())
            .min()
            .unwrap_or(fallback_deadline);

        let cached_msg = CachedMessage::new(
            message.header.rcode,
            MessageFlags {
                authoritative: message.header.authoritative,
                authentic_data: message.header.authentic_data,
            },
            answer_rrsets,
            authority_rrsets,
            additional_rrsets,
            earliest_deadline,
        );

        outcome
            .admitted
            .push(CacheEntry::Positive(PositiveEntry::Message(cached_msg)));
    }

    fn admit_answers(
        &self,
        bailiwick: &Bailiwick,
        message: &Message,
        now: Instant,
        outcome: &mut AdmissionOutcome,
    ) -> Vec<CachedRRset> {
        let raw_rrsets = self.group_records(&message.answers);
        let mut admitted = Vec::new();

        for raw in raw_rrsets {
            if !bailiwick.permits(&raw.owner) {
                outcome.rejected.push(RejectedRecord {
                    owner: raw.owner,
                    rtype: raw.rtype,
                    reason: RejectReason::OutOfBailiwick,
                });
                continue;
            }

            if raw.ttl == Ttl::ZERO {
                outcome.rejected.push(RejectedRecord {
                    owner: raw.owner,
                    rtype: raw.rtype,
                    reason: RejectReason::ZeroTtl,
                });
                continue;
            }

            if let Some(cached) = self.to_cached_rrset(raw, now) {
                admitted.push(cached);
            }
        }

        admitted
    }

    fn admit_authorities(
        &self,
        bailiwick: &Bailiwick,
        message: &Message,
        now: Instant,
        outcome: &mut AdmissionOutcome,
    ) -> Vec<CachedRRset> {
        let raw_rrsets = self.group_records(&message.authorities);
        let mut admitted = Vec::new();

        for raw in raw_rrsets {
            let is_permitted_type = matches!(raw.rtype, RecordType::SOA | RecordType::NS);
            let is_in_or_above =
                bailiwick.permits(&raw.owner) || bailiwick.zone().is_subdomain_of(&raw.owner);

            if !is_permitted_type || !is_in_or_above {
                outcome.rejected.push(RejectedRecord {
                    owner: raw.owner,
                    rtype: raw.rtype,
                    reason: RejectReason::OutOfBailiwick,
                });
                continue;
            }

            if raw.ttl == Ttl::ZERO {
                outcome.rejected.push(RejectedRecord {
                    owner: raw.owner,
                    rtype: raw.rtype,
                    reason: RejectReason::ZeroTtl,
                });
                continue;
            }

            if let Some(cached) = self.to_cached_rrset(raw, now) {
                admitted.push(cached);
            }
        }

        admitted
    }

    fn admit_additionals(
        &self,
        message: &Message,
        authority_rrsets: &[CachedRRset],
        now: Instant,
        outcome: &mut AdmissionOutcome,
    ) -> Vec<CachedRRset> {
        let raw_rrsets = self.group_records(&message.additionals);
        let mut admitted = Vec::new();

        for raw in raw_rrsets {
            let is_address = matches!(raw.rtype, RecordType::A | RecordType::AAAA);
            let is_glue = is_address
                && authority_rrsets.iter().any(|auth| {
                    auth.rtype() == RecordType::NS && raw.owner.is_subdomain_of(auth.owner())
                });

            if !is_glue {
                outcome.rejected.push(RejectedRecord {
                    owner: raw.owner,
                    rtype: raw.rtype,
                    reason: RejectReason::OutOfBailiwick,
                });
                continue;
            }

            if raw.ttl == Ttl::ZERO {
                outcome.rejected.push(RejectedRecord {
                    owner: raw.owner,
                    rtype: raw.rtype,
                    reason: RejectReason::ZeroTtl,
                });
                continue;
            }

            if let Some(cached) = self.to_cached_rrset(raw, now) {
                admitted.push(cached);
            }
        }

        admitted
    }

    fn to_cached_rrset(&self, raw: RawRRset, now: Instant) -> Option<CachedRRset> {
        let clamped_ttl = self.ttl.clamp(raw.ttl);
        let deadline = Deadline::from_ttl(now, clamped_ttl).ok()?;
        let rrset = RRset::new(raw.owner, raw.rtype, raw.rclass, raw.rdata).ok()?;
        Some(CachedRRset::new(rrset, raw.ttl, deadline))
    }
}

//! Admission control, bailiwick enforcement, and cache entry ingestion.

use std::time::Instant;

use styx_proto::{Message, RData, RecordType, ResourceRecord, ResponseCode, Ttl};

use crate::domain::answer::AnswerSource;
use crate::domain::cache::admission_outcome::{
    AdmissionOutcome, RejectReason, RejectedRecord, Tally,
};
use crate::domain::cache::admission_request::AdmissionRequest;
use crate::domain::cache::bailiwick::Bailiwick;
use crate::domain::cache::chain_denial::chain_is_complete;
use crate::domain::cache::dnssec::DnssecMetadata;
use crate::domain::cache::entry::CacheEntry;
use crate::domain::cache::key::CanonicalName;
use crate::domain::cache::negative_entry::{DenialKind, NegativeEntry};
use crate::domain::cache::positive_entry::{
    CachedMessage, CachedRRset, MessageFlags, PositiveEntry,
};
use crate::domain::cache::refusal::{check_question, speaks_for_question, Refusal};
use crate::domain::cache::rrset::RRset;
use crate::domain::cache::section_admission::{label_refused, AdmittedSections, SectionAdmission};
use crate::domain::cache::ttl::{Deadline, TtlPolicy};

/// Gatekeeper deciding what may enter the answer cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admission {
    ttl: TtlPolicy,
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

    /// Evaluates a DNS response and its provenance for cache admission.
    ///
    /// The response must echo exactly the client question the request was built from;
    /// otherwise it is refused whole, before any record is judged.
    #[must_use]
    pub fn evaluate(&self, request: AdmissionRequest<'_>) -> AdmissionOutcome {
        let mut tally = Tally::default();
        self.judge(&request, &mut tally);
        AdmissionOutcome::new(request.into_key(), tally)
    }

    fn judge(&self, request: &AdmissionRequest<'_>, tally: &mut Tally) {
        let message = request.message();

        if let Some(reason) = self.check_source_eligibility(request.source()) {
            tally.refuse(
                Refusal::of(reason),
                Self::reject_all_records(message, reason),
            );
            return;
        }

        if let Some(refusal) = check_question(request.question(), message) {
            let records = Self::reject_all_records(message, refusal.reason());
            tally.refuse(refusal, records);
            return;
        }

        // An error reply caches nothing, but what it carried is not lost silently.
        if !speaks_for_question(message) {
            for record in Self::reject_all_records(message, RejectReason::ErrorResponse) {
                tally.reject(record);
            }
            return;
        }

        // Check for RFC 2308 negative response (NXDOMAIN or NODATA)
        let is_nxdomain = message.header.rcode == ResponseCode::NXDOMAIN;
        let is_nodata = message.header.rcode == ResponseCode::NOERROR && message.answers.is_empty();

        // An NXDOMAIN that follows an alias chain speaks for the chain's last name, not
        // for the qname, so it is cached with its chain as a positive entry instead.
        if (is_nxdomain && message.answers.is_empty()) || is_nodata {
            let kind = if is_nxdomain {
                DenialKind::NxDomain
            } else {
                DenialKind::NoData
            };
            self.evaluate_denial(kind, request, tally);
            return;
        }

        // Positive response processing
        self.evaluate_positive(request, tally);
    }

    fn check_source_eligibility(&self, source: AnswerSource) -> Option<RejectReason> {
        match source {
            AnswerSource::LocalRecord | AnswerSource::Blocked | AnswerSource::AaaaFiltered => {
                Some(RejectReason::ForgedAnswer)
            }
            AnswerSource::CacheHit | AnswerSource::Error => Some(RejectReason::InadmissibleSource),
            AnswerSource::Upstream | AnswerSource::Recursion => None,
        }
    }

    fn reject_all_records(message: &Message, reason: RejectReason) -> Vec<RejectedRecord> {
        message
            .answers
            .iter()
            .chain(&message.authorities)
            .chain(&message.additionals)
            .map(|rr| RejectedRecord {
                owner: CanonicalName::canonicalize(&rr.owner),
                rtype: rr.rtype,
                reason,
            })
            .collect()
    }

    fn evaluate_denial(&self, kind: DenialKind, request: &AdmissionRequest<'_>, tally: &mut Tally) {
        let message = request.message();
        let now = request.now();
        let soa_record = message
            .authorities
            .iter()
            .find(|rr| rr.rtype == RecordType::SOA);
        let Some(rr) = soa_record else {
            tally.reject(RejectedRecord {
                owner: request.key().qname().clone(),
                rtype: RecordType::SOA,
                reason: RejectReason::NoSoaInDenial,
            });
            return;
        };

        let RData::Soa(soa_rdata) = &rr.rdata else {
            return;
        };

        if rr.ttl == Ttl::ZERO {
            tally.reject(RejectedRecord {
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

        tally.admit_entry(CacheEntry::Negative(negative_entry));
    }

    fn evaluate_positive(&self, request: &AdmissionRequest<'_>, tally: &mut Tally) {
        let message = request.message();
        let now = request.now();
        let qname = request.key().qname();
        let bailiwick = Bailiwick::of_response(qname, message);
        let qtype = request.key().qtype();
        let scope = bailiwick.answer_scope(qname, &message.answers);
        if !chain_is_complete(message, &scope, qtype) {
            tally.refuse(
                Refusal::of(RejectReason::IncompleteChain),
                label_refused(&bailiwick, &scope, message),
            );
            return;
        }

        let sections = SectionAdmission::new(&self.ttl);
        let admitted = sections.admit(&bailiwick, &scope, message, now, tally);
        if admitted.answers.is_empty() {
            return;
        }
        if !Self::survivors_complete(&bailiwick, qname, qtype, message, &admitted, now) {
            tally.refuse(
                Refusal::of(RejectReason::IncompleteChain),
                admitted.into_rejected(RejectReason::IncompleteChain),
            );
            return;
        }
        Self::push_positive(message, admitted, now, tally);
    }

    /// Whether what admission kept of `message` still ends its alias chain where it
    /// should. A link dropped after the chain looked complete (a zero TTL, say) leaves
    /// a bare alias or an address nothing points to, and must not be stored.
    fn survivors_complete(
        bailiwick: &Bailiwick,
        qname: &CanonicalName,
        qtype: RecordType,
        message: &Message,
        admitted: &AdmittedSections,
        now: Instant,
    ) -> bool {
        let records_of = |rrsets: &[CachedRRset]| -> Option<Vec<ResourceRecord>> {
            let mut records = Vec::new();
            for rrset in rrsets {
                records.extend(rrset.to_resource_records(now).ok()?);
            }
            Some(records)
        };
        let (Some(answers), Some(authorities)) = (
            records_of(&admitted.answers),
            records_of(&admitted.authorities),
        ) else {
            return false;
        };
        let mut survivors = message.clone();
        survivors.answers = answers;
        survivors.authorities = authorities;
        survivors.additionals.clear();
        let scope = bailiwick.answer_scope(qname, &survivors.answers);
        chain_is_complete(&survivors, &scope, qtype)
    }

    fn push_positive(
        message: &Message,
        admitted: AdmittedSections,
        now: Instant,
        tally: &mut Tally,
    ) {
        let AdmittedSections {
            mut answers,
            authorities,
            additionals,
        } = admitted;
        if answers.len() == 1 && authorities.is_empty() && additionals.is_empty() {
            if let Some(rrset) = answers.pop() {
                tally.admit_entry(CacheEntry::Positive(PositiveEntry::RRset(rrset)));
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

        let earliest_deadline = answers
            .iter()
            .chain(&authorities)
            .chain(&additionals)
            .map(|r| r.deadline())
            .min()
            .unwrap_or(fallback_deadline);

        let cached_msg = CachedMessage::new(
            message.header.rcode,
            MessageFlags {
                authentic_data: message.header.authentic_data,
            },
            answers,
            authorities,
            additionals,
            earliest_deadline,
        );

        tally.admit_entry(CacheEntry::Positive(PositiveEntry::Message(cached_msg)));
    }
}

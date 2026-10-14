//! Admission control, bailiwick enforcement, and cache entry ingestion.

use std::time::Instant;

use styx_proto::{Message, RData, RecordType, ResourceRecord, ResponseCode, Ttl};

use crate::domain::answer::AnswerSource;
use crate::domain::cache::admission_outcome::{AdmissionOutcome, RejectReason, RejectedRecord};
use crate::domain::cache::bailiwick::Bailiwick;
use crate::domain::cache::chain_denial::chain_is_complete;
use crate::domain::cache::dnssec::DnssecMetadata;
use crate::domain::cache::entry::CacheEntry;
use crate::domain::cache::key::CanonicalName;
use crate::domain::cache::negative_entry::{DenialKind, NegativeEntry};
use crate::domain::cache::positive_entry::{
    CachedMessage, CachedRRset, MessageFlags, PositiveEntry,
};
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

        // An NXDOMAIN that follows an alias chain speaks for the chain's last name, not
        // for the qname, so it is cached with its chain as a positive entry instead.
        if (is_nxdomain && message.answers.is_empty()) || is_nodata {
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
        let judged = matches!(
            message.header.rcode,
            ResponseCode::NOERROR | ResponseCode::NXDOMAIN
        );
        let question = message.questions.first();
        if judged && question.is_none() {
            let mut records = Vec::new();
            self.reject_all_records(message, RejectReason::MalformedResponse, &mut records);
            outcome.refuse(RejectReason::MalformedResponse, records);
            return;
        }
        let qname = question.map_or_else(
            || bailiwick.zone().clone(),
            |question| CanonicalName::canonicalize(&question.qname),
        );
        let scope = bailiwick.answer_scope(&qname, &message.answers);
        let qtype = question.filter(|_| judged).map(|question| question.qtype);
        if qtype.is_some_and(|qtype| !chain_is_complete(message, &scope, qtype)) {
            outcome.refuse(
                RejectReason::IncompleteChain,
                label_refused(bailiwick, &scope, message),
            );
            return;
        }

        let sections = SectionAdmission::new(&self.ttl);
        let admitted = sections.admit(bailiwick, &scope, message, now, outcome);
        if admitted.answers.is_empty() {
            return;
        }
        if let Some(qtype) = qtype {
            if !Self::survivors_complete(bailiwick, &qname, qtype, message, &admitted, now) {
                outcome.refuse(
                    RejectReason::IncompleteChain,
                    admitted.into_rejected(RejectReason::IncompleteChain),
                );
                return;
            }
        }
        Self::push_positive(message, admitted, now, outcome);
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
        outcome: &mut AdmissionOutcome,
    ) {
        let AdmittedSections {
            mut answers,
            authorities,
            additionals,
        } = admitted;
        if answers.len() == 1 && authorities.is_empty() && additionals.is_empty() {
            if let Some(rrset) = answers.pop() {
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
                authoritative: message.header.authoritative,
                authentic_data: message.header.authentic_data,
            },
            answers,
            authorities,
            additionals,
            earliest_deadline,
        );

        outcome
            .admitted
            .push(CacheEntry::Positive(PositiveEntry::Message(cached_msg)));
    }
}

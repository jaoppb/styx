//! Admission of each section of a positive response, and the labelling of the records
//! of an answer that is refused whole.
//!
//! The answer section is held to the [`AnswerScope`]; the authority section may carry
//! only SOA and NS at or above the bailiwick zone, or the SOA that closes an alias
//! chain (ADR 0020); the additional section may carry only glue for those NS. A refused
//! answer is labelled with these same rules, so a legitimate record in it is never
//! reported as a forgery.

use std::time::Instant;

use styx_proto::{Message, RData, RecordClass, RecordType, ResourceRecord, Ttl};

use crate::domain::cache::admission_outcome::{AdmissionOutcome, RejectReason, RejectedRecord};
use crate::domain::cache::answer_scope::AnswerScope;
use crate::domain::cache::bailiwick::Bailiwick;
use crate::domain::cache::chain_denial::{ends_in_denial, soa_closes_chain};
use crate::domain::cache::key::CanonicalName;
use crate::domain::cache::positive_entry::CachedRRset;
use crate::domain::cache::rrset::RRset;
use crate::domain::cache::ttl::{Deadline, TtlPolicy};

struct RawRRset {
    owner: CanonicalName,
    rtype: RecordType,
    rclass: RecordClass,
    ttl: Ttl,
    rdata: Vec<RData>,
}

/// The RRsets of each section that survived admission.
#[derive(Default)]
pub(crate) struct AdmittedSections {
    pub(crate) answers: Vec<CachedRRset>,
    pub(crate) authorities: Vec<CachedRRset>,
    pub(crate) additionals: Vec<CachedRRset>,
}

impl AdmittedSections {
    /// Every admitted RRset as the rejected record it becomes if the answer is refused.
    pub(crate) fn into_rejected(self, reason: RejectReason) -> Vec<RejectedRecord> {
        self.answers
            .iter()
            .chain(&self.authorities)
            .chain(&self.additionals)
            .map(|rrset| RejectedRecord::new(rrset.owner().clone(), rrset.rtype(), reason))
            .collect()
    }
}

/// Section-by-section admission under one TTL policy.
pub(crate) struct SectionAdmission<'a> {
    ttl: &'a TtlPolicy,
}

impl<'a> SectionAdmission<'a> {
    pub(crate) const fn new(ttl: &'a TtlPolicy) -> Self {
        Self { ttl }
    }

    /// Admits the three sections of `message`. Authority and additional records are
    /// only considered once the answer section yields something to attach them to.
    pub(crate) fn admit(
        &self,
        bailiwick: &Bailiwick,
        scope: &AnswerScope,
        message: &Message,
        now: Instant,
        outcome: &mut AdmissionOutcome,
    ) -> AdmittedSections {
        let answers = self.admit_answers(scope, message, now, outcome);
        if answers.is_empty() {
            return AdmittedSections::default();
        }
        let authorities = self.admit_authorities(bailiwick, scope, message, now, outcome);
        let additionals = self.admit_additionals(message, &authorities, now, outcome);
        AdmittedSections {
            answers,
            authorities,
            additionals,
        }
    }

    fn admit_answers(
        &self,
        scope: &AnswerScope,
        message: &Message,
        now: Instant,
        outcome: &mut AdmissionOutcome,
    ) -> Vec<CachedRRset> {
        let mut admitted = Vec::new();
        for raw in group_records(&message.answers) {
            if !scope.permits(&raw.owner, raw.rtype) {
                outcome
                    .rejected
                    .push(raw.rejected(RejectReason::OutOfBailiwick));
                continue;
            }
            admitted.extend(self.store(raw, now, outcome));
        }
        admitted
    }

    fn admit_authorities(
        &self,
        bailiwick: &Bailiwick,
        scope: &AnswerScope,
        message: &Message,
        now: Instant,
        outcome: &mut AdmissionOutcome,
    ) -> Vec<CachedRRset> {
        let denial = ends_in_denial(message, scope);
        let mut admitted = Vec::new();
        for mut raw in group_records(&message.authorities) {
            if !authority_permitted(bailiwick, scope, &raw.owner, raw.rtype, denial) {
                outcome
                    .rejected
                    .push(raw.rejected(RejectReason::OutOfBailiwick));
                continue;
            }
            if denial && raw.rtype == RecordType::SOA {
                raw.ttl = self.negative_ttl(&raw);
            }
            admitted.extend(self.store(raw, now, outcome));
        }
        admitted
    }

    /// RFC 2308 section 5: a negative answer lives for the smaller of the SOA's own
    /// TTL and its MINIMUM field.
    fn negative_ttl(&self, raw: &RawRRset) -> Ttl {
        let minimum = raw.rdata.iter().find_map(|rdata| match rdata {
            RData::Soa(soa) => Some(soa.minimum()),
            _ => None,
        });
        minimum.map_or(raw.ttl, |minimum| {
            self.ttl.effective_negative_ttl_raw(raw.ttl, minimum)
        })
    }

    fn admit_additionals(
        &self,
        message: &Message,
        authorities: &[CachedRRset],
        now: Instant,
        outcome: &mut AdmissionOutcome,
    ) -> Vec<CachedRRset> {
        let name_servers: Vec<CanonicalName> = authorities
            .iter()
            .filter(|auth| auth.rtype() == RecordType::NS)
            .map(|auth| auth.owner().clone())
            .collect();
        let mut admitted = Vec::new();
        for raw in group_records(&message.additionals) {
            if !is_glue(&raw.owner, raw.rtype, &name_servers) {
                outcome
                    .rejected
                    .push(raw.rejected(RejectReason::OutOfBailiwick));
                continue;
            }
            admitted.extend(self.store(raw, now, outcome));
        }
        admitted
    }

    /// Turns an RRset that passed its section's rule into a cache RRset, or records
    /// why it cannot be stored: a zero TTL is served once and never kept.
    fn store(
        &self,
        raw: RawRRset,
        now: Instant,
        outcome: &mut AdmissionOutcome,
    ) -> Option<CachedRRset> {
        if raw.ttl == Ttl::ZERO {
            outcome.rejected.push(raw.rejected(RejectReason::ZeroTtl));
            return None;
        }
        let (owner, rtype) = (raw.owner.clone(), raw.rtype);
        let cached = self.to_cached_rrset(raw, now);
        if cached.is_none() {
            outcome
                .rejected
                .push(RejectedRecord::new(owner, rtype, RejectReason::Unstorable));
        }
        cached
    }

    fn to_cached_rrset(&self, raw: RawRRset, now: Instant) -> Option<CachedRRset> {
        let clamped_ttl = self.ttl.clamp(raw.ttl);
        let deadline = Deadline::from_ttl(now, clamped_ttl).ok()?;
        let rrset = RRset::new(raw.owner, raw.rtype, raw.rclass, raw.rdata).ok()?;
        Some(CachedRRset::new(rrset, raw.ttl, deadline))
    }
}

impl RawRRset {
    fn rejected(self, reason: RejectReason) -> RejectedRecord {
        RejectedRecord::new(self.owner, self.rtype, reason)
    }
}

fn group_records(records: &[ResourceRecord]) -> Vec<RawRRset> {
    let mut groups: Vec<RawRRset> = Vec::new();
    for rr in records {
        let owner = CanonicalName::canonicalize(&rr.owner);
        match groups
            .iter_mut()
            .find(|g| g.owner == owner && g.rtype == rr.rtype && g.rclass == rr.rclass)
        {
            Some(existing) => merge_record_into_group(existing, rr),
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

/// Whether an authority RRset may be cached with this response: an SOA or NS at or
/// above the bailiwick zone, or an SOA that closes the alias chain the answer ends
/// in a denial of (ADR 0020).
fn authority_permitted(
    bailiwick: &Bailiwick,
    scope: &AnswerScope,
    owner: &CanonicalName,
    rtype: RecordType,
    denial: bool,
) -> bool {
    if !matches!(rtype, RecordType::SOA | RecordType::NS) {
        return false;
    }
    let in_or_above = bailiwick.permits(owner) || bailiwick.zone().is_subdomain_of(owner);
    let closes_chain = denial && rtype == RecordType::SOA && soa_closes_chain(scope, owner);
    in_or_above || closes_chain
}

/// Whether an additional record is an address for a name below an NS owner.
fn is_glue(owner: &CanonicalName, rtype: RecordType, name_servers: &[CanonicalName]) -> bool {
    matches!(rtype, RecordType::A | RecordType::AAAA)
        && name_servers
            .iter()
            .any(|server| owner.is_subdomain_of(server))
}

/// Every record of an answer refused whole, labelled by the rule of its own section:
/// a record the answer had no standing to carry is out of bailiwick, as it would be
/// in any other answer, so a forgery stays visible; the rest are refused only because
/// the answer they belong to is.
pub(crate) fn label_refused(
    bailiwick: &Bailiwick,
    scope: &AnswerScope,
    message: &Message,
) -> Vec<RejectedRecord> {
    let denial = ends_in_denial(message, scope);
    let label = |owner: CanonicalName, rtype: RecordType, standing: bool| {
        let reason = if standing {
            RejectReason::IncompleteChain
        } else {
            RejectReason::OutOfBailiwick
        };
        RejectedRecord::new(owner, rtype, reason)
    };
    let mut labelled = Vec::new();
    for record in &message.answers {
        let owner = CanonicalName::canonicalize(&record.owner);
        let standing = scope.permits(&owner, record.rtype);
        labelled.push(label(owner, record.rtype, standing));
    }
    let mut name_servers = Vec::new();
    for record in &message.authorities {
        let owner = CanonicalName::canonicalize(&record.owner);
        let standing = authority_permitted(bailiwick, scope, &owner, record.rtype, denial);
        if standing && record.rtype == RecordType::NS {
            name_servers.push(owner.clone());
        }
        labelled.push(label(owner, record.rtype, standing));
    }
    for record in &message.additionals {
        let owner = CanonicalName::canonicalize(&record.owner);
        let standing = is_glue(&owner, record.rtype, &name_servers);
        labelled.push(label(owner, record.rtype, standing));
    }
    labelled
}

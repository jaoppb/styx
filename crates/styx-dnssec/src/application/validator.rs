//! DNSSEC validator walking chains of trust from anchors to responses.

use std::sync::Arc;

use styx_core::Clock;
use styx_proto::domain::rdata::DnskeyRdata;
use styx_proto::{Message, Name, RData, RecordType, ResourceRecord};

use crate::application::denial_verifier::verify_denial_proofs;
use crate::application::descent::{walk_chain_descent, DescentResult};
use crate::domain::chain::ZoneCutMaterial;
use crate::domain::policy::ValidationPolicy;
use crate::domain::ports::{ChainSource, TrustAnchorSource};
use crate::domain::signature::{compute_dnskey_digest, verify_rrsig_record};
use crate::domain::trust_anchor::TrustAnchor;
use crate::domain::verdict::{ValidationOutcome, ValidationVerdict, VerdictReason};

/// Pure DNSSEC validator orchestrating chain-of-trust verification.
pub struct Validator<C: Clock> {
    clock: Arc<C>,
    policy: ValidationPolicy,
}

impl<C: Clock> Validator<C> {
    /// Constructs a new [`Validator`].
    #[must_use]
    pub fn new(clock: Arc<C>, policy: ValidationPolicy) -> Self {
        Self { clock, policy }
    }

    /// Returns the validator's configured policy.
    #[must_use]
    pub fn policy(&self) -> &ValidationPolicy {
        &self.policy
    }

    /// Returns the clock instance used by the validator.
    #[must_use]
    pub fn clock(&self) -> &C {
        self.clock.as_ref()
    }

    /// Evaluates a DNS message and returns a [`ValidationOutcome`].
    pub fn validate<S: ChainSource, A: TrustAnchorSource>(
        &self,
        msg: &Message,
        chain_source: &S,
        anchor_source: &A,
    ) -> ValidationOutcome {
        let Some(q) = msg.questions.first() else {
            return ValidationOutcome::new(
                ValidationVerdict::Indeterminate,
                VerdictReason::NoPathToAnchor,
            );
        };

        let span = tracing::info_span!(
            "dnssec_validate",
            qname = %q.qname,
            qtype = %q.qtype.value(),
        );
        let _guard = span.enter();

        let outcome = self.execute_validation(&q.qname, q.qtype, msg, chain_source, anchor_source);
        tracing::info!(
            verdict = ?outcome.verdict,
            reason = ?outcome.reason,
            failure_mode = ?self.policy.failure_mode,
            "DNSSEC validation completed"
        );
        outcome
    }

    fn execute_validation<S: ChainSource, A: TrustAnchorSource>(
        &self,
        qname: &Name,
        qtype: RecordType,
        msg: &Message,
        chain_source: &S,
        anchor_source: &A,
    ) -> ValidationOutcome {
        let anchors = match anchor_source.anchors() {
            Ok(a) if !a.is_empty() => a,
            _ => {
                return ValidationOutcome::new(
                    ValidationVerdict::Indeterminate,
                    VerdictReason::NoPathToAnchor,
                );
            }
        };

        let active_keys = match walk_chain_descent(self, qname, chain_source, &anchors) {
            DescentResult::AuthenticatedKeys(keys) => keys,
            DescentResult::Terminated(outcome) => return outcome,
        };

        if !msg.answers.is_empty() {
            self.verify_answer_rrsets(msg, &active_keys)
        } else {
            verify_denial_proofs(self, qname, qtype, msg, &active_keys)
        }
    }

    /// Authenticates the root zone cut against the given trust anchor.
    pub(crate) fn authenticate_root_cut(
        &self,
        cut: &ZoneCutMaterial,
        anchor: &TrustAnchor,
    ) -> Result<Vec<ResourceRecord>, ValidationOutcome> {
        let dnskeys = match cut.dnskey.as_ref() {
            Some(k) if !k.is_empty() => k,
            _ => {
                return Err(ValidationOutcome::new(
                    ValidationVerdict::Bogus,
                    VerdictReason::NoPathToAnchor,
                ));
            }
        };

        let auth_key = self.find_matching_anchor_key(dnskeys, cut, anchor)?;

        if !self.has_valid_signature_for_set(dnskeys, &cut.dnskey_signatures, auth_key, &cut.zone) {
            return Err(ValidationOutcome::new(
                ValidationVerdict::Bogus,
                VerdictReason::NoValidRrsig,
            ));
        }

        Ok(dnskeys.clone())
    }

    fn find_matching_anchor_key<'a>(
        &self,
        dnskeys: &'a [ResourceRecord],
        cut: &ZoneCutMaterial,
        anchor: &TrustAnchor,
    ) -> Result<&'a DnskeyRdata, ValidationOutcome> {
        for rr in dnskeys {
            let RData::Dnskey(ref dnskey) = rr.rdata else {
                continue;
            };
            if dnskey.key_tag() != anchor.key_tag() || dnskey.algorithm() != anchor.algorithm() {
                continue;
            }
            let Some(computed) = compute_dnskey_digest(&cut.zone, dnskey, anchor.digest_type())
            else {
                continue;
            };
            if computed.as_slice() == anchor.digest() {
                return Ok(dnskey);
            }
        }

        Err(ValidationOutcome::new(
            ValidationVerdict::Bogus,
            VerdictReason::DsDnskeyMismatch,
        ))
    }

    /// Verifies that signatures cover an RRset with a trusted DNSKEY.
    pub(crate) fn has_valid_signature_for_set(
        &self,
        rrset: &[ResourceRecord],
        signatures: &[ResourceRecord],
        dnskey: &DnskeyRdata,
        dnskey_owner: &Name,
    ) -> bool {
        signatures.iter().any(|sig_rr| match sig_rr.rdata {
            RData::Rrsig(ref rrsig) => verify_rrsig_record(
                rrsig,
                rrset,
                dnskey,
                dnskey_owner,
                self.clock.as_ref(),
                &self.policy.algorithms,
            )
            .is_ok(),
            _ => false,
        })
    }

    /// Verifies that all given records (grouped by RRset) have valid RRSIG signatures from `dnskeys`.
    pub(crate) fn verify_records_signature(
        &self,
        records: &[ResourceRecord],
        signatures: &[ResourceRecord],
        dnskeys: &[ResourceRecord],
    ) -> bool {
        let rrsets = group_into_rrsets(records);
        if rrsets.is_empty() {
            return false;
        }

        for rrset in &rrsets {
            let set_validated = dnskeys.iter().any(|key_rr| match key_rr.rdata {
                RData::Dnskey(ref dnskey) => {
                    self.has_valid_signature_for_set(rrset, signatures, dnskey, &key_rr.owner)
                }
                _ => false,
            });
            if !set_validated {
                return false;
            }
        }

        true
    }

    fn verify_answer_rrsets(&self, msg: &Message, dnskeys: &[ResourceRecord]) -> ValidationOutcome {
        let mut signatures = Vec::new();
        let mut data_records = Vec::new();

        for rr in &msg.answers {
            if let RData::Rrsig(_) = rr.rdata {
                signatures.push(rr.clone());
            } else {
                data_records.push(rr.clone());
            }
        }

        if data_records.is_empty()
            || !self.verify_records_signature(&data_records, &signatures, dnskeys)
        {
            return ValidationOutcome::new(ValidationVerdict::Bogus, VerdictReason::NoValidRrsig);
        }

        ValidationOutcome::new(ValidationVerdict::Secure, VerdictReason::AnchorMatched)
    }
}

fn is_same_rrset(a: &ResourceRecord, b: &ResourceRecord) -> bool {
    a.owner == b.owner && a.rclass == b.rclass && a.rtype == b.rtype
}

fn group_into_rrsets(records: &[ResourceRecord]) -> Vec<Vec<ResourceRecord>> {
    let mut rrsets: Vec<Vec<ResourceRecord>> = Vec::new();
    for rr in records {
        let mut found = false;
        for set in &mut rrsets {
            if set.first().is_some_and(|first| is_same_rrset(first, rr)) {
                set.push(rr.clone());
                found = true;
                break;
            }
        }
        if !found {
            rrsets.push(vec![rr.clone()]);
        }
    }
    rrsets
}

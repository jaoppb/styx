//! Key and signature authentication shared by the chain descent and the answer checks.

use std::collections::HashMap;

use styx_core::Clock;
use styx_proto::domain::rdata::{DnskeyRdata, DsRdata, RrsigRdata};
use styx_proto::{Name, RData, RecordClass, RecordType, ResourceRecord};

use crate::domain::canonical::build_canonical_signed_data;
use crate::domain::chain::SignedRrset;
use crate::domain::policy::{AlgorithmSupport, DigestType, DnssecAlgorithm, ValidationPolicy};
use crate::domain::signature::{
    check_rrsig_metadata, check_single_ds_linkage, key_matches_rrsig, verify_rrsig_bytes,
};
use crate::domain::verdict::{ValidationOutcome, VerdictReason};

/// Wildcard synthesis claim emitted when an answer RRset verified only via a wildcard RRSIG.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WildcardClaim {
    pub(crate) owner: Name,
    pub(crate) signature_labels: u8,
}

/// How an RRSIG that verified covers its RRset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignatureMatch {
    /// The RRset as it stands, at its own owner name.
    Direct,
    /// An expansion of the wildcard one label above the RRSIG's `labels` count.
    Wildcard(u8),
}

impl SignatureMatch {
    fn of(owner: &Name, labels: u8) -> Self {
        if is_expansion(owner, labels) {
            Self::Wildcard(labels)
        } else {
            Self::Direct
        }
    }
}

/// Per-validation budget bounding signature trials and failures (KeyTrap protection).
#[derive(Debug)]
pub(crate) struct VerificationBudget {
    verifications_remaining: u16,
    failures_remaining: u16,
    max_keys_per_tag_algorithm: u8,
}

impl VerificationBudget {
    pub(crate) fn from_policy(policy: &ValidationPolicy) -> Self {
        Self {
            verifications_remaining: policy.max_signature_verifications,
            failures_remaining: policy.max_signature_failures,
            max_keys_per_tag_algorithm: policy.max_keys_per_tag_algorithm,
        }
    }

    fn consume_attempt(&mut self) -> Result<(), VerdictReason> {
        if self.verifications_remaining == 0 {
            return Err(VerdictReason::SignatureBudgetExceeded);
        }
        self.verifications_remaining = self.verifications_remaining.saturating_sub(1);
        Ok(())
    }

    fn record_failure(&mut self) -> Result<(), VerdictReason> {
        if self.failures_remaining == 0 {
            return Err(VerdictReason::SignatureBudgetExceeded);
        }
        self.failures_remaining = self.failures_remaining.saturating_sub(1);
        Ok(())
    }
}

/// Verifies RRSIGs and DS-to-DNSKEY linkage under one policy and one clock.
#[derive(Debug)]
pub(crate) struct Authenticator<C: Clock> {
    clock: C,
    policy: ValidationPolicy,
}

impl<C: Clock> Authenticator<C> {
    pub(crate) fn new(clock: C, policy: ValidationPolicy) -> Self {
        Self { clock, policy }
    }

    pub(crate) fn policy(&self) -> &ValidationPolicy {
        &self.policy
    }

    /// Authenticates `zone`'s DNSKEY RRset against the DS records vouching for it — a
    /// trust anchor is a DS record nobody signed — and returns the authenticated keys.
    ///
    /// The error is the outcome the whole validation ends with: `Insecure` when no
    /// voucher uses a supported algorithm (RFC 4035 §5.2), `Bogus` otherwise.
    pub(crate) fn authenticate_keys(
        &self,
        zone: &Name,
        dnskey: &SignedRrset,
        vouchers: &[DsRdata],
        budget: &mut VerificationBudget,
    ) -> Result<Vec<ResourceRecord>, ValidationOutcome> {
        if vouchers.is_empty() {
            return Err(ValidationOutcome::bogus(VerdictReason::DsDnskeyMismatch));
        }
        let usable = self.usable_vouchers(vouchers)?;
        if !is_zone_dnskey_rrset(zone, &dnskey.records) {
            return Err(ValidationOutcome::bogus(VerdictReason::DsDnskeyMismatch));
        }
        let vouched: Vec<ResourceRecord> = vouched_keys(zone, &dnskey.records, &usable)
            .cloned()
            .collect();
        if vouched.is_empty() {
            return Err(ValidationOutcome::bogus(VerdictReason::DsDnskeyMismatch));
        }
        let records: Vec<&ResourceRecord> = dnskey.records.iter().collect();
        let signatures: Vec<&ResourceRecord> = dnskey.signatures.iter().collect();
        match self.verify_rrset_against_keys(&records, &signatures, &vouched, budget) {
            Ok(SignatureMatch::Direct) => Ok(dnskey.records.clone()),
            Ok(SignatureMatch::Wildcard(_)) => {
                Err(ValidationOutcome::bogus(VerdictReason::NoValidRrsig))
            }
            Err(reason) => Err(ValidationOutcome::bogus(reason)),
        }
    }

    /// Verifies that every RRset in `records` carries a valid RRSIG from one of `keys`
    /// that covers it as it stands, not as an expansion of a wildcard.
    pub(crate) fn authenticate_unexpanded<'a, 'b>(
        &self,
        records: impl IntoIterator<Item = &'a ResourceRecord>,
        signatures: impl IntoIterator<Item = &'b ResourceRecord>,
        keys: &[ResourceRecord],
        budget: &mut VerificationBudget,
    ) -> Result<(), VerdictReason> {
        let claims = self.authenticate_rrsets(records, signatures, keys, budget)?;
        if claims.is_empty() {
            Ok(())
        } else {
            Err(VerdictReason::NoValidRrsig)
        }
    }

    /// Verifies every RRset in `records` against `keys`, returning any wildcard synthesis
    /// claims where an RRset verified solely through a wildcard RRSIG (`labels < owner.label_count()`).
    pub(crate) fn authenticate_rrsets<'a, 'b>(
        &self,
        records: impl IntoIterator<Item = &'a ResourceRecord>,
        signatures: impl IntoIterator<Item = &'b ResourceRecord>,
        keys: &[ResourceRecord],
        budget: &mut VerificationBudget,
    ) -> Result<Vec<WildcardClaim>, VerdictReason> {
        let rrsets = group_into_rrsets(records);
        if rrsets.is_empty() {
            return Err(VerdictReason::NoValidRrsig);
        }
        let signature_list: Vec<&ResourceRecord> = signatures.into_iter().collect();
        let mut wildcard_claims = Vec::new();
        for rrset in rrsets {
            let SignatureMatch::Wildcard(labels) =
                self.verify_rrset_against_keys(&rrset, &signature_list, keys, budget)?
            else {
                continue;
            };
            if let Some(first) = rrset.first() {
                wildcard_claims.push(WildcardClaim {
                    owner: first.owner.clone(),
                    signature_labels: labels,
                });
            }
        }
        Ok(wildcard_claims)
    }

    fn verify_rrset_against_keys(
        &self,
        rrset: &[&ResourceRecord],
        signatures: &[&ResourceRecord],
        keys: &[ResourceRecord],
        budget: &mut VerificationBudget,
    ) -> Result<SignatureMatch, VerdictReason> {
        let Some(first) = rrset.first() else {
            return Err(VerdictReason::NoValidRrsig);
        };
        let tagged = tagged_keys(keys);
        let mut last_error = VerdictReason::NoValidRrsig;
        let mut per_tag_algorithm: HashMap<(u16, u8), u8> = HashMap::new();
        for signature_record in signatures {
            let RData::Rrsig(ref rrsig) = signature_record.rdata else {
                continue;
            };
            if !signature_record.owner.eq_ignore_case(&first.owner)
                || signature_record.rclass != first.rclass
                || rrsig.type_covered() != first.rtype
            {
                continue;
            }
            let tag_algorithm = (rrsig.key_tag(), rrsig.algorithm());
            let tried = per_tag_algorithm.entry(tag_algorithm).or_insert(0);
            let limit = budget.max_keys_per_tag_algorithm;
            if *tried >= limit {
                continue;
            }
            let matching =
                matching_keys_for_rrsig(rrsig, &tagged, usize::from(limit.saturating_sub(*tried)));
            if matching.is_empty() {
                continue;
            }
            let algorithm = match check_rrsig_metadata(rrsig, rrset, &self.clock) {
                Ok(algorithm) => algorithm,
                Err(reason) => {
                    last_error = reason;
                    continue;
                }
            };
            if let Some(found) = self.verify_rrsig_with_matching_keys(
                rrset, rrsig, algorithm, &matching, tried, budget,
            )? {
                return Ok(found);
            }
        }
        Err(last_error)
    }

    fn verify_rrsig_with_matching_keys(
        &self,
        rrset: &[&ResourceRecord],
        rrsig: &RrsigRdata,
        algorithm: DnssecAlgorithm,
        matching: &[&DnskeyRdata],
        tried: &mut u8,
        budget: &mut VerificationBudget,
    ) -> Result<Option<SignatureMatch>, VerdictReason> {
        let Some(first) = rrset.first() else {
            return Err(VerdictReason::NoValidRrsig);
        };
        let Ok(signed_data) = build_canonical_signed_data(rrsig, rrset) else {
            return Ok(None);
        };
        for &key in matching {
            budget.consume_attempt()?;
            *tried = tried.saturating_add(1);
            if verify_rrsig_bytes(algorithm, key, &signed_data, rrsig.signature()) {
                return Ok(Some(SignatureMatch::of(&first.owner, rrsig.labels())));
            }
            budget.record_failure()?;
        }
        Ok(None)
    }

    fn usable_vouchers<'a>(
        &self,
        vouchers: &'a [DsRdata],
    ) -> Result<Vec<&'a DsRdata>, ValidationOutcome> {
        let usable: Vec<&DsRdata> = vouchers
            .iter()
            .filter(|ds| {
                AlgorithmSupport::both(
                    DnssecAlgorithm::new(ds.algorithm()).support(),
                    DigestType::new(ds.digest_type()).support(),
                ) == AlgorithmSupport::Supported
            })
            .collect();
        if usable.is_empty() {
            // The DS RRset is already authenticated by the parent, so treating the child
            // as unsigned opens no downgrade an attacker could forge (RFC 6840 §5.2).
            return Err(ValidationOutcome::insecure(
                VerdictReason::UnsupportedAlgorithm,
            ));
        }
        Ok(usable)
    }
}

/// A DNSKEY with its key tag computed once, however many RRSIGs it is matched against.
struct TaggedKey<'a> {
    owner: &'a Name,
    key: &'a DnskeyRdata,
    tag: u16,
}

fn tagged_keys(keys: &[ResourceRecord]) -> Vec<TaggedKey<'_>> {
    keys.iter()
        .filter_map(|record| match record.rdata {
            RData::Dnskey(ref key) => Some(TaggedKey {
                owner: &record.owner,
                key,
                tag: key.key_tag(),
            }),
            _ => None,
        })
        .collect()
}

fn matching_keys_for_rrsig<'a>(
    rrsig: &RrsigRdata,
    keys: &[TaggedKey<'a>],
    remaining: usize,
) -> Vec<&'a DnskeyRdata> {
    keys.iter()
        .filter(|tagged| key_matches_rrsig(rrsig, tagged.key, tagged.owner, tagged.tag))
        .map(|tagged| tagged.key)
        .take(remaining)
        .collect()
}

/// Whether every record of `records` is a DNSKEY of class IN owned by `zone`: the only
/// RRset a DS or a trust anchor for `zone` can vouch for.
fn is_zone_dnskey_rrset(zone: &Name, records: &[ResourceRecord]) -> bool {
    records.iter().all(|record| {
        record.owner.eq_ignore_case(zone)
            && record.rclass == RecordClass::In
            && record.rtype == RecordType::DNSKEY
            && matches!(record.rdata, RData::Dnskey(_))
    })
}

/// Every DNSKEY record in `dnskeys` that one of `vouchers` matches.
fn vouched_keys<'a>(
    zone: &'a Name,
    dnskeys: &'a [ResourceRecord],
    vouchers: &'a [&DsRdata],
) -> impl Iterator<Item = &'a ResourceRecord> {
    dnskeys.iter().filter(move |record| match record.rdata {
        RData::Dnskey(ref key) => vouchers
            .iter()
            .any(|ds| check_single_ds_linkage(zone, ds, key)),
        _ => false,
    })
}

/// Whether an RRSIG with `labels` labels over `owner` covers a wildcard expansion.
/// A literal `*` owner has one label more than its RRSIG's count but is not an
/// expansion (RFC 4035 §5.3.2).
fn is_expansion(owner: &Name, labels: u8) -> bool {
    let labels = usize::from(labels);
    let owner_labels = owner.label_count();
    if labels >= owner_labels {
        return false;
    }
    let literal_wildcard = owner
        .labels()
        .next()
        .is_some_and(|first| first.as_bytes() == b"*");
    !(literal_wildcard && labels.checked_add(1) == Some(owner_labels))
}

pub(crate) fn group_into_rrsets<'a>(
    records: impl IntoIterator<Item = &'a ResourceRecord>,
) -> Vec<Vec<&'a ResourceRecord>> {
    let mut rrsets: HashMap<(&Name, RecordClass, RecordType), Vec<&ResourceRecord>> =
        HashMap::new();
    for record in records {
        rrsets
            .entry((&record.owner, record.rclass, record.rtype))
            .or_default()
            .push(record);
    }
    rrsets.into_values().collect()
}

#[cfg(test)]
mod tests {
    use styx_core::test_util::TestClock;

    use super::*;
    use crate::domain::verdict::ValidationVerdict;

    #[test]
    fn authenticate_keys_rejects_empty_vouchers_as_bogus() {
        let auth = Authenticator::new(TestClock::new(), ValidationPolicy::default());
        let mut budget = VerificationBudget::from_policy(auth.policy());
        let zone = Name::from_ascii("example.").unwrap();
        let dnskey = SignedRrset::new(Vec::new(), Vec::new());

        let outcome = auth
            .authenticate_keys(&zone, &dnskey, &[], &mut budget)
            .unwrap_err();
        assert_eq!(
            outcome,
            ValidationOutcome::bogus(VerdictReason::DsDnskeyMismatch)
        );
        assert_ne!(outcome.verdict, ValidationVerdict::Insecure);
    }
}

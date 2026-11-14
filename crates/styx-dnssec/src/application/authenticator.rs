//! Key and signature authentication shared by the chain descent and the answer checks.

use std::collections::HashMap;

use styx_core::Clock;
use styx_proto::domain::rdata::{DnskeyRdata, DsRdata};
use styx_proto::{Name, RData, ResourceRecord};

use crate::domain::chain::SignedRrset;
use crate::domain::policy::{AlgorithmSupport, DigestType, DnssecAlgorithm, ValidationPolicy};
use crate::domain::signature::{check_single_ds_linkage, verify_rrsig_record};
use crate::domain::verdict::{ValidationOutcome, VerdictReason};

/// Wildcard synthesis claim emitted when an answer RRset verified only via a wildcard RRSIG.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WildcardClaim {
    pub(crate) owner: Name,
    pub(crate) sig_labels: u8,
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
    /// voucher uses an algorithm the policy supports (RFC 4035 §5.2), `Bogus` otherwise.
    pub(crate) fn authenticate_keys(
        &self,
        zone: &Name,
        dnskey: &SignedRrset,
        vouchers: &[DsRdata],
    ) -> Result<Vec<ResourceRecord>, ValidationOutcome> {
        let usable = self.usable_vouchers(vouchers)?;
        let key = find_vouched_key(zone, &dnskey.records, &usable)
            .ok_or_else(|| ValidationOutcome::bogus(VerdictReason::DsDnskeyMismatch))?;
        let records: Vec<&ResourceRecord> = dnskey.records.iter().collect();
        let signatures: Vec<&ResourceRecord> = dnskey.signatures.iter().collect();
        if self
            .verify_rrset_with_key(&records, &signatures, key, zone)
            .is_err()
        {
            return Err(ValidationOutcome::bogus(VerdictReason::NoValidRrsig));
        }
        Ok(dnskey.records.clone())
    }

    /// Whether every RRset in `records` carries a valid RRSIG from one of `keys`.
    pub(crate) fn records_signed_by_any<'a, 'b>(
        &self,
        records: impl IntoIterator<Item = &'a ResourceRecord>,
        signatures: impl IntoIterator<Item = &'b ResourceRecord>,
        keys: &[ResourceRecord],
    ) -> bool {
        self.authenticate_rrsets(records, signatures, keys).is_ok()
    }

    /// Verifies every RRset in `records` against `keys`, returning any wildcard synthesis
    /// claims where an RRset verified solely through a wildcard RRSIG (`labels < owner.label_count()`).
    pub(crate) fn authenticate_rrsets<'a, 'b>(
        &self,
        records: impl IntoIterator<Item = &'a ResourceRecord>,
        signatures: impl IntoIterator<Item = &'b ResourceRecord>,
        keys: &[ResourceRecord],
    ) -> Result<Vec<WildcardClaim>, VerdictReason> {
        let rrsets = group_into_rrsets(records);
        if rrsets.is_empty() {
            return Err(VerdictReason::NoValidRrsig);
        }
        let sig_list: Vec<&ResourceRecord> = signatures.into_iter().collect();
        let mut wildcard_claims = Vec::new();
        for rrset in rrsets {
            let Some(labels) = self.verify_rrset_against_keys(&rrset, &sig_list, keys)? else {
                continue;
            };
            if let Some(first) = rrset.first() {
                wildcard_claims.push(WildcardClaim {
                    owner: first.owner.clone(),
                    sig_labels: labels,
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
    ) -> Result<Option<u8>, VerdictReason> {
        let mut wildcard_labels: Option<u8> = None;
        for key_record in keys {
            let RData::Dnskey(ref key) = key_record.rdata else {
                continue;
            };
            let Ok(labels) = self.verify_rrset_with_key(rrset, signatures, key, &key_record.owner)
            else {
                continue;
            };
            let Some(first) = rrset.first() else {
                return Err(VerdictReason::NoValidRrsig);
            };
            if usize::from(labels) == first.owner.label_count() {
                return Ok(None);
            }
            wildcard_labels = Some(labels);
        }
        wildcard_labels.map(Some).ok_or(VerdictReason::NoValidRrsig)
    }

    fn verify_rrset_with_key(
        &self,
        rrset: &[&ResourceRecord],
        signatures: &[&ResourceRecord],
        dnskey: &DnskeyRdata,
        dnskey_owner: &Name,
    ) -> Result<u8, VerdictReason> {
        for signature in signatures {
            let RData::Rrsig(ref rrsig) = signature.rdata else {
                continue;
            };
            if verify_rrsig_record(
                rrsig,
                rrset,
                dnskey,
                dnskey_owner,
                &self.clock,
                &self.policy.algorithms,
            )
            .is_ok()
            {
                return Ok(rrsig.labels());
            }
        }
        Err(VerdictReason::NoValidRrsig)
    }

    fn usable_vouchers<'a>(
        &self,
        vouchers: &'a [DsRdata],
    ) -> Result<Vec<&'a DsRdata>, ValidationOutcome> {
        let mut usable = Vec::new();
        let mut any_unknown = false;
        for ds in vouchers {
            let support = AlgorithmSupport::combine(
                self.policy
                    .algorithms
                    .classify_sig(DnssecAlgorithm::new(ds.algorithm())),
                self.policy
                    .algorithms
                    .classify_digest(DigestType::new(ds.digest_type())),
            );
            match support {
                AlgorithmSupport::Supported => usable.push(ds),
                AlgorithmSupport::UnknownTreatAsInsecure => any_unknown = true,
                AlgorithmSupport::Refused => {}
            }
        }
        if !usable.is_empty() {
            return Ok(usable);
        }
        if any_unknown {
            return Err(ValidationOutcome::insecure(
                VerdictReason::UnsupportedAlgorithm,
            ));
        }
        Err(ValidationOutcome::bogus(VerdictReason::DsDnskeyMismatch))
    }
}

fn find_vouched_key<'a>(
    zone: &Name,
    dnskeys: &'a [ResourceRecord],
    vouchers: &[&DsRdata],
) -> Option<&'a DnskeyRdata> {
    dnskeys.iter().find_map(|record| match record.rdata {
        RData::Dnskey(ref key) => vouchers
            .iter()
            .any(|ds| check_single_ds_linkage(zone, ds, key))
            .then_some(key),
        _ => None,
    })
}

fn group_into_rrsets<'a>(
    records: impl IntoIterator<Item = &'a ResourceRecord>,
) -> Vec<Vec<&'a ResourceRecord>> {
    let mut rrsets: HashMap<_, Vec<&ResourceRecord>> = HashMap::new();
    for record in records {
        rrsets
            .entry((&record.owner, record.rclass, record.rtype))
            .or_default()
            .push(record);
    }
    rrsets.into_values().collect()
}

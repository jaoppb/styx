//! Key and signature authentication shared by the chain descent and the answer checks.

use std::borrow::Borrow;
use std::collections::HashMap;

use styx_core::Clock;
use styx_proto::domain::rdata::{DnskeyRdata, DsRdata};
use styx_proto::{Name, RData, ResourceRecord};

use crate::domain::chain::SignedRrset;
use crate::domain::policy::{AlgorithmSupport, ValidationPolicy};
use crate::domain::signature::{check_single_ds_linkage, verify_rrsig_record};
use crate::domain::verdict::{ValidationOutcome, VerdictReason};

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
        if !self.rrset_signed_by(&dnskey.records, &dnskey.signatures, key, zone) {
            return Err(ValidationOutcome::bogus(VerdictReason::NoValidRrsig));
        }
        Ok(dnskey.records.clone())
    }

    /// Whether every RRset in `records` carries a valid RRSIG from one of `keys`.
    pub(crate) fn records_signed_by_any<R, S>(
        &self,
        records: &[R],
        signatures: &[S],
        keys: &[ResourceRecord],
    ) -> bool
    where
        R: Borrow<ResourceRecord>,
        S: Borrow<ResourceRecord>,
    {
        let rrsets = group_into_rrsets(records);
        !rrsets.is_empty()
            && rrsets.iter().all(|rrset| {
                keys.iter().any(|key_record| match key_record.rdata {
                    RData::Dnskey(ref key) => {
                        self.rrset_signed_by(rrset, signatures, key, &key_record.owner)
                    }
                    _ => false,
                })
            })
    }

    fn usable_vouchers<'a>(
        &self,
        vouchers: &'a [DsRdata],
    ) -> Result<Vec<&'a DsRdata>, ValidationOutcome> {
        let usable: Vec<&DsRdata> = vouchers
            .iter()
            .filter(|ds| self.classify_voucher(ds) == AlgorithmSupport::Supported)
            .collect();
        if !usable.is_empty() {
            return Ok(usable);
        }
        let any_unknown = vouchers
            .iter()
            .any(|ds| self.classify_voucher(ds) == AlgorithmSupport::UnknownTreatAsInsecure);
        if any_unknown {
            return Err(ValidationOutcome::insecure(
                VerdictReason::UnsupportedAlgorithm,
            ));
        }
        Err(ValidationOutcome::bogus(VerdictReason::DsDnskeyMismatch))
    }

    fn classify_voucher(&self, ds: &DsRdata) -> AlgorithmSupport {
        let algorithms = &self.policy.algorithms;
        match (
            algorithms.classify_sig(ds.algorithm()),
            algorithms.classify_digest(ds.digest_type()),
        ) {
            (AlgorithmSupport::Supported, AlgorithmSupport::Supported) => {
                AlgorithmSupport::Supported
            }
            (AlgorithmSupport::Refused, _) | (_, AlgorithmSupport::Refused) => {
                AlgorithmSupport::Refused
            }
            _ => AlgorithmSupport::UnknownTreatAsInsecure,
        }
    }

    fn rrset_signed_by<R, S>(
        &self,
        rrset: &[R],
        signatures: &[S],
        dnskey: &DnskeyRdata,
        dnskey_owner: &Name,
    ) -> bool
    where
        R: Borrow<ResourceRecord>,
        S: Borrow<ResourceRecord>,
    {
        signatures
            .iter()
            .any(|signature| match signature.borrow().rdata {
                RData::Rrsig(ref rrsig) => verify_rrsig_record(
                    rrsig,
                    rrset,
                    dnskey,
                    dnskey_owner,
                    &self.clock,
                    &self.policy.algorithms,
                )
                .is_ok(),
                _ => false,
            })
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

fn group_into_rrsets<R: Borrow<ResourceRecord>>(records: &[R]) -> Vec<Vec<&ResourceRecord>> {
    let mut rrsets: HashMap<_, Vec<&ResourceRecord>> = HashMap::new();
    for record in records {
        let record = record.borrow();
        rrsets
            .entry((&record.owner, record.rclass, record.rtype))
            .or_default()
            .push(record);
    }
    rrsets.into_values().collect()
}

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
    /// voucher uses a supported algorithm (RFC 4035 §5.2), `Bogus` otherwise.
    ///
    /// Every key a voucher matches is tried, not only the first: during a KSK rollover
    /// the RRset carries a published key that does not sign yet, or no longer signs, and
    /// any matched key that signs is enough (RFC 4035 §5.2).
    pub(crate) fn authenticate_keys(
        &self,
        zone: &Name,
        dnskey: &SignedRrset,
        vouchers: &[DsRdata],
    ) -> Result<Vec<ResourceRecord>, ValidationOutcome> {
        let usable = self.usable_vouchers(vouchers)?;
        let mut vouched = vouched_keys(zone, &dnskey.records, &usable).peekable();
        if vouched.peek().is_none() {
            return Err(ValidationOutcome::bogus(VerdictReason::DsDnskeyMismatch));
        }
        let records: Vec<&ResourceRecord> = dnskey.records.iter().collect();
        let signatures: Vec<&ResourceRecord> = dnskey.signatures.iter().collect();
        let signs = vouched.any(|key| {
            self.verify_rrset_with_key(&records, &signatures, key, zone)
                .is_ok()
        });
        if signs {
            Ok(dnskey.records.clone())
        } else {
            Err(ValidationOutcome::bogus(VerdictReason::NoValidRrsig))
        }
    }

    /// Verifies that every RRset in `records` carries a valid RRSIG from one of `keys`
    /// that covers it as it stands, not as an expansion of a wildcard.
    ///
    /// Denial records and DS RRsets must never come from a wildcard: an RRSIG over
    /// `*.example. NSEC` would otherwise vouch for the same NSEC moved to any owner
    /// (RFC 4035 §5.3.4, §5.4).
    pub(crate) fn authenticate_unexpanded<'a, 'b>(
        &self,
        records: impl IntoIterator<Item = &'a ResourceRecord>,
        signatures: impl IntoIterator<Item = &'b ResourceRecord>,
        keys: &[ResourceRecord],
    ) -> Result<(), VerdictReason> {
        let claims = self.authenticate_rrsets(records, signatures, keys)?;
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
            if !is_expansion(&first.owner, labels) {
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
            if verify_rrsig_record(rrsig, rrset, dnskey, dnskey_owner, &self.clock).is_ok() {
                return Ok(rrsig.labels());
            }
        }
        Err(VerdictReason::NoValidRrsig)
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

/// Every DNSKEY in `dnskeys` that one of `vouchers` matches.
fn vouched_keys<'a>(
    zone: &'a Name,
    dnskeys: &'a [ResourceRecord],
    vouchers: &'a [&DsRdata],
) -> impl Iterator<Item = &'a DnskeyRdata> {
    dnskeys.iter().filter_map(move |record| match record.rdata {
        RData::Dnskey(ref key) => vouchers
            .iter()
            .any(|ds| check_single_ds_linkage(zone, ds, key))
            .then_some(key),
        _ => None,
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

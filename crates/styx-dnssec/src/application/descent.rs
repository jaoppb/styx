//! Chain descent walking and intermediate zone cut validation.

use styx_core::Clock;
use styx_proto::domain::rdata::DsRdata;
use styx_proto::{Name, RData, ResourceRecord};

use crate::application::authenticator::Authenticator;
use crate::domain::chain::{Delegation, ZoneCutMaterial};
use crate::domain::denial::DenialProof;
use crate::domain::error::DenialError;
use crate::domain::ports::ChainSource;
use crate::domain::trust_anchor::TrustAnchor;
use crate::domain::verdict::{ValidationOutcome, VerdictReason};

/// The outcome of walking a chain of trust down to a target zone.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Descent {
    /// Descent reached the target zone with authenticated DNSKEY records.
    Secure(Vec<ResourceRecord>),
    /// Descent completed with a terminal outcome (e.g. Insecure at an unsigned delegation).
    Ended(ValidationOutcome),
}

/// The outcome of stepping across a single candidate zone cut.
#[derive(Debug)]
enum CutStep {
    /// Not a cut; continue descent within the existing zone.
    NotACut,
    /// Secure cut; advance descent into the child zone with authenticated keys.
    Child(Vec<ResourceRecord>),
    /// Terminal outcome (e.g. proven unsigned delegation).
    Ended(ValidationOutcome),
}

/// The trust-anchored zone a descent starts from, with its anchors in DS form.
struct AnchoredZone {
    zone: Name,
    vouchers: Vec<DsRdata>,
}

impl AnchoredZone {
    /// The deepest anchored zone that encloses `qname`, with every anchor configured
    /// for it, so that a rollover's old and new anchors both count.
    fn closest(qname: &Name, anchors: &[TrustAnchor]) -> Option<Self> {
        let zone = anchors
            .iter()
            .map(TrustAnchor::owner)
            .filter(|owner| qname.is_subdomain_of(owner))
            .max_by_key(|owner| owner.label_count())?
            .clone();
        let vouchers = anchors
            .iter()
            .filter(|anchor| anchor.owner() == &zone)
            .map(|anchor| {
                DsRdata::new(
                    anchor.key_tag(),
                    anchor.algorithm(),
                    anchor.digest_type(),
                    anchor.digest().to_vec(),
                )
            })
            .collect();
        Some(Self { zone, vouchers })
    }
}

/// Walks zone cuts from the closest trust anchor down to `qname` and returns the
/// authenticated DNSKEYs or the terminal outcome that ended descent early.
pub(crate) fn walk_chain_descent<C: Clock, S: ChainSource>(
    authenticator: &Authenticator<C>,
    qname: &Name,
    chain_source: &S,
    anchors: &[TrustAnchor],
) -> Result<Descent, ValidationOutcome> {
    let anchored = AnchoredZone::closest(qname, anchors)
        .ok_or_else(|| ValidationOutcome::indeterminate(VerdictReason::NoPathToAnchor))?;

    let material = fetch_material(chain_source, &anchored.zone)?;
    let dnskey = material
        .delegation
        .dnskey()
        .ok_or_else(|| ValidationOutcome::indeterminate(VerdictReason::ChainMaterialUnavailable))?;
    let mut keys = authenticator.authenticate_keys(&anchored.zone, dnskey, &anchored.vouchers)?;

    let mut current_zone = anchored.zone;
    let mut cuts_crossed = 0u8;
    while let Some(next_zone) = find_next_zone_cut(qname, &current_zone) {
        let material = fetch_material(chain_source, &next_zone)?;
        match step_into_cut(authenticator, &material, &keys)? {
            CutStep::NotACut => {}
            CutStep::Child(child_keys) => {
                cuts_crossed = cuts_crossed.saturating_add(1);
                if cuts_crossed > authenticator.policy().max_zone_cuts {
                    return Err(ValidationOutcome::indeterminate(
                        VerdictReason::NoPathToAnchor,
                    ));
                }
                keys = child_keys;
            }
            CutStep::Ended(outcome) => return Ok(Descent::Ended(outcome)),
        }
        current_zone = next_zone;
    }

    Ok(Descent::Secure(keys))
}

fn fetch_material<S: ChainSource>(
    chain_source: &S,
    zone: &Name,
) -> Result<ZoneCutMaterial, ValidationOutcome> {
    chain_source.material_for(zone).map_err(|error| {
        tracing::warn!(%zone, %error, "DNSSEC chain material unavailable");
        ValidationOutcome::indeterminate(VerdictReason::ChainMaterialUnavailable)
    })
}

/// Crosses the name `material` describes: `NotACut` when it is not a zone cut,
/// `Child` with child DNSKEYs on a signed delegation, or `Ended` on an unsigned delegation.
fn step_into_cut<C: Clock>(
    authenticator: &Authenticator<C>,
    material: &ZoneCutMaterial,
    parent_keys: &[ResourceRecord],
) -> Result<CutStep, ValidationOutcome> {
    match material.delegation {
        Delegation::NotACut => Ok(CutStep::NotACut),
        Delegation::Apex { .. } => Err(ValidationOutcome::indeterminate(
            VerdictReason::NoPathToAnchor,
        )),
        Delegation::Signed { ref ds, ref dnskey } => {
            let ds_records: Vec<&ResourceRecord> = ds.records.iter().collect();
            let ds_signatures: Vec<&ResourceRecord> = ds.signatures.iter().collect();
            if !authenticator.records_signed_by_any(&ds_records, &ds_signatures, parent_keys) {
                return Err(ValidationOutcome::bogus(VerdictReason::NoValidRrsig));
            }
            let vouchers = ds_records_at(&material.zone, &ds.records);
            authenticator
                .authenticate_keys(&material.zone, dnskey, &vouchers)
                .map(CutStep::Child)
        }
        Delegation::Unsigned {
            ref ds_denial,
            ref signatures,
        } => {
            verify_ds_denial(
                authenticator,
                &material.zone,
                ds_denial,
                signatures,
                parent_keys,
            )?;
            Ok(CutStep::Ended(ValidationOutcome::insecure(
                VerdictReason::ProvenUnsignedDelegation,
            )))
        }
    }
}

fn ds_records_at(zone: &Name, records: &[ResourceRecord]) -> Vec<DsRdata> {
    records
        .iter()
        .filter(|record| &record.owner == zone)
        .filter_map(|record| match record.rdata {
            RData::Ds(ref ds) => Some(ds.clone()),
            _ => None,
        })
        .collect()
}

/// Accepts a proof of DS absence only when the parent zone signed it.
fn verify_ds_denial<C: Clock>(
    authenticator: &Authenticator<C>,
    zone: &Name,
    proof: &DenialProof,
    signatures: &[ResourceRecord],
    parent_keys: &[ResourceRecord],
) -> Result<(), ValidationOutcome> {
    let proof_records: Vec<&ResourceRecord> = proof.records().iter().collect();
    let sig_records: Vec<&ResourceRecord> = signatures.iter().collect();
    if !authenticator.records_signed_by_any(&proof_records, &sig_records, parent_keys) {
        return Err(ValidationOutcome::bogus(VerdictReason::NoValidRrsig));
    }
    match proof.prove_ds_absence(zone, authenticator.policy().nsec3_max_iterations) {
        Ok(()) => Ok(()),
        Err(error) => {
            tracing::warn!(%zone, %error, "DS-absence denial proof failed verification");
            match error {
                DenialError::Nsec3IterationsExceeded => Err(ValidationOutcome::bogus(
                    VerdictReason::Nsec3IterationsExceeded,
                )),
                _ => Err(ValidationOutcome::bogus(
                    VerdictReason::DenialProofIncomplete,
                )),
            }
        }
    }
}

/// The name one label below `current_zone` on the way down to `qname`.
pub(crate) fn find_next_zone_cut(qname: &Name, current_zone: &Name) -> Option<Name> {
    if current_zone.label_count() >= qname.label_count() {
        return None;
    }
    qname.ancestor(current_zone.label_count().saturating_add(1))
}

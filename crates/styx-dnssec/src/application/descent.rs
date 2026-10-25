//! Chain descent walking and intermediate zone cut validation.
//!
//! Every function here returns `Result<_, ValidationOutcome>`, where the error is the
//! outcome that ends the validation early — `Insecure` for a proven unsigned
//! delegation as much as `Bogus` or `Indeterminate`.

use styx_core::Clock;
use styx_proto::domain::rdata::DsRdata;
use styx_proto::{Name, RData, ResourceRecord};

use crate::application::authenticator::Authenticator;
use crate::domain::chain::{Delegation, ZoneCutMaterial};
use crate::domain::denial::DenialProof;
use crate::domain::nsec3::verify_nsec3_ds_absence;
use crate::domain::ports::{ChainRequest, ChainSource};
use crate::domain::trust_anchor::TrustAnchor;
use crate::domain::verdict::{ValidationOutcome, VerdictReason};

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
/// DNSKEY RRset authenticated for the zone that `qname` lives in.
pub(crate) fn walk_chain_descent<C: Clock, S: ChainSource>(
    authenticator: &Authenticator<C>,
    qname: &Name,
    chain_source: &S,
    anchors: &[TrustAnchor],
) -> Result<Vec<ResourceRecord>, ValidationOutcome> {
    let anchored = AnchoredZone::closest(qname, anchors)
        .ok_or_else(|| ValidationOutcome::indeterminate(VerdictReason::NoPathToAnchor))?;
    let request = ChainRequest::new(qname.clone());

    let material = fetch_material(chain_source, &anchored.zone, &request)?;
    let dnskey = material
        .delegation
        .dnskey()
        .ok_or_else(|| ValidationOutcome::indeterminate(VerdictReason::ChainMaterialUnavailable))?;
    let mut keys = authenticator.authenticate_keys(&anchored.zone, dnskey, &anchored.vouchers)?;

    let mut current_zone = anchored.zone;
    let mut cuts_crossed = 0u8;
    while let Some(next_zone) = find_next_zone_cut(qname, &current_zone) {
        let material = fetch_material(chain_source, &next_zone, &request)?;
        if let Some(child_keys) = step_into_cut(authenticator, &material, &keys)? {
            cuts_crossed = cuts_crossed.saturating_add(1);
            if cuts_crossed > authenticator.policy().max_zone_cuts {
                return Err(ValidationOutcome::indeterminate(
                    VerdictReason::NoPathToAnchor,
                ));
            }
            keys = child_keys;
        }
        current_zone = next_zone;
    }

    Ok(keys)
}

fn fetch_material<S: ChainSource>(
    chain_source: &S,
    zone: &Name,
    request: &ChainRequest,
) -> Result<ZoneCutMaterial, ValidationOutcome> {
    chain_source.material_for(zone, request).map_err(|error| {
        tracing::warn!(%zone, %error, "DNSSEC chain material unavailable");
        ValidationOutcome::indeterminate(VerdictReason::ChainMaterialUnavailable)
    })
}

/// Crosses the name `material` describes: `None` when it is not a zone cut, otherwise
/// the child zone's DNSKEY RRset authenticated through `parent_keys`.
fn step_into_cut<C: Clock>(
    authenticator: &Authenticator<C>,
    material: &ZoneCutMaterial,
    parent_keys: &[ResourceRecord],
) -> Result<Option<Vec<ResourceRecord>>, ValidationOutcome> {
    match material.delegation {
        Delegation::NotACut => Ok(None),
        Delegation::Apex { .. } => Err(ValidationOutcome::indeterminate(
            VerdictReason::NoPathToAnchor,
        )),
        Delegation::Signed { ref ds, ref dnskey } => {
            if !authenticator.records_signed_by_any(&ds.records, &ds.signatures, parent_keys) {
                return Err(ValidationOutcome::bogus(VerdictReason::NoValidRrsig));
            }
            let vouchers = ds_records_at(&material.zone, &ds.records);
            authenticator
                .authenticate_keys(&material.zone, dnskey, &vouchers)
                .map(Some)
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
            Err(ValidationOutcome::insecure(
                VerdictReason::ProvenUnsignedDelegation,
            ))
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
    if !authenticator.records_signed_by_any(proof.records(), signatures, parent_keys) {
        return Err(ValidationOutcome::bogus(VerdictReason::NoValidRrsig));
    }
    let proven = match proof {
        DenialProof::Nsec(nsec) => nsec.prove_ds_absence(zone).is_ok(),
        DenialProof::Nsec3(nsec3) => {
            verify_nsec3_ds_absence(nsec3, zone, authenticator.policy().nsec3_max_iterations)
                .is_ok()
        }
    };
    if !proven {
        return Err(ValidationOutcome::indeterminate(
            VerdictReason::NoPathToAnchor,
        ));
    }
    Ok(())
}

/// The name one label below `current_zone` on the way down to `qname`.
pub(crate) fn find_next_zone_cut(qname: &Name, current_zone: &Name) -> Option<Name> {
    if current_zone.label_count() >= qname.label_count() {
        return None;
    }
    qname.ancestor(current_zone.label_count().saturating_add(1))
}

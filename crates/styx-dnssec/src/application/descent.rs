//! Chain descent walking and intermediate zone cut validation.

use std::collections::HashMap;

use styx_core::Clock;
use styx_proto::domain::rdata::DsRdata;
use styx_proto::{Name, RData, RecordType, ResourceRecord};

use crate::application::authenticator::{Authenticator, VerificationBudget};
use crate::domain::chain::{Delegation, ZoneCutMaterial};
use crate::domain::denial::DenialProof;
use crate::domain::ports::ChainSource;
use crate::domain::trust_anchor::{TrustAnchor, TrustAnchors};
use crate::domain::verdict::{ValidationOutcome, VerdictReason};

/// Maximum `ChainSource::material_for` calls per descent (`NotACut` probe bound).
const MAX_DESCENT_PROBES: usize = 32;

/// Authenticated zone and its DNSKEY RRset reached by chain descent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SecureZone {
    pub(crate) zone: Name,
    pub(crate) keys: Vec<ResourceRecord>,
}

#[derive(Debug, Clone)]
enum CachedStep {
    NotACut,
    Secure(Vec<ResourceRecord>),
}

/// Per-validation cache of authenticated cuts and non-cuts along the chain descent.
#[derive(Debug, Default)]
pub(crate) struct DescentCache {
    steps: HashMap<Name, Result<CachedStep, ValidationOutcome>>,
}

/// The outcome of stepping across a single candidate zone cut.
#[derive(Debug)]
enum CutStep {
    /// Not a cut; continue descent within the existing zone.
    NotACut,
    /// Secure cut; advance descent into the child zone with authenticated keys.
    Child(Vec<ResourceRecord>),
}

/// The trust-anchored zone a descent starts from, with its anchors in DS form.
struct AnchoredZone {
    zone: Name,
    vouchers: Vec<DsRdata>,
}

impl AnchoredZone {
    /// The deepest anchored zone that encloses `qname`, with every anchor configured
    /// for it, so that a rollover's old and new anchors both count.
    fn closest(qname: &Name, anchors: &TrustAnchors) -> Option<Self> {
        let anchors = anchors.as_slice();
        let zone = anchors
            .iter()
            .map(TrustAnchor::owner)
            .filter(|owner| qname.is_subdomain_of(owner))
            .max_by_key(|owner| owner.label_count())?
            .clone();
        let vouchers = anchors
            .iter()
            .filter(|anchor| anchor.owner() == &zone)
            .map(|anchor| anchor.ds().clone())
            .collect();
        Some(Self { zone, vouchers })
    }
}

/// The name whose zone signs an RRset of `rtype` owned by `owner`: the owner itself,
/// except for DS, which is the parent side of a cut and so is signed by the zone above
/// it (RFC 4035 §2.4, §5.2). The root has no parent and answers its own DS questions.
pub(crate) fn signer_search_name(owner: &Name, rtype: RecordType) -> Name {
    if rtype == RecordType::DS {
        if let Some(parent) = owner.parent() {
            return parent;
        }
    }
    owner.clone()
}

/// Walks zone cuts from the closest trust anchor down to `qname` and returns the
/// authenticated zone and DNSKEYs or the terminal outcome that ended descent early.
pub(crate) async fn walk_chain_descent<C: Clock, S: ChainSource>(
    authenticator: &Authenticator<C>,
    qname: &Name,
    chain_source: &S,
    anchors: &TrustAnchors,
    budget: &mut VerificationBudget,
    cache: &mut DescentCache,
) -> Result<SecureZone, ValidationOutcome> {
    let anchored = AnchoredZone::closest(qname, anchors)
        .ok_or_else(|| ValidationOutcome::indeterminate(VerdictReason::NoPathToAnchor))?;

    let mut keys =
        authenticate_anchored_zone(authenticator, &anchored, chain_source, budget, cache).await?;

    let mut current_zone = anchored.zone;
    let mut authoritative_zone = current_zone.clone();
    let mut cuts_crossed = 0u8;
    let mut probes = 0usize;
    while let Some(next_zone) = find_next_zone_cut(qname, &current_zone) {
        probes = probes.saturating_add(1);
        if probes > MAX_DESCENT_PROBES {
            return Err(ValidationOutcome::indeterminate(
                VerdictReason::MaxZoneCutsExceeded,
            ));
        }
        let step = step_cached(
            authenticator,
            &authoritative_zone,
            &next_zone,
            &keys,
            chain_source,
            budget,
            cache,
        )
        .await?;
        if let CachedStep::Secure(child_keys) = step {
            cuts_crossed = cuts_crossed.saturating_add(1);
            if cuts_crossed > authenticator.policy().max_zone_cuts {
                return Err(ValidationOutcome::indeterminate(
                    VerdictReason::MaxZoneCutsExceeded,
                ));
            }
            keys = child_keys;
            authoritative_zone = next_zone.clone();
        }
        current_zone = next_zone;
    }

    Ok(SecureZone {
        zone: authoritative_zone,
        keys,
    })
}

async fn authenticate_anchored_zone<C: Clock, S: ChainSource>(
    authenticator: &Authenticator<C>,
    anchored: &AnchoredZone,
    chain_source: &S,
    budget: &mut VerificationBudget,
    cache: &mut DescentCache,
) -> Result<Vec<ResourceRecord>, ValidationOutcome> {
    if let Some(cached) = cache.steps.get(&anchored.zone) {
        return match cached {
            Ok(CachedStep::Secure(keys)) => Ok(keys.clone()),
            Ok(CachedStep::NotACut) => Err(ValidationOutcome::indeterminate(
                VerdictReason::ChainMaterialUnavailable,
            )),
            Err(outcome) => Err(outcome.clone()),
        };
    }
    let result = async {
        let material = fetch_material(chain_source, &anchored.zone).await?;
        let dnskey = material.delegation.dnskey().ok_or_else(|| {
            ValidationOutcome::indeterminate(VerdictReason::ChainMaterialUnavailable)
        })?;
        authenticator.authenticate_keys(&anchored.zone, dnskey, &anchored.vouchers, budget)
    }
    .await;
    cache.steps.insert(
        anchored.zone.clone(),
        result.clone().map(CachedStep::Secure),
    );
    result
}

async fn step_cached<C: Clock, S: ChainSource>(
    authenticator: &Authenticator<C>,
    authoritative_zone: &Name,
    next_zone: &Name,
    parent_keys: &[ResourceRecord],
    chain_source: &S,
    budget: &mut VerificationBudget,
    cache: &mut DescentCache,
) -> Result<CachedStep, ValidationOutcome> {
    if let Some(cached) = cache.steps.get(next_zone) {
        return cached.clone();
    }
    let result = async {
        let material = fetch_material(chain_source, next_zone).await?;
        if !material.zone.eq_ignore_case(next_zone) {
            tracing::warn!(requested = %next_zone, described = %material.zone, "chain material describes another name");
            return Err(ValidationOutcome::indeterminate(
                VerdictReason::ChainMaterialUnavailable,
            ));
        }
        match step_into_cut(authenticator, authoritative_zone, &material, parent_keys, budget)? {
            CutStep::NotACut => Ok(CachedStep::NotACut),
            CutStep::Child(child_keys) => Ok(CachedStep::Secure(child_keys)),
        }
    }
    .await;
    cache.steps.insert(next_zone.clone(), result.clone());
    result
}

async fn fetch_material<S: ChainSource>(
    chain_source: &S,
    zone: &Name,
) -> Result<ZoneCutMaterial, ValidationOutcome> {
    chain_source.material_for(zone).await.map_err(|error| {
        tracing::warn!(%zone, %error, "DNSSEC chain material unavailable");
        ValidationOutcome::indeterminate(VerdictReason::ChainMaterialUnavailable)
    })
}

/// Crosses the name `material` describes: `NotACut` when it is not a zone cut,
/// `Child` with child DNSKEYs on a signed delegation, or `Err(outcome)` on termination.
fn step_into_cut<C: Clock>(
    authenticator: &Authenticator<C>,
    parent_zone: &Name,
    material: &ZoneCutMaterial,
    parent_keys: &[ResourceRecord],
    budget: &mut VerificationBudget,
) -> Result<CutStep, ValidationOutcome> {
    match material.delegation {
        Delegation::NotACut => Ok(CutStep::NotACut),
        Delegation::Apex { .. } => Err(ValidationOutcome::indeterminate(
            VerdictReason::UnexpectedZoneApex,
        )),
        Delegation::Signed { ref ds, ref dnskey } => {
            authenticator
                .authenticate_unexpanded(&ds.records, &ds.signatures, parent_keys, budget)
                .map_err(ValidationOutcome::bogus)?;
            let vouchers = ds_records_at(&material.zone, &ds.records);
            authenticator
                .authenticate_keys(&material.zone, dnskey, &vouchers, budget)
                .map(CutStep::Child)
        }
        Delegation::Unsigned {
            ref ds_denial,
            ref signatures,
        } => match verify_ds_denial(
            authenticator,
            parent_zone,
            &material.zone,
            ds_denial,
            signatures,
            parent_keys,
            budget,
        ) {
            Ok(()) => Err(ValidationOutcome::insecure(
                VerdictReason::ProvenUnsignedDelegation,
            )),
            Err(outcome) => Err(outcome),
        },
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
    parent_zone: &Name,
    zone: &Name,
    proof: &DenialProof,
    signatures: &[ResourceRecord],
    parent_keys: &[ResourceRecord],
    budget: &mut VerificationBudget,
) -> Result<(), ValidationOutcome> {
    authenticator
        .authenticate_unexpanded(proof.records(), signatures, parent_keys, budget)
        .map_err(ValidationOutcome::bogus)?;
    let result = proof.prove_ds_absence(
        parent_zone,
        zone,
        authenticator.policy().nsec3_max_iterations,
    );
    result.map_err(|error| {
        tracing::warn!(%zone, %error, "DS-absence denial proof failed verification");
        ValidationOutcome::from(error)
    })
}

/// The name one label below `current_zone` on the way down to `qname`.
pub(crate) fn find_next_zone_cut(qname: &Name, current_zone: &Name) -> Option<Name> {
    if current_zone.label_count() >= qname.label_count() {
        return None;
    }
    qname.ancestor(current_zone.label_count().saturating_add(1))
}

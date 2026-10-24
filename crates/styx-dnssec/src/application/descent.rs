//! Chain descent walking and intermediate zone cut validation.

use styx_core::Clock;
use styx_proto::domain::rdata::DnskeyRdata;
use styx_proto::{Label, Name, RData, ResourceRecord};

use crate::application::validator::Validator;
use crate::domain::chain::ZoneCutMaterial;
use crate::domain::denial::DenialProof;
use crate::domain::nsec3::verify_nsec3_ds_absence;
use crate::domain::ports::{ChainRequest, ChainSource};
use crate::domain::signature::check_single_ds_linkage;
use crate::domain::trust_anchor::TrustAnchor;
use crate::domain::verdict::{
    ValidationOutcome, ValidationPolicy, ValidationVerdict, VerdictReason,
};

/// Result of walking the DNSSEC chain descent from trust anchors.
#[derive(Debug)]
pub(crate) enum DescentResult {
    /// Chain descent reached the target zone with authenticated DNSKEYs.
    AuthenticatedKeys(Vec<ResourceRecord>),
    /// Descent terminated early with a final validation outcome.
    Terminated(ValidationOutcome),
}

enum StepResult {
    Authenticated(Vec<ResourceRecord>),
    UnsignedDelegation,
    NoCut,
}

/// Walks zone cuts from the root trust anchor down to the target zone.
pub(crate) fn walk_chain_descent<C: Clock, S: ChainSource>(
    validator: &Validator<C>,
    qname: &Name,
    chain_source: &S,
    anchors: &[TrustAnchor],
) -> DescentResult {
    let root = Name::root();
    let Some(anchor) = anchors.iter().find(|a| a.owner() == &root) else {
        return DescentResult::Terminated(ValidationOutcome::new(
            ValidationVerdict::Indeterminate,
            VerdictReason::NoPathToAnchor,
            validator.is_enforced(),
        ));
    };

    let request = ChainRequest::new(Some(qname.clone()));
    let mut current_keys =
        match fetch_and_auth_root(validator, chain_source, anchor, &request, &root) {
            Ok(keys) => keys,
            Err(outcome) => return DescentResult::Terminated(outcome),
        };

    let cuts_limit = usize::from(validator.policy().max_zone_cuts);
    let mut current_zone = root;
    let mut cuts_count = 0usize;

    while &current_zone != qname && cuts_count < cuts_limit {
        cuts_count = cuts_count.saturating_add(1);
        let Some(next_zone) = find_next_zone_cut(qname, &current_zone) else {
            break;
        };

        match step_child_cut(validator, chain_source, &next_zone, &request, &current_keys) {
            Ok(StepResult::Authenticated(new_keys)) => {
                current_keys = new_keys;
                current_zone = next_zone;
            }
            Ok(StepResult::UnsignedDelegation) => {
                return DescentResult::Terminated(ValidationOutcome::new(
                    ValidationVerdict::Insecure,
                    VerdictReason::ProvenUnsignedDelegation,
                    validator.is_enforced(),
                ));
            }
            Ok(StepResult::NoCut) => {
                break;
            }
            Err(outcome) => return DescentResult::Terminated(outcome),
        }
    }

    DescentResult::AuthenticatedKeys(current_keys)
}

fn fetch_and_auth_root<C: Clock, S: ChainSource>(
    validator: &Validator<C>,
    chain_source: &S,
    anchor: &TrustAnchor,
    request: &ChainRequest,
    root: &Name,
) -> Result<Vec<ResourceRecord>, ValidationOutcome> {
    let root_material = chain_source.material_for(root, request).map_err(|_| {
        ValidationOutcome::new(
            ValidationVerdict::Indeterminate,
            VerdictReason::ChainMaterialUnavailable,
            validator.is_enforced(),
        )
    })?;

    let root_cut = root_material.cut_for(root).ok_or_else(|| {
        ValidationOutcome::new(
            ValidationVerdict::Indeterminate,
            VerdictReason::NoPathToAnchor,
            validator.is_enforced(),
        )
    })?;

    validator.authenticate_root_cut(root_cut, anchor)
}

fn step_child_cut<C: Clock, S: ChainSource>(
    validator: &Validator<C>,
    chain_source: &S,
    next_zone: &Name,
    request: &ChainRequest,
    current_keys: &[ResourceRecord],
) -> Result<StepResult, ValidationOutcome> {
    let material = match chain_source.material_for(next_zone, request) {
        Ok(m) => m,
        Err(_) => return Ok(StepResult::NoCut),
    };

    let cut = match material.cut_for(next_zone) {
        Some(c) => c,
        None => return Ok(StepResult::NoCut),
    };

    match verify_child_zone_cut(validator, cut, current_keys)? {
        Some(keys) => Ok(StepResult::Authenticated(keys)),
        None => Ok(StepResult::UnsignedDelegation),
    }
}

/// Verifies cryptographic linkage and delegation for a child zone cut.
pub(crate) fn verify_child_zone_cut<C: Clock>(
    validator: &Validator<C>,
    cut: &ZoneCutMaterial,
    _parent_keys: &[ResourceRecord],
) -> Result<Option<Vec<ResourceRecord>>, ValidationOutcome> {
    let ds_records = match cut.ds.as_ref() {
        Some(ds) if !ds.is_empty() => ds,
        _ => {
            if verify_ds_denial(validator.policy(), cut) {
                return Ok(None);
            }
            return Err(ValidationOutcome::new(
                ValidationVerdict::Indeterminate,
                VerdictReason::NoPathToAnchor,
                validator.is_enforced(),
            ));
        }
    };

    let child_dnskeys = match cut.dnskey.as_ref() {
        Some(k) if !k.is_empty() => k,
        _ => {
            return Err(ValidationOutcome::new(
                ValidationVerdict::Bogus,
                VerdictReason::DsDnskeyMismatch,
                validator.is_enforced(),
            ));
        }
    };

    let child_key = find_authenticated_child_key(validator, cut, ds_records, child_dnskeys)?;

    if !validator.has_valid_signature_for_set(
        child_dnskeys,
        &cut.dnskey_signatures,
        &child_key,
        &cut.zone,
    ) {
        return Err(ValidationOutcome::new(
            ValidationVerdict::Bogus,
            VerdictReason::NoValidRrsig,
            validator.is_enforced(),
        ));
    }

    Ok(Some(child_dnskeys.clone()))
}

fn find_authenticated_child_key<C: Clock>(
    validator: &Validator<C>,
    cut: &ZoneCutMaterial,
    ds_records: &[ResourceRecord],
    child_dnskeys: &[ResourceRecord],
) -> Result<DnskeyRdata, ValidationOutcome> {
    for child_rr in child_dnskeys {
        let RData::Dnskey(ref child_key) = child_rr.rdata else {
            continue;
        };
        let matches = ds_records.iter().any(|ds_rr| match ds_rr.rdata {
            RData::Ds(ref ds) => check_single_ds_linkage(&cut.zone, ds, child_key),
            _ => false,
        });
        if matches {
            return Ok(child_key.clone());
        }
    }

    Err(ValidationOutcome::new(
        ValidationVerdict::Bogus,
        VerdictReason::DsDnskeyMismatch,
        validator.is_enforced(),
    ))
}

fn verify_ds_denial(policy: &ValidationPolicy, cut: &ZoneCutMaterial) -> bool {
    match cut.ds_denial.as_ref() {
        Some(DenialProof::Nsec(nsec)) => nsec.prove_ds_absence(&cut.zone).is_ok(),
        Some(DenialProof::Nsec3(nsec3)) => {
            verify_nsec3_ds_absence(nsec3, &cut.zone, policy.nsec3_max_iterations).is_ok()
        }
        None => false,
    }
}

/// Helper to derive the next intermediate zone cut between `current_zone` and `qname`.
pub(crate) fn find_next_zone_cut(qname: &Name, current_zone: &Name) -> Option<Name> {
    let q_count = qname.label_count();
    let cur_count = current_zone.label_count();
    if cur_count >= q_count {
        return None;
    }
    let next_len = cur_count.saturating_add(1);
    let to_drop = q_count.saturating_sub(next_len);
    let mut labels = Vec::new();
    for l in qname.labels().skip(to_drop) {
        let lbl = Label::new(l.as_bytes().to_vec()).ok()?;
        labels.push(lbl);
    }
    Name::new(labels).ok()
}

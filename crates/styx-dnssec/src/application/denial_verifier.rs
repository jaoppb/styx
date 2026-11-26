//! Denial of existence proof verification (NSEC and NSEC3).

use styx_core::Clock;
use styx_proto::{Message, Name, RData, RecordType, ResourceRecord};

use crate::application::authenticator::{Authenticator, VerificationBudget};
use crate::domain::denial::{DenialProof, DenialStrength};
use crate::domain::nsec3::is_nsec3_in_zone;
use crate::domain::verdict::{ValidationOutcome, VerdictReason};

/// Selects NSEC/NSEC3 records and RRSIGs belonging to `signer_zone` from `authorities`.
fn zone_denial_records<'a>(
    authorities: &'a [ResourceRecord],
    signer_zone: &Name,
) -> (Vec<&'a ResourceRecord>, Vec<&'a ResourceRecord>) {
    let mut zone_signatures = Vec::new();
    let mut child_signed_owners: Vec<&Name> = Vec::new();
    for record in authorities {
        let RData::Rrsig(ref rrsig) = record.rdata else {
            continue;
        };
        if rrsig.signer_name().eq_ignore_case(signer_zone) {
            zone_signatures.push(record);
        } else if rrsig.type_covered() == RecordType::NSEC
            && rrsig.signer_name().is_subdomain_of(signer_zone)
        {
            child_signed_owners.push(&record.owner);
        }
    }

    let denial_records = authorities
        .iter()
        .filter(|record| match record.rdata {
            RData::Nsec3(_) => is_nsec3_in_zone(record, signer_zone),
            RData::Nsec(_) => {
                record.owner.is_subdomain_of(signer_zone)
                    && !is_child_signed_only(record, &zone_signatures, &child_signed_owners)
            }
            _ => false,
        })
        .collect();
    (denial_records, zone_signatures)
}

fn is_child_signed_only(
    record: &ResourceRecord,
    zone_signatures: &[&ResourceRecord],
    child_signed_owners: &[&Name],
) -> bool {
    let has_zone_signature = zone_signatures.iter().any(|signature| {
        matches!(signature.rdata, RData::Rrsig(ref rrsig) if rrsig.type_covered() == RecordType::NSEC)
            && signature.owner.eq_ignore_case(&record.owner)
    });
    !has_zone_signature
        && child_signed_owners
            .iter()
            .any(|owner| owner.eq_ignore_case(&record.owner))
}

/// The NSEC or NSEC3 records of `message`'s authority section belonging to `signer_zone`,
/// authenticated against `keys` as they stand (never through a wildcard RRSIG) and
/// assembled into one proof.
pub(crate) fn authenticated_denial_proof<C: Clock>(
    authenticator: &Authenticator<C>,
    signer_zone: &Name,
    message: &Message,
    keys: &[ResourceRecord],
    budget: &mut VerificationBudget,
) -> Result<DenialProof, ValidationOutcome> {
    let (denial_records, signatures) = zone_denial_records(&message.authorities, signer_zone);
    if denial_records.is_empty() {
        return Err(ValidationOutcome::bogus(
            VerdictReason::DenialProofIncomplete,
        ));
    }
    authenticator
        .authenticate_unexpanded(denial_records.iter().copied(), signatures, keys, budget)
        .map_err(ValidationOutcome::bogus)?;
    DenialProof::from_records(&denial_records).map_err(|error| {
        tracing::warn!(%error, "failed to construct denial proof from records");
        ValidationOutcome::from(error)
    })
}

/// The outcome a verified denial ends with: Secure when proven outright, Insecure when
/// it rests on an NSEC3 Opt-Out span.
pub(crate) fn denial_outcome(strength: DenialStrength) -> ValidationOutcome {
    match strength {
        DenialStrength::Proven => ValidationOutcome::secure(VerdictReason::ProvenDenialOfExistence),
        DenialStrength::OptOut => ValidationOutcome::insecure(VerdictReason::Nsec3OptOut),
    }
}

/// Verifies the denial-of-existence proof in `message`'s authority section for
/// (`qname`, `qtype`) within `signer_zone`.
pub(crate) fn verify_denial_proofs<C: Clock>(
    authenticator: &Authenticator<C>,
    signer_zone: &Name,
    qname: &Name,
    qtype: RecordType,
    message: &Message,
    active_keys: &[ResourceRecord],
    budget: &mut VerificationBudget,
) -> ValidationOutcome {
    let proof = match authenticated_denial_proof(
        authenticator,
        signer_zone,
        message,
        active_keys,
        budget,
    ) {
        Ok(proof) => proof,
        Err(outcome) => return outcome,
    };
    let rcode = message.header.rcode;
    let cap = authenticator.policy().nsec3_max_iterations;
    match proof.verify(signer_zone, qname, qtype, rcode, cap) {
        Ok(strength) => denial_outcome(strength),
        Err(error) => {
            tracing::warn!(%error, %qname, ?qtype, ?rcode, "denial of existence verification failed");
            ValidationOutcome::from(error)
        }
    }
}

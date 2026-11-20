//! Denial of existence proof verification (NSEC and NSEC3).

use styx_core::Clock;
use styx_proto::{Message, Name, RData, RecordType, ResourceRecord};

use crate::application::authenticator::Authenticator;
use crate::domain::denial::{DenialProof, DenialStrength};
use crate::domain::verdict::{ValidationOutcome, VerdictReason};

/// The NSEC or NSEC3 records of `message`'s authority section, authenticated against
/// `keys` as they stand (never through a wildcard RRSIG) and assembled into one proof.
pub(crate) fn authenticated_denial_proof<C: Clock>(
    authenticator: &Authenticator<C>,
    message: &Message,
    keys: &[ResourceRecord],
) -> Result<DenialProof, ValidationOutcome> {
    let mut denial_records = Vec::new();
    let mut signatures = Vec::new();
    for record in &message.authorities {
        match record.rdata {
            RData::Nsec(_) | RData::Nsec3(_) => denial_records.push(record),
            RData::Rrsig(_) => signatures.push(record),
            _ => {}
        }
    }
    if denial_records.is_empty() {
        return Err(ValidationOutcome::bogus(
            VerdictReason::DenialProofIncomplete,
        ));
    }
    authenticator
        .authenticate_unexpanded(
            denial_records.iter().copied(),
            signatures.iter().copied(),
            keys,
        )
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
) -> ValidationOutcome {
    let proof = match authenticated_denial_proof(authenticator, message, active_keys) {
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

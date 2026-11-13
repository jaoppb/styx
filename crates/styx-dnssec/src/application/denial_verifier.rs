//! Denial of existence proof verification (NSEC and NSEC3).

use styx_core::Clock;
use styx_proto::{Message, Name, RData, RecordType, ResourceRecord};

use crate::application::authenticator::Authenticator;
use crate::domain::denial::DenialProof;
use crate::domain::verdict::{ValidationOutcome, VerdictReason};

/// Verifies the denial-of-existence proof in `message`'s authority section.
pub(crate) fn verify_denial_proofs<C: Clock>(
    authenticator: &Authenticator<C>,
    signer_zone: &Name,
    qname: &Name,
    qtype: RecordType,
    message: &Message,
    active_keys: &[ResourceRecord],
) -> ValidationOutcome {
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
        return ValidationOutcome::bogus(VerdictReason::DenialProofIncomplete);
    }
    if !authenticator.records_signed_by_any(
        denial_records.iter().copied(),
        signatures.iter().copied(),
        active_keys,
    ) {
        return ValidationOutcome::bogus(VerdictReason::NoValidRrsig);
    }

    let proof = match DenialProof::from_records(&denial_records) {
        Ok(proof) => proof,
        Err(error) => {
            tracing::warn!(%error, "failed to construct denial proof from records");
            return ValidationOutcome::from(error);
        }
    };

    let rcode = message.header.rcode;
    let cap = authenticator.policy().nsec3_max_iterations;
    match proof.verify(signer_zone, qname, qtype, rcode, cap) {
        Ok(()) => ValidationOutcome::secure(VerdictReason::ProvenDenialOfExistence),
        Err(error) => {
            tracing::warn!(%error, %qname, ?qtype, ?rcode, "denial of existence verification failed");
            ValidationOutcome::from(error)
        }
    }
}

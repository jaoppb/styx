//! Denial of existence proof verification (NSEC and NSEC3).

use styx_core::Clock;
use styx_proto::{Message, Name, RData, RecordType, ResourceRecord, ResponseCode};

use crate::application::authenticator::Authenticator;
use crate::domain::denial::{Nsec3Flags, Nsec3Params, Nsec3Proof, NsecProof};
use crate::domain::error::DenialError;
use crate::domain::nsec3::{verify_nsec3_nodata, verify_nsec3_nxdomain};
use crate::domain::policy::Nsec3IterationsCap;
use crate::domain::verdict::{ValidationOutcome, VerdictReason};

/// Verifies the denial-of-existence proof in `message`'s authority section.
pub(crate) fn verify_denial_proofs<C: Clock>(
    authenticator: &Authenticator<C>,
    qname: &Name,
    qtype: RecordType,
    message: &Message,
    active_keys: &[ResourceRecord],
) -> ValidationOutcome {
    let mut nsec_records = Vec::new();
    let mut nsec3_records = Vec::new();
    let mut signatures = Vec::new();
    for record in &message.authorities {
        match record.rdata {
            RData::Nsec(_) => nsec_records.push(record),
            RData::Nsec3(_) => nsec3_records.push(record),
            RData::Rrsig(_) => signatures.push(record),
            _ => {}
        }
    }

    let denial_records: Vec<&ResourceRecord> =
        nsec_records.iter().chain(&nsec3_records).copied().collect();
    if denial_records.is_empty() {
        return ValidationOutcome::bogus(VerdictReason::DenialProofIncomplete);
    }
    if !authenticator.records_signed_by_any(&denial_records, &signatures, active_keys) {
        return ValidationOutcome::bogus(VerdictReason::NoValidRrsig);
    }

    let rcode = message.header.rcode;
    let proven = if nsec_records.is_empty() {
        prove_with_nsec3(
            qname,
            qtype,
            rcode,
            nsec3_records,
            authenticator.policy().nsec3_max_iterations,
        )
    } else {
        prove_with_nsec(qname, qtype, rcode, nsec_records)
    };
    match proven {
        Ok(()) => ValidationOutcome::secure(VerdictReason::AnchorMatched),
        Err(DenialError::Nsec3IterationsExceeded) => {
            ValidationOutcome::bogus(VerdictReason::Nsec3IterationsExceeded)
        }
        Err(_) => ValidationOutcome::bogus(VerdictReason::DenialProofIncomplete),
    }
}

fn prove_with_nsec(
    qname: &Name,
    qtype: RecordType,
    rcode: ResponseCode,
    records: Vec<&ResourceRecord>,
) -> Result<(), DenialError> {
    let proof = NsecProof::new(records.into_iter().cloned().collect());
    if rcode == ResponseCode::NXDOMAIN {
        proof.prove_name_does_not_exist(qname)?;
        return proof.prove_no_wildcard(qname);
    }
    if rcode == ResponseCode::NOERROR {
        return proof.prove_type_does_not_exist(qname, qtype);
    }
    Err(DenialError::DenialProofIncomplete)
}

fn prove_with_nsec3(
    qname: &Name,
    qtype: RecordType,
    rcode: ResponseCode,
    records: Vec<&ResourceRecord>,
    max_iterations: Nsec3IterationsCap,
) -> Result<(), DenialError> {
    let Some(RData::Nsec3(rdata)) = records.first().map(|record| &record.rdata) else {
        return Err(DenialError::DenialProofIncomplete);
    };
    let params = Nsec3Params::new(
        rdata.hash_algorithm(),
        Nsec3Flags::new(rdata.flags()),
        rdata.iterations(),
        rdata.salt().to_vec(),
    );
    let proof = Nsec3Proof::new(params, records.into_iter().cloned().collect());
    if rcode == ResponseCode::NXDOMAIN {
        return verify_nsec3_nxdomain(&proof, qname, max_iterations);
    }
    if rcode == ResponseCode::NOERROR {
        return verify_nsec3_nodata(&proof, qname, qtype, max_iterations);
    }
    Err(DenialError::DenialProofIncomplete)
}

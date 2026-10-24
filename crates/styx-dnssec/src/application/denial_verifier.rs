//! Denial of existence proof verification (NSEC and NSEC3).

use styx_proto::{Message, Name, RData, RecordType, ResourceRecord, ResponseCode};

use crate::domain::denial::{Nsec3Flags, Nsec3Params, Nsec3Proof, NsecProof};
use crate::domain::nsec3::verify_nsec3_nxdomain;
use crate::domain::verdict::{
    Nsec3IterationsCap, ValidationOutcome, ValidationVerdict, VerdictReason,
};

/// Verifies denial-of-existence proofs present in `msg.authorities`.
pub(crate) fn verify_denial_proofs(
    qname: &Name,
    qtype: RecordType,
    msg: &Message,
    enforced: bool,
    max_iterations: Nsec3IterationsCap,
) -> ValidationOutcome {
    let mut nsec_records = Vec::new();
    let mut nsec3_records = Vec::new();

    for rr in &msg.authorities {
        match rr.rdata {
            RData::Nsec(_) => nsec_records.push(rr.clone()),
            RData::Nsec3(_) => nsec3_records.push(rr.clone()),
            _ => {}
        }
    }

    if !nsec_records.is_empty() {
        if let Some(outcome) = verify_nsec_denial(qname, qtype, msg, nsec_records, enforced) {
            return outcome;
        }
    }

    if !nsec3_records.is_empty() {
        if let Some(outcome) =
            verify_nsec3_denial(qname, msg, nsec3_records, enforced, max_iterations)
        {
            return outcome;
        }
    }

    ValidationOutcome::new(
        ValidationVerdict::Bogus,
        VerdictReason::DenialProofIncomplete,
        enforced,
    )
}

fn verify_nsec_denial(
    qname: &Name,
    qtype: RecordType,
    msg: &Message,
    records: Vec<ResourceRecord>,
    enforced: bool,
) -> Option<ValidationOutcome> {
    let proof = NsecProof::new(records);
    if msg.header.rcode == ResponseCode::NXDOMAIN {
        let valid = proof.prove_name_does_not_exist(qname).is_ok()
            && proof.prove_no_wildcard(qname).is_ok();
        let reason = if valid {
            VerdictReason::AnchorMatched
        } else {
            VerdictReason::DenialProofIncomplete
        };
        let verdict = if valid {
            ValidationVerdict::Secure
        } else {
            ValidationVerdict::Bogus
        };
        return Some(ValidationOutcome::new(verdict, reason, enforced));
    }

    if msg.header.rcode == ResponseCode::NOERROR {
        let valid = proof.prove_type_does_not_exist(qname, qtype).is_ok();
        let reason = if valid {
            VerdictReason::AnchorMatched
        } else {
            VerdictReason::DenialProofIncomplete
        };
        let verdict = if valid {
            ValidationVerdict::Secure
        } else {
            ValidationVerdict::Bogus
        };
        return Some(ValidationOutcome::new(verdict, reason, enforced));
    }

    None
}

fn verify_nsec3_denial(
    qname: &Name,
    msg: &Message,
    records: Vec<ResourceRecord>,
    enforced: bool,
    max_iterations: Nsec3IterationsCap,
) -> Option<ValidationOutcome> {
    let first = records.first()?;
    let RData::Nsec3(ref rdata) = first.rdata else {
        return None;
    };

    let params = Nsec3Params::new(
        rdata.hash_algorithm(),
        Nsec3Flags::new(rdata.flags()),
        rdata.iterations(),
        rdata.salt().to_vec(),
    );
    let proof = Nsec3Proof::new(params, records);

    if msg.header.rcode == ResponseCode::NXDOMAIN {
        let valid = verify_nsec3_nxdomain(&proof, qname, max_iterations).is_ok();
        let reason = if valid {
            VerdictReason::AnchorMatched
        } else {
            VerdictReason::DenialProofIncomplete
        };
        let verdict = if valid {
            ValidationVerdict::Secure
        } else {
            ValidationVerdict::Bogus
        };
        return Some(ValidationOutcome::new(verdict, reason, enforced));
    }

    None
}

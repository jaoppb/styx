//! Denial of existence proof models for NSEC and NSEC3.

use std::cmp::Ordering;

use styx_proto::application::canonical::canonical_name_cmp;
use styx_proto::{Label, Name, RData, RecordType, ResourceRecord};

use crate::domain::error::DenialError;
use crate::domain::verdict::Nsec3IterationsCap;

/// Prepends a `*` wildcard label to `name`.
pub fn prepend_wildcard(name: &Name) -> Result<Name, styx_proto::NameError> {
    let mut labels = Vec::with_capacity(name.label_count().saturating_add(1));
    labels.push(Label::new(b"*".to_vec())?);
    for l in name.labels() {
        labels.push(Label::new(l.as_bytes().to_vec())?);
    }
    Name::new(labels)
}

/// Wrapped NSEC3 flags octet (RFC 5155 §3.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Nsec3Flags(u8);

impl Nsec3Flags {
    /// Constructs a new [`Nsec3Flags`].
    #[must_use]
    pub const fn new(raw: u8) -> Self {
        Self(raw)
    }

    /// Returns whether the Opt-Out flag (bit 0) is set.
    #[must_use]
    pub const fn is_opt_out(&self) -> bool {
        (self.0 & 0x01) != 0
    }

    /// Returns the raw flags octet.
    #[must_use]
    pub const fn raw(&self) -> u8 {
        self.0
    }
}

/// NSEC3 parameters governing denial hashing and iteration limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nsec3Params {
    /// Hash algorithm (1 = SHA-1).
    pub hash_algorithm: u8,
    /// Flags, including Opt-Out.
    pub flags: Nsec3Flags,
    /// Iteration count for hash computation.
    pub iterations: u16,
    /// Salt octets appended during hashing.
    pub salt: Vec<u8>,
}

impl Nsec3Params {
    /// Constructs a new [`Nsec3Params`].
    #[must_use]
    pub fn new(hash_algorithm: u8, flags: Nsec3Flags, iterations: u16, salt: Vec<u8>) -> Self {
        Self {
            hash_algorithm,
            flags,
            iterations,
            salt,
        }
    }

    /// Checks that the iterations do not exceed the mandatory safety cap.
    ///
    /// # Errors
    /// Returns [`DenialError::Nsec3IterationsExceeded`] if `iterations > cap.value()`.
    pub fn check_iterations(&self, cap: Nsec3IterationsCap) -> Result<(), DenialError> {
        if self.iterations > cap.value() {
            return Err(DenialError::Nsec3IterationsExceeded);
        }
        Ok(())
    }
}

/// Checks whether an NSEC record covers `qname` in canonical order.
#[must_use]
pub fn nsec_covers_name(owner: &Name, next: &Name, qname: &Name) -> bool {
    let cmp_owner_next = canonical_name_cmp(owner, next);
    let cmp_owner_q = canonical_name_cmp(owner, qname);
    let cmp_q_next = canonical_name_cmp(qname, next);

    if cmp_owner_next == Ordering::Less {
        // Normal span: owner < qname < next
        cmp_owner_q == Ordering::Less && cmp_q_next == Ordering::Less
    } else if cmp_owner_next == Ordering::Greater {
        // Apex wrap-around: owner > next
        cmp_owner_q == Ordering::Less || cmp_q_next == Ordering::Less
    } else {
        // RFC 4035 §5.4: single NSEC in zone covers all names except owner itself
        cmp_owner_q != Ordering::Equal
    }
}

/// NSEC-based proof of non-existence (RFC 4035 §5.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NsecProof {
    /// NSEC records constituting the proof.
    pub records: Vec<ResourceRecord>,
}

impl NsecProof {
    /// Constructs a new [`NsecProof`].
    #[must_use]
    pub fn new(records: Vec<ResourceRecord>) -> Self {
        Self { records }
    }

    /// Proves that `qname` does not exist in the zone.
    ///
    /// # Errors
    /// Returns [`DenialError::NotCovered`] if no NSEC covers `qname`.
    pub fn prove_name_does_not_exist(&self, qname: &Name) -> Result<(), DenialError> {
        let covered = self.records.iter().any(|rr| match rr.rdata {
            RData::Nsec(ref nsec) => nsec_covers_name(&rr.owner, nsec.next_domain(), qname),
            _ => false,
        });
        if covered {
            Ok(())
        } else {
            Err(DenialError::NotCovered)
        }
    }

    /// Proves that `qtype` does not exist at `qname` (NODATA proof).
    ///
    /// # Errors
    /// Returns [`DenialError::NotCovered`] if record is absent, contains `qtype`, or contains CNAME.
    pub fn prove_type_does_not_exist(
        &self,
        qname: &Name,
        qtype: RecordType,
    ) -> Result<(), DenialError> {
        for rr in &self.records {
            if &rr.owner != qname {
                continue;
            }
            let RData::Nsec(ref nsec) = rr.rdata else {
                continue;
            };
            if nsec.types().contains(qtype) || nsec.types().contains(RecordType::CNAME) {
                return Err(DenialError::NotCovered);
            }
            return Ok(());
        }
        Err(DenialError::NotCovered)
    }

    /// Proves that no wildcard can synthesize the target `qname`.
    ///
    /// # Errors
    /// Returns [`DenialError::DenialProofIncomplete`] if wildcard coverage is missing.
    pub fn prove_no_wildcard(&self, qname: &Name) -> Result<(), DenialError> {
        let parent = qname.parent().ok_or(DenialError::DenialProofIncomplete)?;
        let wildcard_name =
            prepend_wildcard(&parent).map_err(|_| DenialError::DenialProofIncomplete)?;
        self.prove_name_does_not_exist(&wildcard_name)
            .map_err(|_| DenialError::DenialProofIncomplete)
    }

    /// Proves that the DS record is absent at `zone` (unsigned delegation).
    ///
    /// # Errors
    /// Returns [`DenialError::NotCovered`] if proof fails.
    pub fn prove_ds_absence(&self, zone: &Name) -> Result<(), DenialError> {
        for rr in &self.records {
            if &rr.owner != zone {
                continue;
            }
            let RData::Nsec(ref nsec) = rr.rdata else {
                continue;
            };
            if !nsec.types().contains(RecordType::DS) {
                return Ok(());
            }
        }
        Err(DenialError::NotCovered)
    }
}

/// NSEC3-based hashed proof of non-existence (RFC 5155).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nsec3Proof {
    /// Parameters used by this NSEC3 proof.
    pub params: Nsec3Params,
    /// NSEC3 records constituting the proof.
    pub records: Vec<ResourceRecord>,
}

impl Nsec3Proof {
    /// Constructs a new [`Nsec3Proof`].
    #[must_use]
    pub fn new(params: Nsec3Params, records: Vec<ResourceRecord>) -> Self {
        Self { params, records }
    }

    /// Returns whether Opt-Out applies to this proof.
    #[must_use]
    pub fn opt_out_applies(&self) -> bool {
        self.params.flags.is_opt_out()
    }
}

/// Top-level denial proof container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenialProof {
    /// NSEC proof.
    Nsec(NsecProof),
    /// NSEC3 proof.
    Nsec3(Nsec3Proof),
}

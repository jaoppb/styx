//! Denial of existence proof models for NSEC and NSEC3.

use std::cmp::Ordering;

use styx_proto::application::canonical::canonical_name_cmp;
use styx_proto::{Name, RData, RecordType, ResourceRecord, ResponseCode};

use crate::domain::error::DenialError;
pub use crate::domain::nsec3::Nsec3Proof;
use crate::domain::policy::{Nsec3HashAlgorithm, Nsec3IterationsCap};

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
    pub hash_algorithm: Nsec3HashAlgorithm,
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
    pub fn new(
        hash_algorithm: Nsec3HashAlgorithm,
        flags: Nsec3Flags,
        iterations: u16,
        salt: Vec<u8>,
    ) -> Self {
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

/// Shared closest-encloser proof legs for NSEC and NSEC3 verification.
///
/// Given a query name and a strict ancestor `closest_encloser`, derives the
/// `next_closer` name (one label below `closest_encloser` towards `qname`) and
/// the `wildcard` name (`*.<closest_encloser>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosestEncloserProof {
    closest_encloser: Name,
    next_closer: Name,
    wildcard: Name,
}

impl ClosestEncloserProof {
    /// Derives the next-closer and wildcard names from `qname` and `closest_encloser`.
    ///
    /// # Errors
    /// Returns [`DenialError::DenialProofIncomplete`] if `closest_encloser` is not a
    /// strict ancestor of `qname` or wildcard construction fails.
    pub fn new(qname: &Name, closest_encloser: Name) -> Result<Self, DenialError> {
        if qname.label_count() <= closest_encloser.label_count()
            || !qname.is_subdomain_of(&closest_encloser)
        {
            return Err(DenialError::DenialProofIncomplete);
        }
        let next_closer = qname
            .ancestor(closest_encloser.label_count().saturating_add(1))
            .ok_or(DenialError::DenialProofIncomplete)?;
        let wildcard = closest_encloser
            .with_wildcard()
            .map_err(|_| DenialError::DenialProofIncomplete)?;
        Ok(Self {
            closest_encloser,
            next_closer,
            wildcard,
        })
    }

    /// Returns the closest encloser name.
    #[must_use]
    pub fn closest_encloser(&self) -> &Name {
        &self.closest_encloser
    }

    /// Returns the next-closer name one label below `closest_encloser`.
    #[must_use]
    pub fn next_closer(&self) -> &Name {
        &self.next_closer
    }

    /// Returns the wildcard name `*.<closest_encloser>`.
    #[must_use]
    pub fn wildcard(&self) -> &Name {
        &self.wildcard
    }
}

/// Returns the longest common ancestor of two domain names.
#[must_use]
pub fn longest_common_ancestor(left: &Name, right: &Name) -> Name {
    let max_labels = left.label_count().min(right.label_count());
    for label_count in (1..=max_labels).rev() {
        let Some(left_anc) = left.ancestor(label_count) else {
            continue;
        };
        let Some(right_anc) = right.ancestor(label_count) else {
            continue;
        };
        if left_anc.eq_ignore_case(&right_anc) {
            return left_anc;
        }
    }
    Name::root()
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

fn nsec_closest_encloser(qname: &Name, owner: &Name, next: &Name) -> Name {
    let left = longest_common_ancestor(qname, owner);
    let right = longest_common_ancestor(qname, next);
    if left.label_count() >= right.label_count() {
        left
    } else {
        right
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
        let covered = self.records.iter().any(|record| match record.rdata {
            RData::Nsec(ref nsec) => nsec_covers_name(&record.owner, nsec.next_domain(), qname),
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
    /// Returns [`DenialError::NotCovered`] if record is absent, contains `qtype`,
    /// contains `CNAME`, or represents a delegation cut for non-DS queries.
    pub fn prove_type_does_not_exist(
        &self,
        qname: &Name,
        qtype: RecordType,
    ) -> Result<(), DenialError> {
        for record in &self.records {
            if &record.owner != qname {
                continue;
            }
            let RData::Nsec(ref nsec) = record.rdata else {
                continue;
            };
            let is_delegation = qtype != RecordType::DS
                && nsec.types().contains(RecordType::NS)
                && !nsec.types().contains(RecordType::SOA);
            if nsec.types().contains(qtype)
                || nsec.types().contains(RecordType::CNAME)
                || is_delegation
            {
                return Err(DenialError::NotCovered);
            }
            return Ok(());
        }
        Err(DenialError::NotCovered)
    }

    /// Proves NODATA within `signer_zone`.
    ///
    /// # Errors
    /// Returns [`DenialError`] if `qname` or the proof records fall outside `signer_zone`
    /// or NODATA proof fails.
    pub fn prove_nodata_in_zone(
        &self,
        signer_zone: &Name,
        qname: &Name,
        qtype: RecordType,
    ) -> Result<(), DenialError> {
        if !qname.is_subdomain_of(signer_zone) || !self.all_in_zone(signer_zone) {
            return Err(DenialError::NotCovered);
        }
        self.prove_type_does_not_exist(qname, qtype)
    }

    /// Proves that no wildcard exists at `*.<closest_encloser>`.
    ///
    /// # Errors
    /// Returns [`DenialError::DenialProofIncomplete`] if wildcard coverage is missing.
    pub fn prove_no_wildcard(&self, closest_encloser: &Name) -> Result<(), DenialError> {
        let wildcard_name = closest_encloser
            .with_wildcard()
            .map_err(|_| DenialError::DenialProofIncomplete)?;
        self.prove_name_does_not_exist(&wildcard_name)
            .map_err(|_| DenialError::DenialProofIncomplete)
    }

    /// Proves NXDOMAIN within `signer_zone`, deriving the closest encloser from a
    /// covering NSEC and checking that no wildcard exists at that closest encloser.
    ///
    /// # Errors
    /// Returns [`DenialError`] if coverage, zone membership, or wildcard denial fails.
    pub fn prove_nxdomain(&self, signer_zone: &Name, qname: &Name) -> Result<(), DenialError> {
        if !qname.is_subdomain_of(signer_zone) || !self.all_in_zone(signer_zone) {
            return Err(DenialError::NotCovered);
        }
        let encloser = self
            .covering_enclosers(qname)
            .into_iter()
            .find(|encloser| {
                encloser.is_subdomain_of(signer_zone) && !self.is_delegation_or_dname(encloser)
            })
            .ok_or(DenialError::NotCovered)?;
        let legs = ClosestEncloserProof::new(qname, encloser)?;
        self.prove_no_wildcard(legs.closest_encloser())
    }

    /// Proves that no closer name than `sig_labels` exists for a wildcard-synthesized answer.
    ///
    /// # Errors
    /// Returns [`DenialError`] if `owner` is not covered within `signer_zone` or a closer
    /// non-terminal exists below `sig_labels`.
    pub fn prove_wildcard_expansion(
        &self,
        signer_zone: &Name,
        owner: &Name,
        signature_labels: u8,
    ) -> Result<(), DenialError> {
        if !owner.is_subdomain_of(signer_zone) || !self.all_in_zone(signer_zone) {
            return Err(DenialError::NotCovered);
        }
        let max_encloser_labels = usize::from(signature_labels);
        let covered = self.covering_enclosers(owner).into_iter().any(|encloser| {
            encloser.is_subdomain_of(signer_zone) && encloser.label_count() <= max_encloser_labels
        });
        if covered {
            Ok(())
        } else {
            Err(DenialError::DenialProofIncomplete)
        }
    }

    /// Proves that the DS record is absent at `zone` (unsigned delegation).
    ///
    /// # Errors
    /// Returns [`DenialError::NotCovered`] if proof fails.
    pub fn prove_ds_absence(&self, zone: &Name) -> Result<(), DenialError> {
        for record in &self.records {
            if &record.owner != zone {
                continue;
            }
            let RData::Nsec(ref nsec) = record.rdata else {
                continue;
            };
            if nsec.types().contains(RecordType::NS)
                && !nsec.types().contains(RecordType::DS)
                && !nsec.types().contains(RecordType::SOA)
            {
                return Ok(());
            }
        }
        Err(DenialError::NotCovered)
    }

    fn all_in_zone(&self, signer_zone: &Name) -> bool {
        !self.records.is_empty()
            && self
                .records
                .iter()
                .all(|record| record.owner.is_subdomain_of(signer_zone))
    }

    fn covering_enclosers(&self, qname: &Name) -> Vec<Name> {
        self.records
            .iter()
            .filter_map(|record| match record.rdata {
                RData::Nsec(ref nsec)
                    if nsec_covers_name(&record.owner, nsec.next_domain(), qname) =>
                {
                    Some(nsec_closest_encloser(
                        qname,
                        &record.owner,
                        nsec.next_domain(),
                    ))
                }
                _ => None,
            })
            .collect()
    }

    fn is_delegation_or_dname(&self, name: &Name) -> bool {
        self.records.iter().any(|record| {
            let RData::Nsec(ref nsec) = record.rdata else {
                return false;
            };
            if !record.owner.eq_ignore_case(name) {
                return false;
            }
            let is_delegation =
                nsec.types().contains(RecordType::NS) && !nsec.types().contains(RecordType::SOA);
            is_delegation || nsec.types().contains(RecordType::DNAME)
        })
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

impl DenialProof {
    /// Constructs a [`DenialProof`] from a collection of denial resource records.
    ///
    /// # Errors
    /// Returns [`DenialError::DenialProofIncomplete`] if no NSEC or NSEC3 records are present,
    /// if NSEC and NSEC3 records are mixed, or if NSEC3 parameters conflict.
    pub fn from_records(records: &[&ResourceRecord]) -> Result<Self, DenialError> {
        let mut nsec_records = Vec::new();
        let mut nsec3_records = Vec::new();
        for &record in records {
            match record.rdata {
                RData::Nsec(_) => nsec_records.push(record.clone()),
                RData::Nsec3(_) => nsec3_records.push(record),
                _ => {}
            }
        }
        if !nsec_records.is_empty() && !nsec3_records.is_empty() {
            return Err(DenialError::DenialProofIncomplete);
        }
        if !nsec_records.is_empty() {
            return Ok(Self::Nsec(NsecProof::new(nsec_records)));
        }
        Nsec3Proof::from_records(&nsec3_records).map(Self::Nsec3)
    }

    /// The NSEC or NSEC3 records the proof rests on.
    #[must_use]
    pub fn records(&self) -> &[ResourceRecord] {
        match self {
            Self::Nsec(proof) => &proof.records,
            Self::Nsec3(proof) => proof.records(),
        }
    }

    /// Verifies the denial proof for a given zone, question, and response code.
    ///
    /// # Errors
    /// Returns [`DenialError`] if the proof fails to cover the question or exceeds iteration caps.
    pub fn verify(
        &self,
        signer_zone: &Name,
        qname: &Name,
        qtype: RecordType,
        rcode: ResponseCode,
        cap: Nsec3IterationsCap,
    ) -> Result<(), DenialError> {
        match (self, rcode) {
            (Self::Nsec(proof), ResponseCode::NXDOMAIN) => proof.prove_nxdomain(signer_zone, qname),
            (Self::Nsec(proof), ResponseCode::NOERROR) => {
                proof.prove_nodata_in_zone(signer_zone, qname, qtype)
            }
            (Self::Nsec3(proof), ResponseCode::NXDOMAIN) => {
                proof.prove_name_does_not_exist(signer_zone, qname, cap)
            }
            (Self::Nsec3(proof), ResponseCode::NOERROR) => {
                proof.prove_type_does_not_exist(signer_zone, qname, qtype, cap)
            }
            _ => Err(DenialError::DenialProofIncomplete),
        }
    }

    /// Verifies that no closer name exists for a wildcard-synthesized positive answer.
    ///
    /// # Errors
    /// Returns [`DenialError`] if wildcard non-existence proof fails.
    pub fn verify_wildcard_expansion(
        &self,
        signer_zone: &Name,
        owner: &Name,
        signature_labels: u8,
        cap: Nsec3IterationsCap,
    ) -> Result<(), DenialError> {
        match self {
            Self::Nsec(proof) => {
                proof.prove_wildcard_expansion(signer_zone, owner, signature_labels)
            }
            Self::Nsec3(proof) => {
                proof.prove_wildcard_expansion(signer_zone, owner, signature_labels, cap)
            }
        }
    }

    /// Verifies that DS is absent at `zone` under `signer_zone`.
    ///
    /// # Errors
    /// Returns [`DenialError`] if the proof fails.
    pub fn prove_ds_absence(
        &self,
        signer_zone: &Name,
        zone: &Name,
        cap: Nsec3IterationsCap,
    ) -> Result<(), DenialError> {
        match self {
            Self::Nsec(proof) => {
                if !zone.is_subdomain_of(signer_zone) || !proof.all_in_zone(signer_zone) {
                    return Err(DenialError::NotCovered);
                }
                proof.prove_ds_absence(zone)
            }
            Self::Nsec3(proof) => proof.prove_ds_absence(signer_zone, zone, cap),
        }
    }
}

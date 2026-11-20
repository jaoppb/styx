//! Iterated salted NSEC3 hashing and closest-encloser derivation (RFC 5155).

use std::cmp::Ordering;

use data_encoding::BASE32_DNSSEC;
use styx_proto::domain::rdata::Nsec3Rdata;
use styx_proto::{Name, RData, RecordType, ResourceRecord};

use crate::domain::denial::{ClosestEncloserProof, DenialStrength, Nsec3Flags, Nsec3Params};
use crate::domain::error::DenialError;
use crate::domain::node_types::OwnerTypes;
use crate::domain::policy::{Nsec3HashAlgorithm, Nsec3IterationsCap};

/// Decodes base32hex (RFC 5155) bytes into a binary digest, rejecting invalid
/// lengths, non-alphabet characters, and non-zero trailing padding bits.
#[must_use]
pub fn base32hex_decode(input: &[u8]) -> Option<Vec<u8>> {
    BASE32_DNSSEC.decode(input).ok()
}

/// Computes the iterated salted NSEC3 hash over a domain name (RFC 5155 §5).
///
/// # Errors
/// Returns [`DenialError`] if hash algorithm is unsupported or iteration cap is exceeded.
pub fn hash_nsec3_name(
    name: &Name,
    params: &Nsec3Params,
    cap: Nsec3IterationsCap,
) -> Result<Vec<u8>, DenialError> {
    if params.hash_algorithm != Nsec3HashAlgorithm::SHA1 {
        return Err(DenialError::UnsupportedHashAlgorithm(params.hash_algorithm));
    }
    params.check_iterations(cap)?;

    let canonical_name = name.to_canonical();
    let wire_name = canonical_name.as_wire_bytes();

    let mut buf = Vec::with_capacity(wire_name.len().saturating_add(params.salt.len()));
    buf.extend_from_slice(wire_name);
    buf.extend_from_slice(&params.salt);

    let mut current_digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &buf)
        .as_ref()
        .to_vec();

    for _ in 0..params.iterations {
        let mut step_buf =
            Vec::with_capacity(current_digest.len().saturating_add(params.salt.len()));
        step_buf.extend_from_slice(&current_digest);
        step_buf.extend_from_slice(&params.salt);
        current_digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &step_buf)
            .as_ref()
            .to_vec();
    }

    Ok(current_digest)
}

/// Checks whether an NSEC3 record covers a target hash in hash order.
#[must_use]
pub fn nsec3_covers_hash(owner: &[u8], next: &[u8], target: &[u8]) -> bool {
    let cmp_owner_next = owner.cmp(next);
    let cmp_owner_target = owner.cmp(target);
    let cmp_target_next = target.cmp(next);

    if cmp_owner_next == Ordering::Less {
        cmp_owner_target == Ordering::Less && cmp_target_next == Ordering::Less
    } else if cmp_owner_next == Ordering::Greater {
        cmp_owner_target == Ordering::Less || cmp_target_next == Ordering::Less
    } else {
        // RFC 5155 §7.2.1: single NSEC3 in zone covers all other hashes
        cmp_owner_target != Ordering::Equal
    }
}

/// Extracts the binary owner hash from an NSEC3 record's first label.
fn extract_owner_hash(record: &ResourceRecord) -> Option<Vec<u8>> {
    let first_label = record.owner.labels().next()?;
    base32hex_decode(first_label.as_bytes())
}

fn is_nsec3_in_zone(record: &ResourceRecord, signer_zone: &Name) -> bool {
    record.owner.label_count() == signer_zone.label_count().saturating_add(1)
        && record
            .owner
            .parent()
            .is_some_and(|parent| parent.eq_ignore_case(signer_zone))
}

fn find_matching_nsec3<'a>(
    records: &'a [ResourceRecord],
    target_hash: &[u8],
) -> Option<&'a Nsec3Rdata> {
    records.iter().find_map(|record| {
        let RData::Nsec3(ref nsec3) = record.rdata else {
            return None;
        };
        let owner_hash = extract_owner_hash(record)?;
        (owner_hash.as_slice() == target_hash).then_some(nsec3)
    })
}

/// The NSEC3 records in `records` that cover `target_hash`.
fn covering_nsec3s<'a>(
    records: &'a [ResourceRecord],
    target_hash: &'a [u8],
) -> impl Iterator<Item = &'a Nsec3Rdata> {
    records.iter().filter_map(move |record| {
        let RData::Nsec3(ref nsec3) = record.rdata else {
            return None;
        };
        let owner_hash = extract_owner_hash(record)?;
        nsec3_covers_hash(&owner_hash, nsec3.next_hashed_owner(), target_hash).then_some(nsec3)
    })
}

/// Whether any NSEC3 in `records` covers `target_hash`.
fn is_hash_covered(records: &[ResourceRecord], target_hash: &[u8]) -> bool {
    covering_nsec3s(records, target_hash).next().is_some()
}

/// How the next closer name is covered, which decides whether a denial built on it can
/// be Secure (RFC 5155 §9.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NextCloserCover {
    /// Covered, and no covering NSEC3 has Opt-Out set.
    Strict,
    /// A covering NSEC3 has Opt-Out set: an unsigned delegation may exist there.
    OptOut,
}

impl NextCloserCover {
    fn of(records: &[ResourceRecord], target_hash: &[u8]) -> Option<Self> {
        let mut cover = None;
        for nsec3 in covering_nsec3s(records, target_hash) {
            if nsec3.opt_out() {
                return Some(Self::OptOut);
            }
            cover = Some(Self::Strict);
        }
        cover
    }

    const fn strength(self) -> DenialStrength {
        match self {
            Self::Strict => DenialStrength::Proven,
            Self::OptOut => DenialStrength::OptOut,
        }
    }
}

/// A closest provable encloser proof: the encloser and its legs, and how the next
/// closer name is covered.
struct EncloserProof {
    legs: ClosestEncloserProof,
    cover: NextCloserCover,
}

/// Whether the NSEC3 matching `target_hash`, owned by `name`, proves `qtype` absent.
/// `Ok(false)` when no NSEC3 matches.
fn nsec3_matches_nodata(
    records: &[ResourceRecord],
    name: &Name,
    target_hash: &[u8],
    qtype: RecordType,
) -> Result<bool, DenialError> {
    let Some(nsec3) = find_matching_nsec3(records, target_hash) else {
        return Ok(false);
    };
    if OwnerTypes::new(name, nsec3.types()).denies(qtype) {
        Ok(true)
    } else {
        Err(DenialError::NotCovered)
    }
}

/// NSEC3-based hashed proof of non-existence (RFC 5155).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nsec3Proof {
    params: Nsec3Params,
    records: Vec<ResourceRecord>,
}

impl Nsec3Proof {
    /// Constructs a validated [`Nsec3Proof`] from NSEC3 records with uniform parameters.
    ///
    /// # Errors
    /// Returns [`DenialError::DenialProofIncomplete`] if `records` is empty, contains
    /// non-NSEC3 records, or has mismatched hash parameters.
    pub fn from_records(records: &[&ResourceRecord]) -> Result<Self, DenialError> {
        let Some(&first) = records.first() else {
            return Err(DenialError::DenialProofIncomplete);
        };
        let RData::Nsec3(ref rdata) = first.rdata else {
            return Err(DenialError::DenialProofIncomplete);
        };
        let params = Nsec3Params::new(
            Nsec3HashAlgorithm::new(rdata.hash_algorithm()),
            Nsec3Flags::new(rdata.flags()),
            rdata.iterations(),
            rdata.salt().to_vec(),
        );
        let mut owned_records = Vec::with_capacity(records.len());
        for &record in records {
            let RData::Nsec3(ref other) = record.rdata else {
                return Err(DenialError::DenialProofIncomplete);
            };
            if Nsec3HashAlgorithm::new(other.hash_algorithm()) != params.hash_algorithm
                || other.iterations() != params.iterations
                || other.salt() != params.salt.as_slice()
            {
                return Err(DenialError::DenialProofIncomplete);
            }
            owned_records.push(record.clone());
        }
        Ok(Self {
            params,
            records: owned_records,
        })
    }

    /// Returns the validated NSEC3 parameters shared by every record in this proof.
    #[must_use]
    pub fn params(&self) -> &Nsec3Params {
        &self.params
    }

    /// Returns the NSEC3 records constituting this proof.
    #[must_use]
    pub fn records(&self) -> &[ResourceRecord] {
        &self.records
    }

    /// Returns whether Opt-Out applies to this proof.
    #[must_use]
    pub fn opt_out_applies(&self) -> bool {
        self.params.flags.is_opt_out()
    }

    /// Derives the closest encloser within `signer_zone` and verifies its NSEC3 record is
    /// neither a delegation point (RFC 5155 §8.3) nor a DNAME.
    ///
    /// # Errors
    /// Returns [`DenialError`] if no ancestor matches, the closest encloser is invalid,
    /// or hashing fails.
    pub fn find_closest_encloser(
        &self,
        signer_zone: &Name,
        qname: &Name,
        cap: Nsec3IterationsCap,
    ) -> Result<Name, DenialError> {
        self.validate_zone_records(signer_zone)?;
        if !qname.is_subdomain_of(signer_zone) {
            return Err(DenialError::NotCovered);
        }
        for label_count in (signer_zone.label_count()..=qname.label_count()).rev() {
            let Some(candidate) = qname.ancestor(label_count) else {
                continue;
            };
            let hash = hash_nsec3_name(&candidate, &self.params, cap)?;
            let Some(nsec3) = find_matching_nsec3(&self.records, &hash) else {
                continue;
            };
            if OwnerTypes::new(&candidate, nsec3.types()).ends_authority() {
                return Err(DenialError::DenialProofIncomplete);
            }
            return Ok(candidate);
        }
        Err(DenialError::NotCovered)
    }

    /// Evaluates a full three-part NSEC3 proof of non-existence (RFC 5155 §7.2.1, §8.3).
    ///
    /// # Errors
    /// Returns [`DenialError`] if any leg is incomplete, out-of-zone, or fails to cover.
    pub fn prove_name_does_not_exist(
        &self,
        signer_zone: &Name,
        qname: &Name,
        cap: Nsec3IterationsCap,
    ) -> Result<DenialStrength, DenialError> {
        let proof = self.closest_encloser_legs(signer_zone, qname, cap)?;
        let wildcard_hash = hash_nsec3_name(proof.legs.wildcard(), &self.params, cap)?;
        if !is_hash_covered(&self.records, &wildcard_hash) {
            return Err(DenialError::DenialProofIncomplete);
        }
        Ok(proof.cover.strength())
    }

    /// Verifies an NSEC3 proof that no DS exists at the delegation `zone`: either the
    /// NSEC3 matching `zone` lists NS without DS or SOA (RFC 5155 §8.6), or a closest
    /// provable encloser proof for `zone` whose next closer name is covered by an Opt-Out
    /// NSEC3, so `zone` may be an unsigned delegation (RFC 5155 §8.6, §6).
    ///
    /// # Errors
    /// Returns [`DenialError`] if proof fails or records fall outside `signer_zone`.
    pub fn prove_ds_absence(
        &self,
        signer_zone: &Name,
        zone: &Name,
        cap: Nsec3IterationsCap,
    ) -> Result<(), DenialError> {
        self.validate_zone_records(signer_zone)?;
        if !zone.is_subdomain_of(signer_zone) {
            return Err(DenialError::NotCovered);
        }
        let zone_hash = hash_nsec3_name(zone, &self.params, cap)?;
        if let Some(nsec3) = find_matching_nsec3(&self.records, &zone_hash) {
            return if OwnerTypes::new(zone, nsec3.types()).is_unsigned_delegation() {
                Ok(())
            } else {
                Err(DenialError::NotCovered)
            };
        }
        match self.closest_encloser_legs(signer_zone, zone, cap)?.cover {
            NextCloserCover::OptOut => Ok(()),
            NextCloserCover::Strict => Err(DenialError::NotCovered),
        }
    }

    /// Verifies an NSEC3 NODATA proof (RFC 5155 §7.2.3, §7.2.4, §8.4).
    ///
    /// # Errors
    /// Returns [`DenialError`] if proof fails or records fall outside `signer_zone`.
    pub fn prove_type_does_not_exist(
        &self,
        signer_zone: &Name,
        qname: &Name,
        qtype: RecordType,
        cap: Nsec3IterationsCap,
    ) -> Result<DenialStrength, DenialError> {
        self.validate_zone_records(signer_zone)?;
        if !qname.is_subdomain_of(signer_zone) {
            return Err(DenialError::NotCovered);
        }
        let qname_hash = hash_nsec3_name(qname, &self.params, cap)?;
        if nsec3_matches_nodata(&self.records, qname, &qname_hash, qtype)? {
            return Ok(DenialStrength::Proven);
        }

        let proof = self.closest_encloser_legs(signer_zone, qname, cap)?;
        // RFC 5155 §8.6: a DS NODATA with no matching NSEC3 holds only as an opt-out
        // span, which proves nothing Secure.
        if qtype == RecordType::DS && proof.cover == NextCloserCover::OptOut {
            return Ok(DenialStrength::OptOut);
        }
        let wildcard = proof.legs.wildcard();
        let wildcard_hash = hash_nsec3_name(wildcard, &self.params, cap)?;
        if nsec3_matches_nodata(&self.records, wildcard, &wildcard_hash, qtype)? {
            return Ok(proof.cover.strength());
        }

        Err(DenialError::NotCovered)
    }

    /// Verifies that no closer name exists for a wildcard-synthesized positive answer (RFC 5155 §7.2.6).
    ///
    /// # Errors
    /// Returns [`DenialError`] if the next-closer name is uncovered or out-of-zone.
    pub fn prove_wildcard_expansion(
        &self,
        signer_zone: &Name,
        owner: &Name,
        signature_labels: u8,
        cap: Nsec3IterationsCap,
    ) -> Result<DenialStrength, DenialError> {
        self.validate_zone_records(signer_zone)?;
        if !owner.is_subdomain_of(signer_zone) {
            return Err(DenialError::NotCovered);
        }
        let closest_encloser = owner
            .ancestor(usize::from(signature_labels))
            .ok_or(DenialError::DenialProofIncomplete)?;
        if !closest_encloser.is_subdomain_of(signer_zone) {
            return Err(DenialError::NotCovered);
        }
        let ce_hash = hash_nsec3_name(&closest_encloser, &self.params, cap)?;
        if let Some(ce_nsec3) = find_matching_nsec3(&self.records, &ce_hash) {
            if OwnerTypes::new(&closest_encloser, ce_nsec3.types()).ends_authority() {
                return Err(DenialError::DenialProofIncomplete);
            }
        }
        let legs = ClosestEncloserProof::new(owner, closest_encloser)?;
        let next_closer_hash = hash_nsec3_name(legs.next_closer(), &self.params, cap)?;
        NextCloserCover::of(&self.records, &next_closer_hash)
            .map(NextCloserCover::strength)
            .ok_or(DenialError::DenialProofIncomplete)
    }

    fn validate_zone_records(&self, signer_zone: &Name) -> Result<(), DenialError> {
        let valid = !self.records.is_empty()
            && self.records.iter().all(|record| {
                is_nsec3_in_zone(record, signer_zone) && extract_owner_hash(record).is_some()
            });
        if valid {
            Ok(())
        } else {
            Err(DenialError::DenialProofIncomplete)
        }
    }

    fn closest_encloser_legs(
        &self,
        signer_zone: &Name,
        qname: &Name,
        cap: Nsec3IterationsCap,
    ) -> Result<EncloserProof, DenialError> {
        let closest_encloser = self.find_closest_encloser(signer_zone, qname, cap)?;
        let legs = ClosestEncloserProof::new(qname, closest_encloser)?;
        let next_closer_hash = hash_nsec3_name(legs.next_closer(), &self.params, cap)?;
        let cover = NextCloserCover::of(&self.records, &next_closer_hash)
            .ok_or(DenialError::DenialProofIncomplete)?;
        Ok(EncloserProof { legs, cover })
    }
}

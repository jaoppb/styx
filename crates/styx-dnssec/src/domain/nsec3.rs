//! Iterated salted NSEC3 hashing and closest-encloser derivation (RFC 5155).

use std::collections::HashMap;

use data_encoding::BASE32_DNSSEC;
use styx_proto::domain::rdata::Nsec3Rdata;
use styx_proto::{Name, RData, RecordType, ResourceRecord};

use crate::domain::denial::{ring_covers, ClosestEncloserProof, DenialStrength, Nsec3Params};
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
    let salt_len = params.salt.len();

    let mut initial = Vec::with_capacity(wire_name.len().saturating_add(salt_len));
    initial.extend_from_slice(wire_name);
    initial.extend_from_slice(&params.salt);
    let first = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &initial);

    if params.iterations == 0 {
        return Ok(first.as_ref().to_vec());
    }

    let digest_len = first.as_ref().len();
    let mut step_buffer = Vec::with_capacity(digest_len.saturating_add(salt_len));
    step_buffer.extend_from_slice(first.as_ref());
    step_buffer.extend_from_slice(&params.salt);

    for _ in 0..params.iterations {
        let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &step_buffer);
        if let Some(prefix) = step_buffer.get_mut(..digest_len) {
            prefix.copy_from_slice(digest.as_ref());
        }
    }

    Ok(step_buffer.get(..digest_len).unwrap_or_default().to_vec())
}

/// Checks whether an NSEC3 record covers a target hash in hash order.
#[must_use]
pub fn nsec3_covers_hash(owner: &[u8], next: &[u8], target: &[u8]) -> bool {
    ring_covers(owner, next, target, Ord::cmp)
}

/// The length of an SHA-1 digest, the only NSEC3 hash defined (RFC 5155 §5, §10.1).
const SHA1_DIGEST_LENGTH: usize = 20;

/// Extracts the binary owner hash from an NSEC3 record's first label, checking both it
/// and the next hashed owner against the digest length of a known hash algorithm.
fn extract_owner_hash(
    record: &ResourceRecord,
    hash_algorithm: Nsec3HashAlgorithm,
) -> Result<Vec<u8>, DenialError> {
    let RData::Nsec3(ref nsec3) = record.rdata else {
        return Err(DenialError::DenialProofIncomplete);
    };
    let owner_hash = record
        .owner
        .labels()
        .next()
        .and_then(|label| base32hex_decode(label.as_bytes()))
        .ok_or(DenialError::DenialProofIncomplete)?;
    let wrong_length = hash_algorithm == Nsec3HashAlgorithm::SHA1
        && (owner_hash.len() != SHA1_DIGEST_LENGTH
            || nsec3.next_hashed_owner().len() != SHA1_DIGEST_LENGTH);
    if wrong_length {
        return Err(DenialError::DenialProofIncomplete);
    }
    Ok(owner_hash)
}

/// Whether `record` is an NSEC3 owned directly below `signer_zone`, the only place its
/// zone can hold one (RFC 5155 §7.1).
pub(crate) fn is_nsec3_in_zone(record: &ResourceRecord, signer_zone: &Name) -> bool {
    record.owner.label_count() == signer_zone.label_count().saturating_add(1)
        && record
            .owner
            .parent()
            .is_some_and(|parent| parent.eq_ignore_case(signer_zone))
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

/// NSEC3-based hashed proof of non-existence (RFC 5155).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nsec3Proof {
    params: Nsec3Params,
    records: Vec<ResourceRecord>,
    owner_hashes: Vec<Vec<u8>>,
}

impl Nsec3Proof {
    /// Constructs a validated [`Nsec3Proof`] from NSEC3 records with uniform parameters.
    ///
    /// # Errors
    /// Returns [`DenialError::DenialProofIncomplete`] if `records` is empty, contains
    /// non-NSEC3 records, has mismatched hash parameters, or an owner name that is not a
    /// hash of the algorithm's length.
    pub fn from_records(records: &[&ResourceRecord]) -> Result<Self, DenialError> {
        let Some(&first) = records.first() else {
            return Err(DenialError::DenialProofIncomplete);
        };
        let RData::Nsec3(ref rdata) = first.rdata else {
            return Err(DenialError::DenialProofIncomplete);
        };
        let params = Nsec3Params::new(
            Nsec3HashAlgorithm::new(rdata.hash_algorithm()),
            rdata.iterations(),
            rdata.salt().to_vec(),
        );
        let mut owned_records = Vec::with_capacity(records.len());
        let mut owner_hashes = Vec::with_capacity(records.len());
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
            owner_hashes.push(extract_owner_hash(record, params.hash_algorithm)?);
            owned_records.push(record.clone());
        }
        Ok(Self {
            params,
            records: owned_records,
            owner_hashes,
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

    fn entries(&self) -> impl Iterator<Item = (&[u8], &Nsec3Rdata)> {
        self.records
            .iter()
            .zip(self.owner_hashes.iter())
            .filter_map(|(record, owner_hash)| match record.rdata {
                RData::Nsec3(ref nsec3) => Some((owner_hash.as_slice(), nsec3)),
                _ => None,
            })
    }

    fn find_matching(&self, target_hash: &[u8]) -> Option<&Nsec3Rdata> {
        self.entries()
            .find(|(owner_hash, _)| *owner_hash == target_hash)
            .map(|(_, nsec3)| nsec3)
    }

    fn covering<'a>(&'a self, target_hash: &'a [u8]) -> impl Iterator<Item = &'a Nsec3Rdata> {
        self.entries()
            .filter(move |(owner_hash, nsec3)| {
                nsec3_covers_hash(owner_hash, nsec3.next_hashed_owner(), target_hash)
            })
            .map(|(_, nsec3)| nsec3)
    }

    fn is_hash_covered(&self, target_hash: &[u8]) -> bool {
        self.covering(target_hash).next().is_some()
    }

    fn next_closer_cover(&self, target_hash: &[u8]) -> Option<NextCloserCover> {
        let mut cover = None;
        for nsec3 in self.covering(target_hash) {
            if nsec3.opt_out() {
                return Some(NextCloserCover::OptOut);
            }
            cover = Some(NextCloserCover::Strict);
        }
        cover
    }

    fn matches_nodata(
        &self,
        name: &Name,
        target_hash: &[u8],
        qtype: RecordType,
    ) -> Result<bool, DenialError> {
        let Some(nsec3) = self.find_matching(target_hash) else {
            return Ok(false);
        };
        if OwnerTypes::new(name, nsec3.types()).denies(qtype) {
            Ok(true)
        } else {
            Err(DenialError::NotCovered)
        }
    }

    fn cached_hash(
        &self,
        name: &Name,
        cap: Nsec3IterationsCap,
        cache: &mut HashMap<Name, Vec<u8>>,
    ) -> Result<Vec<u8>, DenialError> {
        if let Some(existing) = cache.get(name) {
            return Ok(existing.clone());
        }
        let digest = hash_nsec3_name(name, &self.params, cap)?;
        cache.insert(name.clone(), digest.clone());
        Ok(digest)
    }

    fn find_closest_encloser(
        &self,
        signer_zone: &Name,
        qname: &Name,
        cap: Nsec3IterationsCap,
        cache: &mut HashMap<Name, Vec<u8>>,
    ) -> Result<Name, DenialError> {
        self.validate_zone_records(signer_zone)?;
        if !qname.is_subdomain_of(signer_zone) {
            return Err(DenialError::NotCovered);
        }
        for label_count in (signer_zone.label_count()..=qname.label_count()).rev() {
            let Some(candidate) = qname.ancestor(label_count) else {
                continue;
            };
            let hash = self.cached_hash(&candidate, cap, cache)?;
            let Some(nsec3) = self.find_matching(&hash) else {
                continue;
            };
            if OwnerTypes::new(&candidate, nsec3.types()).ends_authority() {
                return Err(DenialError::DenialProofIncomplete);
            }
            return Ok(candidate);
        }
        Err(DenialError::NotCovered)
    }

    pub(crate) fn prove_name_does_not_exist(
        &self,
        signer_zone: &Name,
        qname: &Name,
        cap: Nsec3IterationsCap,
    ) -> Result<DenialStrength, DenialError> {
        let mut cache = HashMap::new();
        let proof = self.closest_encloser_legs(signer_zone, qname, cap, &mut cache)?;
        let wildcard_hash = self.cached_hash(proof.legs.wildcard(), cap, &mut cache)?;
        if !self.is_hash_covered(&wildcard_hash) {
            return Err(DenialError::DenialProofIncomplete);
        }
        Ok(proof.cover.strength())
    }

    pub(crate) fn prove_ds_absence(
        &self,
        signer_zone: &Name,
        zone: &Name,
        cap: Nsec3IterationsCap,
    ) -> Result<(), DenialError> {
        self.validate_zone_records(signer_zone)?;
        if !zone.is_subdomain_of(signer_zone) {
            return Err(DenialError::NotCovered);
        }
        let mut cache = HashMap::new();
        let zone_hash = self.cached_hash(zone, cap, &mut cache)?;
        if let Some(nsec3) = self.find_matching(&zone_hash) {
            return if OwnerTypes::new(zone, nsec3.types()).is_unsigned_delegation() {
                Ok(())
            } else {
                Err(DenialError::NotCovered)
            };
        }
        match self
            .closest_encloser_legs(signer_zone, zone, cap, &mut cache)?
            .cover
        {
            NextCloserCover::OptOut => Ok(()),
            NextCloserCover::Strict => Err(DenialError::NotCovered),
        }
    }

    pub(crate) fn prove_type_does_not_exist(
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
        let mut cache = HashMap::new();
        let qname_hash = self.cached_hash(qname, cap, &mut cache)?;
        if self.matches_nodata(qname, &qname_hash, qtype)? {
            return Ok(DenialStrength::Proven);
        }

        let proof = self.closest_encloser_legs(signer_zone, qname, cap, &mut cache)?;
        // RFC 5155 §8.6: a DS NODATA with no matching NSEC3 holds only as an opt-out
        // span, which proves nothing Secure.
        if qtype == RecordType::DS && proof.cover == NextCloserCover::OptOut {
            return Ok(DenialStrength::OptOut);
        }
        let wildcard = proof.legs.wildcard();
        let wildcard_hash = self.cached_hash(wildcard, cap, &mut cache)?;
        if self.matches_nodata(wildcard, &wildcard_hash, qtype)? {
            return Ok(proof.cover.strength());
        }

        Err(DenialError::NotCovered)
    }

    pub(crate) fn prove_wildcard_expansion(
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
        let mut cache = HashMap::new();
        let closest_encloser_hash = self.cached_hash(&closest_encloser, cap, &mut cache)?;
        if let Some(closest_encloser_nsec3) = self.find_matching(&closest_encloser_hash) {
            if OwnerTypes::new(&closest_encloser, closest_encloser_nsec3.types()).ends_authority() {
                return Err(DenialError::DenialProofIncomplete);
            }
        }
        let legs = ClosestEncloserProof::new(owner, closest_encloser)?;
        let next_closer_hash = self.cached_hash(legs.next_closer(), cap, &mut cache)?;
        self.next_closer_cover(&next_closer_hash)
            .map(NextCloserCover::strength)
            .ok_or(DenialError::DenialProofIncomplete)
    }

    fn validate_zone_records(&self, signer_zone: &Name) -> Result<(), DenialError> {
        let valid = !self.records.is_empty()
            && self
                .records
                .iter()
                .all(|record| is_nsec3_in_zone(record, signer_zone));
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
        cache: &mut HashMap<Name, Vec<u8>>,
    ) -> Result<EncloserProof, DenialError> {
        let closest_encloser = self.find_closest_encloser(signer_zone, qname, cap, cache)?;
        let legs = ClosestEncloserProof::new(qname, closest_encloser)?;
        let next_closer_hash = self.cached_hash(legs.next_closer(), cap, cache)?;
        let cover = self
            .next_closer_cover(&next_closer_hash)
            .ok_or(DenialError::DenialProofIncomplete)?;
        Ok(EncloserProof { legs, cover })
    }
}

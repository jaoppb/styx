//! Iterated salted NSEC3 hashing and closest-encloser derivation (RFC 5155).

use std::cmp::Ordering;

use styx_proto::{Name, RData, RecordType, ResourceRecord};

use crate::domain::denial::{prepend_wildcard, Nsec3Params, Nsec3Proof};
use crate::domain::error::DenialError;
use crate::domain::verdict::Nsec3IterationsCap;

const BASE32HEX_CHARS: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";

/// Converts an ASCII character to its 5-bit base32hex value.
fn base32hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c.saturating_sub(b'0')),
        b'a'..=b'v' => Some(c.saturating_sub(b'a').saturating_add(10)),
        b'A'..=b'V' => Some(c.saturating_sub(b'A').saturating_add(10)),
        _ => None,
    }
}

/// Decodes base32hex bytes into a binary digest.
#[must_use]
pub fn base32hex_decode(input: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(20);
    let mut bit_buf: u64 = 0;
    let mut bit_count: usize = 0;

    for &b in input {
        let val = base32hex_val(b)?;
        bit_buf = (bit_buf << 5) | u64::from(val);
        bit_count = bit_count.saturating_add(5);
        if bit_count >= 8 {
            bit_count = bit_count.saturating_sub(8);
            let byte = (bit_buf >> bit_count) & 0xFF;
            if let Ok(b_u8) = u8::try_from(byte) {
                out.push(b_u8);
            }
        }
    }
    Some(out)
}

/// Encodes binary digest bytes to a lowercase base32hex string.
#[must_use]
pub fn base32hex_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(32);
    let mut bit_buf: u64 = 0;
    let mut bit_count: usize = 0;

    for &byte in input {
        bit_buf = (bit_buf << 8) | u64::from(byte);
        bit_count = bit_count.saturating_add(8);
        while bit_count >= 5 {
            bit_count = bit_count.saturating_sub(5);
            let idx = (bit_buf >> bit_count) & 0x1F;
            if let Some(&ch) = BASE32HEX_CHARS.get(idx as usize) {
                out.push(ch as char);
            }
        }
    }
    if bit_count > 0 {
        let shift = 5usize.saturating_sub(bit_count);
        let idx = (bit_buf << shift) & 0x1F;
        if let Some(&ch) = BASE32HEX_CHARS.get(idx as usize) {
            out.push(ch as char);
        }
    }
    out
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
    if params.hash_algorithm != 1 {
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
fn extract_owner_hash(rr: &ResourceRecord) -> Option<Vec<u8>> {
    let first_label = rr.owner.labels().next()?;
    base32hex_decode(first_label.as_bytes())
}

/// Derives the Closest Encloser (CE) for `qname` matching an NSEC3 record in `proof`.
///
/// # Errors
/// Returns [`DenialError`] if no ancestor is covered or cap is exceeded.
pub fn find_closest_encloser(
    proof: &Nsec3Proof,
    qname: &Name,
    cap: Nsec3IterationsCap,
) -> Result<Name, DenialError> {
    for label_count in (0..=qname.label_count()).rev() {
        let Some(candidate) = qname.ancestor(label_count) else {
            continue;
        };
        let hash = hash_nsec3_name(&candidate, &proof.params, cap)?;
        let found = proof
            .records
            .iter()
            .any(|rr| extract_owner_hash(rr).is_some_and(|owner_hash| owner_hash == hash));
        if found {
            return Ok(candidate);
        }
    }
    Err(DenialError::NotCovered)
}

/// Finds the next closer name with one more label than `ce` under `qname`.
fn get_next_closer_name(qname: &Name, closest_encloser: &Name) -> Option<Name> {
    if qname.label_count() <= closest_encloser.label_count() {
        return None;
    }
    qname.ancestor(closest_encloser.label_count().saturating_add(1))
}

/// Verifies whether `target_hash` is covered by any NSEC3 in `records`.
fn is_hash_covered(records: &[ResourceRecord], target_hash: &[u8]) -> bool {
    records.iter().any(|rr| {
        let RData::Nsec3(ref nsec3) = rr.rdata else {
            return false;
        };
        let Some(owner_hash) = extract_owner_hash(rr) else {
            return false;
        };
        nsec3_covers_hash(&owner_hash, nsec3.next_hashed_owner(), target_hash)
    })
}

/// Evaluates a full three-part NSEC3 proof of non-existence (RFC 5155 §7.2.1).
///
/// # Errors
/// Returns [`DenialError`] if any leg is incomplete or fails to cover.
pub fn verify_nsec3_nxdomain(
    proof: &Nsec3Proof,
    qname: &Name,
    cap: Nsec3IterationsCap,
) -> Result<(), DenialError> {
    // 1. Closest encloser exists
    let ce = find_closest_encloser(proof, qname, cap)?;

    // 2. Next closer is covered
    let nc = match get_next_closer_name(qname, &ce) {
        Some(nc) => nc,
        None => return Err(DenialError::DenialProofIncomplete),
    };
    let nc_hash = hash_nsec3_name(&nc, &proof.params, cap)?;
    if !is_hash_covered(&proof.records, &nc_hash) {
        return Err(DenialError::DenialProofIncomplete);
    }

    // 3. Wildcard at closest encloser is covered or proven absent
    let wildcard = match prepend_wildcard(&ce) {
        Ok(w) => w,
        Err(_) => return Err(DenialError::DenialProofIncomplete),
    };
    let wc_hash = hash_nsec3_name(&wildcard, &proof.params, cap)?;
    if !is_hash_covered(&proof.records, &wc_hash) {
        return Err(DenialError::DenialProofIncomplete);
    }

    Ok(())
}

/// Verifies an NSEC3 proof of absent DS record at delegation (RFC 5155 §7.2.7).
///
/// # Errors
/// Returns [`DenialError`] if proof fails.
pub fn verify_nsec3_ds_absence(
    proof: &Nsec3Proof,
    zone: &Name,
    cap: Nsec3IterationsCap,
) -> Result<(), DenialError> {
    let zone_hash = hash_nsec3_name(zone, &proof.params, cap)?;
    for rr in &proof.records {
        let RData::Nsec3(ref nsec3) = rr.rdata else {
            continue;
        };
        let Some(owner_hash) = extract_owner_hash(rr) else {
            continue;
        };
        let matches_exact_without_ds =
            owner_hash == zone_hash && !nsec3.types().contains(styx_proto::RecordType::DS);
        let opt_out_covers = nsec3.opt_out()
            && nsec3_covers_hash(&owner_hash, nsec3.next_hashed_owner(), &zone_hash);
        if matches_exact_without_ds || opt_out_covers {
            return Ok(());
        }
    }
    Err(DenialError::NotCovered)
}

fn nsec3_matches_nodata(
    records: &[ResourceRecord],
    target_hash: &[u8],
    qtype: RecordType,
) -> Result<bool, DenialError> {
    for rr in records {
        let RData::Nsec3(ref nsec3) = rr.rdata else {
            continue;
        };
        let Some(owner_hash) = extract_owner_hash(rr) else {
            continue;
        };
        if owner_hash.as_slice() == target_hash {
            if nsec3.types().contains(qtype) || nsec3.types().contains(RecordType::CNAME) {
                return Err(DenialError::NotCovered);
            }
            return Ok(true);
        }
    }
    Ok(false)
}

/// Verifies an NSEC3 NODATA proof (RFC 5155 §7.2.3 and §7.2.4).
///
/// # Errors
/// Returns [`DenialError`] if proof fails.
pub fn verify_nsec3_nodata(
    proof: &Nsec3Proof,
    qname: &Name,
    qtype: RecordType,
    cap: Nsec3IterationsCap,
) -> Result<(), DenialError> {
    let qname_hash = hash_nsec3_name(qname, &proof.params, cap)?;
    if nsec3_matches_nodata(&proof.records, &qname_hash, qtype)? {
        return Ok(());
    }

    let ce = find_closest_encloser(proof, qname, cap)?;
    let nc = match get_next_closer_name(qname, &ce) {
        Some(nc) => nc,
        None => return Err(DenialError::DenialProofIncomplete),
    };
    let nc_hash = hash_nsec3_name(&nc, &proof.params, cap)?;
    if !is_hash_covered(&proof.records, &nc_hash) {
        return Err(DenialError::DenialProofIncomplete);
    }

    let wildcard = prepend_wildcard(&ce).map_err(|_| DenialError::DenialProofIncomplete)?;
    let wc_hash = hash_nsec3_name(&wildcard, &proof.params, cap)?;
    if nsec3_matches_nodata(&proof.records, &wc_hash, qtype)? {
        return Ok(());
    }

    Err(DenialError::NotCovered)
}

//! Cryptographic signature verification and DS-to-DNSKEY digest computation.

use styx_core::Clock;
use styx_proto::domain::rdata::{DnskeyRdata, DsRdata, RrsigRdata};
use styx_proto::{Name, ResourceRecord};

use crate::domain::canonical::build_canonical_signed_data;
use crate::domain::verdict::{AlgorithmSet, AlgorithmSupport, VerdictReason};

/// Verifies an RSA-SHA256 signature according to RFC 5702 and RFC 3110.
fn verify_rsa_signature(
    public_key: &[u8],
    signed_data: &[u8],
    signature: &[u8],
) -> Result<(), VerdictReason> {
    let first_byte = match public_key.first() {
        Some(&b) => b,
        None => return Err(VerdictReason::NoValidRrsig),
    };

    let (exp_start, exp_len) = if first_byte == 0 {
        if public_key.len() < 3 {
            return Err(VerdictReason::NoValidRrsig);
        }
        let b1 = match public_key.get(1) {
            Some(&b) => b,
            None => return Err(VerdictReason::NoValidRrsig),
        };
        let b2 = match public_key.get(2) {
            Some(&b) => b,
            None => return Err(VerdictReason::NoValidRrsig),
        };
        (3usize, usize::from(u16::from_be_bytes([b1, b2])))
    } else {
        (1usize, usize::from(first_byte))
    };

    let exp_end = exp_start.saturating_add(exp_len);
    let exp = match public_key.get(exp_start..exp_end) {
        Some(e) => e,
        None => return Err(VerdictReason::NoValidRrsig),
    };
    let modulus = match public_key.get(exp_end..) {
        Some(m) if !m.is_empty() => m,
        _ => return Err(VerdictReason::NoValidRrsig),
    };

    let rsa_key = ring::signature::RsaPublicKeyComponents { n: modulus, e: exp };
    if rsa_key
        .verify(
            &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            signed_data,
            signature,
        )
        .is_ok()
        || rsa_key
            .verify(
                &ring::signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
                signed_data,
                signature,
            )
            .is_ok()
    {
        Ok(())
    } else {
        Err(VerdictReason::NoValidRrsig)
    }
}

/// Verifies an ECDSA P-256 signature according to RFC 6605.
fn verify_ecdsa_p256_signature(
    public_key: &[u8],
    signed_data: &[u8],
    signature: &[u8],
) -> Result<(), VerdictReason> {
    if public_key.len() != 64 {
        return Err(VerdictReason::NoValidRrsig);
    }
    let mut uncompressed = Vec::with_capacity(65);
    uncompressed.push(0x04);
    uncompressed.extend_from_slice(public_key);

    let key = ring::signature::UnparsedPublicKey::new(
        &ring::signature::ECDSA_P256_SHA256_FIXED,
        &uncompressed,
    );
    if key.verify(signed_data, signature).is_ok() {
        Ok(())
    } else {
        Err(VerdictReason::NoValidRrsig)
    }
}

/// Verifies an Ed25519 signature according to RFC 8080.
fn verify_ed25519_signature(
    public_key: &[u8],
    signed_data: &[u8],
    signature: &[u8],
) -> Result<(), VerdictReason> {
    if public_key.len() != 32 {
        return Err(VerdictReason::NoValidRrsig);
    }
    let key = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key);
    if key.verify(signed_data, signature).is_ok() {
        Ok(())
    } else {
        Err(VerdictReason::NoValidRrsig)
    }
}

/// Verifies a cryptographic signature based on the algorithm specified.
fn verify_crypto_signature(
    algorithm: u8,
    public_key: &[u8],
    signed_data: &[u8],
    signature: &[u8],
) -> Result<(), VerdictReason> {
    match algorithm {
        8 => verify_rsa_signature(public_key, signed_data, signature),
        13 => verify_ecdsa_p256_signature(public_key, signed_data, signature),
        15 => verify_ed25519_signature(public_key, signed_data, signature),
        _ => Err(VerdictReason::UnsupportedAlgorithm),
    }
}

/// Verifies a single [`RrsigRdata`] over an RRset using a [`DnskeyRdata`] and injected [`Clock`].
///
/// # Errors
/// Returns a [`VerdictReason`] if validation fails.
pub fn verify_rrsig_record<C: Clock>(
    rrsig: &RrsigRdata,
    rrset: &[ResourceRecord],
    dnskey: &DnskeyRdata,
    dnskey_owner: &Name,
    clock: &C,
    algorithms: &AlgorithmSet,
) -> Result<(), VerdictReason> {
    if rrsig.key_tag() != dnskey.key_tag() || rrsig.algorithm() != dnskey.algorithm() {
        return Err(VerdictReason::NoValidRrsig);
    }
    if rrsig.signer_name() != dnskey_owner {
        return Err(VerdictReason::NoValidRrsig);
    }

    let now_secs = match clock
        .now_utc()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
    {
        Ok(d) => u32::try_from(d.as_secs()).unwrap_or(u32::MAX),
        Err(_) => 0,
    };
    if now_secs < rrsig.signature_inception() {
        return Err(VerdictReason::SignatureNotYetValid);
    }
    if now_secs > rrsig.signature_expiration() {
        return Err(VerdictReason::SignatureExpired);
    }

    match algorithms.classify_sig(rrsig.algorithm()) {
        AlgorithmSupport::Supported => {}
        AlgorithmSupport::UnknownTreatAsInsecure => {
            return Err(VerdictReason::UnsupportedAlgorithm)
        }
        AlgorithmSupport::Refused => return Err(VerdictReason::NoValidRrsig),
    }

    let signed_data = match build_canonical_signed_data(rrsig, rrset) {
        Ok(data) => data,
        Err(_) => return Err(VerdictReason::NoValidRrsig),
    };

    verify_crypto_signature(
        rrsig.algorithm(),
        dnskey.public_key(),
        &signed_data,
        rrsig.signature(),
    )
}

/// Computes the cryptographic digest of a DNSKEY according to RFC 4034 §5.1.4.
#[must_use]
pub fn compute_dnskey_digest(
    zone_name: &Name,
    dnskey: &DnskeyRdata,
    digest_type: u8,
) -> Option<Vec<u8>> {
    let canonical_name = zone_name.to_canonical();
    let wire_name = canonical_name.as_wire_bytes();

    let mut rdata_bytes = Vec::with_capacity(4usize.saturating_add(dnskey.public_key().len()));
    rdata_bytes.extend_from_slice(&dnskey.flags().to_be_bytes());
    rdata_bytes.push(dnskey.protocol());
    rdata_bytes.push(dnskey.algorithm());
    rdata_bytes.extend_from_slice(dnskey.public_key());

    let mut input = Vec::with_capacity(wire_name.len().saturating_add(rdata_bytes.len()));
    input.extend_from_slice(wire_name);
    input.extend_from_slice(&rdata_bytes);

    match digest_type {
        2 => {
            let digest = ring::digest::digest(&ring::digest::SHA256, &input);
            Some(digest.as_ref().to_vec())
        }
        4 => {
            let digest = ring::digest::digest(&ring::digest::SHA384, &input);
            Some(digest.as_ref().to_vec())
        }
        _ => None,
    }
}

/// Checks whether a single DS record authenticates a candidate DNSKEY.
#[must_use]
pub fn check_single_ds_linkage(zone_name: &Name, ds: &DsRdata, dnskey: &DnskeyRdata) -> bool {
    if ds.key_tag() != dnskey.key_tag() || ds.algorithm() != dnskey.algorithm() {
        return false;
    }
    match compute_dnskey_digest(zone_name, dnskey, ds.digest_type()) {
        Some(computed) => computed.as_slice() == ds.digest(),
        None => false,
    }
}

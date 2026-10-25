//! Cryptographic signature verification and DS-to-DNSKEY digest computation.

use ring::signature::{self, RsaPublicKeyComponents};
use styx_core::Clock;
use styx_proto::domain::rdata::{DnskeyRdata, DsRdata, RrsigRdata};
use styx_proto::{Name, ResourceRecord};

use crate::domain::canonical::build_canonical_signed_data;
use crate::domain::policy::{AlgorithmSet, AlgorithmSupport};
use crate::domain::verdict::VerdictReason;

/// Splits an RFC 3110 RSA public key into its exponent and modulus.
fn rsa_components(public_key: &[u8]) -> Option<RsaPublicKeyComponents<&[u8]>> {
    let (&first, rest) = public_key.split_first()?;
    let (exponent_length, rest) = if first == 0 {
        let (length, rest) = rest.split_first_chunk::<2>()?;
        (usize::from(u16::from_be_bytes(*length)), rest)
    } else {
        (usize::from(first), rest)
    };
    let (exponent, modulus) = rest.split_at_checked(exponent_length)?;
    if modulus.is_empty() {
        return None;
    }
    Some(RsaPublicKeyComponents {
        n: modulus,
        e: exponent,
    })
}

/// Verifies an RSA/SHA-256 signature (RFC 5702).
fn verify_rsa_signature(public_key: &[u8], signed_data: &[u8], signature: &[u8]) -> bool {
    let Some(key) = rsa_components(public_key) else {
        return false;
    };
    key.verify(
        &signature::RSA_PKCS1_2048_8192_SHA256,
        signed_data,
        signature,
    )
    .is_ok()
        || key
            .verify(
                &signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
                signed_data,
                signature,
            )
            .is_ok()
}

/// Verifies an ECDSA P-256/SHA-256 signature (RFC 6605).
fn verify_ecdsa_p256_signature(public_key: &[u8], signed_data: &[u8], signature: &[u8]) -> bool {
    if public_key.len() != 64 {
        return false;
    }
    let mut uncompressed = Vec::with_capacity(65);
    uncompressed.push(0x04);
    uncompressed.extend_from_slice(public_key);
    signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &uncompressed)
        .verify(signed_data, signature)
        .is_ok()
}

/// Verifies an Ed25519 signature (RFC 8080).
fn verify_ed25519_signature(public_key: &[u8], signed_data: &[u8], signature: &[u8]) -> bool {
    public_key.len() == 32
        && signature::UnparsedPublicKey::new(&signature::ED25519, public_key)
            .verify(signed_data, signature)
            .is_ok()
}

/// Dispatches to the primitive for `algorithm`. Only reached for an algorithm the
/// policy classified as supported, so an algorithm without a primitive here fails.
fn verify_crypto_signature(
    algorithm: u8,
    public_key: &[u8],
    signed_data: &[u8],
    signature: &[u8],
) -> bool {
    match algorithm {
        AlgorithmSet::RSASHA256 => verify_rsa_signature(public_key, signed_data, signature),
        AlgorithmSet::ECDSAP256SHA256 => {
            verify_ecdsa_p256_signature(public_key, signed_data, signature)
        }
        AlgorithmSet::ED25519 => verify_ed25519_signature(public_key, signed_data, signature),
        _ => false,
    }
}

/// RFC 1982 serial-number comparison over 32 bits: whether `earlier` precedes `later`.
fn serial_precedes(earlier: u32, later: u32) -> bool {
    earlier != later && later.wrapping_sub(earlier) < 0x8000_0000
}

/// The clock's current time as an RRSIG timestamp: seconds since the epoch modulo
/// 2^32, compared by serial arithmetic (RFC 4034 §3.1.5). `None` before the epoch.
fn rrsig_now<C: Clock>(clock: &C) -> Option<u32> {
    let seconds = clock
        .now_utc()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .ok()?
        .as_secs();
    u32::try_from(seconds & u64::from(u32::MAX)).ok()
}

/// Checks the RRSIG validity window against the injected clock.
fn check_validity_window<C: Clock>(rrsig: &RrsigRdata, clock: &C) -> Result<(), VerdictReason> {
    let now = rrsig_now(clock).ok_or(VerdictReason::SignatureNotYetValid)?;
    if serial_precedes(now, rrsig.signature_inception()) {
        return Err(VerdictReason::SignatureNotYetValid);
    }
    if serial_precedes(rrsig.signature_expiration(), now) {
        return Err(VerdictReason::SignatureExpired);
    }
    Ok(())
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
    if rrsig.key_tag() != dnskey.key_tag()
        || rrsig.algorithm() != dnskey.algorithm()
        || rrsig.signer_name() != dnskey_owner
    {
        return Err(VerdictReason::NoValidRrsig);
    }
    match algorithms.classify_sig(rrsig.algorithm()) {
        AlgorithmSupport::Supported => {}
        AlgorithmSupport::UnknownTreatAsInsecure => {
            return Err(VerdictReason::UnsupportedAlgorithm)
        }
        AlgorithmSupport::Refused => return Err(VerdictReason::NoValidRrsig),
    }
    check_validity_window(rrsig, clock)?;

    let signed_data =
        build_canonical_signed_data(rrsig, rrset).map_err(|_| VerdictReason::NoValidRrsig)?;
    if verify_crypto_signature(
        rrsig.algorithm(),
        dnskey.public_key(),
        &signed_data,
        rrsig.signature(),
    ) {
        Ok(())
    } else {
        Err(VerdictReason::NoValidRrsig)
    }
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
        AlgorithmSet::DIGEST_SHA1 => {
            let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &input);
            Some(digest.as_ref().to_vec())
        }
        AlgorithmSet::DIGEST_SHA256 => {
            let digest = ring::digest::digest(&ring::digest::SHA256, &input);
            Some(digest.as_ref().to_vec())
        }
        AlgorithmSet::DIGEST_SHA384 => {
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

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use styx_core::test_util::TestClock;
    use styx_proto::RecordType;

    use super::*;

    fn rrsig(inception: u32, expiration: u32) -> RrsigRdata {
        RrsigRdata::new(
            RecordType::A,
            AlgorithmSet::ED25519,
            0,
            300,
            expiration,
            inception,
            0,
            Name::root(),
            Vec::new(),
        )
    }

    fn clock_at(seconds: u64) -> TestClock {
        let clock = TestClock::new();
        let now = SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(seconds));
        clock.set_utc(now.unwrap());
        clock
    }

    #[test]
    fn a_window_spanning_the_32_bit_wrap_is_valid_on_both_sides() {
        let window = rrsig(0xFFFF_FF00, 0x0000_0100);
        assert_eq!(
            check_validity_window(&window, &clock_at(0xFFFF_FFF0)),
            Ok(())
        );
        assert_eq!(
            check_validity_window(&window, &clock_at(0x1_0000_0010)),
            Ok(())
        );
    }

    #[test]
    fn a_window_spanning_the_32_bit_wrap_still_expires() {
        let window = rrsig(0xFFFF_FF00, 0x0000_0100);
        assert_eq!(
            check_validity_window(&window, &clock_at(0x1_0000_0200)),
            Err(VerdictReason::SignatureExpired)
        );
        assert_eq!(
            check_validity_window(&window, &clock_at(0xFFFF_FE00)),
            Err(VerdictReason::SignatureNotYetValid)
        );
    }

    #[test]
    fn time_after_2106_wraps_instead_of_saturating() {
        let window = rrsig(0x0000_0010, 0x0000_1000);
        assert_eq!(
            check_validity_window(&window, &clock_at(0x1_0000_0100)),
            Ok(())
        );
    }
}

//! RFC 4034 Canonical DNS Name and RRset Ordering.
//!
//! Provides the canonical ordering rules required by DNSSEC signature validation:
//! - Canonical name ordering (RFC 4034 §6.1): right-to-left label comparison.
//! - Canonical RRset ordering (RFC 4034 §6.3): binary comparison of RDATA octets.
//! - Original-TTL substitution (RFC 4034 §3.1.8).

use std::cmp::Ordering;

use crate::application::encoder::Encoder;
use crate::domain::name::Name;
use crate::domain::record::{ResourceRecord, Ttl};

/// Compares two domain names in RFC 4034 §6.1 canonical order.
///
/// Order is determined by comparing labels from right to left (most significant
/// to least significant). Each label is compared as lowercase octets in unsigned order.
#[must_use]
pub fn canonical_name_cmp(a: &Name, b: &Name) -> Ordering {
    let mut a_iter = a.labels().rev();
    let mut b_iter = b.labels().rev();

    loop {
        match (a_iter.next(), b_iter.next()) {
            (Some(la), Some(lb)) => match compare_labels_canonical(la.as_bytes(), lb.as_bytes()) {
                Ordering::Equal => continue,
                other => return other,
            },
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (None, None) => return Ordering::Equal,
        }
    }
}

fn compare_labels_canonical(a: &[u8], b: &[u8]) -> Ordering {
    for (&ca, &cb) in a.iter().zip(b.iter()) {
        match ca.to_ascii_lowercase().cmp(&cb.to_ascii_lowercase()) {
            Ordering::Equal => continue,
            other => return other,
        }
    }
    a.len().cmp(&b.len())
}

/// Compares two resource records in RFC 4034 §6.3 canonical RRset order.
///
/// Records are ordered by owner name (canonically), then type, class,
/// and finally by their canonical RDATA octet serialization.
#[must_use]
pub fn canonical_rr_cmp(a: &ResourceRecord, b: &ResourceRecord) -> Ordering {
    match canonical_name_cmp(&a.owner, &b.owner) {
        Ordering::Equal => {}
        other => return other,
    }
    match a.rtype.value().cmp(&b.rtype.value()) {
        Ordering::Equal => {}
        other => return other,
    }
    match a.rclass.to_u16().cmp(&b.rclass.to_u16()) {
        Ordering::Equal => {}
        other => return other,
    }

    // Compare wire-encoded canonical RDATA
    let mut enc_a = Encoder::new_canonical(usize::MAX);
    let mut enc_b = Encoder::new_canonical(usize::MAX);
    match (enc_a.encode_rdata(&a.rdata), enc_b.encode_rdata(&b.rdata)) {
        (Ok(()), Ok(())) => enc_a.buf.cmp(&enc_b.buf),
        (Err(_), Ok(())) => Ordering::Less,
        (Ok(()), Err(_)) => Ordering::Greater,
        (Err(_), Err(_)) => Ordering::Equal,
    }
}

/// Creates a copy of `rr` with its TTL replaced by the signature's original TTL (RFC 4034 §3.1.8).
#[must_use]
pub fn with_original_ttl(rr: &ResourceRecord, original_ttl: u32) -> ResourceRecord {
    let mut copy = rr.clone();
    copy.ttl = Ttl::from_secs(original_ttl);
    copy
}

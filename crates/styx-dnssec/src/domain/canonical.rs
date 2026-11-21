//! RFC 4034 canonical serialization and RRset ordering for signature validation.

use styx_proto::application::canonical::canonical_rr_cmp;
use styx_proto::application::encoder::Encoder;
use styx_proto::domain::error::EncodeError;
use styx_proto::domain::rdata::RrsigRdata;
use styx_proto::{Name, ResourceRecord};
use thiserror::Error;

/// Errors occurring during RFC 4034 canonical serialization.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CanonicalError {
    /// RRSIG `labels` count exceeds the record owner's label count.
    #[error("RRSIG label count {signature_labels} exceeds owner label count {owner_labels}")]
    InvalidLabelCount {
        /// Label count declared in the RRSIG header.
        signature_labels: u8,
        /// Actual label count of the record owner name.
        owner_labels: usize,
    },

    /// Canonical wire encoding failed.
    #[error(transparent)]
    Encode(#[from] EncodeError),
}

/// Resolves the canonical owner name for an RRset under an RRSIG.
///
/// Under RFC 4034 §3.1.8.1, if the RRSIG labels field is strictly less than the
/// number of non-root labels in the RR owner name, the record was synthesized
/// from a wildcard. The owner name must be truncated from the left to the number
/// of labels indicated by `rrsig_labels`, with a single `*` label prepended.
///
/// # Errors
/// Returns [`CanonicalError::InvalidLabelCount`] if `rrsig_labels` exceeds `owner`'s label count,
/// or [`CanonicalError::Encode`] if wildcard construction overflows wire bounds.
pub fn canonical_owner_for_rrsig(owner: &Name, rrsig_labels: u8) -> Result<Name, CanonicalError> {
    let owner_count = owner.label_count();
    let signature_label_count = usize::from(rrsig_labels);

    if signature_label_count == owner_count {
        return Ok(owner.clone());
    }

    let Some(ancestor) = owner.ancestor(signature_label_count) else {
        return Err(CanonicalError::InvalidLabelCount {
            signature_labels: rrsig_labels,
            owner_labels: owner_count,
        });
    };
    ancestor
        .with_wildcard()
        .map_err(|error| CanonicalError::Encode(EncodeError::from(error)))
}

/// Encodes one resource record into the canonical wire buffer.
fn encode_canonical_rr(
    encoder: &mut Encoder,
    canonical_owner: &Name,
    record: &ResourceRecord,
    original_ttl: u32,
) -> Result<(), EncodeError> {
    encoder.write_name(canonical_owner)?;
    encoder.write_u16(record.rtype.value())?;
    encoder.write_u16(record.rclass.to_u16())?;
    encoder.write_u32(original_ttl)?;

    let rdlength_pos = encoder.buf.len();
    encoder.write_u16(0)?;
    let rdata_start = encoder.buf.len();
    encoder.encode_rdata(&record.rdata)?;
    let rdata_len = encoder.buf.len().saturating_sub(rdata_start);
    let rdlength_u16 =
        u16::try_from(rdata_len).map_err(|_| EncodeError::RdLengthOverflow(rdata_len))?;
    let rdlength_bytes = rdlength_u16.to_be_bytes();
    if let Some(slot) = encoder
        .buf
        .get_mut(rdlength_pos..rdlength_pos.saturating_add(2))
    {
        slot.copy_from_slice(&rdlength_bytes);
    }
    Ok(())
}

/// Builds the RFC 4034 canonical byte stream that an RRSIG signature was computed over.
///
/// # Errors
/// Returns [`CanonicalError`] if serialization or label-count checks fail.
pub fn build_canonical_signed_data(
    rrsig: &RrsigRdata,
    rrset: &[&ResourceRecord],
) -> Result<Vec<u8>, CanonicalError> {
    let mut encoder = Encoder::new_canonical(usize::MAX);

    // 1. RRSIG RDATA prefix excluding signature field (RFC 4034 §3.1.8.1)
    encoder.write_u16(rrsig.type_covered().value())?;
    encoder.write_u8(rrsig.algorithm())?;
    encoder.write_u8(rrsig.labels())?;
    encoder.write_u32(rrsig.original_ttl())?;
    encoder.write_u32(rrsig.signature_expiration())?;
    encoder.write_u32(rrsig.signature_inception())?;
    encoder.write_u16(rrsig.key_tag())?;
    encoder.write_name(rrsig.signer_name())?;

    // 2. Sort RRset according to RFC 4034 §6.3 canonical RR ordering
    let mut sorted_records: Vec<&ResourceRecord> = rrset.to_vec();
    sorted_records.sort_by(|left, right| canonical_rr_cmp(left, right));

    // 3. Serialize sorted records with canonical owner and original TTL
    for record in sorted_records {
        let canonical_owner = canonical_owner_for_rrsig(&record.owner, rrsig.labels())?;
        encode_canonical_rr(&mut encoder, &canonical_owner, record, rrsig.original_ttl())?;
    }

    Ok(encoder.buf)
}

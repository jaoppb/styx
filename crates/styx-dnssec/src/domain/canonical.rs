//! RFC 4034 canonical serialization and RRset ordering for signature validation.

use styx_proto::application::canonical::canonical_rr_cmp;
use styx_proto::application::encoder::Encoder;
use styx_proto::domain::error::EncodeError;
use styx_proto::domain::rdata::RrsigRdata;
use styx_proto::{Label, Name, ResourceRecord};

/// Resolves the canonical owner name for an RRset under an RRSIG.
///
/// Under RFC 4034 §3.1.8.1, if the RRSIG labels field is strictly less than the
/// number of non-root labels in the RR owner name, the record was synthesized
/// from a wildcard. The owner name must be truncated from the left to the number
/// of labels indicated by `rrsig_labels`, with a single `*` label prepended.
pub fn canonical_owner_for_rrsig(owner: &Name, rrsig_labels: u8) -> Result<Name, EncodeError> {
    let owner_count = owner.label_count();
    let sig_count = usize::from(rrsig_labels);

    if sig_count == owner_count {
        return Ok(owner.clone());
    }

    if sig_count > owner_count {
        return Err(EncodeError::TooManyRecords);
    }

    let to_drop = owner_count.saturating_sub(sig_count);
    let mut labels: Vec<Label> = Vec::with_capacity(sig_count.saturating_add(1));
    labels.push(Label::new(b"*".to_vec())?);
    for label in owner.labels().skip(to_drop) {
        labels.push(Label::new(label.as_bytes().to_vec())?);
    }
    Name::new(labels).map_err(EncodeError::from)
}

/// Encodes one resource record into the canonical wire buffer.
fn encode_canonical_rr(
    encoder: &mut Encoder,
    canonical_owner: &Name,
    rr: &ResourceRecord,
    original_ttl: u32,
) -> Result<(), EncodeError> {
    encoder.write_name(canonical_owner)?;
    encoder.write_u16(rr.rtype.value())?;
    encoder.write_u16(rr.rclass.to_u16())?;
    encoder.write_u32(original_ttl)?;

    let rdlength_pos = encoder.buf.len();
    encoder.write_u16(0)?;
    let rdata_start = encoder.buf.len();
    encoder.encode_rdata(&rr.rdata)?;
    let rdata_len = encoder.buf.len().saturating_sub(rdata_start);
    let rdlen_u16 =
        u16::try_from(rdata_len).map_err(|_| EncodeError::RdLengthOverflow(rdata_len))?;
    let rdlen_bytes = rdlen_u16.to_be_bytes();
    if let Some(slot) = encoder
        .buf
        .get_mut(rdlength_pos..rdlength_pos.saturating_add(2))
    {
        slot.copy_from_slice(&rdlen_bytes);
    }
    Ok(())
}

/// Builds the RFC 4034 canonical byte stream that an RRSIG signature was computed over.
///
/// # Errors
/// Returns [`EncodeError`] if serialization fails.
pub fn build_canonical_signed_data(
    rrsig: &RrsigRdata,
    rrset: &[ResourceRecord],
) -> Result<Vec<u8>, EncodeError> {
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
    let mut sorted_records = rrset.to_vec();
    sorted_records.sort_by(canonical_rr_cmp);

    // 3. Serialize sorted records with canonical owner and original TTL
    for rr in &sorted_records {
        let canonical_owner = canonical_owner_for_rrsig(&rr.owner, rrsig.labels())?;
        encode_canonical_rr(&mut encoder, &canonical_owner, rr, rrsig.original_ttl())?;
    }

    Ok(encoder.buf)
}

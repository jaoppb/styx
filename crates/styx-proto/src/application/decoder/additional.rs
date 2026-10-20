//! Additional-section decoding, where the EDNS(0) OPT pseudo-record is lifted out.

use super::{Decoder, MIN_RECORD_BYTES};
use crate::domain::edns::Opt;
use crate::domain::error::DecodeError;
use crate::domain::header::Header;
use crate::domain::question::Question;
use crate::domain::rdata::RData;
use crate::domain::record::{RecordType, ResourceRecord};
use crate::domain::unsupported_edns::UnsupportedEdns;

/// The additional section with its OPT record lifted out.
pub(super) struct AdditionalSection {
    pub(super) records: Vec<ResourceRecord>,
    pub(super) opt: Option<Opt>,
    /// Upper octet of the 12-bit RCODE, from the OPT TTL (zero without an OPT).
    pub(super) extended_rcode: u8,
}

/// Why the additional section could not be decoded.
///
/// An unsupported EDNS version is kept apart from a malformed message: it is the one failure
/// the caller must answer differently, and it needs the header and questions that only
/// `decode_message` holds.
pub(super) enum AdditionalFault {
    UnsupportedEdnsVersion(u8),
    Malformed(DecodeError),
}

impl From<DecodeError> for AdditionalFault {
    fn from(err: DecodeError) -> Self {
        Self::Malformed(err)
    }
}

impl AdditionalFault {
    pub(super) fn into_decode_error(self, header: &Header, questions: &[Question]) -> DecodeError {
        match self {
            Self::UnsupportedEdnsVersion(version) => DecodeError::UnsupportedEdnsVersion(
                UnsupportedEdns::new(version, header.clone(), questions.to_vec()),
            ),
            Self::Malformed(err) => err,
        }
    }
}

impl Decoder<'_> {
    pub(super) fn decode_additionals(
        &mut self,
        count: u16,
    ) -> Result<AdditionalSection, AdditionalFault> {
        let count_usize = usize::from(count);
        let rem = self.cursor.remaining();
        let cap = match rem.checked_div(MIN_RECORD_BYTES) {
            Some(max) => count_usize.min(max),
            None => 0,
        };
        let mut section = AdditionalSection {
            records: Vec::with_capacity(cap),
            opt: None,
            extended_rcode: 0,
        };

        for _ in 0..count {
            if self.cursor.remaining() < MIN_RECORD_BYTES {
                return Err(DecodeError::SectionCountMismatch.into());
            }
            let record = self.decode_single_record()?;
            self.handle_additional(record, &mut section)?;
        }
        Ok(section)
    }

    fn handle_additional(
        &self,
        record: ResourceRecord,
        section: &mut AdditionalSection,
    ) -> Result<(), AdditionalFault> {
        if record.rtype != RecordType::OPT {
            section.records.push(record);
            return Ok(());
        }
        if section.opt.is_some() {
            return Err(DecodeError::MultipleOptRecords.into());
        }
        section.opt = Some(self.parse_opt_record(&record, section)?);
        Ok(())
    }

    /// Parses the OPT record and records its extended RCODE octet on the section.
    fn parse_opt_record(
        &self,
        record: &ResourceRecord,
        section: &mut AdditionalSection,
    ) -> Result<Opt, AdditionalFault> {
        if !record.owner.is_root() {
            return Err(DecodeError::MalformedOpt.into());
        }
        let udp_payload_size = record.rclass.to_u16();
        let ttl_val = record.ttl.seconds();
        let version = match u8::try_from((ttl_val >> 16) & 0xFF) {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!("edns version conversion error: {e}");
                0
            }
        };
        if version != 0 {
            return Err(AdditionalFault::UnsupportedEdnsVersion(version));
        }
        section.extended_rcode = match u8::try_from((ttl_val >> 24) & 0xFF) {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!("extended rcode conversion error: {e}");
                0
            }
        };
        let dnssec_ok = ((ttl_val >> 8) & 0x80) != 0;

        let options = match &record.rdata {
            RData::Unknown(u) => self.parse_edns_options(u.octets())?,
            _ => return Err(DecodeError::MalformedOpt.into()),
        };

        Ok(Opt::new(udp_payload_size, version, dnssec_ok, options))
    }
}

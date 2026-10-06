//! Encodes DNS messages to wire format with compression and size budgeting.
//!
//! Provides both standard compressing encoding and RFC 4034 canonical mode
//! (compression disabled, lowercased names).

mod rdata;

use std::collections::HashMap;

use crate::domain::edns::Opt;
use crate::domain::error::EncodeError;
use crate::domain::header::{Header, ResponseCodeParts};
use crate::domain::message::Message;
use crate::domain::name::Name;
use crate::domain::question::Question;
use crate::domain::record::{RecordType, ResourceRecord};

const MAX_COMPRESSION_OFFSET: usize = 16383;

/// DNS message encoder.
pub struct Encoder {
    /// Output buffer.
    pub buf: Vec<u8>,
    /// Suffix compression table mapping case-folded wire suffixes to byte offsets.
    pub offsets: HashMap<Vec<u8>, u16>,
    /// Maximum allowed bytes to write.
    pub budget: usize,
    /// Whether name compression is active.
    pub compression_enabled: bool,
    /// Whether domain names should be lowercased before encoding.
    pub lowercase_names: bool,
}

impl Encoder {
    /// Creates a new encoder with standard compression enabled.
    #[must_use]
    pub fn new(budget: usize) -> Self {
        Self {
            buf: Vec::with_capacity(budget.min(4096)),
            offsets: HashMap::new(),
            budget,
            compression_enabled: true,
            lowercase_names: false,
        }
    }

    /// Creates an encoder in RFC 4034 canonical mode (uncompressed, lowercased names).
    #[must_use]
    pub fn new_canonical(budget: usize) -> Self {
        Self {
            buf: Vec::with_capacity(budget.min(4096)),
            offsets: HashMap::new(),
            budget,
            compression_enabled: false,
            lowercase_names: true,
        }
    }

    /// Encodes a full [`Message`] into bytes.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError`] if the budget is exceeded or fields overflow.
    pub fn encode_message(&mut self, msg: &Message) -> Result<(), EncodeError> {
        let arcount = self.calculate_arcount(msg)?;
        self.encode_header(
            &msg.header,
            msg.questions.len(),
            msg.answers.len(),
            msg.authorities.len(),
            arcount,
        )?;

        for q in &msg.questions {
            self.encode_question(q)?;
        }
        for rr in &msg.answers {
            self.encode_record(rr)?;
        }
        for rr in &msg.authorities {
            self.encode_record(rr)?;
        }
        for rr in &msg.additionals {
            self.encode_record(rr)?;
        }
        if let Some(opt) = &msg.opt {
            self.encode_opt_record(opt)?;
        }
        Ok(())
    }

    fn calculate_arcount(&self, msg: &Message) -> Result<u16, EncodeError> {
        let opt_add = if msg.opt.is_some() { 1 } else { 0 };
        let total = msg
            .additionals
            .len()
            .checked_add(opt_add)
            .ok_or(EncodeError::TooManyRecords)?;
        u16::try_from(total).map_err(|_| EncodeError::TooManyRecords)
    }

    fn encode_header(
        &mut self,
        hdr: &Header,
        qdcount: usize,
        ancount: usize,
        nscount: usize,
        arcount: u16,
    ) -> Result<(), EncodeError> {
        self.write_u16(hdr.id)?;
        let mut flags: u16 = 0;
        if hdr.kind == crate::domain::header::MessageKind::Response {
            flags |= 0x8000;
        }
        flags |= (u16::from(hdr.opcode.to_u8()) & 0x0F) << 11;
        if hdr.authoritative {
            flags |= 0x0400;
        }
        if hdr.truncated {
            flags |= 0x0200;
        }
        if hdr.recursion_desired {
            flags |= 0x0100;
        }
        if hdr.recursion_available {
            flags |= 0x0080;
        }
        if hdr.authentic_data {
            flags |= 0x0020;
        }
        if hdr.checking_disabled {
            flags |= 0x0010;
        }
        let ResponseCodeParts { header_nibble, .. } = hdr.rcode.split();
        flags |= u16::from(header_nibble & 0x0F);

        self.write_u16(flags)?;
        self.write_u16(u16::try_from(qdcount).map_err(|_| EncodeError::TooManyRecords)?)?;
        self.write_u16(u16::try_from(ancount).map_err(|_| EncodeError::TooManyRecords)?)?;
        self.write_u16(u16::try_from(nscount).map_err(|_| EncodeError::TooManyRecords)?)?;
        self.write_u16(arcount)?;
        Ok(())
    }

    fn encode_question(&mut self, q: &Question) -> Result<(), EncodeError> {
        self.write_name(&q.qname)?;
        self.write_u16(q.qtype.value())?;
        self.write_u16(q.qclass.to_u16())?;
        Ok(())
    }

    /// Encodes a single resource record.
    pub fn encode_record(&mut self, rr: &ResourceRecord) -> Result<(), EncodeError> {
        self.write_name(&rr.owner)?;
        self.write_u16(rr.rtype.value())?;
        self.write_u16(rr.rclass.to_u16())?;
        self.write_u32(rr.ttl.seconds())?;

        let rdlength_pos = self.buf.len();
        self.write_u16(0)?; // placeholder

        let rdata_start = self.buf.len();
        self.encode_rdata(&rr.rdata)?;
        let rdata_end = self.buf.len();

        let rdlen = rdata_end.saturating_sub(rdata_start);
        let rdlen_u16 = u16::try_from(rdlen).map_err(|_| EncodeError::RdLengthOverflow(rdlen))?;
        let bytes = rdlen_u16.to_be_bytes();
        if let Some(slot) = self
            .buf
            .get_mut(rdlength_pos..rdlength_pos.saturating_add(2))
        {
            slot.copy_from_slice(&bytes);
        }
        Ok(())
    }

    fn encode_opt_record(&mut self, opt: &Opt) -> Result<(), EncodeError> {
        self.write_u8(0)?; // Root owner name
        self.write_u16(RecordType::OPT.value())?;
        self.write_u16(opt.udp_payload_size())?;

        let ext_rcode = u32::from(opt.extended_rcode()) << 24;
        let ver = u32::from(opt.version()) << 16;
        let do_bit = if opt.dnssec_ok() { 0x8000 } else { 0 };
        self.write_u32(ext_rcode | ver | do_bit)?;

        let rdlength_pos = self.buf.len();
        self.write_u16(0)?;
        let start = self.buf.len();
        for opt_entry in opt.options() {
            self.write_u16(opt_entry.code)?;
            let len_u16 = u16::try_from(opt_entry.data.len())
                .map_err(|_| EncodeError::RdLengthOverflow(opt_entry.data.len()))?;
            self.write_u16(len_u16)?;
            self.write_slice(&opt_entry.data)?;
        }
        let rdlen = self.buf.len().saturating_sub(start);
        let rdlen_u16 = u16::try_from(rdlen).map_err(|_| EncodeError::RdLengthOverflow(rdlen))?;
        let bytes = rdlen_u16.to_be_bytes();
        if let Some(slot) = self
            .buf
            .get_mut(rdlength_pos..rdlength_pos.saturating_add(2))
        {
            slot.copy_from_slice(&bytes);
        }
        Ok(())
    }

    /// Writes an octet to the output buffer, verifying budget.
    pub fn write_u8(&mut self, val: u8) -> Result<(), EncodeError> {
        self.check_budget(1)?;
        self.buf.push(val);
        Ok(())
    }

    /// Writes a 16-bit integer big-endian, verifying budget.
    pub fn write_u16(&mut self, val: u16) -> Result<(), EncodeError> {
        self.check_budget(2)?;
        self.buf.extend_from_slice(&val.to_be_bytes());
        Ok(())
    }

    /// Writes a 32-bit integer big-endian, verifying budget.
    pub fn write_u32(&mut self, val: u32) -> Result<(), EncodeError> {
        self.check_budget(4)?;
        self.buf.extend_from_slice(&val.to_be_bytes());
        Ok(())
    }

    /// Writes a slice to the output buffer, verifying budget.
    pub fn write_slice(&mut self, slice: &[u8]) -> Result<(), EncodeError> {
        self.check_budget(slice.len())?;
        self.buf.extend_from_slice(slice);
        Ok(())
    }

    fn check_budget(&self, additional: usize) -> Result<(), EncodeError> {
        let total = self.buf.len().saturating_add(additional);
        if total > self.budget {
            return Err(EncodeError::BudgetExceeded {
                bytes_written: self.buf.len(),
            });
        }
        Ok(())
    }

    fn find_compression_pointer(&self, wire_suffix: &[u8]) -> Option<u16> {
        if !self.compression_enabled {
            return None;
        }
        let &ptr = self.offsets.get(wire_suffix)?;
        if usize::from(ptr) <= MAX_COMPRESSION_OFFSET {
            Some(ptr)
        } else {
            None
        }
    }

    fn record_compression_offset(&mut self, wire_suffix: &[u8]) {
        if !self.compression_enabled {
            return;
        }
        let cur_pos = self.buf.len();
        if cur_pos <= MAX_COMPRESSION_OFFSET {
            if let Ok(pos_u16) = u16::try_from(cur_pos) {
                self.offsets.insert(wire_suffix.to_vec(), pos_u16);
            }
        }
    }

    /// Writes a domain name using compression if enabled and within offset limits.
    pub fn write_name(&mut self, name: &Name) -> Result<(), EncodeError> {
        let canonical_name = if self.lowercase_names {
            Some(name.to_canonical())
        } else {
            None
        };
        let target_name = canonical_name.as_ref().unwrap_or(name);

        if target_name.is_root() {
            return self.write_u8(0);
        }

        let wire = target_name.as_wire_bytes();
        let lower_wire_buf = if self.lowercase_names {
            None
        } else {
            Some(target_name.to_lowercase_wire())
        };
        let lookup_wire = lower_wire_buf.as_deref().unwrap_or(wire);

        for offset in target_name.label_offsets() {
            let suffix_lookup = match lookup_wire.get(offset..) {
                Some(s) => s,
                None => break,
            };

            if let Some(ptr) = self.find_compression_pointer(suffix_lookup) {
                return self.write_u16(0xC000 | ptr);
            }
            self.record_compression_offset(suffix_lookup);

            let &label_len = match wire.get(offset) {
                Some(l) => l,
                None => break,
            };
            let start = match offset.checked_add(1) {
                Some(s) => s,
                None => break,
            };
            let end = match start.checked_add(usize::from(label_len)) {
                Some(e) => e,
                None => break,
            };
            let label_bytes = match wire.get(start..end) {
                Some(b) => b,
                None => break,
            };
            self.write_u8(label_len)?;
            self.write_slice(label_bytes)?;
        }
        self.write_u8(0)
    }
}

impl Message {
    /// Encodes the message into `out` within the specified size `budget`.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError`] if the budget is exceeded or encoding fails.
    pub fn encode(&self, out: &mut [u8], budget: usize) -> Result<usize, EncodeError> {
        let max_budget = budget.min(out.len());
        let mut encoder = Encoder::new(max_budget);
        encoder.encode_message(self)?;
        let written = encoder.buf.len();
        if let Some(slot) = out.get_mut(..written) {
            slot.copy_from_slice(&encoder.buf);
            Ok(written)
        } else {
            Err(EncodeError::BudgetExceeded {
                bytes_written: written,
            })
        }
    }

    /// Encodes the message in RFC 4034 canonical form into `out`.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError`] if encoding fails or `out` is too small.
    pub fn encode_canonical(&self, out: &mut [u8]) -> Result<usize, EncodeError> {
        let mut encoder = Encoder::new_canonical(out.len());
        encoder.encode_message(self)?;
        let written = encoder.buf.len();
        if let Some(slot) = out.get_mut(..written) {
            slot.copy_from_slice(&encoder.buf);
            Ok(written)
        } else {
            Err(EncodeError::BudgetExceeded {
                bytes_written: written,
            })
        }
    }
}

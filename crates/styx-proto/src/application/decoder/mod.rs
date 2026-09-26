//! Defensively decodes DNS messages from byte buffers.
//!
//! Enforces:
//! - Name decompression with loop detection and quadratic expansion budget.
//! - Bounded pre-allocation based on remaining bytes.
//! - Section count verification.
//! - RDATA bounds checking (no overruns or trailing bytes).
//! - Zero panics on any input.

mod rdata;

use std::collections::HashSet;

use crate::application::cursor::Cursor;
use crate::domain::edns::Opt;
use crate::domain::error::DecodeError;
use crate::domain::header::{Header, MessageKind, Opcode, ResponseCode};
use crate::domain::message::Message;
use crate::domain::name::{Label, Name, MAX_LABEL_LEN, MAX_NAME_LEN};
use crate::domain::question::Question;
use crate::domain::rdata::RData;
use crate::domain::record::{RecordClass, RecordType, ResourceRecord, Ttl};

/// Minimum bytes required for a Question section entry.
const MIN_QUESTION_BYTES: usize = 5;

/// Minimum bytes required for a Resource Record entry.
const MIN_RECORD_BYTES: usize = 11;

/// Default name expansion budget in total expanded octets per message.
pub const DEFAULT_EXPANSION_BUDGET: usize = 2048;

/// DNS message decoder.
pub struct Decoder<'a> {
    /// Bounds-checked read cursor.
    pub cursor: Cursor<'a>,
    /// Expansion budget for decompression.
    pub expansion_budget: usize,
    /// Known valid label start offsets for compression pointer validation.
    pub valid_label_starts: HashSet<usize>,
}

impl<'a> Decoder<'a> {
    /// Creates a new decoder over the input buffer.
    #[must_use]
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            cursor: Cursor::new(buf),
            expansion_budget: DEFAULT_EXPANSION_BUDGET,
            valid_label_starts: HashSet::new(),
        }
    }

    /// Decodes a full DNS message.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] on malformed input or boundary violations.
    pub fn decode_message(&mut self) -> Result<Message, DecodeError> {
        let (header, qdcount, ancount, nscount, arcount) = self.decode_header()?;
        let questions = self.decode_questions(qdcount)?;
        let answers = self.decode_records(ancount)?;
        let authorities = self.decode_records(nscount)?;
        let (additionals, opt) = self.decode_additionals(arcount)?;

        Ok(Message {
            header,
            questions,
            answers,
            authorities,
            additionals,
            opt,
        })
    }

    /// Reads an octet.
    pub fn read_u8(&mut self) -> Result<u8, DecodeError> {
        self.cursor.read_u8()
    }

    /// Reads a 16-bit integer.
    pub fn read_u16(&mut self) -> Result<u16, DecodeError> {
        self.cursor.read_u16()
    }

    /// Reads a 32-bit integer.
    pub fn read_u32(&mut self) -> Result<u32, DecodeError> {
        self.cursor.read_u32()
    }

    /// Reads a slice of octets.
    pub fn read_slice(&mut self, len: usize) -> Result<&'a [u8], DecodeError> {
        self.cursor.read_slice(len)
    }

    /// Decodes a domain name with compression pointer resolution.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] on invalid pointers, loops, or length violations.
    pub fn read_name(&mut self) -> Result<Name, DecodeError> {
        let mut labels = Vec::new();
        let mut visited = HashSet::new();
        let mut return_pos = None;
        let mut expanded_bytes = 0usize;

        loop {
            let pos = self.cursor.position();
            visited.insert(pos);
            match self.read_label_or_pointer()? {
                LabelStep::Root => break,
                LabelStep::Normal(label) => {
                    handle_normal_label(
                        label,
                        &mut labels,
                        &mut expanded_bytes,
                        return_pos.is_some(),
                        &mut self.expansion_budget,
                    )?;
                }
                LabelStep::Pointer(target) => {
                    self.handle_pointer_step(target, &mut visited, pos, &mut return_pos)?;
                }
            }
        }

        if let Some(pos) = return_pos {
            self.cursor.seek(pos)?;
        }
        Name::new(labels).map_err(DecodeError::from)
    }

    fn handle_pointer_step(
        &mut self,
        target: usize,
        visited: &mut HashSet<usize>,
        ptr_start: usize,
        return_pos: &mut Option<usize>,
    ) -> Result<(), DecodeError> {
        let ptr_pos = self.cursor.position();
        if return_pos.is_none() {
            *return_pos = Some(ptr_pos);
        }
        self.resolve_pointer_target(ptr_start, target, visited)?;
        self.cursor.seek(target)
    }

    fn read_label_or_pointer(&mut self) -> Result<LabelStep, DecodeError> {
        let pos = self.cursor.position();
        let b = self.cursor.read_u8()?;
        if b == 0 {
            return Ok(LabelStep::Root);
        }

        let label_type = b & 0xC0;
        if label_type == 0xC0 {
            let b2 = self.cursor.read_u8()?;
            let target = (usize::from(b & 0x3F) << 8) | usize::from(b2);
            self.valid_label_starts.insert(pos);
            return Ok(LabelStep::Pointer(target));
        }

        if label_type != 0 {
            return Err(DecodeError::ReservedBitsSet);
        }

        let len = usize::from(b);
        if len > MAX_LABEL_LEN {
            return Err(DecodeError::LabelTooLong);
        }
        let octets = self.cursor.read_slice(len)?.to_vec();
        self.valid_label_starts.insert(pos);
        let label = Label::new(octets).map_err(DecodeError::from)?;
        Ok(LabelStep::Normal(label))
    }

    fn resolve_pointer_target(
        &self,
        ptr_start: usize,
        target: usize,
        visited: &HashSet<usize>,
    ) -> Result<(), DecodeError> {
        let buf_len = self.cursor.len();
        if target >= buf_len {
            return Err(DecodeError::PointerOutOfRange {
                pointer: target,
                len: buf_len,
            });
        }
        if target == ptr_start || visited.contains(&target) {
            return Err(DecodeError::CompressionLoop(target));
        }
        if target >= ptr_start || !self.valid_label_starts.contains(&target) {
            return Err(DecodeError::PointerOutOfRange {
                pointer: target,
                len: buf_len,
            });
        }
        Ok(())
    }

    fn decode_header(&mut self) -> Result<(Header, u16, u16, u16, u16), DecodeError> {
        let id = self.cursor.read_u16()?;
        let flags = self.cursor.read_u16()?;
        let qdcount = self.cursor.read_u16()?;
        let ancount = self.cursor.read_u16()?;
        let nscount = self.cursor.read_u16()?;
        let arcount = self.cursor.read_u16()?;

        let kind = if (flags & 0x8000) == 0 {
            MessageKind::Query
        } else {
            MessageKind::Response
        };
        let opcode = match u8::try_from((flags >> 11) & 0x0F) {
            Ok(op) => Opcode::from_u8(op),
            Err(_) => Opcode::Unknown(0),
        };
        let authoritative = (flags & 0x0400) != 0;
        let truncated = (flags & 0x0200) != 0;
        let recursion_desired = (flags & 0x0100) != 0;
        let recursion_available = (flags & 0x0080) != 0;
        let authentic_data = (flags & 0x0020) != 0;
        let checking_disabled = (flags & 0x0010) != 0;
        let header_rcode = match u8::try_from(flags & 0x000F) {
            Ok(rc) => rc,
            Err(e) => {
                tracing::debug!("header rcode conversion error: {e}");
                0
            }
        };
        let rcode = ResponseCode::from_parts(header_rcode, 0);

        let header = Header {
            id,
            kind,
            opcode,
            authoritative,
            truncated,
            recursion_desired,
            recursion_available,
            authentic_data,
            checking_disabled,
            rcode,
        };
        Ok((header, qdcount, ancount, nscount, arcount))
    }

    fn decode_questions(&mut self, count: u16) -> Result<Vec<Question>, DecodeError> {
        let count_usize = usize::from(count);
        let rem = self.cursor.remaining();
        let cap = match rem.checked_div(MIN_QUESTION_BYTES) {
            Some(max) => count_usize.min(max),
            None => 0,
        };
        let mut questions = Vec::with_capacity(cap);

        for _ in 0..count {
            if self.cursor.remaining() < MIN_QUESTION_BYTES {
                return Err(DecodeError::SectionCountMismatch);
            }
            let qname = self.read_name()?;
            let qtype = RecordType::from_u16(self.cursor.read_u16()?);
            let qclass = RecordClass::from_u16(self.cursor.read_u16()?);
            questions.push(Question::new(qname, qtype, qclass));
        }
        Ok(questions)
    }

    fn decode_records(&mut self, count: u16) -> Result<Vec<ResourceRecord>, DecodeError> {
        let count_usize = usize::from(count);
        let rem = self.cursor.remaining();
        let cap = match rem.checked_div(MIN_RECORD_BYTES) {
            Some(max) => count_usize.min(max),
            None => 0,
        };
        let mut records = Vec::with_capacity(cap);

        for _ in 0..count {
            if self.cursor.remaining() < MIN_RECORD_BYTES {
                return Err(DecodeError::SectionCountMismatch);
            }
            records.push(self.decode_single_record()?);
        }
        Ok(records)
    }

    fn decode_single_record(&mut self) -> Result<ResourceRecord, DecodeError> {
        let owner = self.read_name()?;
        let rtype = RecordType::from_u16(self.cursor.read_u16()?);
        let rclass = RecordClass::from_u16(self.cursor.read_u16()?);
        let ttl = Ttl::from_secs(self.cursor.read_u32()?);
        let rdlength = usize::from(self.cursor.read_u16()?);

        if self.cursor.remaining() < rdlength {
            return Err(DecodeError::SectionCountMismatch);
        }
        let rdata_start = self.cursor.position();
        let rdata = self.decode_rdata(rtype, rdlength)?;
        let rdata_end = self.cursor.position();

        let consumed = rdata_end.saturating_sub(rdata_start);
        if consumed < rdlength {
            return Err(DecodeError::TrailingRdataBytes {
                remaining: rdlength.saturating_sub(consumed),
            });
        }
        if consumed > rdlength {
            return Err(DecodeError::RdataOverrun);
        }

        Ok(ResourceRecord::new(owner, rtype, rclass, ttl, rdata))
    }

    fn decode_additionals(
        &mut self,
        count: u16,
    ) -> Result<(Vec<ResourceRecord>, Option<Opt>), DecodeError> {
        let count_usize = usize::from(count);
        let rem = self.cursor.remaining();
        let cap = match rem.checked_div(MIN_RECORD_BYTES) {
            Some(max) => count_usize.min(max),
            None => 0,
        };
        let mut additionals = Vec::with_capacity(cap);
        let mut opt = None;

        for _ in 0..count {
            if self.cursor.remaining() < MIN_RECORD_BYTES {
                return Err(DecodeError::SectionCountMismatch);
            }
            let record = self.decode_single_record()?;
            self.handle_additional(record, &mut additionals, &mut opt)?;
        }
        Ok((additionals, opt))
    }

    fn handle_additional(
        &self,
        record: ResourceRecord,
        additionals: &mut Vec<ResourceRecord>,
        opt: &mut Option<Opt>,
    ) -> Result<(), DecodeError> {
        if record.rtype != RecordType::OPT {
            additionals.push(record);
            return Ok(());
        }
        if opt.is_some() {
            return Err(DecodeError::MultipleOptRecords);
        }
        *opt = Some(self.parse_opt_record(&record)?);
        Ok(())
    }

    fn parse_opt_record(&self, record: &ResourceRecord) -> Result<Opt, DecodeError> {
        if !record.owner.is_root() {
            return Err(DecodeError::MalformedOpt);
        }
        let udp_payload_size = record.rclass.to_u16();
        let ttl_val = record.ttl.seconds();
        let extended_rcode = match u8::try_from((ttl_val >> 24) & 0xFF) {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!("extended rcode conversion error: {e}");
                0
            }
        };
        let version = match u8::try_from((ttl_val >> 16) & 0xFF) {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!("edns version conversion error: {e}");
                0
            }
        };
        if version != 0 {
            return Err(DecodeError::UnsupportedEdnsVersion(version));
        }
        let dnssec_ok = ((ttl_val >> 8) & 0x80) != 0;

        let options = match &record.rdata {
            RData::Unknown(u) => self.parse_edns_options(u.octets())?,
            _ => return Err(DecodeError::MalformedOpt),
        };

        Ok(Opt::new(
            udp_payload_size,
            extended_rcode,
            version,
            dnssec_ok,
            options,
        ))
    }
}

fn handle_normal_label(
    label: Label,
    labels: &mut Vec<Label>,
    expanded_bytes: &mut usize,
    is_pointer: bool,
    expansion_budget: &mut usize,
) -> Result<(), DecodeError> {
    let next = expanded_bytes
        .checked_add(label.len().saturating_add(1))
        .ok_or(DecodeError::ExpansionBudgetExceeded)?;
    if next > MAX_NAME_LEN {
        return Err(DecodeError::NameTooLong);
    }
    *expanded_bytes = next;
    if is_pointer {
        *expansion_budget = expansion_budget
            .checked_sub(label.len())
            .ok_or(DecodeError::ExpansionBudgetExceeded)?;
    }
    labels.push(label);
    Ok(())
}

enum LabelStep {
    Root,
    Normal(Label),
    Pointer(usize),
}

impl Message {
    /// Decodes a DNS wire message from raw byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] if parsing fails.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        Decoder::new(bytes).decode_message()
    }
}

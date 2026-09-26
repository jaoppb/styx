//! Encodes DNS messages to wire format with compression and size budgeting.
//!
//! Provides both standard compressing encoding and RFC 4034 canonical mode
//! (compression disabled, lowercased names).

use std::collections::HashMap;

use crate::domain::edns::Opt;
use crate::domain::error::EncodeError;
use crate::domain::header::Header;
use crate::domain::message::Message;
use crate::domain::name::Name;
use crate::domain::question::Question;
use crate::domain::rdata::basic::{MxRdata, SoaRdata, SrvRdata, TxtRdata};
use crate::domain::rdata::dnssec::{
    DnskeyRdata, DsRdata, Nsec3ParamRdata, Nsec3Rdata, NsecRdata, RrsigRdata,
};
use crate::domain::rdata::RData;
use crate::domain::record::{RecordType, ResourceRecord};

const MAX_COMPRESSION_OFFSET: usize = 16383;

/// DNS message encoder.
pub struct Encoder {
    /// Output buffer.
    pub buf: Vec<u8>,
    /// Suffix compression table mapping case-insensitive names to offsets.
    pub offsets: HashMap<Name, u16>,
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
        let (header_nibble, _) = hdr.rcode.split();
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

    fn find_compression_pointer(&self, name: &Name) -> Option<u16> {
        if !self.compression_enabled {
            return None;
        }
        let &ptr = self.offsets.get(name)?;
        if usize::from(ptr) <= MAX_COMPRESSION_OFFSET {
            Some(ptr)
        } else {
            None
        }
    }

    fn record_compression_offset(&mut self, name: &Name) {
        if !self.compression_enabled {
            return;
        }
        let cur_pos = self.buf.len();
        if cur_pos <= MAX_COMPRESSION_OFFSET {
            if let Ok(pos_u16) = u16::try_from(cur_pos) {
                self.offsets.insert(name.clone(), pos_u16);
            }
        }
    }

    /// Writes a domain name using compression if enabled and within offset limits.
    pub fn write_name(&mut self, name: &Name) -> Result<(), EncodeError> {
        let target_name = if self.lowercase_names {
            name.to_canonical()
        } else {
            name.clone()
        };

        if target_name.is_root() {
            return self.write_u8(0);
        }

        let mut current = target_name;
        while !current.is_root() {
            if let Some(ptr) = self.find_compression_pointer(&current) {
                return self.write_u16(0xC000 | ptr);
            }
            self.record_compression_offset(&current);

            let Some(first_label) = current.labels().first() else {
                break;
            };
            let label_len = first_label.len();
            let len_u8 = match u8::try_from(label_len) {
                Ok(l) => l,
                Err(_) => return Err(EncodeError::LabelTooLong),
            };
            self.write_u8(len_u8)?;
            self.write_slice(first_label.as_bytes())?;

            current = match current.parent() {
                Some(p) => p,
                None => Name::root(),
            };
        }
        self.write_u8(0)
    }

    /// Encodes typed RDATA into the buffer.
    pub fn encode_rdata(&mut self, rdata: &RData) -> Result<(), EncodeError> {
        match rdata {
            RData::A(addr) => self.write_slice(&addr.octets()),
            RData::Aaaa(addr) => self.write_slice(&addr.octets()),
            RData::Cname(name) | RData::Ns(name) | RData::Ptr(name) => self.write_name(name),
            RData::Soa(soa) => self.encode_soa(soa),
            RData::Mx(mx) => self.encode_mx(mx),
            RData::Txt(txt) => self.encode_txt(txt),
            RData::Srv(srv) => self.encode_srv(srv),
            RData::Dnskey(k) => self.encode_dnskey(k),
            RData::Ds(ds) => self.encode_ds(ds),
            RData::Rrsig(sig) => self.encode_rrsig(sig),
            RData::Nsec(nsec) => self.encode_nsec(nsec),
            RData::Nsec3(n3) => self.encode_nsec3(n3),
            RData::Nsec3Param(p) => self.encode_nsec3param(p),
            RData::Unknown(u) => self.write_slice(u.octets()),
        }
    }

    fn encode_soa(&mut self, soa: &SoaRdata) -> Result<(), EncodeError> {
        self.write_name(soa.mname())?;
        self.write_name(soa.rname())?;
        self.write_u32(soa.serial())?;
        self.write_u32(soa.refresh())?;
        self.write_u32(soa.retry())?;
        self.write_u32(soa.expire())?;
        self.write_u32(soa.minimum())?;
        Ok(())
    }

    fn encode_mx(&mut self, mx: &MxRdata) -> Result<(), EncodeError> {
        self.write_u16(mx.preference())?;
        self.write_name(mx.exchange())?;
        Ok(())
    }

    fn encode_txt(&mut self, txt: &TxtRdata) -> Result<(), EncodeError> {
        for s in txt.strings() {
            let len = u8::try_from(s.octets.len())
                .map_err(|_| EncodeError::RdLengthOverflow(s.octets.len()))?;
            self.write_u8(len)?;
            self.write_slice(&s.octets)?;
        }
        Ok(())
    }

    fn encode_srv(&mut self, srv: &SrvRdata) -> Result<(), EncodeError> {
        self.write_u16(srv.priority())?;
        self.write_u16(srv.weight())?;
        self.write_u16(srv.port())?;
        self.write_name(srv.target())?;
        Ok(())
    }

    fn encode_dnskey(&mut self, k: &DnskeyRdata) -> Result<(), EncodeError> {
        self.write_u16(k.flags())?;
        self.write_u8(k.protocol())?;
        self.write_u8(k.algorithm())?;
        self.write_slice(k.public_key())?;
        Ok(())
    }

    fn encode_ds(&mut self, ds: &DsRdata) -> Result<(), EncodeError> {
        self.write_u16(ds.key_tag())?;
        self.write_u8(ds.algorithm())?;
        self.write_u8(ds.digest_type())?;
        self.write_slice(ds.digest())?;
        Ok(())
    }

    fn encode_rrsig(&mut self, sig: &RrsigRdata) -> Result<(), EncodeError> {
        self.write_u16(sig.type_covered().value())?;
        self.write_u8(sig.algorithm())?;
        self.write_u8(sig.labels())?;
        self.write_u32(sig.original_ttl())?;
        self.write_u32(sig.signature_expiration())?;
        self.write_u32(sig.signature_inception())?;
        self.write_u16(sig.key_tag())?;
        self.write_name(sig.signer_name())?;
        self.write_slice(sig.signature())?;
        Ok(())
    }

    fn encode_nsec(&mut self, nsec: &NsecRdata) -> Result<(), EncodeError> {
        self.write_name(nsec.next_domain())?;
        self.write_slice(nsec.types().windows())?;
        Ok(())
    }

    fn encode_nsec3(&mut self, n3: &Nsec3Rdata) -> Result<(), EncodeError> {
        self.write_u8(n3.hash_algorithm())?;
        self.write_u8(n3.flags())?;
        self.write_u16(n3.iterations())?;
        let salt_len = u8::try_from(n3.salt().len())
            .map_err(|_| EncodeError::RdLengthOverflow(n3.salt().len()))?;
        self.write_u8(salt_len)?;
        self.write_slice(n3.salt())?;
        let next_len = u8::try_from(n3.next_hashed_owner().len())
            .map_err(|_| EncodeError::RdLengthOverflow(n3.next_hashed_owner().len()))?;
        self.write_u8(next_len)?;
        self.write_slice(n3.next_hashed_owner())?;
        self.write_slice(n3.types().windows())?;
        Ok(())
    }

    fn encode_nsec3param(&mut self, p: &Nsec3ParamRdata) -> Result<(), EncodeError> {
        self.write_u8(p.hash_algorithm())?;
        self.write_u8(p.flags())?;
        self.write_u16(p.iterations())?;
        let salt_len = u8::try_from(p.salt().len())
            .map_err(|_| EncodeError::RdLengthOverflow(p.salt().len()))?;
        self.write_u8(salt_len)?;
        self.write_slice(p.salt())?;
        Ok(())
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

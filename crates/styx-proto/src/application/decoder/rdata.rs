//! RDATA decoding routines for standard and DNSSEC resource records.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::application::decoder::Decoder;
use crate::domain::edns::EdnsOption;
use crate::domain::error::DecodeError;
use crate::domain::rdata::basic::{MxRdata, SoaRdata, SrvRdata, TxtRdata};
use crate::domain::rdata::dnssec::{
    DnskeyRdata, DsRdata, Nsec3ParamRdata, Nsec3Rdata, NsecRdata, RrsigRdata, TypeBitmap,
};
use crate::domain::rdata::{CharacterString, RData, UnknownRdata};
use crate::domain::record::RecordType;

impl<'a> Decoder<'a> {
    pub(super) fn decode_rdata(
        &mut self,
        rtype: RecordType,
        rdlen: usize,
    ) -> Result<RData, DecodeError> {
        match rtype {
            RecordType::A => self.decode_a(rdlen),
            RecordType::AAAA => self.decode_aaaa(rdlen),
            RecordType::CNAME => Ok(RData::Cname(self.read_name()?)),
            RecordType::NS => Ok(RData::Ns(self.read_name()?)),
            RecordType::PTR => Ok(RData::Ptr(self.read_name()?)),
            RecordType::SOA => self.decode_soa(),
            RecordType::MX => self.decode_mx(),
            RecordType::TXT => self.decode_txt(rdlen),
            RecordType::SRV => self.decode_srv(),
            RecordType::DNSKEY => self.decode_dnskey(rdlen),
            RecordType::DS => self.decode_ds(rdlen),
            RecordType::RRSIG => self.decode_rrsig(rdlen),
            RecordType::NSEC => self.decode_nsec(rdlen),
            RecordType::NSEC3 => self.decode_nsec3(rdlen),
            RecordType::NSEC3PARAM => self.decode_nsec3param(),
            _ => Ok(RData::Unknown(UnknownRdata::new(
                rtype,
                self.cursor.read_slice(rdlen)?.to_vec(),
            ))),
        }
    }

    fn decode_a(&mut self, rdlen: usize) -> Result<RData, DecodeError> {
        if rdlen != 4 {
            return Err(DecodeError::BadRdLength {
                expected: 4,
                actual: rdlen,
            });
        }
        let s = self.cursor.read_slice(4)?;
        let Some(&b0) = s.first() else {
            return Err(DecodeError::UnexpectedEof(self.cursor.position()));
        };
        let Some(&b1) = s.get(1) else {
            return Err(DecodeError::UnexpectedEof(self.cursor.position()));
        };
        let Some(&b2) = s.get(2) else {
            return Err(DecodeError::UnexpectedEof(self.cursor.position()));
        };
        let Some(&b3) = s.get(3) else {
            return Err(DecodeError::UnexpectedEof(self.cursor.position()));
        };
        Ok(RData::A(Ipv4Addr::new(b0, b1, b2, b3)))
    }

    fn decode_aaaa(&mut self, rdlen: usize) -> Result<RData, DecodeError> {
        if rdlen != 16 {
            return Err(DecodeError::BadRdLength {
                expected: 16,
                actual: rdlen,
            });
        }
        let s = self.cursor.read_slice(16)?;
        let mut octets = [0u8; 16];
        octets.copy_from_slice(s);
        Ok(RData::Aaaa(Ipv6Addr::from(octets)))
    }

    fn decode_soa(&mut self) -> Result<RData, DecodeError> {
        let mname = self.read_name()?;
        let rname = self.read_name()?;
        let serial = self.cursor.read_u32()?;
        let refresh = self.cursor.read_u32()?;
        let retry = self.cursor.read_u32()?;
        let expire = self.cursor.read_u32()?;
        let minimum = self.cursor.read_u32()?;
        Ok(RData::Soa(SoaRdata::new(
            mname, rname, serial, refresh, retry, expire, minimum,
        )))
    }

    fn decode_mx(&mut self) -> Result<RData, DecodeError> {
        let preference = self.cursor.read_u16()?;
        let exchange = self.read_name()?;
        Ok(RData::Mx(MxRdata::new(preference, exchange)))
    }

    fn decode_txt(&mut self, rdlen: usize) -> Result<RData, DecodeError> {
        let start = self.cursor.position();
        let mut strings = Vec::new();
        while self.cursor.position().saturating_sub(start) < rdlen {
            let len = usize::from(self.cursor.read_u8()?);
            let octets = self.cursor.read_slice(len)?.to_vec();
            strings.push(CharacterString::new(octets));
        }
        if strings.is_empty() {
            return Err(DecodeError::BadRdLength {
                expected: 1,
                actual: 0,
            });
        }
        Ok(RData::Txt(TxtRdata::new(strings)))
    }

    fn decode_srv(&mut self) -> Result<RData, DecodeError> {
        let priority = self.cursor.read_u16()?;
        let weight = self.cursor.read_u16()?;
        let port = self.cursor.read_u16()?;
        let target = self.read_name()?;
        Ok(RData::Srv(SrvRdata::new(priority, weight, port, target)))
    }

    fn decode_dnskey(&mut self, rdlen: usize) -> Result<RData, DecodeError> {
        let flags = self.cursor.read_u16()?;
        let protocol = self.cursor.read_u8()?;
        let algorithm = self.cursor.read_u8()?;
        let key_len = rdlen.checked_sub(4).ok_or(DecodeError::BadRdLength {
            expected: 4,
            actual: rdlen,
        })?;
        let public_key = self.cursor.read_slice(key_len)?.to_vec();
        Ok(RData::Dnskey(DnskeyRdata::new(
            flags, protocol, algorithm, public_key,
        )))
    }

    fn decode_ds(&mut self, rdlen: usize) -> Result<RData, DecodeError> {
        let key_tag = self.cursor.read_u16()?;
        let algorithm = self.cursor.read_u8()?;
        let digest_type = self.cursor.read_u8()?;
        let digest_len = rdlen.checked_sub(4).ok_or(DecodeError::BadRdLength {
            expected: 4,
            actual: rdlen,
        })?;
        let digest = self.cursor.read_slice(digest_len)?.to_vec();
        Ok(RData::Ds(DsRdata::new(
            key_tag,
            algorithm,
            digest_type,
            digest,
        )))
    }

    fn decode_rrsig(&mut self, rdlen: usize) -> Result<RData, DecodeError> {
        let start = self.cursor.position();
        let type_covered = RecordType::from_u16(self.cursor.read_u16()?);
        let algorithm = self.cursor.read_u8()?;
        let labels = self.cursor.read_u8()?;
        let original_ttl = self.cursor.read_u32()?;
        let expiration = self.cursor.read_u32()?;
        let inception = self.cursor.read_u32()?;
        let key_tag = self.cursor.read_u16()?;
        let signer_name = self.read_name()?;
        let header_and_name_len = self.cursor.position().saturating_sub(start);
        let sig_len = rdlen
            .checked_sub(header_and_name_len)
            .ok_or(DecodeError::RdataOverrun)?;
        let signature = self.cursor.read_slice(sig_len)?.to_vec();
        Ok(RData::Rrsig(RrsigRdata::new(
            type_covered,
            algorithm,
            labels,
            original_ttl,
            expiration,
            inception,
            key_tag,
            signer_name,
            signature,
        )))
    }

    fn decode_nsec(&mut self, rdlen: usize) -> Result<RData, DecodeError> {
        let start = self.cursor.position();
        let next_domain = self.read_name()?;
        let domain_len = self.cursor.position().saturating_sub(start);
        let bitmap_len = rdlen
            .checked_sub(domain_len)
            .ok_or(DecodeError::RdataOverrun)?;
        let types = TypeBitmap::new(self.cursor.read_slice(bitmap_len)?.to_vec());
        Ok(RData::Nsec(NsecRdata::new(next_domain, types)))
    }

    fn decode_nsec3(&mut self, rdlen: usize) -> Result<RData, DecodeError> {
        let hash_algorithm = self.cursor.read_u8()?;
        let flags = self.cursor.read_u8()?;
        let iterations = self.cursor.read_u16()?;
        let salt_len = usize::from(self.cursor.read_u8()?);
        let salt = self.cursor.read_slice(salt_len)?.to_vec();
        let hash_len = usize::from(self.cursor.read_u8()?);
        let next_hashed_owner = self.cursor.read_slice(hash_len)?.to_vec();

        let prefix_len = 6usize.saturating_add(salt_len).saturating_add(hash_len);
        let bitmap_len = rdlen
            .checked_sub(prefix_len)
            .ok_or(DecodeError::RdataOverrun)?;
        let types = TypeBitmap::new(self.cursor.read_slice(bitmap_len)?.to_vec());
        Ok(RData::Nsec3(Nsec3Rdata::new(
            hash_algorithm,
            flags,
            iterations,
            salt,
            next_hashed_owner,
            types,
        )))
    }

    fn decode_nsec3param(&mut self) -> Result<RData, DecodeError> {
        let hash_algorithm = self.cursor.read_u8()?;
        let flags = self.cursor.read_u8()?;
        let iterations = self.cursor.read_u16()?;
        let salt_len = usize::from(self.cursor.read_u8()?);
        let salt = self.cursor.read_slice(salt_len)?.to_vec();
        Ok(RData::Nsec3Param(Nsec3ParamRdata::new(
            hash_algorithm,
            flags,
            iterations,
            salt,
        )))
    }

    pub(super) fn parse_edns_options(
        &self,
        mut octets: &[u8],
    ) -> Result<Vec<EdnsOption>, DecodeError> {
        let mut options = Vec::new();
        while !octets.is_empty() {
            if octets.len() < 4 {
                return Err(DecodeError::MalformedOpt);
            }
            let b0 = match octets.first() {
                Some(&b) => b,
                None => 0,
            };
            let b1 = match octets.get(1) {
                Some(&b) => b,
                None => 0,
            };
            let b2 = match octets.get(2) {
                Some(&b) => b,
                None => 0,
            };
            let b3 = match octets.get(3) {
                Some(&b) => b,
                None => 0,
            };
            let code = (u16::from(b0) << 8) | u16::from(b1);
            let len = usize::from((u16::from(b2) << 8) | u16::from(b3));
            let rest = octets.get(4..).ok_or(DecodeError::MalformedOpt)?;
            if rest.len() < len {
                return Err(DecodeError::MalformedOpt);
            }
            let data = rest.get(..len).ok_or(DecodeError::MalformedOpt)?.to_vec();
            options.push(EdnsOption::new(code, data));
            octets = rest.get(len..).ok_or(DecodeError::MalformedOpt)?;
        }
        Ok(options)
    }
}

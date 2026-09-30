//! RDATA wire encoders for standard and DNSSEC resource records.

use crate::application::encoder::Encoder;
use crate::domain::error::EncodeError;
use crate::domain::rdata::basic::{MxRdata, SoaRdata, SrvRdata, TxtRdata};
use crate::domain::rdata::dnssec::{
    DnskeyRdata, DsRdata, Nsec3ParamRdata, Nsec3Rdata, NsecRdata, RrsigRdata,
};
use crate::domain::rdata::RData;

impl Encoder {
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

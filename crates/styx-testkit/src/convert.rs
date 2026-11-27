//! Converts scripted `styx-proto` records into `hickory-proto` records.
//!
//! Tests script records in `styx-proto`'s types because those are what they assert
//! on. The wire bytes, though, are produced by `hickory-proto`: the conversion goes
//! through field values, never through `styx-proto`'s encoder, so the oracle stays
//! independent of the codec under test.

use std::str::FromStr;

use hickory_proto::rr::rdata::{A, AAAA, CNAME, NS, NULL, SOA};
use hickory_proto::rr::{
    DNSClass as HDnsClass, Name as HName, RData as HRData, Record as HRecord,
    RecordType as HRecordType,
};
use hickory_proto::serialize::binary::BinEncodable;
use styx_proto::{RData, RecordType, ResourceRecord};

use crate::error::HarnessError;

/// Parses a presentation-format name into a hickory name, preserving its case.
pub(crate) fn hickory_name(name: &str) -> Result<HName, HarnessError> {
    HName::from_str(name).map_err(HarnessError::from)
}

/// Converts one scripted record.
///
/// # Errors
///
/// Returns [`HarnessError::Protocol`] for a record type the fake does not serve,
/// so an unsupported script fails when the server starts rather than being
/// silently left out of an answer.
pub(crate) fn hickory_record(record: &ResourceRecord) -> Result<HRecord, HarnessError> {
    let owner = hickory_name(&record.owner.to_string())?;
    let rdata = match &record.rdata {
        RData::A(address) => HRData::A(A(*address)),
        RData::Aaaa(address) => HRData::AAAA(AAAA(*address)),
        RData::Cname(target) => HRData::CNAME(CNAME(hickory_name(&target.to_string())?)),
        RData::Ns(target) => HRData::NS(NS(hickory_name(&target.to_string())?)),
        RData::Soa(soa) => HRData::SOA(SOA::new(
            hickory_name(&soa.mname().to_string())?,
            hickory_name(&soa.rname().to_string())?,
            soa.serial(),
            soa_field(soa.refresh())?,
            soa_field(soa.retry())?,
            soa_field(soa.expire())?,
            soa.minimum(),
        )),
        RData::Dnskey(_) | RData::Ds(_) | RData::Rrsig(_) | RData::Nsec(_) | RData::Nsec3(_) => {
            HRData::Unknown {
                code: hickory_type(record.rtype),
                rdata: NULL::with(dnssec_rdata(&record.rdata)?),
            }
        }
        other => {
            return Err(HarnessError::Protocol(format!(
                "the fake name server does not serve {:?} records",
                other.rtype()
            )))
        }
    };
    let mut converted = HRecord::from_rdata(owner, record.ttl.seconds(), rdata);
    converted.dns_class = HDnsClass::IN;
    Ok(converted)
}

/// Builds a DNAME record. Hickory has no typed DNAME, so its RDATA — a single
/// uncompressed domain name (RFC 6672 §2.1) — is encoded by hickory and carried as
/// an RFC 3597 unknown type.
pub(crate) fn dname_record(owner: &str, target: &str, ttl: u32) -> Result<HRecord, HarnessError> {
    let target = hickory_name(target)?.to_bytes()?;
    Ok(HRecord::from_rdata(
        hickory_name(owner)?,
        ttl,
        HRData::Unknown {
            code: HRecordType::DNAME,
            rdata: NULL::with(target),
        },
    ))
}

/// Assembles a DNSSEC record's RDATA from its fields (RFC 4034 §2.1, §3.1, §4.1, §5.1;
/// RFC 5155 §3.2), carried as an RFC 3597 unknown type the way [`dname_record`] carries a
/// DNAME. Names are encoded by hickory, uncompressed as RFC 4034 §6.2 requires, and every
/// other field is a fixed-width big-endian integer or an opaque octet string, so no byte
/// passes through `styx-proto`'s encoder.
fn dnssec_rdata(rdata: &RData) -> Result<Vec<u8>, HarnessError> {
    let mut bytes = Vec::new();
    match rdata {
        RData::Dnskey(key) => {
            bytes.extend(key.flags().to_be_bytes());
            bytes.extend([key.protocol(), key.algorithm()]);
            bytes.extend(key.public_key());
        }
        RData::Ds(ds) => {
            bytes.extend(ds.key_tag().to_be_bytes());
            bytes.extend([ds.algorithm(), ds.digest_type()]);
            bytes.extend(ds.digest());
        }
        RData::Rrsig(sig) => {
            bytes.extend(sig.type_covered().value().to_be_bytes());
            bytes.extend([sig.algorithm(), sig.labels()]);
            bytes.extend(sig.original_ttl().to_be_bytes());
            bytes.extend(sig.signature_expiration().to_be_bytes());
            bytes.extend(sig.signature_inception().to_be_bytes());
            bytes.extend(sig.key_tag().to_be_bytes());
            bytes.extend(hickory_name(&sig.signer_name().to_string())?.to_bytes()?);
            bytes.extend(sig.signature());
        }
        RData::Nsec(nsec) => {
            bytes.extend(hickory_name(&nsec.next_domain().to_string())?.to_bytes()?);
            bytes.extend(nsec.types().windows());
        }
        RData::Nsec3(nsec3) => {
            bytes.extend([nsec3.hash_algorithm(), nsec3.flags()]);
            bytes.extend(nsec3.iterations().to_be_bytes());
            bytes.push(length_octet(nsec3.salt().len())?);
            bytes.extend(nsec3.salt());
            bytes.push(length_octet(nsec3.next_hashed_owner().len())?);
            bytes.extend(nsec3.next_hashed_owner());
            bytes.extend(nsec3.types().windows());
        }
        other => {
            return Err(HarnessError::Protocol(format!(
                "{:?} is not a DNSSEC record type",
                other.rtype()
            )))
        }
    }
    Ok(bytes)
}

fn length_octet(length: usize) -> Result<u8, HarnessError> {
    u8::try_from(length)
        .map_err(|_| HarnessError::Protocol(format!("NSEC3 field of {length} octets")))
}

/// Maps a `styx-proto` record type onto hickory's.
pub(crate) fn hickory_type(rtype: RecordType) -> HRecordType {
    HRecordType::from(rtype.value())
}

fn soa_field(value: u32) -> Result<i32, HarnessError> {
    i32::try_from(value)
        .map_err(|_| HarnessError::Protocol(format!("SOA timer {value} exceeds i32")))
}

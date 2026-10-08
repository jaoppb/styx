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

/// Maps a `styx-proto` record type onto hickory's.
pub(crate) fn hickory_type(rtype: RecordType) -> HRecordType {
    HRecordType::from(rtype.value())
}

fn soa_field(value: u32) -> Result<i32, HarnessError> {
    i32::try_from(value)
        .map_err(|_| HarnessError::Protocol(format!("SOA timer {value} exceeds i32")))
}

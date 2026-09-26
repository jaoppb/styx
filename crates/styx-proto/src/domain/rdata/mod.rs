//! Resource record data (RDATA) taxonomy.
//!
//! Provides the top-level [`RData`] enumeration and supporting types
//! for basic and DNSSEC records.

pub mod basic;
pub mod dnssec;

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

pub use basic::{MxRdata, SoaRdata, SrvRdata, TxtRdata};
pub use dnssec::{
    DnskeyRdata, DsRdata, Nsec3ParamRdata, Nsec3Rdata, NsecRdata, RrsigRdata, TypeBitmap,
};

use crate::domain::name::Name;
use crate::domain::record::RecordType;

/// A DNS <character-string> as defined in RFC 1035 §3.3.
///
/// Treated as binary octets with a single-octet length prefix (0..=255).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CharacterString {
    /// Raw octets of the character string.
    pub octets: Vec<u8>,
}

impl CharacterString {
    /// Creates a character string from octets.
    #[must_use]
    pub fn new(octets: Vec<u8>) -> Self {
        Self { octets }
    }
}

impl fmt::Debug for CharacterString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CharacterString({:?})",
            String::from_utf8_lossy(&self.octets)
        )
    }
}

impl fmt::Display for CharacterString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.octets))
    }
}

/// Opaque RDATA for unmodeled or experimental RRtypes (RFC 3597).
///
/// Unknown RDATA is kept strictly opaque: treating arbitrary bytes as
/// compression pointers or domain names is a vulnerability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownRdata {
    rtype: RecordType,
    octets: Vec<u8>,
}

impl UnknownRdata {
    /// Creates an [`UnknownRdata`] instance.
    #[must_use]
    pub fn new(rtype: RecordType, octets: Vec<u8>) -> Self {
        Self { rtype, octets }
    }

    /// The RRtype of this opaque record.
    #[must_use]
    pub fn rtype(&self) -> RecordType {
        self.rtype
    }

    /// The raw opaque RDATA octets.
    #[must_use]
    pub fn octets(&self) -> &[u8] {
        &self.octets
    }
}

/// Complete RDATA enumeration across all supported v1 RRtypes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    /// IPv4 address (RFC 1035).
    A(Ipv4Addr),
    /// IPv6 address (RFC 3596).
    Aaaa(Ipv6Addr),
    /// Canonical name (RFC 1035).
    Cname(Name),
    /// Authoritative name server (RFC 1035).
    Ns(Name),
    /// Domain name pointer (RFC 1035).
    Ptr(Name),
    /// Start of Authority (RFC 1035).
    Soa(SoaRdata),
    /// Mail exchange (RFC 1035).
    Mx(MxRdata),
    /// Text strings (RFC 1035).
    Txt(TxtRdata),
    /// Service locator (RFC 2782).
    Srv(SrvRdata),
    /// DNSSEC public key (RFC 4034).
    Dnskey(DnskeyRdata),
    /// Delegation signer (RFC 4034).
    Ds(DsRdata),
    /// Resource record signature (RFC 4034).
    Rrsig(RrsigRdata),
    /// Next secure record (RFC 4034).
    Nsec(NsecRdata),
    /// NSEC3 hashed next secure record (RFC 5155).
    Nsec3(Nsec3Rdata),
    /// NSEC3 parameters (RFC 5155).
    Nsec3Param(Nsec3ParamRdata),
    /// Unenumerated or unknown RRtype (RFC 3597).
    Unknown(UnknownRdata),
}

impl RData {
    /// Returns the [`RecordType`] corresponding to this RDATA variant.
    #[must_use]
    pub fn rtype(&self) -> RecordType {
        match self {
            Self::A(_) => RecordType::A,
            Self::Aaaa(_) => RecordType::AAAA,
            Self::Cname(_) => RecordType::CNAME,
            Self::Ns(_) => RecordType::NS,
            Self::Ptr(_) => RecordType::PTR,
            Self::Soa(_) => RecordType::SOA,
            Self::Mx(_) => RecordType::MX,
            Self::Txt(_) => RecordType::TXT,
            Self::Srv(_) => RecordType::SRV,
            Self::Dnskey(_) => RecordType::DNSKEY,
            Self::Ds(_) => RecordType::DS,
            Self::Rrsig(_) => RecordType::RRSIG,
            Self::Nsec(_) => RecordType::NSEC,
            Self::Nsec3(_) => RecordType::NSEC3,
            Self::Nsec3Param(_) => RecordType::NSEC3PARAM,
            Self::Unknown(u) => u.rtype(),
        }
    }
}

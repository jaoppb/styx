//! Resource record definitions, record types, classes, and TTL newtype.
//!
//! Enforces invariants on resource records and provides audited checked arithmetic
//! on TTL decrement operations.

use std::fmt;

use crate::domain::name::Name;
use crate::domain::rdata::RData;

/// DNS Resource Record Type (RFC 1035 §3.2.2, RFC 4034 §3, RFC 5155 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecordType {
    value: u16,
}

impl RecordType {
    /// Host IPv4 address (RFC 1035).
    pub const A: Self = Self { value: 1 };
    /// Authoritative name server (RFC 1035).
    pub const NS: Self = Self { value: 2 };
    /// Canonical name for an alias (RFC 1035).
    pub const CNAME: Self = Self { value: 5 };
    /// Delegation name: aliases a whole subtree (RFC 6672).
    pub const DNAME: Self = Self { value: 39 };
    /// Start of a zone of authority (RFC 1035).
    pub const SOA: Self = Self { value: 6 };
    /// Domain name pointer (RFC 1035).
    pub const PTR: Self = Self { value: 12 };
    /// Mail exchange (RFC 1035).
    pub const MX: Self = Self { value: 15 };
    /// Text strings (RFC 1035).
    pub const TXT: Self = Self { value: 16 };
    /// IPv6 host address (RFC 3596).
    pub const AAAA: Self = Self { value: 28 };
    /// Server selection (RFC 2782).
    pub const SRV: Self = Self { value: 33 };
    /// EDNS0 option pseudo-record (RFC 6891).
    pub const OPT: Self = Self { value: 41 };
    /// Delegation signer (RFC 4034).
    pub const DS: Self = Self { value: 43 };
    /// RRSIG resource record signature (RFC 4034).
    pub const RRSIG: Self = Self { value: 46 };
    /// Next secure record (RFC 4034).
    pub const NSEC: Self = Self { value: 47 };
    /// DNSSEC public key (RFC 4034).
    pub const DNSKEY: Self = Self { value: 48 };
    /// NSEC3 hashed next secure record (RFC 5155).
    pub const NSEC3: Self = Self { value: 50 };
    /// NSEC3 parameters (RFC 5155).
    pub const NSEC3PARAM: Self = Self { value: 51 };
    /// Incremental zone transfer pseudo-type (RFC 1995).
    pub const IXFR: Self = Self { value: 251 };
    /// Full zone transfer pseudo-type (RFC 1035).
    pub const AXFR: Self = Self { value: 252 };
    /// Any record query pseudo-type (RFC 1035).
    pub const ANY: Self = Self { value: 255 };

    /// Creates a record type from its 16-bit integer wire representation.
    #[must_use]
    pub const fn from_u16(value: u16) -> Self {
        Self { value }
    }

    /// Returns the 16-bit integer wire value of this record type.
    #[must_use]
    pub const fn value(self) -> u16 {
        self.value
    }

    /// Returns whether this is a pseudo-rrtype (OPT, ANY, AXFR, IXFR).
    ///
    /// Pseudo-types never appear as stored resource records in zones or caches.
    #[must_use]
    pub fn is_pseudo(self) -> bool {
        matches!(self, Self::OPT | Self::ANY | Self::AXFR | Self::IXFR)
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::A => write!(f, "A"),
            Self::NS => write!(f, "NS"),
            Self::CNAME => write!(f, "CNAME"),
            Self::SOA => write!(f, "SOA"),
            Self::PTR => write!(f, "PTR"),
            Self::MX => write!(f, "MX"),
            Self::TXT => write!(f, "TXT"),
            Self::AAAA => write!(f, "AAAA"),
            Self::SRV => write!(f, "SRV"),
            Self::OPT => write!(f, "OPT"),
            Self::DS => write!(f, "DS"),
            Self::RRSIG => write!(f, "RRSIG"),
            Self::NSEC => write!(f, "NSEC"),
            Self::DNSKEY => write!(f, "DNSKEY"),
            Self::NSEC3 => write!(f, "NSEC3"),
            Self::NSEC3PARAM => write!(f, "NSEC3PARAM"),
            Self::IXFR => write!(f, "IXFR"),
            Self::AXFR => write!(f, "AXFR"),
            Self::ANY => write!(f, "ANY"),
            other => write!(f, "TYPE{}", other.value),
        }
    }
}

/// DNS Record Class (RFC 1035 §3.2.4, RFC 2136).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RecordClass {
    /// Internet (IN, 1).
    In,
    /// Chaos (CH, 3).
    Ch,
    /// Hesiod (HS, 4).
    Hs,
    /// None (NONE, 254) — dynamic update prerequisite.
    None,
    /// Any class wildcard (ANY, 255).
    Any,
    /// Unassigned or unknown class.
    Unknown(u16),
}

impl RecordClass {
    /// Converts a 16-bit integer into a [`RecordClass`].
    #[must_use]
    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => Self::In,
            3 => Self::Ch,
            4 => Self::Hs,
            254 => Self::None,
            255 => Self::Any,
            other => Self::Unknown(other),
        }
    }

    /// Converts this [`RecordClass`] into its 16-bit wire representation.
    #[must_use]
    pub fn to_u16(self) -> u16 {
        match self {
            Self::In => 1,
            Self::Ch => 3,
            Self::Hs => 4,
            Self::None => 254,
            Self::Any => 255,
            Self::Unknown(v) => v,
        }
    }
}

impl fmt::Display for RecordClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::In => write!(f, "IN"),
            Self::Ch => write!(f, "CH"),
            Self::Hs => write!(f, "HS"),
            Self::None => write!(f, "NONE"),
            Self::Any => write!(f, "ANY"),
            Self::Unknown(v) => write!(f, "CLASS{v}"),
        }
    }
}

/// Time To Live in seconds (RFC 1035 §3.2.1, RFC 2181 §8).
///
/// Prevents cache poisoning by ensuring TTL decrements never wrap to huge values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ttl {
    seconds: u32,
}

impl Ttl {
    /// Zero seconds TTL.
    pub const ZERO: Self = Self { seconds: 0 };

    /// Creates a TTL from a seconds value.
    #[must_use]
    pub const fn from_secs(seconds: u32) -> Self {
        Self { seconds }
    }

    /// Returns the TTL duration in seconds.
    #[must_use]
    pub const fn seconds(self) -> u32 {
        self.seconds
    }

    /// Decrements the TTL by `delta` seconds, returning `None` if underflow would occur.
    #[must_use]
    pub fn checked_decrement(self, delta: u32) -> Option<Self> {
        self.seconds.checked_sub(delta).map(Self::from_secs)
    }

    /// Decrements the TTL by `delta` seconds, saturating at 0. Never wraps.
    #[must_use]
    pub fn saturating_decrement(self, delta: u32) -> Self {
        Self::from_secs(self.seconds.saturating_sub(delta))
    }

    /// Clamps the TTL to a maximum value in seconds.
    #[must_use]
    pub fn clamp_to(self, max: u32) -> Self {
        Self::from_secs(self.seconds.min(max))
    }
}

impl fmt::Display for Ttl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.seconds)
    }
}

/// A complete DNS Resource Record (RFC 1035 §4.1.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRecord {
    /// Owner domain name of the record.
    pub owner: Name,
    /// Resource record type.
    pub rtype: RecordType,
    /// Class of data (normally IN).
    pub rclass: RecordClass,
    /// Time To Live in seconds.
    pub ttl: Ttl,
    /// Type-specific record data.
    pub rdata: RData,
}

impl ResourceRecord {
    /// Creates a new Resource Record.
    #[must_use]
    pub fn new(
        owner: Name,
        rtype: RecordType,
        rclass: RecordClass,
        ttl: Ttl,
        rdata: RData,
    ) -> Self {
        Self {
            owner,
            rtype,
            rclass,
            ttl,
            rdata,
        }
    }
}

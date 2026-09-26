//! Basic DNS resolution RDATA types (RFC 1035, RFC 2782).
//!
//! Includes SOA, MX, TXT, and SRV record data structures.

use crate::domain::name::Name;
use crate::domain::rdata::CharacterString;

/// Start of Authority record data (RFC 1035 §3.3.13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoaRdata {
    mname: Name,
    rname: Name,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32,
}

impl SoaRdata {
    /// Creates a new [`SoaRdata`].
    #[must_use]
    pub fn new(
        mname: Name,
        rname: Name,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    ) -> Self {
        Self {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        }
    }

    /// Primary master name server for the zone.
    #[must_use]
    pub fn mname(&self) -> &Name {
        &self.mname
    }

    /// Mailbox of the person responsible for the zone.
    #[must_use]
    pub fn rname(&self) -> &Name {
        &self.rname
    }

    /// Version number of the original copy of the zone.
    #[must_use]
    pub fn serial(&self) -> u32 {
        self.serial
    }

    /// Time interval before the zone should be refreshed.
    #[must_use]
    pub fn refresh(&self) -> u32 {
        self.refresh
    }

    /// Time interval that should elapse before a failed refresh should be retried.
    #[must_use]
    pub fn retry(&self) -> u32 {
        self.retry
    }

    /// Upper limit on the time interval that can elapse before the zone is no longer authoritative.
    #[must_use]
    pub fn expire(&self) -> u32 {
        self.expire
    }

    /// Minimum TTL for negative caching (RFC 2308).
    #[must_use]
    pub fn minimum(&self) -> u32 {
        self.minimum
    }
}

/// Mail Exchange record data (RFC 1035 §3.3.9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MxRdata {
    preference: u16,
    exchange: Name,
}

impl MxRdata {
    /// Creates a new [`MxRdata`].
    #[must_use]
    pub fn new(preference: u16, exchange: Name) -> Self {
        Self {
            preference,
            exchange,
        }
    }

    /// Preference given to this RR among others at the same owner.
    #[must_use]
    pub fn preference(&self) -> u16 {
        self.preference
    }

    /// Host willing to act as a mail exchange.
    #[must_use]
    pub fn exchange(&self) -> &Name {
        &self.exchange
    }
}

/// Text strings record data (RFC 1035 §3.3.14).
///
/// Preserves the exact list of character strings on the wire: zero strings
/// and one empty string are distinct wire representations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxtRdata {
    strings: Vec<CharacterString>,
}

impl TxtRdata {
    /// Creates a new [`TxtRdata`] from a sequence of character strings.
    #[must_use]
    pub fn new(strings: Vec<CharacterString>) -> Self {
        Self { strings }
    }

    /// Returns the sequence of character strings.
    #[must_use]
    pub fn strings(&self) -> &[CharacterString] {
        &self.strings
    }
}

/// Service locator record data (RFC 2782).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrvRdata {
    priority: u16,
    weight: u16,
    port: u16,
    target: Name,
}

impl SrvRdata {
    /// Creates a new [`SrvRdata`].
    #[must_use]
    pub fn new(priority: u16, weight: u16, port: u16, target: Name) -> Self {
        Self {
            priority,
            weight,
            port,
            target,
        }
    }

    /// Priority of the target host (lower value means more preferred).
    #[must_use]
    pub fn priority(&self) -> u16 {
        self.priority
    }

    /// Weighting factor for servers with the same priority.
    #[must_use]
    pub fn weight(&self) -> u16 {
        self.weight
    }

    /// TCP/UDP port on which the service is found.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Domain name of the target host.
    #[must_use]
    pub fn target(&self) -> &Name {
        &self.target
    }
}

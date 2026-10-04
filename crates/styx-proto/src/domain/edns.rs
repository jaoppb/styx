//! EDNS(0) extension mechanisms for DNS (RFC 6891).
//!
//! Models the OPT pseudo-record, unpacking its overloaded header fields
//! (owner name = root, class = UDP payload size, TTL = extended RCODE / version / flags)
//! into domain-meaningful strongly-typed structures.

/// Standard EDNS(0) UDP payload size recommended by DNS Flag Day 2020.
pub const DEFAULT_EDNS_UDP_PAYLOAD_SIZE: u16 = 1232;

/// An individual EDNS(0) option (RFC 6891 §6.1.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdnsOption {
    /// 16-bit option code (assigned by IANA).
    pub code: u16,
    /// Option-specific octets.
    pub data: Vec<u8>,
}

impl EdnsOption {
    /// Creates a new [`EdnsOption`].
    #[must_use]
    pub fn new(code: u16, data: Vec<u8>) -> Self {
        Self { code, data }
    }
}

/// The EDNS(0) OPT pseudo-record (RFC 6891 §6.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opt {
    udp_payload_size: u16,
    extended_rcode: u8,
    version: u8,
    dnssec_ok: bool,
    options: Vec<EdnsOption>,
}

impl Opt {
    /// Creates a new [`Opt`] pseudo-record.
    #[must_use]
    pub fn new(
        udp_payload_size: u16,
        extended_rcode: u8,
        version: u8,
        dnssec_ok: bool,
        options: Vec<EdnsOption>,
    ) -> Self {
        Self {
            udp_payload_size,
            extended_rcode,
            version,
            dnssec_ok,
            options,
        }
    }

    /// The requestor's UDP payload size in octets (RFC 6891 §6.2.3).
    #[must_use]
    pub fn udp_payload_size(&self) -> u16 {
        self.udp_payload_size
    }

    /// Returns a copy of the [`Opt`] record with the UDP payload size updated.
    #[must_use]
    pub fn with_udp_payload_size(mut self, size: u16) -> Self {
        self.udp_payload_size = size;
        self
    }

    /// Sets the sender's UDP payload size.
    pub fn set_udp_payload_size(&mut self, size: u16) {
        self.udp_payload_size = size;
    }

    /// Upper 8 bits of the 12-bit extended RCODE (RFC 6891 §6.1.3).
    #[must_use]
    pub fn extended_rcode(&self) -> u8 {
        self.extended_rcode
    }

    /// The EDNS implementation version (must be 0, RFC 6891 §6.1.3).
    #[must_use]
    pub fn version(&self) -> u8 {
        self.version
    }

    /// The DNSSEC OK (DO) flag bit (RFC 4035 §3.2.1, RFC 6891 §6.1.3).
    #[must_use]
    pub fn dnssec_ok(&self) -> bool {
        self.dnssec_ok
    }

    /// Slice of EDNS options carried in this record.
    #[must_use]
    pub fn options(&self) -> &[EdnsOption] {
        &self.options
    }
}

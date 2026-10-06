//! DNS message header and flag definitions.
//!
//! Models the 12-octet DNS header (RFC 1035 §4.1.1) with flags represented as
//! typed enums and named booleans rather than raw bitfields.

use std::fmt;

/// Indicates whether a DNS message is a query or a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageKind {
    /// A DNS query message (QR = 0).
    Query,
    /// A DNS response message (QR = 1).
    Response,
}

/// The DNS query operation code (RFC 1035 §4.1.1, RFC 1996, RFC 2136).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Opcode {
    /// Standard query (QUERY, 0).
    Query,
    /// Server status request (STATUS, 2).
    Status,
    /// Zone change notification (NOTIFY, 4).
    Notify,
    /// Dynamic update (UPDATE, 5).
    Update,
    /// Unknown or unassigned opcode.
    Unknown(u8),
}

impl Opcode {
    /// Converts a 4-bit nibble into an [`Opcode`].
    #[must_use]
    pub fn from_u8(value: u8) -> Self {
        match value & 0x0F {
            0 => Self::Query,
            2 => Self::Status,
            4 => Self::Notify,
            5 => Self::Update,
            other => Self::Unknown(other),
        }
    }

    /// Converts this [`Opcode`] into its 4-bit wire representation.
    #[must_use]
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Query => 0,
            Self::Status => 2,
            Self::Notify => 4,
            Self::Update => 5,
            Self::Unknown(v) => v & 0x0F,
        }
    }
}

/// A 12-bit DNS response code (extended RCODE, RFC 1035 and RFC 6891).
///
/// Combines the 4-bit RCODE from the DNS header with the 8-bit upper RCODE
/// from the EDNS(0) OPT pseudo-record, allowing values like `BADVERS` (16)
/// to be represented without truncation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResponseCode {
    value: u16,
}

impl ResponseCode {
    /// No error condition (RFC 1035).
    pub const NOERROR: Self = Self { value: 0 };
    /// Format error: the name server was unable to interpret the query (RFC 1035).
    pub const FORMERR: Self = Self { value: 1 };
    /// Server failure: internal server error (RFC 1035).
    pub const SERVFAIL: Self = Self { value: 2 };
    /// Name error: domain name does not exist (RFC 1035).
    pub const NXDOMAIN: Self = Self { value: 3 };
    /// Not implemented: name server does not support the requested operation (RFC 1035).
    pub const NOTIMP: Self = Self { value: 4 };
    /// Refused: name server refuses to perform operation for policy reasons (RFC 1035).
    pub const REFUSED: Self = Self { value: 5 };
    /// Name exists when it should not (RFC 2136).
    pub const YXDOMAIN: Self = Self { value: 6 };
    /// RR set exists when it should not (RFC 2136).
    pub const YXRRSET: Self = Self { value: 7 };
    /// RR set that should exist does not (RFC 2136).
    pub const NXRRSET: Self = Self { value: 8 };
    /// Server not authoritative for zone (RFC 2136).
    pub const NOTAUTH: Self = Self { value: 9 };
    /// Name not contained in zone (RFC 2136).
    pub const NOTZONE: Self = Self { value: 10 };
    /// Bad EDNS version (RFC 6891) or TSIG signature failure (RFC 8945).
    pub const BADVERS_OR_BADSIG: Self = Self { value: 16 };
    /// Key not recognized (RFC 8945).
    pub const BADKEY: Self = Self { value: 17 };
    /// Signature out of time window (RFC 8945).
    pub const BADTIME: Self = Self { value: 18 };
    /// Bad TKEY mode (RFC 2930).
    pub const BADMODE: Self = Self { value: 19 };
    /// Duplicate key name (RFC 8945).
    pub const BADNAME: Self = Self { value: 20 };
    /// Algorithm not supported (RFC 8945).
    pub const BADALG: Self = Self { value: 21 };
    /// Bad truncation (RFC 8945).
    pub const BADTRUNC: Self = Self { value: 22 };
    /// Bad or missing server cookie (RFC 7873).
    pub const BADCOOKIE: Self = Self { value: 23 };

    /// Creates a response code directly from a 12-bit integer value.
    #[must_use]
    pub const fn from_u16(value: u16) -> Self {
        Self {
            value: value & 0x0FFF,
        }
    }

    /// Combines the 4-bit header RCODE with the 8-bit EDNS extended RCODE upper octet.
    #[must_use]
    pub fn from_parts(header_nibble: u8, opt_upper: u8) -> Self {
        let upper = u16::from(opt_upper);
        let lower = u16::from(header_nibble & 0x0F);
        Self {
            value: ((upper << 4) | lower) & 0x0FFF,
        }
    }

    /// Returns the underlying 12-bit response code value.
    #[must_use]
    pub const fn value(self) -> u16 {
        self.value
    }

    /// Splits the 12-bit response code into its component parts.
    #[must_use]
    pub fn split(self) -> ResponseCodeParts {
        let lower = match u8::try_from(self.value & 0x0F) {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!("lower rcode split error: {e}");
                0
            }
        };
        let upper = match u8::try_from((self.value >> 4) & 0xFF) {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!("upper rcode split error: {e}");
                0
            }
        };
        ResponseCodeParts {
            header_nibble: lower,
            opt_upper_octet: upper,
        }
    }
}

impl fmt::Display for ResponseCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::NOERROR => write!(f, "NOERROR"),
            Self::FORMERR => write!(f, "FORMERR"),
            Self::SERVFAIL => write!(f, "SERVFAIL"),
            Self::NXDOMAIN => write!(f, "NXDOMAIN"),
            Self::NOTIMP => write!(f, "NOTIMP"),
            Self::REFUSED => write!(f, "REFUSED"),
            Self::YXDOMAIN => write!(f, "YXDOMAIN"),
            Self::YXRRSET => write!(f, "YXRRSET"),
            Self::NXRRSET => write!(f, "NXRRSET"),
            Self::NOTAUTH => write!(f, "NOTAUTH"),
            Self::NOTZONE => write!(f, "NOTZONE"),
            Self::BADVERS_OR_BADSIG => write!(f, "BADVERS/BADSIG"),
            other => write!(f, "RCODE({})", other.value()),
        }
    }
}

/// Component parts of a 12-bit DNS response code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseCodeParts {
    /// 4-bit header response code nibble.
    pub header_nibble: u8,
    /// 8-bit upper extended response code octet (from EDNS OPT).
    pub opt_upper_octet: u8,
}

/// The 12-octet DNS message header (RFC 1035 §4.1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// 16-bit message transaction identifier.
    pub id: u16,
    /// Query or response kind (QR bit).
    pub kind: MessageKind,
    /// 4-bit operation code.
    pub opcode: Opcode,
    /// Authoritative Answer (AA bit).
    pub authoritative: bool,
    /// Truncation flag (TC bit).
    pub truncated: bool,
    /// Recursion Desired (RD bit).
    pub recursion_desired: bool,
    /// Recursion Available (RA bit).
    pub recursion_available: bool,
    /// Authentic Data (AD bit, RFC 4035 / RFC 6840).
    pub authentic_data: bool,
    /// Checking Disabled (CD bit, RFC 4035).
    pub checking_disabled: bool,
    /// 12-bit response code.
    pub rcode: ResponseCode,
}

impl Header {
    /// Creates a new header with standard query defaults.
    #[must_use]
    pub fn new_query(id: u16, opcode: Opcode, recursion_desired: bool) -> Self {
        Self {
            id,
            kind: MessageKind::Query,
            opcode,
            authoritative: false,
            truncated: false,
            recursion_desired,
            recursion_available: false,
            authentic_data: false,
            checking_disabled: false,
            rcode: ResponseCode::NOERROR,
        }
    }

    /// Clears the Authentic Data (AD) bit.
    ///
    /// Required for blocked replies, local records, and any synthesized responses.
    pub fn clear_authentic_data(&mut self) {
        self.authentic_data = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_standard_rcode() {
        let parts = ResponseCode::NXDOMAIN.split();
        assert_eq!(parts.header_nibble, 3);
        assert_eq!(parts.opt_upper_octet, 0);
    }

    #[test]
    fn test_split_extended_rcode() {
        let parts = ResponseCode::BADVERS_OR_BADSIG.split();
        assert_eq!(parts.header_nibble, 0);
        assert_eq!(parts.opt_upper_octet, 1);
    }

    #[test]
    fn test_split_and_from_parts_roundtrip() {
        let original = ResponseCode::from_parts(0x0E, 0xAB);
        let parts = original.split();
        assert_eq!(parts.header_nibble, 0x0E);
        assert_eq!(parts.opt_upper_octet, 0xAB);
        assert_eq!(
            ResponseCode::from_parts(parts.header_nibble, parts.opt_upper_octet),
            original
        );
    }
}

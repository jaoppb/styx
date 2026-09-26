//! Error types for the DNS wire codec.
//!
//! Every fallible operation returns a crate-owned [`thiserror`] enum.
//! In accordance with privacy design, error strings carry only structural
//! facts (offsets, lengths) and never packet contents or domain names.

use thiserror::Error;

/// Errors produced during presentation or wire-name validation.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NameError {
    /// A single label exceeded the 63-octet RFC 1035 ceiling.
    #[error("label length {0} exceeds RFC 1035 ceiling of 63 octets")]
    LabelTooLong(usize),

    /// A full wire name exceeded the 255-octet RFC 1035 ceiling.
    #[error("wire name length {0} exceeds RFC 1035 ceiling of 255 octets")]
    NameTooLong(usize),

    /// A label was empty where an octet sequence was expected.
    #[error("label is empty")]
    EmptyLabel,

    /// A presentation format string contained a non-ASCII octet or invalid escape.
    #[error("non-ASCII or invalid escape character in presentation name")]
    NonAsciiInPresentation,
}

/// Errors produced while decoding DNS wire messages.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DecodeError {
    /// Unexpected end of input while reading required bytes.
    ///
    /// For UDP responses, callers should interpret this as a signal to retry
    /// over TCP (Phase 3).
    #[error("unexpected end of input at offset {0}")]
    UnexpectedEof(usize),

    /// A label exceeded 63 octets during name decoding.
    #[error("label exceeds 63 octets")]
    LabelTooLong,

    /// A decoded wire name exceeded 255 octets.
    #[error("wire name exceeds 255 octets")]
    NameTooLong,

    /// A compression pointer target is outside the message buffer.
    #[error("compression pointer {pointer} is out of range for buffer length {len}")]
    PointerOutOfRange {
        /// Target offset decoded from the pointer.
        pointer: usize,
        /// Total buffer length.
        len: usize,
    },

    /// A compression pointer loop was detected.
    #[error("compression pointer loop detected at offset {0}")]
    CompressionLoop(usize),

    /// The name expansion budget was exhausted during decompression.
    #[error("compression expansion budget exceeded")]
    ExpansionBudgetExceeded,

    /// An RDLENGTH field did not match the expected length for a fixed-size RRTYPE.
    #[error("RDLENGTH {actual} does not match expected length {expected}")]
    BadRdLength {
        /// Expected byte length.
        expected: usize,
        /// Actual parsed RDLENGTH.
        actual: usize,
    },

    /// Parser attempted to read past the end of the RDATA boundary.
    #[error("RDATA overrun: read past declared RDLENGTH")]
    RdataOverrun,

    /// Unparsed bytes remained in the record after parsing RDATA.
    #[error("trailing RDATA bytes: {remaining} unparsed octets")]
    TrailingRdataBytes {
        /// Number of unparsed trailing octets.
        remaining: usize,
    },

    /// A section had fewer records than declared in the header.
    #[error("section count mismatch: declared records could not be read")]
    SectionCountMismatch,

    /// More than one EDNS(0) OPT pseudo-record was found in the message.
    #[error("multiple OPT pseudo-records present in message")]
    MultipleOptRecords,

    /// An OPT pseudo-record was malformed (e.g. non-root name or truncated option).
    ///
    /// Callers can use this to distinguish broken nameservers from unsupported EDNS.
    #[error("malformed EDNS(0) OPT pseudo-record")]
    MalformedOpt,

    /// The EDNS version in the OPT record is not supported (version != 0).
    ///
    /// Callers should reply with BADVERS.
    #[error("unsupported EDNS version: {0}")]
    UnsupportedEdnsVersion(u8),

    /// Reserved header or flag bits were set where forbidden.
    #[error("reserved bits set in wire input")]
    ReservedBitsSet,

    /// A domain name invariant was violated.
    #[error(transparent)]
    Name(#[from] NameError),
}

/// Errors produced while encoding DNS messages.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EncodeError {
    /// Encoding exceeded the configured byte budget.
    #[error("encoding budget exceeded: {bytes_written} bytes written")]
    BudgetExceeded {
        /// Number of bytes written before the budget limit was reached.
        bytes_written: usize,
    },

    /// A domain name exceeded the 255-octet wire limit.
    #[error("encoded name exceeds 255 octets")]
    NameTooLong,

    /// A label exceeded the 63-octet limit.
    #[error("encoded label exceeds 63 octets")]
    LabelTooLong,

    /// RDATA length exceeded the 65535-octet u16 RDLENGTH limit.
    #[error("RDLENGTH overflow: length {0} exceeds u16::MAX")]
    RdLengthOverflow(usize),

    /// Number of records in a section exceeded the 65535 u16 limit.
    #[error("too many records in section for 16-bit count")]
    TooManyRecords,

    /// A domain name invariant was violated.
    #[error(transparent)]
    Name(#[from] NameError),
}

//! styx shared foundation: DNS wire types and codec (Phase 1).
//!
//! Provides pure, allocation-conscious decoding and encoding of DNS messages,
//! domain name compression and decompression with loop detection and quadratic
//! expansion bounds, EDNS(0) OPT pseudo-record handling, and RFC 4034 canonical form.
//!
//! # Safety
//!
//! Unsafe code is strictly forbidden across this crate.
#![forbid(unsafe_code)]

pub mod application;
pub mod domain;
pub mod infrastructure;

// Public re-exports for consumers
pub use application::canonical::{canonical_name_cmp, canonical_rr_cmp, with_original_ttl};
pub use domain::edns::{EdnsOption, Opt, DEFAULT_EDNS_UDP_PAYLOAD_SIZE};
pub use domain::error::{DecodeError, EncodeError, NameError};
pub use domain::header::{Header, MessageKind, Opcode, ResponseCode};
pub use domain::message::Message;
pub use domain::name::{Label, LabelRef, Name, MAX_LABEL_LEN, MAX_NAME_LEN};
pub use domain::question::Question;
pub use domain::rdata::basic::{MxRdata, SoaRdata, SrvRdata, TxtRdata};
pub use domain::rdata::dnssec::{
    DnskeyRdata, DsRdata, Nsec3ParamRdata, Nsec3Rdata, NsecRdata, RrsigRdata, TypeBitmap,
};
pub use domain::rdata::{CharacterString, RData, UnknownRdata};
pub use domain::record::{RecordClass, RecordType, ResourceRecord, Ttl};
pub use infrastructure::{frame_tcp, read_tcp_frame_length, MAX_TCP_MESSAGE_LEN};

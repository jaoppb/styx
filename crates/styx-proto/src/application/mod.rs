//! DNS wire codec application layer.
//!
//! Contains cursor bounds-checking, encoding, decoding, and RFC 4034 canonical form.

pub mod canonical;
pub mod cursor;
pub mod decoder;
pub mod encoder;

pub use canonical::{canonical_name_cmp, canonical_rr_cmp, with_original_ttl};
pub use cursor::Cursor;
pub use decoder::Decoder;
pub use encoder::Encoder;

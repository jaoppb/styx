//! DNS protocol domain vocabulary and invariants.
//!
//! Types here enforce domain invariants at construction: label and name length
//! bounds, flag semantics, and record representations. They know nothing of
//! the wire layout.

pub mod edns;
pub mod error;
pub mod header;
pub mod message;
pub mod name;
pub mod question;
pub mod rdata;
pub mod record;

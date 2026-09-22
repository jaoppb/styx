//! Domain layer: ports (traits) and the error enums they return.
//!
//! Depends outward on nothing but `styx-proto` and third-party crates. It may
//! not use `crate::application`, `crate::infrastructure`, or any sibling
//! feature crate.
//!
//! The matcher's ports and its `thiserror` error enum land here in phase 8.
//!
//! No synchronous I/O, no `unwrap`, no `expect`, no `panic!`.

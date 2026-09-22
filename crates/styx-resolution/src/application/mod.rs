//! Application layer: orchestration over the ports declared in [`crate::domain`].
//!
//! May use `crate::domain` and `styx-proto`. **May not** use
//! `crate::infrastructure`, and may not name a sibling feature crate.
//!
//! Every fallible operation returns `Result<T, E>` with a crate-owned
//! `thiserror` enum. No synchronous I/O: a database outage must degrade
//! logging and admin, never resolution.

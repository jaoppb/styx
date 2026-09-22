//! Infrastructure layer: adapters implementing the ports in [`crate::domain`].
//!
//! May use `crate::domain`, `crate::application` and `styx-proto`. May not
//! name a sibling feature crate — a cross-feature need is a port here and an
//! adapter wired in the `styx` binary.
//!
//! This is where `tracing` instrumentation lives; `#[tracing::instrument]`
//! goes on meaningful operations rather than on everything.

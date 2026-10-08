//! Test support for styx: in-process fake DNS servers driven over real sockets.
//!
//! **A dev-dependency only.** The fakes encode their responses with `hickory-proto`,
//! the test oracle, never with `styx-proto`'s encoder — if our own codec encoded the
//! fixtures, the resolver and its oracle would share every bug, and a green suite
//! would prove only self-consistency. `hickory-proto` is therefore a normal
//! dependency of this crate, and this crate must never be one of any shipping crate:
//! the `hickory-dev-only` gate rejects any normal or build path that reaches it.
//!
//! Harness pieces that wrap a feature crate's own types (such as a booted
//! `styx-resolution` server) stay in that crate's tests: this crate names no
//! feature crate, so every feature crate can depend on it without a cycle.

pub mod client;
pub mod commandable;
mod convert;
pub mod error;
pub mod fake;
mod responder;
pub mod script;

pub use client::DnsClient;
pub use commandable::{CommandableUpstream, UpstreamBehavior};
pub use error::HarnessError;
pub use fake::{FakeNameServer, FakeRole};
pub use responder::ReceivedQuery;
pub use script::{
    ScriptedAnswer, ScriptedDname, ScriptedGlue, ScriptedOrigin, ScriptedRcode, ScriptedReferral,
    ZoneScript,
};
pub use styx_core::test_util::TestClock;

//! Test harness module exports.
//!
//! The fake servers and the DNS client come from `styx-testkit`, shared with every
//! crate that tests DNS over real sockets. Only [`TestServer`] lives here, because
//! it boots this crate's own `Server`.

#![allow(unused_imports, dead_code)]

pub mod server;

pub use server::{ServerSettings, TestServer};
pub use styx_testkit::{
    CommandableUpstream, DnsClient, FakeNameServer, FakeRole, HarnessError, TestClock,
    UpstreamBehavior, ZoneScript,
};

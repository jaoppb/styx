//! Shared foundation for styx: the one audited outbound Do53 client exchange.
//!
//! Every outbound DNS query styx sends over UDP or TCP — the forwarder's and the
//! recursor's alike — goes through [`Do53Client::exchange`]. That is deliberate:
//! the off-path spoofing defence lives here, once, rather than in two copies that
//! drift apart. Specifically, every exchange
//!
//! - stamps a fresh random 16-bit transaction ID on the query,
//! - binds a fresh ephemeral source port and `connect`s the socket to the server,
//!   so the kernel drops datagrams from any other source,
//! - discards any UDP response whose ID or question does not match the query, and
//!   keeps listening rather than accepting it, and
//! - on a truncated UDP response, retries over TCP with the identical message.
//!
//! The crate is shared foundation, like `styx-proto` and `styx-core`: any crate may
//! depend on it, and it depends on no feature crate.

pub mod domain;
pub mod infrastructure;

pub use domain::exchange::{ExchangeError, Exchanged};
pub use infrastructure::client::Do53Client;
pub use infrastructure::frame::{write_framed, FrameWriteError};

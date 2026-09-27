//! Infrastructure layer: adapters implementing the ports in [`crate::domain`].
//!
//! May use `crate::domain`, `crate::application` and `styx-proto`. May not
//! name a sibling feature crate — a cross-feature need is a port here and an
//! adapter wired in the `styx` binary.
//!
//! This is where `tracing` instrumentation lives; `#[tracing::instrument]`
//! goes on meaningful operations rather than on everything.

pub mod cache;
pub mod clock;
pub mod do53;
pub mod filter;
pub mod local;
pub mod observer;
pub mod response;
pub mod server;
pub mod tcp;
pub mod udp;

pub use cache::{Eviction, EvictionReport, ShardedAnswerCache, DEFAULT_SHARDS};
pub use clock::SystemClock;
pub use do53::Do53Forwarder;
pub use filter::AllowAllFilter;
pub use local::NoLocalRecords;
pub use observer::DiscardObserver;
pub use response::ResponseWriter;
pub use server::{Server, ServerConfig};
pub use tcp::TcpListener;
pub use udp::UdpListener;

//! Infrastructure layer: adapters implementing the ports in [`crate::domain`].
//!
//! May use `crate::domain`, `crate::application`, `styx-core`, and `styx-proto`. May not
//! name a sibling feature crate — a cross-feature need is a port here and an
//! adapter wired in the `styx` binary.
//!
//! This is where `tracing` instrumentation lives; `#[tracing::instrument]`
//! goes on meaningful operations rather than on everything.

pub mod admission;
pub mod cache;
pub mod do53;
pub mod filter;
pub mod local;
pub mod observer;
pub mod response;
pub mod server;
pub mod supervisor;
pub mod tcp;
pub mod tcp_connection;
pub mod tcp_frame;
pub mod udp;
pub mod udp_socket;

pub use admission::{ConnectionBudget, ConnectionPermit, ListenerShared, QueryBudget, QueryPermit};
pub use cache::{Eviction, EvictionReport, ShardedAnswerCache, DEFAULT_SHARDS};
pub use do53::Do53Forwarder;
pub use filter::AllowAllFilter;
pub use local::NoLocalRecords;
pub use observer::DiscardObserver;
pub use response::ResponseWriter;
pub use server::{Server, ServerConfig};
pub use supervisor::{
    run_listener_supervisor, SupervisedListener, SupervisorBackoff, SupervisorBackoffPolicy,
    DEFAULT_HEALTHY_THRESHOLD, DEFAULT_INITIAL_BACKOFF, DEFAULT_MAX_BACKOFF,
};
pub use tcp::TcpListener;
pub use tcp_connection::{ConnectionInFlight, InFlightSlot, OutboundFrame};
pub use tcp_frame::{write_framed, FrameWriteError};
pub use udp::UdpListener;
pub use udp_socket::{bind_reuseport_group, default_socket_count};

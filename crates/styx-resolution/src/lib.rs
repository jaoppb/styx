//! styx resolution: forwarding, the upstream pool, caching and recursion.
//!
//! A **feature crate**. Its layer structure is exactly three modules — no
//! other top-level module belongs here. Later phases fill these in; they do
//! not reshape them.
//!
//! This crate declares the `FilterPolicy` port in [`domain`], which the
//! `styx` binary wires `styx-filtering` into. It must never name
//! `styx-filtering` directly: that is the cross-feature edge
//! `[[restrict-use]]` and the link-graph gate both exist to reject.

pub mod application;
pub mod domain;
pub mod infrastructure;

// Public re-exports for convenience
pub use application::{
    OrderedFailover, Pipeline, PoolMember, ProbeScheduler, RaceAll, RefusedTerminal, RoundRobin,
    TerminalHandler, UpstreamPool, Weighted,
};
pub use domain::answer::{
    AnswerSource, ForgedAnswer, ForgedSource, ResolutionOutcome, ResolvedSource,
};
pub use domain::circuit::{CircuitConfig, CircuitState, FailureCount};
pub use domain::clock::Clock;
pub use domain::config::{PoolConfig, Timeouts, UpstreamConfig};
pub use domain::edns::EdnsBufferSize;
pub use domain::error::{
    ConfigError, FailureClass, ListenerError, PipelineError, PoolError, ServerError, UpstreamError,
};
pub use domain::health::{HealthState, Outcome};
pub use domain::ports::filter::{FilterPolicy, FilterVerdict};
pub use domain::ports::local::LocalRecords;
pub use domain::ports::observer::{QueryDetail, QueryObserver};
pub use domain::probe::{CanaryConfig, ProbeConfig, ProbePolicy};
pub use domain::request::{ClientId, MaxResponseSize, RequestContext, Transport};
pub use domain::selection::{MemberView, Selection, SelectionStrategy, StrategyName};
pub use domain::upstream::{Upstream, UpstreamId, UpstreamKind, UpstreamResponse};
pub use domain::weight::Weight;
pub use infrastructure::clock::SystemClock;
pub use infrastructure::do53::Do53Forwarder;
pub use infrastructure::filter::AllowAllFilter;
pub use infrastructure::local::NoLocalRecords;
pub use infrastructure::observer::DiscardObserver;
pub use infrastructure::response::ResponseWriter;
pub use infrastructure::server::{Server, ServerConfig};
pub use infrastructure::tcp::TcpListener;
pub use infrastructure::udp::UdpListener;

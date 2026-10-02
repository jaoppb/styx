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
    CacheStage, OrderedFailover, Pipeline, PoolMember, ProbeScheduler, RaceAll, RefusedTerminal,
    RoundRobin, TerminalHandler, UpstreamPool, Weighted,
};
pub use domain::answer::{
    AnswerSource, ForgedAnswer, ForgedSource, ResolutionOutcome, ResolutionResponse, ResolvedSource,
};
pub use domain::cache::{
    Admission, AdmissionOutcome, AdmittedCount, AnswerCache, Bailiwick, CacheCapacity, CacheEntry,
    CacheError, CacheKey, CacheStats, CanonicalName, Deadline, DenialKind, DnssecMetadata,
    HeapBytes, Lookup, MessageFlags, NegativeEntry, PositiveEntry, PurgedCount, RRset,
    RejectReason, RejectedRecord, SecurityStatus, TtlPolicy,
};
pub use domain::circuit::{CircuitConfig, CircuitState, FailureCount};
pub use domain::config::{PoolConfig, Timeouts, UpstreamConfig};
pub use domain::edns::EdnsBufferSize;
pub use domain::error::{ConfigError, ListenerError, PipelineError, PoolError, ServerError};
pub use domain::health::{HealthState, Outcome};
pub use domain::limits::ConcurrencyLimits;
pub use domain::ports::filter::{FilterPolicy, FilterVerdict};
pub use domain::ports::local::LocalRecords;
pub use domain::ports::observer::{QueryDetail, QueryObserver};
pub use domain::probe::{CanaryConfig, ProbeConfig, ProbePolicy};
pub use domain::request::{ClientId, MaxResponseSize, RequestContext, Transport};
pub use domain::selection::{MemberView, Selection, SelectionStrategy, StrategyName};
pub use domain::weight::Weight;
pub use infrastructure::cache::{
    Eviction, EvictionReport, Shard, ShardedAnswerCache, DEFAULT_SHARDS,
};
pub use infrastructure::do53::Do53Forwarder;
pub use infrastructure::filter::AllowAllFilter;
pub use infrastructure::local::NoLocalRecords;
pub use infrastructure::observer::DiscardObserver;
pub use infrastructure::response::ResponseWriter;
pub use infrastructure::server::{Server, ServerConfig};
pub use infrastructure::tcp::TcpListener;
pub use infrastructure::udp::UdpListener;
pub use infrastructure::udp_socket::default_socket_count;

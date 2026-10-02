//! Domain layer: ports (traits) and the error enums they return.
//!
//! Depends outward on nothing but `styx-proto`, `styx-core`, and third-party crates. It may
//! not use `crate::application`, `crate::infrastructure`, or any sibling
//! feature crate.
//!
//! A port names no concrete infrastructure and no sibling feature crate. The
//! `FilterPolicy` port lands here, and `styx-filtering` is wired into it by
//! the binary — that indirection is what keeps the two features independent.
//!
//! No synchronous I/O, no `unwrap`, no `expect`, no `panic!`.

pub mod answer;
pub mod cache;
pub mod circuit;
pub mod config;
pub mod edns;
pub mod error;
pub mod health;
pub mod limits;
pub mod ports;
pub mod probe;
pub mod request;
pub mod selection;
pub mod weight;

pub use answer::{AnswerSource, ForgedAnswer, ForgedSource, ResolutionOutcome, ResolvedSource};
pub use cache::{
    Admission, AdmissionOutcome, AdmittedCount, AnswerCache, Bailiwick, CacheCapacity, CacheEntry,
    CacheError, CacheKey, CacheStats, CanonicalName, Deadline, DenialKind, DnssecMetadata,
    HeapBytes, Lookup, MessageFlags, NegativeEntry, PositiveEntry, PurgedCount, RRset,
    RejectReason, RejectedRecord, SecurityStatus, TtlPolicy,
};
pub use circuit::{CircuitConfig, CircuitState, FailureCount};
pub use config::{PoolConfig, Timeouts, UpstreamConfig};
pub use edns::EdnsBufferSize;
pub use error::{ConfigError, ListenerError, PipelineError, PoolError, ServerError};
pub use health::{HealthState, Outcome};
pub use limits::ConcurrencyLimits;
pub use ports::{FilterPolicy, FilterVerdict, LocalRecords, QueryDetail, QueryObserver};
pub use probe::{CanaryConfig, ProbeConfig, ProbePolicy};
pub use request::{ClientId, MaxResponseSize, RequestContext, Transport};
pub use selection::{MemberView, Selection, SelectionStrategy, StrategyName};
pub use weight::Weight;

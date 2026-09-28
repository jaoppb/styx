//! Application layer: orchestration over the ports declared in [`crate::domain`].
//!
//! May use `crate::domain` and `styx-proto`. **May not** use
//! `crate::infrastructure`, and may not name a sibling feature crate.
//!
//! Every fallible operation returns `Result<T, E>` with a crate-owned
//! `thiserror` enum. No synchronous I/O: a database outage must degrade
//! logging and admin, never resolution.

pub mod cache_stage;
pub mod pipeline;
pub mod pool;
pub mod probe_scheduler;
pub mod strategies;
pub mod terminal;

pub use cache_stage::CacheStage;
pub use pipeline::Pipeline;
pub use pool::{PoolMember, UpstreamPool};
pub use probe_scheduler::ProbeScheduler;
pub use strategies::{OrderedFailover, RaceAll, RoundRobin, Weighted};
pub use terminal::{RefusedTerminal, TerminalHandler};

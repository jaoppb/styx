//! Query log observer port.
//!
//! Obligation: Provides metrics, audit logging, and dashboard counters.
//! Implemented by: Query-log pipeline adapter (Phase 10).
//! Hot-path justification: Split into synchronous exact metrics and lossy raw ring.

use std::time::{Duration, SystemTime};

use styx_proto::Question;

use crate::domain::answer::ResolutionOutcome;
use crate::domain::request::ClientId;

/// Detailed trace of an answered query for logging and UI inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryDetail {
    /// Client that originated the query.
    pub client: ClientId,
    /// DNS question being resolved.
    pub question: Question,
    /// Outcome decision reached by the pipeline.
    pub outcome: ResolutionOutcome,
    /// Wall-clock timestamp when query was received.
    pub at: SystemTime,
    /// Elapsed duration spent processing the query.
    pub elapsed: Duration,
}

/// Port for observing query outcomes and ingesting query details.
///
/// Split into two paths:
/// 1. `record_outcome`: Synchronous, infallible atomic metrics update (never dropped).
/// 2. `offer_detail`: Bounded lossy channel for detailed event logs (droppable under load).
pub trait QueryObserver: Send + Sync + 'static {
    /// Records aggregate metrics for a completed query. Infallible and synchronous.
    fn record_outcome(&self, client: &ClientId, question: &Question, outcome: &ResolutionOutcome);

    /// Offers a detailed query log entry to the buffer. May be dropped if full.
    fn offer_detail(&self, detail: QueryDetail);

    /// Returns the total count of detail entries dropped due to full buffers.
    fn dropped_detail(&self) -> u64;

    /// Returns whether detailed query traces are enabled.
    ///
    /// Callers can check this before allocating a [`QueryDetail`].
    fn wants_detail(&self) -> bool {
        true
    }
}

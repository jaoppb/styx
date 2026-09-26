//! Filtering policy port.
//!
//! Obligation: Evaluates client requests against block/allow rules.
//! Implemented by: `styx-filtering` (Phase 8), wired via composition root.
//! Hot-path justification: Evaluated on every query before cache admission.

use styx_proto::Question;

use crate::domain::request::ClientId;

/// Verdict of evaluating a query against filtering policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterVerdict {
    /// Query is permitted to proceed to cache / upstream resolution.
    Allow,
    /// Query is blocked; a synthesized forged response must be returned.
    Block,
}

/// Port for querying client-specific filtering rules.
///
/// Implementations must be synchronous and infallible (`Send + Sync + 'static`).
/// The production implementation holds rules in memory (radix trie / regex set)
/// and never touches disk or network on the hot path.
pub trait FilterPolicy: Send + Sync + 'static {
    /// Evaluates whether the given question from the client is allowed or blocked.
    fn evaluate(&self, client: &ClientId, question: &Question) -> FilterVerdict;
}

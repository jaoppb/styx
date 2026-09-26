//! Local records storage port.
//!
//! Obligation: Provides static custom DNS records (A, AAAA, CNAME, PTR).
//! Implemented by: Storage adapter (Phase 9) backed by Turso DB cached in-memory.
//! Hot-path justification: First pipeline stage; overrides upstream answers.

use styx_proto::{Question, ResourceRecord};

/// Port for querying local custom DNS records.
///
/// In-memory lookup: must never perform synchronous I/O or block the runtime.
/// Any answers returned from this port are treated as Insecure forged answers
/// with AD bit cleared and uncacheable.
pub trait LocalRecords: Send + Sync + 'static {
    /// Returns configured local records matching the question, if any.
    fn lookup(&self, question: &Question) -> Option<Vec<ResourceRecord>>;
}

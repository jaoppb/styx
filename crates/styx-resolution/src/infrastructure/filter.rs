//! No-op implementation of [`FilterPolicy`].

use styx_proto::Question;

use crate::domain::ports::filter::{FilterPolicy, FilterVerdict};
use crate::domain::request::ClientId;

/// No-op filter implementation that permits all queries unconditionally.
#[derive(Debug, Clone, Copy, Default)]
pub struct AllowAllFilter;

impl AllowAllFilter {
    /// Creates a new `AllowAllFilter`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl FilterPolicy for AllowAllFilter {
    fn evaluate(&self, _client: &ClientId, _question: &Question) -> FilterVerdict {
        FilterVerdict::Allow
    }
}

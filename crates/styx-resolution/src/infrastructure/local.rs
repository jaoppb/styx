//! No-op implementation of [`LocalRecords`].

use styx_proto::{Question, ResourceRecord};

use crate::domain::ports::local::LocalRecords;

/// No-op local records implementation that returns `None` unconditionally.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoLocalRecords;

impl NoLocalRecords {
    /// Creates a new `NoLocalRecords`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl LocalRecords for NoLocalRecords {
    fn lookup(&self, _question: &Question) -> Option<Vec<ResourceRecord>> {
        None
    }
}

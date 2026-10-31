//! Whether AAAA questions are resolved or answered NODATA by styx itself.

use styx_proto::{Question, RecordType};

/// How the pipeline treats a question for `AAAA` records.
///
/// Set once from the file's `filter_aaaa` switch. Global: a per-client or per-group
/// version belongs with query-type filtering rules.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum AaaaPolicy {
    /// AAAA questions go through the cache and upstream like any other.
    #[default]
    Resolve,
    /// AAAA questions are answered NOERROR with no records, without asking anyone.
    Filter,
}

impl AaaaPolicy {
    /// Maps the `filter_aaaa` switch onto a policy.
    #[must_use]
    pub const fn from_switch(filter_aaaa: bool) -> Self {
        if filter_aaaa {
            Self::Filter
        } else {
            Self::Resolve
        }
    }

    /// Returns `true` when this policy answers `question` NODATA itself.
    #[must_use]
    pub fn filters(self, question: &Question) -> bool {
        self == Self::Filter && question.qtype == RecordType::AAAA
    }
}

#[cfg(test)]
mod tests {
    use styx_proto::{Name, RecordClass};

    use super::*;

    fn ask(qtype: RecordType) -> Question {
        Question::new(Name::root(), qtype, RecordClass::In)
    }

    #[test]
    fn filter_catches_only_aaaa() {
        assert!(AaaaPolicy::Filter.filters(&ask(RecordType::AAAA)));
        assert!(!AaaaPolicy::Filter.filters(&ask(RecordType::A)));
        assert!(!AaaaPolicy::Filter.filters(&ask(RecordType::ANY)));
    }

    #[test]
    fn resolve_catches_nothing() {
        assert!(!AaaaPolicy::Resolve.filters(&ask(RecordType::AAAA)));
    }
}

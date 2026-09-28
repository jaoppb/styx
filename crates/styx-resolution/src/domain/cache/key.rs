//! Cache key canonicalisation and question indexing.

use std::fmt;

use styx_proto::{Name, Question, RecordClass, RecordType};

use crate::domain::cache::error::CacheError;

/// A domain name stored in canonical form (labels lowercased).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CanonicalName {
    inner: Name,
}

impl CanonicalName {
    /// Canonicalizes a domain name by converting all ASCII characters to lowercase.
    #[must_use]
    pub fn canonicalize(name: &Name) -> Self {
        let lowered_labels: Vec<_> = name
            .labels()
            .iter()
            .map(styx_proto::Label::as_lowercase)
            .collect();
        let inner = Name::new(lowered_labels).unwrap_or_else(|_| Name::root());
        Self { inner }
    }

    /// Returns `true` if `self` is equal to or a subdomain of `other`.
    ///
    /// Root (`.`) is considered a parent of all domain names.
    #[must_use]
    pub fn is_subdomain_of(&self, other: &Self) -> bool {
        if other.inner.is_root() {
            return true;
        }

        let self_labels = self.inner.labels();
        let other_labels = other.inner.labels();

        if self_labels.len() < other_labels.len() {
            return false;
        }

        // Compare labels right-to-left (from TLD up towards leaf)
        self_labels
            .iter()
            .rev()
            .zip(other_labels.iter().rev())
            .all(|(a, b)| a == b)
    }

    /// Returns the number of non-root labels in this domain name.
    #[must_use]
    pub fn label_count(&self) -> usize {
        self.inner.label_count()
    }

    /// Returns a reference to the underlying [`Name`].
    #[must_use]
    pub const fn inner(&self) -> &Name {
        &self.inner
    }

    /// Consumes `self` and returns the underlying [`Name`].
    #[must_use]
    pub fn into_inner(self) -> Name {
        self.inner
    }
}

impl fmt::Debug for CanonicalName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CanonicalName({})", self.inner)
    }
}

impl fmt::Display for CanonicalName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

/// A global cache key indexing answer cache entries.
///
/// Keyed strictly by `(qname, qtype, qclass)` without client or group dimensions.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct CacheKey {
    qname: CanonicalName,
    qtype: RecordType,
    qclass: RecordClass,
}

impl CacheKey {
    /// Creates a `CacheKey` from a client query [`Question`].
    ///
    /// # Errors
    /// Returns [`CacheError::UncacheableQuestion`] if the question asks for a meta-type
    /// (`ANY`, `AXFR`, `IXFR`, or `OPT`).
    pub fn from_question(question: &Question) -> Result<Self, CacheError> {
        if matches!(
            question.qtype,
            RecordType::ANY | RecordType::AXFR | RecordType::IXFR | RecordType::OPT
        ) {
            return Err(CacheError::UncacheableQuestion(question.qtype));
        }

        Ok(Self {
            qname: CanonicalName::canonicalize(&question.qname),
            qtype: question.qtype,
            qclass: question.qclass,
        })
    }

    /// Returns a reference to the canonical query name.
    #[must_use]
    pub const fn qname(&self) -> &CanonicalName {
        &self.qname
    }

    /// Returns the queried record type.
    #[must_use]
    pub const fn qtype(&self) -> RecordType {
        self.qtype
    }

    /// Returns the queried record class.
    #[must_use]
    pub const fn qclass(&self) -> RecordClass {
        self.qclass
    }
}

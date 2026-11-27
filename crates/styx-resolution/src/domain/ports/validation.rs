//! The DNSSEC validation port the cache stage calls on every upstream answer.
//!
//! Validation is a feature of its own (`styx-dnssec`), which this crate may not name: the
//! binary implements this port over it. Forged answers — local records, blocked names, the
//! AAAA filter — leave the pipeline before the cache stage, so they never reach it (ADR 0010).

use std::future::Future;

use styx_proto::{Message, Question};

use crate::domain::cache::dnssec::SecurityStatus;

/// What validating one upstream answer concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Validation {
    /// The security status of the answer: only [`SecurityStatus::Secure`] sets AD.
    pub status: SecurityStatus,
    /// Whether the configured failure mode answers this verdict with SERVFAIL. A client that
    /// set CD gets the answer anyway (RFC 4035 §3.2.2), but it is never cached.
    pub rejected: bool,
}

impl Validation {
    /// The verdict of a resolver that does not validate: nothing is secure, nothing rejected.
    pub const UNVALIDATED: Self = Self {
        status: SecurityStatus::Indeterminate,
        rejected: false,
    };
}

/// Port judging an upstream answer against the DNSSEC chain of trust.
pub trait ResponseValidator: Send + Sync + 'static {
    /// Validates `response`, the upstream answer to `question`.
    ///
    /// Never fails: a chain that cannot be built is a verdict
    /// ([`SecurityStatus::Indeterminate`]), not an error.
    fn validate(
        &self,
        question: &Question,
        response: &Message,
    ) -> impl Future<Output = Validation> + Send;
}

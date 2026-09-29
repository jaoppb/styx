//! Upstream resolution errors and failure classification.

use thiserror::Error;

/// Classification of upstream resolution failures.
///
/// Distinguishes faults attributable to the upstream provider from
/// faults attributable to a specific requested domain name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FailureClass {
    /// Upstream provider is faulty, unreachable, or non-compliant.
    ///
    /// These failures count towards circuit breaker tripping.
    UpstreamFault,
    /// An authoritative answer indicating a domain/name failure.
    ///
    /// These responses do not indicate an upstream failure and must not trip
    /// circuit breakers.
    AnswerFault,
}

/// Errors that can occur when resolving a query against an upstream.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum UpstreamError {
    /// Resolution timed out before the deadline.
    #[error("upstream query timed out")]
    Timeout,

    /// Low-level I/O or transport failure communicating with upstream.
    #[error("upstream transport I/O error: {0}")]
    Transport(std::io::ErrorKind),

    /// Truncated response (TC=1) over UDP and subsequent TCP retry also failed.
    #[error("upstream response was truncated and TCP retry failed")]
    Truncated,

    /// Received response was malformed or failed wire-format decoding.
    #[error("upstream response malformed: {0}")]
    Malformed(String),

    /// Response transaction ID or question section mismatched the query.
    #[error("upstream response ID or question section mismatched query")]
    Mismatched,

    /// Upstream actively refused to answer the query (RCODE=REFUSED).
    #[error("upstream server refused query")]
    Refused,

    /// Upstream returned a Server Failure (RCODE=SERVFAIL).
    #[error("upstream server failure")]
    ServerFailure {
        /// True if attributable to upstream infrastructure, false if name-specific.
        is_upstream: bool,
    },

    /// The resolver or upstream client is shutting down.
    #[error("upstream resolver is shutting down")]
    Shutdown,
}

impl UpstreamError {
    /// Classifies this error into an [`UpstreamFault`] or [`AnswerFault`].
    ///
    /// # Invariant
    /// Only genuine upstream faults trip the circuit breaker.
    #[must_use]
    pub fn classify(&self) -> FailureClass {
        match self {
            Self::Timeout
            | Self::Transport(_)
            | Self::Truncated
            | Self::Malformed(_)
            | Self::Mismatched
            | Self::Refused
            | Self::Shutdown => FailureClass::UpstreamFault,
            Self::ServerFailure { is_upstream } => {
                if *is_upstream {
                    FailureClass::UpstreamFault
                } else {
                    FailureClass::AnswerFault
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_failure_classification_exact() {
        assert_eq!(
            UpstreamError::Timeout.classify(),
            FailureClass::UpstreamFault
        );
        assert_eq!(
            UpstreamError::Transport(std::io::ErrorKind::ConnectionReset).classify(),
            FailureClass::UpstreamFault
        );
        assert_eq!(
            UpstreamError::Truncated.classify(),
            FailureClass::UpstreamFault
        );
        assert_eq!(
            UpstreamError::Malformed("bad packet".into()).classify(),
            FailureClass::UpstreamFault
        );
        assert_eq!(
            UpstreamError::Mismatched.classify(),
            FailureClass::UpstreamFault
        );
        assert_eq!(
            UpstreamError::Refused.classify(),
            FailureClass::UpstreamFault
        );
        assert_eq!(
            UpstreamError::Shutdown.classify(),
            FailureClass::UpstreamFault
        );

        assert_eq!(
            UpstreamError::ServerFailure { is_upstream: true }.classify(),
            FailureClass::UpstreamFault
        );
        assert_eq!(
            UpstreamError::ServerFailure { is_upstream: false }.classify(),
            FailureClass::AnswerFault
        );
    }
}

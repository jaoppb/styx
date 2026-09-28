//! Pipeline error taxonomy.

use styx_proto::{Opcode, RecordClass, ResponseCode};
use thiserror::Error;

/// Errors returned by the request processing pipeline.
///
/// Every variant maps totally to an explicit DNS [`ResponseCode`],
/// ensuring no query is silently dropped on failure.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PipelineError {
    /// The incoming query violates DNS wire specifications (QDCOUNT != 1 or corrupt).
    #[error("malformed query")]
    MalformedQuery,

    /// The query specifies an unsupported DNS opcode.
    #[error("unsupported opcode: {0:?}")]
    UnsupportedOpcode(Opcode),

    /// The query specifies an unsupported record class.
    #[error("unsupported class: {0:?}")]
    UnsupportedClass(RecordClass),

    /// The query contains multiple questions (unsupported by standard resolution).
    #[error("multiple questions in single query")]
    MultipleQuestions,

    /// Internal resolver error.
    #[error("internal server error: {0}")]
    Internal(String),

    /// Upstream pool resolution failure.
    #[error("upstream resolution pool error: {0}")]
    Pool(#[from] crate::domain::error::PoolError),

    /// The query cannot be resolved in the current phase (phase 2 stub terminal).
    #[error("query not resolvable")]
    NotResolvable,
}

impl PipelineError {
    /// Returns the DNS [`ResponseCode`] mapped to this error variant.
    ///
    /// The match is total with no catch-all arm so new variants fail compilation
    /// until their DNS wire status is chosen.
    #[must_use]
    pub fn response_code(&self) -> ResponseCode {
        match self {
            Self::MalformedQuery | Self::MultipleQuestions => ResponseCode::FORMERR,
            Self::UnsupportedOpcode(_) | Self::UnsupportedClass(_) => ResponseCode::NOTIMP,
            Self::Internal(_) | Self::Pool(_) => ResponseCode::SERVFAIL,
            Self::NotResolvable => ResponseCode::REFUSED,
        }
    }
}

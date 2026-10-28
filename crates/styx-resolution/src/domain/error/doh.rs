//! DNS-over-HTTPS request error taxonomy.

use thiserror::Error;

/// Why a DoH request carries no DNS message to answer.
///
/// Each variant becomes an HTTP status with an empty body: never a panic and never a
/// half-formed DNS response. The text names no path, configuration value or address, so
/// it is safe in a client-facing status line.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DohError {
    /// Neither `GET` nor `POST`.
    #[error("method not allowed")]
    MethodNotAllowed,

    /// The request is not for the configured DNS resource.
    #[error("not found")]
    PathNotFound,

    /// A `POST` whose body is not `application/dns-message`.
    #[error("unsupported media type")]
    UnsupportedMediaType,

    /// A `GET` without the `dns` query parameter.
    #[error("missing dns parameter")]
    MissingDnsParameter,

    /// The `dns` parameter is not unpadded base64url.
    #[error("malformed base64url in the dns parameter")]
    MalformedBase64Url,

    /// The message is larger than the configured cap.
    #[error("request body too large")]
    BodyTooLarge,

    /// A `POST` with no body.
    #[error("empty request body")]
    EmptyBody,

    /// A message the resolver does not answer at all, such as a response (QR=1).
    #[error("message not answered")]
    Unanswerable,

    /// The connection's query ceiling is spent.
    #[error("connection query budget exceeded")]
    StreamBudgetExceeded,
}

impl DohError {
    /// The HTTP status this error is answered with. A total match: a new variant does not
    /// compile until its status is chosen.
    #[must_use]
    pub const fn status(&self) -> u16 {
        match self {
            Self::MethodNotAllowed => 405,
            Self::PathNotFound => 404,
            Self::UnsupportedMediaType => 415,
            Self::MissingDnsParameter
            | Self::MalformedBase64Url
            | Self::EmptyBody
            | Self::Unanswerable => 400,
            Self::BodyTooLarge => 413,
            Self::StreamBudgetExceeded => 503,
        }
    }
}

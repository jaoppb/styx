//! DNS-over-HTTPS request error taxonomy.

use thiserror::Error;

/// Why a DoH request carries no DNS message to answer.
///
/// Each variant becomes an HTTP status with an empty body, chosen where the HTTP response
/// is built: never a panic and never a half-formed DNS response. The text names no path, configuration value or address, so
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

    /// Reading the request body took longer than the stream deadline.
    #[error("request body read timed out")]
    BodyReadTimeout,

    /// A `POST` with no body.
    #[error("empty request body")]
    EmptyBody,

    /// A `POST` body that ended before it was complete: the client reset the stream, or
    /// sent fewer octets than it declared.
    #[error("malformed request body")]
    MalformedBody,

    /// A message the resolver does not answer at all, such as a response (QR=1).
    #[error("message not answered")]
    Unanswerable,

    /// The server failed to serialize the DNS response.
    #[error("failed to encode DNS response")]
    EncodeFailed,

    /// The connection's query ceiling is spent.
    #[error("connection query budget exceeded")]
    StreamBudgetExceeded,

    /// The server is shutting down and no longer admitting queries.
    #[error("server shutting down")]
    ShuttingDown,
}

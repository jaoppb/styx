//! TLS server setup error taxonomy.

use thiserror::Error;

/// Errors building the TLS server configuration from a serving identity.
///
/// Raised once at startup and fatal there, before the resolver begins serving. A TLS
/// failure on one connection is never one of these: it is logged and drops that
/// connection only.
#[derive(Debug, Error)]
pub enum TlsError {
    /// The TLS library refused the certificate chain or the key.
    #[error("the TLS library rejected the serving certificate or key: {0}")]
    ConfigurationRejected(String),
}

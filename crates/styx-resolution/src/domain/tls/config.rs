//! The file-owned description of encrypted inbound: where DoT and DoH listen, which
//! certificate they serve, and the bounds on each connection.
//!
//! Everything here lives in the TOML file and nowhere else. Rotating a certificate is an
//! edit and a restart, the same cost already accepted for upstreams.

use std::net::SocketAddr;
use std::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::domain::error::ConfigError;

/// The cap on one DNS message carried over a stream transport.
///
/// The two-octet length prefix cannot describe more than 65535 octets, so that is the
/// ceiling every configured cap must stay under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamMessageLimit {
    octets: u16,
}

impl StreamMessageLimit {
    /// The largest message a two-octet length prefix can describe.
    #[must_use]
    pub const fn protocol_max() -> Self {
        Self { octets: u16::MAX }
    }

    /// Validates a configured cap.
    ///
    /// # Errors
    /// Returns [`ConfigError::Invalid`] for zero or anything above 65535.
    pub fn from_configured(raw: usize) -> Result<Self, ConfigError> {
        match u16::try_from(raw) {
            Ok(octets) if octets > 0 => Ok(Self { octets }),
            _ => Err(ConfigError::Invalid(format!(
                "[tls]: max_request_body_bytes must be between 1 and 65535, got {raw}"
            ))),
        }
    }

    /// The cap in octets.
    #[must_use]
    pub const fn octets(self) -> u16 {
        self.octets
    }

    /// Returns `true` when `len` octets fit under the cap.
    #[must_use]
    pub fn admits(self, len: u64) -> bool {
        len <= u64::from(self.octets)
    }
}

/// The one HTTP resource the DoH endpoint answers on, such as `/dns-query`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DohResourcePath {
    path: String,
}

impl DohResourcePath {
    /// The path RFC 8484 uses in its examples.
    pub const DEFAULT: &'static str = "/dns-query";

    /// Validates a configured path: absolute, and with no query, fragment or whitespace.
    ///
    /// # Errors
    /// Returns [`ConfigError::Invalid`] for any other shape.
    pub fn new(raw: String) -> Result<Self, ConfigError> {
        let well_formed = raw.starts_with('/')
            && !raw
                .chars()
                .any(|c| c == '?' || c == '#' || c.is_whitespace() || c.is_control());
        if !well_formed {
            return Err(ConfigError::Invalid(format!(
                "[tls]: doh_path must be an absolute HTTP path such as {}, got {raw:?}",
                Self::DEFAULT
            )));
        }
        Ok(Self { path: raw })
    }

    /// Returns `true` when a request path names this resource.
    #[must_use]
    pub fn matches(&self, candidate: &str) -> bool {
        self.path == candidate
    }

    /// The path as configured.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.path
    }
}

/// Where the serving certificate comes from.
///
/// There are exactly two variants and deliberately no third. styx owns no PKI and
/// implements no ACME client: an ACME client would need inbound reachability or DNS-01
/// control, persistent renewal state and a scheduler — an unbounded, security-critical
/// surface added to a v1 that already carries two hand-written security-critical
/// subsystems (the recursor and the DNSSEC validator), to solve a problem every operator
/// already solves elsewhere. Bring a certificate from whatever pipeline you already have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateSource {
    /// The operator named a certificate chain and its private key.
    OperatorSupplied {
        /// PEM file holding the leaf certificate first, then any intermediates.
        cert_path: PathBuf,
        /// PEM file holding the private key.
        key_path: PathBuf,
    },
    /// No certificate was configured: a self-signed one is generated once into `dir`
    /// and reused on every later boot.
    SelfSigned {
        /// Directory the generated certificate and key are persisted in.
        dir: PathBuf,
        /// Subject alternative names minted into the certificate.
        names: Vec<String>,
    },
}

/// Bounds on the stateful encrypted transports, one value per exhaustion path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncryptedLimits {
    /// How long a client may take to complete the TLS handshake.
    pub handshake_timeout: Duration,
    /// How long a connection may sit with no query outstanding.
    pub idle_timeout: Duration,
    /// Open connections per listener; each listener has its own ceiling.
    pub max_connections: NonZeroUsize,
    /// Concurrent HTTP/2 streams per DoH connection.
    pub max_streams_per_connection: NonZeroU32,
    /// Queries one connection may carry before it is closed.
    pub max_queries_per_connection: NonZeroU64,
    /// Cap on a DoH request's DNS message.
    pub max_request_body: StreamMessageLimit,
}

impl EncryptedLimits {
    /// Default handshake deadline.
    pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
    /// Default idle deadline.
    pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
    /// Default connection ceiling per listener.
    pub const DEFAULT_MAX_CONNECTIONS: NonZeroUsize = NonZeroUsize::MIN.saturating_add(127);
    /// Default HTTP/2 stream ceiling, the floor RFC 9113 §6.5.2 recommends.
    pub const DEFAULT_MAX_STREAMS: NonZeroU32 = NonZeroU32::MIN.saturating_add(99);
    /// Default per-connection query ceiling.
    pub const DEFAULT_MAX_QUERIES: NonZeroU64 = NonZeroU64::MIN.saturating_add(9_999);
}

impl Default for EncryptedLimits {
    fn default() -> Self {
        Self {
            handshake_timeout: Self::DEFAULT_HANDSHAKE_TIMEOUT,
            idle_timeout: Self::DEFAULT_IDLE_TIMEOUT,
            max_connections: Self::DEFAULT_MAX_CONNECTIONS,
            max_streams_per_connection: Self::DEFAULT_MAX_STREAMS,
            max_queries_per_connection: Self::DEFAULT_MAX_QUERIES,
            max_request_body: StreamMessageLimit::protocol_max(),
        }
    }
}

/// The `[tls]` section once validated: off, or on with at least one listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsConfig {
    dot_listen_addrs: Vec<SocketAddr>,
    doh_listen_addrs: Vec<SocketAddr>,
    source: CertificateSource,
    self_signed_dir: PathBuf,
    doh_path: DohResourcePath,
    allow_http1: bool,
    limits: EncryptedLimits,
}

/// The validated parts a [`TlsConfig`] is assembled from.
#[derive(Debug, Clone)]
pub struct TlsConfigParts {
    /// DoT listen addresses; empty disables DoT.
    pub dot_listen_addrs: Vec<SocketAddr>,
    /// DoH listen addresses; empty disables DoH.
    pub doh_listen_addrs: Vec<SocketAddr>,
    /// Operator certificate path, if any.
    pub cert_path: Option<PathBuf>,
    /// Operator key path, if any.
    pub key_path: Option<PathBuf>,
    /// Where self-signed material lives.
    pub self_signed_dir: PathBuf,
    /// Names minted into a self-signed certificate.
    pub self_signed_names: Vec<String>,
    /// The DoH resource.
    pub doh_path: DohResourcePath,
    /// Whether DoH also offers HTTP/1.1.
    pub allow_http1: bool,
    /// Connection bounds.
    pub limits: EncryptedLimits,
}

impl TlsConfig {
    /// Assembles an enabled configuration.
    ///
    /// # Errors
    /// Returns [`ConfigError::Invalid`] when only one of the certificate and key paths is
    /// set, when neither DoT nor DoH has an address, when a self-signed certificate would
    /// carry no name, or when a timeout is zero.
    pub fn new(parts: TlsConfigParts) -> Result<Self, ConfigError> {
        if parts.dot_listen_addrs.is_empty() && parts.doh_listen_addrs.is_empty() {
            return Err(invalid(
                "enabled with neither dot_listen_addrs nor doh_listen_addrs",
            ));
        }
        if parts.limits.handshake_timeout.is_zero() || parts.limits.idle_timeout.is_zero() {
            return Err(invalid(
                "handshake_timeout_secs and idle_timeout_secs must be non-zero",
            ));
        }
        let source = match (parts.cert_path, parts.key_path) {
            (Some(cert_path), Some(key_path)) => CertificateSource::OperatorSupplied {
                cert_path,
                key_path,
            },
            (None, None) if parts.self_signed_names.is_empty() => {
                return Err(invalid("self_signed_names must name at least one host"));
            }
            (None, None) => CertificateSource::SelfSigned {
                dir: parts.self_signed_dir.clone(),
                names: parts.self_signed_names,
            },
            _ => return Err(invalid("cert_path and key_path must be set together")),
        };
        Ok(Self {
            dot_listen_addrs: parts.dot_listen_addrs,
            doh_listen_addrs: parts.doh_listen_addrs,
            source,
            self_signed_dir: parts.self_signed_dir,
            doh_path: parts.doh_path,
            allow_http1: parts.allow_http1,
            limits: parts.limits,
        })
    }

    /// DoT listen addresses.
    #[must_use]
    pub fn dot_listen_addrs(&self) -> &[SocketAddr] {
        &self.dot_listen_addrs
    }

    /// DoH listen addresses.
    #[must_use]
    pub fn doh_listen_addrs(&self) -> &[SocketAddr] {
        &self.doh_listen_addrs
    }

    /// Where the serving certificate comes from.
    #[must_use]
    pub fn certificate_source(&self) -> &CertificateSource {
        &self.source
    }

    /// The directory self-signed material lives in. Read even when an operator
    /// certificate is configured, to warn about material left there from an earlier boot.
    #[must_use]
    pub fn self_signed_dir(&self) -> &Path {
        &self.self_signed_dir
    }

    /// The DoH resource path.
    #[must_use]
    pub fn doh_path(&self) -> &DohResourcePath {
        &self.doh_path
    }

    /// Whether DoH also offers HTTP/1.1.
    #[must_use]
    pub fn allow_http1(&self) -> bool {
        self.allow_http1
    }

    /// Connection bounds.
    #[must_use]
    pub fn limits(&self) -> EncryptedLimits {
        self.limits
    }
}

fn invalid(reason: &str) -> ConfigError {
    ConfigError::Invalid(format!("[tls]: {reason}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts() -> TlsConfigParts {
        TlsConfigParts {
            dot_listen_addrs: vec![SocketAddr::from(([127, 0, 0, 1], 853))],
            doh_listen_addrs: Vec::new(),
            cert_path: None,
            key_path: None,
            self_signed_dir: PathBuf::from("tls"),
            self_signed_names: vec!["localhost".into()],
            doh_path: DohResourcePath::new(DohResourcePath::DEFAULT.into()).unwrap(),
            allow_http1: false,
            limits: EncryptedLimits::default(),
        }
    }

    #[test]
    fn stream_limit_rejects_zero_and_values_past_the_prefix() {
        assert!(StreamMessageLimit::from_configured(0).is_err());
        assert!(StreamMessageLimit::from_configured(65_536).is_err());
        assert_eq!(
            StreamMessageLimit::from_configured(65_535).unwrap(),
            StreamMessageLimit::protocol_max()
        );
        let cap = StreamMessageLimit::from_configured(512).unwrap();
        assert!(cap.admits(512));
        assert!(!cap.admits(513));
    }

    #[test]
    fn doh_path_must_be_absolute_with_no_query_or_whitespace() {
        for bad in ["dns-query", "/dns-query?dns=x", "/a b", "/a#b", ""] {
            assert!(DohResourcePath::new(bad.into()).is_err(), "{bad:?}");
        }
        let path = DohResourcePath::new("/dns-query".into()).unwrap();
        assert!(path.matches("/dns-query"));
        assert!(!path.matches("/dns-query/"));
    }

    #[test]
    fn absence_of_both_paths_means_self_signed() {
        let config = TlsConfig::new(parts()).unwrap();
        assert!(matches!(
            config.certificate_source(),
            CertificateSource::SelfSigned { .. }
        ));
    }

    #[test]
    fn both_paths_mean_operator_supplied() {
        let mut parts = parts();
        parts.cert_path = Some("cert.pem".into());
        parts.key_path = Some("key.pem".into());
        let config = TlsConfig::new(parts).unwrap();
        assert!(matches!(
            config.certificate_source(),
            CertificateSource::OperatorSupplied { .. }
        ));
        assert_eq!(config.self_signed_dir(), Path::new("tls"));
    }

    #[test]
    fn one_path_without_the_other_is_refused() {
        let mut cert_only = parts();
        cert_only.cert_path = Some("cert.pem".into());
        assert!(TlsConfig::new(cert_only).is_err());

        let mut key_only = parts();
        key_only.key_path = Some("key.pem".into());
        assert!(TlsConfig::new(key_only).is_err());
    }

    #[test]
    fn enabled_with_no_listener_or_a_zero_timeout_is_refused() {
        let mut no_listener = parts();
        no_listener.dot_listen_addrs.clear();
        assert!(TlsConfig::new(no_listener).is_err());

        let mut zero = parts();
        zero.limits.idle_timeout = Duration::ZERO;
        assert!(TlsConfig::new(zero).is_err());
    }
}

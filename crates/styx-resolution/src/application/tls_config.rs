//! The `[tls]` section of the TOML file.
//!
//! Encrypted inbound is off unless `enabled = true`: the self-signed path mints a key pair
//! on first boot, and an install that never asked for DoT or DoH should not get one.
//! Parsing never opens a certificate file; the binary loads them once, at startup.

use std::net::SocketAddr;
use std::num::{NonZeroU64, NonZeroUsize};
use std::path::PathBuf;

use serde::Deserialize;

use crate::domain::error::ConfigError;
use crate::domain::tls::{
    BoundedTimeout, CertificateSource, DohResourcePath, EncryptedLimits, StreamConcurrencyLimit,
    StreamMessageLimit, TlsConfig, TlsConfigParts,
};

/// Where generated self-signed material is kept when `self_signed_dir` is unset.
pub const DEFAULT_SELF_SIGNED_DIR: &str = "/var/lib/styx/tls";

/// The name minted into a self-signed certificate when `self_signed_names` is unset.
pub const DEFAULT_SELF_SIGNED_NAME: &str = "localhost";

fn default_dot_listen_addrs() -> Vec<SocketAddr> {
    vec![SocketAddr::from(([127, 0, 0, 1], 853))]
}

fn default_doh_listen_addrs() -> Vec<SocketAddr> {
    vec![SocketAddr::from(([127, 0, 0, 1], 443))]
}

#[derive(Debug, Deserialize)]
struct RawFile {
    tls: Option<RawTls>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTls {
    enabled: Option<bool>,
    dot_listen_addrs: Option<Vec<SocketAddr>>,
    doh_listen_addrs: Option<Vec<SocketAddr>>,
    cert_path: Option<PathBuf>,
    key_path: Option<PathBuf>,
    self_signed_dir: Option<PathBuf>,
    self_signed_names: Option<Vec<String>>,
    doh_path: Option<String>,
    allow_http1: Option<bool>,
    handshake_timeout_secs: Option<u64>,
    idle_timeout_secs: Option<u64>,
    max_connections: Option<NonZeroUsize>,
    max_streams_per_connection: Option<u32>,
    max_queries_per_connection: Option<NonZeroU64>,
    max_request_body_bytes: Option<usize>,
}

impl TlsConfig {
    /// Reads the `[tls]` section of a whole styx TOML file.
    ///
    /// Returns `Ok(None)` when the section is absent or `enabled` is not `true`.
    ///
    /// # Errors
    /// Returns [`ConfigError::Toml`] for malformed TOML or an unknown key, and
    /// [`ConfigError::Invalid`] for a value [`TlsConfig::new`] or one of its newtypes refuses.
    pub fn from_toml_str(content: &str) -> Result<Option<Self>, ConfigError> {
        let file: RawFile = toml::from_str(content)?;
        let Some(raw) = file.tls else {
            return Ok(None);
        };
        if raw.enabled != Some(true) {
            return Ok(None);
        }
        Self::new(parts_from(raw)?).map(Some)
    }
}

fn parts_from(raw: RawTls) -> Result<TlsConfigParts, ConfigError> {
    let doh_path = DohResourcePath::new(
        raw.doh_path
            .unwrap_or_else(|| DohResourcePath::DEFAULT.to_owned()),
    )?;
    let defaults = EncryptedLimits::default();
    let max_request_body = match raw.max_request_body_bytes {
        Some(octets) => StreamMessageLimit::from_configured(octets)?,
        None => defaults.max_request_body,
    };
    let limits = EncryptedLimits {
        handshake_timeout: match raw.handshake_timeout_secs {
            Some(seconds) => BoundedTimeout::from_secs(seconds)?,
            None => defaults.handshake_timeout,
        },
        idle_timeout: match raw.idle_timeout_secs {
            Some(seconds) => BoundedTimeout::from_secs(seconds)?,
            None => defaults.idle_timeout,
        },
        max_connections: raw.max_connections.unwrap_or(defaults.max_connections),
        max_streams_per_connection: match raw.max_streams_per_connection {
            Some(streams) => StreamConcurrencyLimit::from_configured(streams)?,
            None => defaults.max_streams_per_connection,
        },
        max_queries_per_connection: raw
            .max_queries_per_connection
            .unwrap_or(defaults.max_queries_per_connection),
        max_request_body,
    };
    Ok(TlsConfigParts {
        dot_listen_addrs: raw
            .dot_listen_addrs
            .unwrap_or_else(default_dot_listen_addrs),
        doh_listen_addrs: raw
            .doh_listen_addrs
            .unwrap_or_else(default_doh_listen_addrs),
        source: certificate_source(raw.cert_path, raw.key_path, raw.self_signed_names)?,
        self_signed_dir: raw
            .self_signed_dir
            .unwrap_or_else(|| PathBuf::from(DEFAULT_SELF_SIGNED_DIR)),
        doh_path,
        allow_http1: raw.allow_http1.unwrap_or(false),
        limits,
    })
}

/// Both operator paths select the operator pair; neither selects self-signed material.
fn certificate_source(
    cert_path: Option<PathBuf>,
    key_path: Option<PathBuf>,
    self_signed_names: Option<Vec<String>>,
) -> Result<CertificateSource, ConfigError> {
    match (cert_path, key_path) {
        (Some(cert_path), Some(key_path)) => Ok(CertificateSource::OperatorSupplied {
            cert_path,
            key_path,
        }),
        (None, None) => Ok(CertificateSource::SelfSigned {
            names: self_signed_names.unwrap_or_else(|| vec![DEFAULT_SELF_SIGNED_NAME.to_owned()]),
        }),
        _ => Err(ConfigError::Invalid(
            "[tls]: cert_path and key_path must be set together".to_owned(),
        )),
    }
}

#[cfg(test)]
mod schema_keys;

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::domain::tls::CertificateSource;

    #[test]
    fn absent_or_disabled_section_means_no_encrypted_inbound() {
        assert_eq!(TlsConfig::from_toml_str("listen_addrs = []").unwrap(), None);
        assert_eq!(
            TlsConfig::from_toml_str("[tls]\ncert_path = \"c\"\nkey_path = \"k\"").unwrap(),
            None
        );
        assert_eq!(
            TlsConfig::from_toml_str("[tls]\nenabled = false").unwrap(),
            None
        );
    }

    #[test]
    fn enabled_alone_gets_the_documented_defaults() {
        let config = TlsConfig::from_toml_str("[tls]\nenabled = true")
            .unwrap()
            .unwrap();
        assert_eq!(config.dot_listen_addrs(), default_dot_listen_addrs());
        assert_eq!(config.doh_listen_addrs(), default_doh_listen_addrs());
        assert_eq!(config.doh_path().as_str(), "/dns-query");
        assert!(!config.allow_http1());
        assert_eq!(config.limits(), EncryptedLimits::default());
        assert_eq!(
            config.certificate_source(),
            &CertificateSource::SelfSigned {
                names: vec![DEFAULT_SELF_SIGNED_NAME.to_owned()],
            }
        );
        assert_eq!(
            config.self_signed_dir(),
            PathBuf::from(DEFAULT_SELF_SIGNED_DIR)
        );
    }

    #[test]
    fn keys_override_the_defaults() {
        let config = TlsConfig::from_toml_str(
            "[tls]\nenabled = true\ndoh_listen_addrs = []\nidle_timeout_secs = 7\n\
             max_request_body_bytes = 4096\ncert_path = \"c.pem\"\nkey_path = \"k.pem\"",
        )
        .unwrap()
        .unwrap();
        assert!(config.doh_listen_addrs().is_empty());
        assert_eq!(
            config.limits().idle_timeout.as_duration(),
            Duration::from_secs(7)
        );
        assert_eq!(config.limits().max_request_body.octets(), 4096);
        assert!(matches!(
            config.certificate_source(),
            CertificateSource::OperatorSupplied { .. }
        ));
    }

    #[test]
    fn invalid_values_and_unknown_keys_are_refused() {
        for content in [
            "[tls]\nenabled = true\ncert_path = \"c.pem\"",
            "[tls]\nenabled = true\nkey_path = \"k.pem\"",
            "[tls]\nenabled = true\ndoh_path = \"dns-query\"",
            "[tls]\nenabled = true\nmax_request_body_bytes = 70000",
            "[tls]\nenabled = true\nmax_connections = 0",
            "[tls]\nenabled = true\nmax_queries_per_connection = 0",
            "[tls]\nenabled = true\nself_signed_names = []",
            "[tls]\nenabled = true\nmax_streams_per_connection = 0",
            "[tls]\nenabled = true\nhandshake_timeout_secs = 0",
            "[tls]\nenabled = true\nhandshake_timeout_secs = 3601",
            "[tls]\nenabled = true\nidle_timeout_secs = 3601",
            "[tls]\nenabled = true\ndot_listen_addrs = []\ndoh_listen_addrs = []",
            "[tls]\nenabled = true\ncert_pth = \"c.pem\"",
        ] {
            assert!(TlsConfig::from_toml_str(content).is_err(), "{content}");
        }
    }
}

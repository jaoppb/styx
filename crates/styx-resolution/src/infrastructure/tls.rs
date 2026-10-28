//! The TLS server configurations the DoT and DoH listeners serve, built once from the one
//! serving identity.
//!
//! This uses rustls, an established pure-Rust TLS implementation, on purpose. styx's
//! from-scratch commitment covers the DNS stack — wire codec, server loop, caches,
//! recursion, DNSSEC validation — and says nothing about TLS; the project already relies on
//! established cryptography elsewhere. Writing a TLS stack would add a third hand-written
//! security-critical subsystem to a v1 whose scope is already its largest risk. Do not read
//! the from-scratch rule as forbidding a TLS library.
//!
//! The two configurations differ only in ALPN. DoT offers `dot`; DoH offers `h2`, plus
//! `http/1.1` only when the operator opts in. Neither ever offers `h3`: DNS over QUIC is a
//! v1 non-goal, and half-advertising it would suggest otherwise. rustls refuses a client
//! whose ALPN list shares nothing with the server's, so a mismatch fails the handshake
//! cleanly instead of hanging. No client certificate is requested: there is no per-user
//! identity to bind a session to.

use std::sync::Arc;

use rustls::crypto::ring::default_provider;
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};
use rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

use crate::domain::error::TlsError;
use crate::domain::tls::{PrivateKeyEncoding, ServingIdentity};

/// ALPN identifier for DNS over TLS (RFC 7858 §3.2, IANA ALPN registry).
pub const ALPN_DOT: &[u8] = b"dot";
/// ALPN identifier for HTTP/2.
pub const ALPN_H2: &[u8] = b"h2";
/// ALPN identifier for HTTP/1.1.
pub const ALPN_HTTP1: &[u8] = b"http/1.1";

/// One acceptor per encrypted listener role, sharing a certificate.
#[derive(Clone)]
pub struct TlsServerSetup {
    dot: TlsAcceptor,
    doh: TlsAcceptor,
}

impl TlsServerSetup {
    /// Builds both configurations from `identity`.
    ///
    /// # Errors
    /// Returns [`TlsError::ConfigurationRejected`] when rustls refuses the chain or key.
    pub fn build(identity: &ServingIdentity, allow_http1: bool) -> Result<Self, TlsError> {
        let mut doh_alpn = vec![ALPN_H2.to_vec()];
        if allow_http1 {
            doh_alpn.push(ALPN_HTTP1.to_vec());
        }
        Ok(Self {
            dot: acceptor(identity, vec![ALPN_DOT.to_vec()])?,
            doh: acceptor(identity, doh_alpn)?,
        })
    }

    /// The acceptor for DNS over TLS.
    #[must_use]
    pub fn dot(&self) -> TlsAcceptor {
        self.dot.clone()
    }

    /// The acceptor for DNS over HTTPS.
    #[must_use]
    pub fn doh(&self) -> TlsAcceptor {
        self.doh.clone()
    }
}

fn acceptor(identity: &ServingIdentity, alpn: Vec<Vec<u8>>) -> Result<TlsAcceptor, TlsError> {
    let rejected = |error: rustls::Error| TlsError::ConfigurationRejected(error.to_string());
    let chain = identity
        .chain()
        .iter()
        .map(|der| CertificateDer::from(der.clone()))
        .collect();
    let mut config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(rejected)?
        .with_no_client_auth()
        .with_single_cert(chain, private_key(identity))
        .map_err(rejected)?;
    config.alpn_protocols = alpn;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn private_key(identity: &ServingIdentity) -> PrivateKeyDer<'static> {
    let der = identity.key().der().to_vec();
    match identity.key().encoding() {
        PrivateKeyEncoding::Pkcs1 => PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(der)),
        PrivateKeyEncoding::Sec1 => PrivateKeyDer::Sec1(PrivateSec1KeyDer::from(der)),
        PrivateKeyEncoding::Pkcs8 => PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der)),
    }
}

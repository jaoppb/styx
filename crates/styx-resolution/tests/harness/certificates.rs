//! Certificate fixtures minted against a chosen time, and a scratch directory for them.
//!
//! A fixture pinned to a real date expires on a day nobody chose and turns the suite red
//! for reasons unrelated to any change, so every window here comes from the caller.

#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rcgen::{CertificateParams, KeyPair, PublicKeyData};

/// A fixed instant tests treat as "now".
pub fn fixture_now() -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(1_800_000_000))
        .unwrap()
}

/// A PEM certificate and key.
#[derive(Debug, Clone)]
pub struct TestCertificate {
    pub cert_pem: String,
    pub key_pem: String,
}

impl TestCertificate {
    /// A self-signed leaf for `names`, valid from `not_before` to `not_after`.
    pub fn mint(names: &[&str], not_before: SystemTime, not_after: SystemTime) -> Self {
        let mut params =
            CertificateParams::new(names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>())
                .unwrap();
        params.not_before = not_before.into();
        params.not_after = not_after.into();
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        Self {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
        }
    }

    /// A leaf for `localhost` and `127.0.0.1`, valid a day either side of [`fixture_now`].
    pub fn valid() -> Self {
        let day = Duration::from_secs(86_400);
        Self::mint(
            &["localhost", "127.0.0.1"],
            fixture_now().checked_sub(day).unwrap(),
            fixture_now().checked_add(day).unwrap(),
        )
    }

    /// The pin computed from the key alone, independently of the certificate parser.
    pub fn independent_pin(&self) -> String {
        pin_of_key(&self.key_pem)
    }

    /// The DER of the leaf certificate.
    pub fn cert_der(&self) -> Vec<u8> {
        rustls::pki_types::pem::PemObject::from_pem_slice(self.cert_pem.as_bytes())
            .map(|der: rustls::pki_types::CertificateDer<'static>| der.to_vec())
            .unwrap()
    }
}

/// `pin-sha256="…"` of the public half of a PEM private key.
pub fn pin_of_key(key_pem: &str) -> String {
    let key = KeyPair::from_pem(key_pem).unwrap();
    let digest = ring::digest::digest(&ring::digest::SHA256, &key.subject_public_key_info());
    format!("pin-sha256=\"{}\"", STANDARD.encode(digest.as_ref()))
}

/// A fresh directory under cargo's per-target scratch area, left for `cargo clean`.
pub struct Scratch(PathBuf);

impl Scratch {
    pub fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "styx-tls-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        Self(dir)
    }

    pub fn dir(&self) -> &Path {
        &self.0
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    /// Writes `fullchain.pem` and `privkey.pem`, returning both paths.
    pub async fn write_pair(&self, cert_pem: &str, key_pem: &str) -> (PathBuf, PathBuf) {
        tokio::fs::create_dir_all(&self.0).await.unwrap();
        let cert = self.path("fullchain.pem");
        let key = self.path("privkey.pem");
        tokio::fs::write(&cert, cert_pem).await.unwrap();
        tokio::fs::write(&key, key_pem).await.unwrap();
        (cert, key)
    }
}

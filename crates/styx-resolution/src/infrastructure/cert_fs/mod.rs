//! Certificate files on disk: the operator's PEM pair, and styx's own self-signed pair.
//!
//! Startup-only I/O. Everything here runs once, before any listener binds, and never on a
//! request path.

mod self_signed;

use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, SystemTime};

use rustls::crypto::ring::default_provider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::CertifiedKey;
use rustls::{Error as TlsLibraryError, InconsistentKeys};
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;
use x509_parser::time::ASN1Time;

use crate::domain::error::CertificateError;
use crate::domain::tls::{
    CertificateOrigin, OperatorCertificateLoader, PrivateKeyEncoding, PrivateKeyMaterial,
    ServingIdentity, ServingIdentityParts, SpkiPin, ValidityWindow,
};

pub use self_signed::{SelfSignedGenerator, SELF_SIGNED_CERT_FILE, SELF_SIGNED_KEY_FILE};

/// Reads an operator-supplied certificate chain and key from PEM files.
#[derive(Debug, Default, Clone, Copy)]
pub struct FilesystemCertificateReader;

impl FilesystemCertificateReader {
    /// Creates a reader.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl OperatorCertificateLoader for FilesystemCertificateReader {
    async fn load(
        &self,
        cert_path: &Path,
        key_path: &Path,
    ) -> Result<ServingIdentity, CertificateError> {
        let pair = PemPair {
            cert_path,
            cert_pem: read_file(cert_path).await?,
            key_path,
            key_pem: read_file(key_path).await?,
        };
        pair.identity(CertificateOrigin::OperatorSupplied, false)
    }
}

/// A certificate file and its key file, both read into memory.
struct PemPair<'a> {
    cert_path: &'a Path,
    cert_pem: Vec<u8>,
    key_path: &'a Path,
    key_pem: Vec<u8>,
}

impl PemPair<'_> {
    /// Parses both files, checks the key against the leaf, and assembles the identity.
    fn identity(
        &self,
        origin: CertificateOrigin,
        freshly_generated: bool,
    ) -> Result<ServingIdentity, CertificateError> {
        let chain = self.chain()?;
        let key = self.key()?;
        let material = key_material(&key, self.key_path)?;
        self.check_key_matches(&chain, key)?;
        let leaf = chain
            .first()
            .ok_or_else(|| CertificateError::NoCertificateInFile {
                path: self.cert_path.to_path_buf(),
            })?;
        let facts = leaf_facts(self.cert_path, leaf)?;
        ServingIdentity::new(ServingIdentityParts {
            chain: chain.iter().map(|cert| cert.to_vec()).collect(),
            key: material,
            pin: facts.pin,
            validity: facts.validity,
            subject_names: facts.names,
            origin,
            freshly_generated,
        })
    }

    fn chain(&self) -> Result<Vec<CertificateDer<'static>>, CertificateError> {
        let chain = CertificateDer::pem_slice_iter(&self.cert_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| CertificateError::MalformedCertificate {
                path: self.cert_path.to_path_buf(),
                reason: error.to_string(),
            })?;
        if chain.is_empty() {
            return Err(CertificateError::NoCertificateInFile {
                path: self.cert_path.to_path_buf(),
            });
        }
        Ok(chain)
    }

    fn key(&self) -> Result<PrivateKeyDer<'static>, CertificateError> {
        PrivateKeyDer::from_pem_slice(&self.key_pem).map_err(|error| {
            CertificateError::MalformedKey {
                path: self.key_path.to_path_buf(),
                reason: error.to_string(),
            }
        })
    }

    /// Refuses a key that is not the leaf's, so a mismatch is one startup message rather
    /// than a handshake failure on every connection.
    fn check_key_matches(
        &self,
        chain: &[CertificateDer<'static>],
        key: PrivateKeyDer<'static>,
    ) -> Result<(), CertificateError> {
        match CertifiedKey::from_der(chain.to_vec(), key, &default_provider()) {
            Ok(_) => Ok(()),
            Err(TlsLibraryError::InconsistentKeys(InconsistentKeys::KeyMismatch)) => {
                Err(CertificateError::KeyMismatch {
                    cert_path: self.cert_path.to_path_buf(),
                    key_path: self.key_path.to_path_buf(),
                })
            }
            Err(error) => Err(CertificateError::MalformedKey {
                path: self.key_path.to_path_buf(),
                reason: error.to_string(),
            }),
        }
    }
}

async fn read_file(path: &Path) -> Result<Vec<u8>, CertificateError> {
    tokio::fs::read(path)
        .await
        .map_err(|error| CertificateError::PathUnreadable {
            path: path.to_path_buf(),
            reason: error.to_string(),
        })
}

fn key_material(
    key: &PrivateKeyDer<'_>,
    key_path: &Path,
) -> Result<PrivateKeyMaterial, CertificateError> {
    let encoding = match key {
        PrivateKeyDer::Pkcs1(_) => PrivateKeyEncoding::Pkcs1,
        PrivateKeyDer::Sec1(_) => PrivateKeyEncoding::Sec1,
        PrivateKeyDer::Pkcs8(_) => PrivateKeyEncoding::Pkcs8,
        _ => {
            return Err(CertificateError::MalformedKey {
                path: key_path.to_path_buf(),
                reason: "unsupported private key encoding".into(),
            })
        }
    };
    Ok(PrivateKeyMaterial::new(encoding, key.secret_der().to_vec()))
}

/// What the serving identity needs from the leaf certificate.
struct LeafFacts {
    pin: SpkiPin,
    validity: ValidityWindow,
    names: Vec<String>,
}

fn leaf_facts(path: &Path, leaf: &CertificateDer<'_>) -> Result<LeafFacts, CertificateError> {
    let malformed = |reason: String| CertificateError::MalformedCertificate {
        path: path.to_path_buf(),
        reason,
    };
    let (_, cert) =
        x509_parser::parse_x509_certificate(leaf).map_err(|error| malformed(error.to_string()))?;
    let validity = ValidityWindow {
        not_before: system_time(cert.validity().not_before)
            .ok_or_else(|| malformed("notBefore is out of range".into()))?,
        not_after: system_time(cert.validity().not_after)
            .ok_or_else(|| malformed("notAfter is out of range".into()))?,
    };
    Ok(LeafFacts {
        pin: SpkiPin::from_spki_der(cert.public_key().raw)?,
        validity,
        names: subject_names(&cert),
    })
}

fn system_time(time: ASN1Time) -> Option<SystemTime> {
    let seconds = time.timestamp();
    let magnitude = Duration::from_secs(seconds.unsigned_abs());
    if seconds >= 0 {
        SystemTime::UNIX_EPOCH.checked_add(magnitude)
    } else {
        SystemTime::UNIX_EPOCH.checked_sub(magnitude)
    }
}

fn subject_names(cert: &X509Certificate<'_>) -> Vec<String> {
    let Ok(Some(extension)) = cert.subject_alternative_name() else {
        return Vec::new();
    };
    extension
        .value
        .general_names
        .iter()
        .filter_map(|name| match name {
            GeneralName::DNSName(dns) => Some((*dns).to_owned()),
            GeneralName::IPAddress(octets) => ip_from_octets(octets).map(|ip| ip.to_string()),
            _ => None,
        })
        .collect()
}

fn ip_from_octets(octets: &[u8]) -> Option<IpAddr> {
    if let Ok(v4) = <[u8; 4]>::try_from(octets) {
        return Some(IpAddr::from(v4));
    }
    <[u8; 16]>::try_from(octets).ok().map(IpAddr::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x509_times_before_and_after_the_epoch_convert() {
        let after = ASN1Time::from_timestamp(86_400).unwrap();
        assert_eq!(
            system_time(after),
            SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(86_400))
        );
        let before = ASN1Time::from_timestamp(-60).unwrap();
        assert_eq!(
            system_time(before),
            SystemTime::UNIX_EPOCH.checked_sub(Duration::from_secs(60))
        );
    }
}

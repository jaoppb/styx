//! The self-signed fallback: generated once, persisted, and reused on every later boot.
//!
//! Regenerating per boot would be stateless, but it would invalidate every pin the
//! operator distributed on every restart. So styx writes key material to disk and owns its
//! permissions: the key is owner-only, and a key found readable by anyone else is refused.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use rcgen::{CertificateParams, DnType, KeyPair};
use time::OffsetDateTime;
use tokio::io::AsyncWriteExt;

use crate::domain::error::CertificateError;
use crate::domain::tls::{CertificateOrigin, SelfSignedStore, ServingIdentity};
use crate::infrastructure::cert_fs::{read_file, PemPair};

/// File name of the persisted self-signed certificate.
pub const SELF_SIGNED_CERT_FILE: &str = "cert.pem";

/// File name of the persisted self-signed private key.
pub const SELF_SIGNED_KEY_FILE: &str = "key.pem";

/// How far before generation the certificate's window opens, to absorb client clock skew.
const BACKDATE: Duration = Duration::from_secs(60 * 60);

/// How long a generated certificate stays valid. It is reused for its whole life and
/// trusted by pin rather than by chain, so a short life would only schedule an outage.
const LIFETIME: Duration = Duration::from_secs(10 * 365 * 24 * 60 * 60);

/// Generates and persists self-signed material, and reloads it on later boots.
#[derive(Debug, Default, Clone, Copy)]
pub struct SelfSignedGenerator;

impl SelfSignedGenerator {
    /// Creates a generator.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl SelfSignedStore for SelfSignedGenerator {
    async fn load_existing(&self, dir: &Path) -> Result<Option<ServingIdentity>, CertificateError> {
        let cert_path = dir.join(SELF_SIGNED_CERT_FILE);
        let key_path = dir.join(SELF_SIGNED_KEY_FILE);
        match (exists(&cert_path).await?, exists(&key_path).await?) {
            (false, false) => return Ok(None),
            (true, false) => return Err(incomplete(cert_path, key_path)),
            (false, true) => return Err(incomplete(key_path, cert_path)),
            (true, true) => {}
        }
        check_owner_only(&key_path).await?;
        let pair = PemPair {
            cert_path: &cert_path,
            cert_pem: read_file(&cert_path).await?,
            key_path: &key_path,
            key_pem: read_file(&key_path).await?,
        };
        pair.identity(CertificateOrigin::SelfSigned, false)
            .map(Some)
    }

    async fn generate(
        &self,
        dir: &Path,
        names: &[String],
        now: SystemTime,
    ) -> Result<ServingIdentity, CertificateError> {
        let minted = mint(names, now)?;
        let cert_path = dir.join(SELF_SIGNED_CERT_FILE);
        let key_path = dir.join(SELF_SIGNED_KEY_FILE);
        create_dir(dir).await?;
        write_new(&key_path, minted.key_pem.as_bytes(), 0o600).await?;
        write_new(&cert_path, minted.cert_pem.as_bytes(), 0o644).await?;
        let pair = PemPair {
            cert_path: &cert_path,
            cert_pem: minted.cert_pem.into_bytes(),
            key_path: &key_path,
            key_pem: minted.key_pem.into_bytes(),
        };
        pair.identity(CertificateOrigin::SelfSigned, true)
    }
}

/// A freshly minted certificate and key, PEM-encoded.
pub(crate) struct Minted {
    pub(crate) cert_pem: String,
    pub(crate) key_pem: String,
}

/// Mints a self-signed certificate for `names`, valid from shortly before `now`.
///
/// The window comes from the caller's clock, never the system's, so a test fixture does
/// not expire on a date nobody chose.
pub(crate) fn mint(names: &[String], now: SystemTime) -> Result<Minted, CertificateError> {
    let generation = |error: rcgen::Error| CertificateError::GenerationFailed(error.to_string());
    let not_before = now.checked_sub(BACKDATE).unwrap_or(now);
    let not_after = now
        .checked_add(LIFETIME)
        .ok_or_else(|| CertificateError::GenerationFailed("validity window overflows".into()))?;
    let mut params = CertificateParams::new(names.to_vec()).map_err(generation)?;
    params.not_before = OffsetDateTime::from(not_before);
    params.not_after = OffsetDateTime::from(not_after);
    params
        .distinguished_name
        .push(DnType::CommonName, "styx self-signed");
    let key = KeyPair::generate().map_err(generation)?;
    let cert = params.self_signed(&key).map_err(generation)?;
    Ok(Minted {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    })
}

fn incomplete(present: PathBuf, missing: PathBuf) -> CertificateError {
    CertificateError::IncompleteMaterial { present, missing }
}

async fn exists(path: &Path) -> Result<bool, CertificateError> {
    tokio::fs::try_exists(path)
        .await
        .map_err(|error| CertificateError::PathUnreadable {
            path: path.to_path_buf(),
            reason: error.to_string(),
        })
}

async fn create_dir(dir: &Path) -> Result<(), CertificateError> {
    let mut builder = tokio::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    builder.mode(0o700);
    builder
        .create(dir)
        .await
        .map_err(|error| CertificateError::PersistFailed {
            path: dir.to_path_buf(),
            reason: error.to_string(),
        })
}

/// Writes a file that must not exist yet, with `mode` applied at creation so the key is
/// never readable by anyone else, even briefly.
async fn write_new(path: &Path, contents: &[u8], mode: u32) -> Result<(), CertificateError> {
    let persist = |error: std::io::Error| CertificateError::PersistFailed {
        path: path.to_path_buf(),
        reason: error.to_string(),
    };
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(mode);
    #[cfg(not(unix))]
    let _ = mode;
    let mut file = options.open(path).await.map_err(persist)?;
    file.write_all(contents).await.map_err(persist)?;
    file.sync_all().await.map_err(persist)
}

#[cfg(unix)]
async fn check_owner_only(key_path: &Path) -> Result<(), CertificateError> {
    use std::os::unix::fs::PermissionsExt;

    let metadata =
        tokio::fs::metadata(key_path)
            .await
            .map_err(|error| CertificateError::PathUnreadable {
                path: key_path.to_path_buf(),
                reason: error.to_string(),
            })?;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(CertificateError::InsecurePermissions {
            path: key_path.to_path_buf(),
        });
    }
    Ok(())
}

#[cfg(not(unix))]
async fn check_owner_only(_key_path: &Path) -> Result<(), CertificateError> {
    Ok(())
}

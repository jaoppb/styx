//! The self-signed fallback: generated once, persisted, and reused on every later boot.
//!
//! Regenerating per boot would be stateless, but it would invalidate every pin the
//! operator distributed on every restart. So styx writes key material to disk and owns its
//! permissions: the key is owner-only, and a key found readable by anyone else is refused.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use rcgen::{CertificateParams, DnType, KeyPair};
use time::OffsetDateTime;
use tokio::io::AsyncWriteExt;

use crate::domain::error::CertificateError;
use crate::domain::tls::{CertificateOrigin, SelfSignedStore, ServingIdentity, SpkiPin};
#[cfg(unix)]
use crate::infrastructure::cert_fs::open_owner_checked;
use crate::infrastructure::cert_fs::{read_cert_pin, PemPair};

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
        check_dir_safe(dir)?;
        let key_pem = read_owner_only(&key_path).await?;
        let pair = PemPair::read_cert_with_key(&cert_path, &key_path, key_pem).await?;
        pair.identity(CertificateOrigin::SelfSigned, false)
            .map(Some)
    }

    async fn load_pin(&self, dir: &Path) -> Result<Option<SpkiPin>, CertificateError> {
        let cert_path = dir.join(SELF_SIGNED_CERT_FILE);
        if !exists(&cert_path).await? {
            return Ok(None);
        }
        read_cert_pin(&cert_path).await.map(Some)
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
        persist_pair(
            dir,
            &cert_path,
            &key_path,
            minted.cert_pem.as_bytes(),
            minted.key_pem.as_bytes(),
        )
        .await?;
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
        })?;
    check_dir_safe(dir)
}

/// Writes both files to temporary paths in `dir`, syncs them, and renames them into place
/// with the certificate last. A failure styx sees removes what it wrote, temporary files
/// included. A crash between the two renames can still leave the key without its
/// certificate; the next boot refuses that as incomplete material rather than reusing it.
async fn persist_pair(
    dir: &Path,
    cert_path: &Path,
    key_path: &Path,
    cert_bytes: &[u8],
    key_bytes: &[u8],
) -> Result<(), CertificateError> {
    let (temp_key, temp_cert) = temp_paths(dir);
    let mut cert_renamed = false;
    let outcome = async {
        write_new(&temp_key, key_bytes, 0o600).await?;
        write_new(&temp_cert, cert_bytes, 0o644).await?;
        rename_file(&temp_key, key_path).await?;
        rename_file(&temp_cert, cert_path).await?;
        cert_renamed = true;
        sync_dir(dir).await
    }
    .await;
    if let Err(err) = outcome {
        remove_quietly(&temp_key).await;
        remove_quietly(&temp_cert).await;
        if !cert_renamed {
            remove_quietly(key_path).await;
        }
        return Err(err);
    }
    Ok(())
}

fn temp_paths(dir: &Path) -> (PathBuf, PathBuf) {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let seq = NEXT.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let key = dir.join(format!(".{SELF_SIGNED_KEY_FILE}.{pid}.{seq}.tmp"));
    let cert = dir.join(format!(".{SELF_SIGNED_CERT_FILE}.{pid}.{seq}.tmp"));
    (key, cert)
}

async fn rename_file(from: &Path, to: &Path) -> Result<(), CertificateError> {
    tokio::fs::rename(from, to)
        .await
        .map_err(|error| CertificateError::PersistFailed {
            path: to.to_path_buf(),
            reason: error.to_string(),
        })
}

async fn remove_quietly(path: &Path) {
    let _ = tokio::fs::remove_file(path).await;
}

#[cfg(unix)]
async fn sync_dir(dir: &Path) -> Result<(), CertificateError> {
    let handle =
        tokio::fs::File::open(dir)
            .await
            .map_err(|error| CertificateError::PersistFailed {
                path: dir.to_path_buf(),
                reason: error.to_string(),
            })?;
    handle
        .sync_all()
        .await
        .map_err(|error| CertificateError::PersistFailed {
            path: dir.to_path_buf(),
            reason: error.to_string(),
        })
}

#[cfg(not(unix))]
async fn sync_dir(_dir: &Path) -> Result<(), CertificateError> {
    Ok(())
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
fn check_dir_safe(dir: &Path) -> Result<(), CertificateError> {
    use rustix::fs::{Mode, OFlags};

    open_owner_checked(
        dir,
        OFlags::RDONLY | OFlags::DIRECTORY,
        Mode::WGRP | Mode::WOTH,
        |path| CertificateError::InsecureDirectory { path },
    )?;
    Ok(())
}

#[cfg(not(unix))]
fn check_dir_safe(_dir: &Path) -> Result<(), CertificateError> {
    Ok(())
}

#[cfg(unix)]
async fn read_owner_only(key_path: &Path) -> Result<Vec<u8>, CertificateError> {
    use rustix::fs::{Mode, OFlags};
    use tokio::io::AsyncReadExt;

    let owned = open_owner_checked(key_path, OFlags::RDONLY, Mode::RWXG | Mode::RWXO, |path| {
        CertificateError::InsecurePermissions { path }
    })?;
    let mut file = tokio::fs::File::from_std(std::fs::File::from(owned));
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .await
        .map_err(|error| CertificateError::PathUnreadable {
            path: key_path.to_path_buf(),
            reason: error.to_string(),
        })?;
    Ok(bytes)
}

#[cfg(not(unix))]
async fn read_owner_only(key_path: &Path) -> Result<Vec<u8>, CertificateError> {
    crate::infrastructure::cert_fs::read_file(key_path).await
}

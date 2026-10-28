//! The certificate files on disk: the operator's PEM pair is checked loudly at startup, and
//! self-signed material is generated once, owner-only, and reused (issue #9).

#![allow(clippy::unwrap_used)]

mod harness;

use std::time::Duration;

use harness::certificates::{fixture_now, pin_of_key, Scratch, TestCertificate};
use styx_resolution::domain::error::CertificateError;
use styx_resolution::domain::tls::{CertificateOrigin, OperatorCertificateLoader, SelfSignedStore};
use styx_resolution::infrastructure::cert_fs::{
    FilesystemCertificateReader, SelfSignedGenerator, SELF_SIGNED_CERT_FILE, SELF_SIGNED_KEY_FILE,
};

fn names() -> Vec<String> {
    vec!["localhost".into(), "127.0.0.1".into()]
}

#[tokio::test]
async fn first_boot_generates_and_later_boots_reuse_the_same_pin() {
    let scratch = Scratch::new();
    let store = SelfSignedGenerator::new();
    assert!(store.load_existing(scratch.dir()).await.unwrap().is_none());

    let generated = store
        .generate(scratch.dir(), &names(), fixture_now())
        .await
        .unwrap();
    assert!(generated.freshly_generated());
    assert_eq!(generated.origin(), CertificateOrigin::SelfSigned);
    assert_eq!(generated.subject_names(), names().as_slice());
    assert_eq!(
        Some(generated.validity().not_before),
        fixture_now().checked_sub(Duration::from_secs(3600))
    );

    let key_pem = tokio::fs::read_to_string(scratch.path(SELF_SIGNED_KEY_FILE))
        .await
        .unwrap();
    assert_eq!(generated.pin().to_pin_directive(), pin_of_key(&key_pem));

    let reused = store.load_existing(scratch.dir()).await.unwrap().unwrap();
    assert!(!reused.freshly_generated());
    assert_eq!(reused.pin(), generated.pin());
}

#[cfg(unix)]
#[tokio::test]
async fn the_key_is_written_owner_only_and_refused_once_readable_by_others() {
    use std::os::unix::fs::PermissionsExt;

    let scratch = Scratch::new();
    let store = SelfSignedGenerator::new();
    store
        .generate(scratch.dir(), &names(), fixture_now())
        .await
        .unwrap();
    let key_path = scratch.path(SELF_SIGNED_KEY_FILE);
    let mode = tokio::fs::metadata(&key_path)
        .await
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);

    tokio::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644))
        .await
        .unwrap();
    let error = store.load_existing(scratch.dir()).await.unwrap_err();
    assert!(
        matches!(error, CertificateError::InsecurePermissions { ref path } if *path == key_path),
        "{error}"
    );
}

#[tokio::test]
async fn half_of_the_self_signed_pair_is_an_error() {
    let scratch = Scratch::new();
    tokio::fs::create_dir_all(scratch.dir()).await.unwrap();
    tokio::fs::write(
        scratch.path(SELF_SIGNED_CERT_FILE),
        TestCertificate::valid().cert_pem,
    )
    .await
    .unwrap();

    let error = SelfSignedGenerator::new()
        .load_existing(scratch.dir())
        .await
        .unwrap_err();
    assert!(
        matches!(error, CertificateError::IncompleteMaterial { .. }),
        "{error}"
    );
}

#[tokio::test]
async fn an_operator_pair_loads_with_its_names_window_and_pin() {
    let scratch = Scratch::new();
    let fixture = TestCertificate::valid();
    let (cert, key) = scratch
        .write_pair(&fixture.cert_pem, &fixture.key_pem)
        .await;

    let identity = FilesystemCertificateReader::new()
        .load(&cert, &key)
        .await
        .unwrap();
    assert_eq!(identity.origin(), CertificateOrigin::OperatorSupplied);
    assert!(!identity.freshly_generated());
    assert_eq!(identity.chain(), [fixture.cert_der()].as_slice());
    assert_eq!(identity.subject_names(), names().as_slice());
    assert_eq!(identity.pin().to_pin_directive(), fixture.independent_pin());
}

#[tokio::test]
async fn a_key_from_another_certificate_is_a_mismatch_naming_both_files() {
    let scratch = Scratch::new();
    let leaf = TestCertificate::valid();
    let other = TestCertificate::valid();
    let (cert, key) = scratch.write_pair(&leaf.cert_pem, &other.key_pem).await;

    let error = FilesystemCertificateReader::new()
        .load(&cert, &key)
        .await
        .unwrap_err();
    assert!(
        matches!(error, CertificateError::KeyMismatch { ref cert_path, ref key_path }
            if *cert_path == cert && *key_path == key),
        "{error}"
    );
}

#[tokio::test]
async fn missing_and_malformed_operator_files_name_the_file_at_fault() {
    let scratch = Scratch::new();
    let fixture = TestCertificate::valid();
    let reader = FilesystemCertificateReader::new();

    let missing = scratch.path("absent.pem");
    let error = reader.load(&missing, &missing).await.unwrap_err();
    assert!(error.to_string().contains("absent.pem"), "{error}");

    let (cert, key) = scratch
        .write_pair("not a certificate", &fixture.key_pem)
        .await;
    let error = reader.load(&cert, &key).await.unwrap_err();
    assert!(
        matches!(error, CertificateError::NoCertificateInFile { ref path } if *path == cert),
        "{error}"
    );

    let (cert, key) = scratch.write_pair(&fixture.cert_pem, "not a key").await;
    let error = reader.load(&cert, &key).await.unwrap_err();
    assert!(
        matches!(error, CertificateError::MalformedKey { ref path, .. } if *path == key),
        "{error}"
    );
}

//! Choosing the serving certificate: an operator path wins when configured, self-signed
//! material only when none is, never as a fallback; the pin is announced once (issue #9).

#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use styx_core::TestClock;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::Layer;

use styx_resolution::application::certificate::CertificateProvisioner;
use styx_resolution::domain::error::CertificateError;
use styx_resolution::domain::tls::{
    CertificateOrigin, DohResourcePath, EncryptedLimits, OperatorCertificateLoader,
    PrivateKeyEncoding, PrivateKeyMaterial, SelfSignedStore, ServingIdentity, ServingIdentityParts,
    ServingIdentityProvider, SpkiPin, TlsConfig, TlsConfigParts, ValidityWindow,
};

fn epoch_plus(days: u32) -> SystemTime {
    SystemTime::UNIX_EPOCH
        .checked_add(
            Duration::from_secs(86_400)
                .checked_mul(20_000_u32.checked_add(days).unwrap())
                .unwrap(),
        )
        .unwrap()
}

fn identity(spki: &[u8], origin: CertificateOrigin, fresh: bool) -> ServingIdentity {
    ServingIdentity::new(ServingIdentityParts {
        chain: vec![vec![0x30]],
        key: PrivateKeyMaterial::new(PrivateKeyEncoding::Pkcs8, vec![1]),
        pin: SpkiPin::from_spki_der(spki).unwrap(),
        validity: ValidityWindow {
            not_before: epoch_plus(0),
            not_after: epoch_plus(10),
        },
        subject_names: vec!["localhost".into()],
        origin,
        freshly_generated: fresh,
    })
    .unwrap()
}

/// An operator loader that serves one identity, or fails as if the file were missing.
struct FakeLoader {
    serves: Option<ServingIdentity>,
    loads: Arc<AtomicUsize>,
}

impl OperatorCertificateLoader for FakeLoader {
    async fn load(
        &self,
        cert_path: &Path,
        _key_path: &Path,
    ) -> Result<ServingIdentity, CertificateError> {
        self.loads.fetch_add(1, Ordering::Relaxed);
        self.serves
            .clone()
            .ok_or_else(|| CertificateError::PathUnreadable {
                path: cert_path.to_path_buf(),
                reason: "not found".into(),
            })
    }
}

/// A self-signed directory that may already hold material, and records generations.
struct FakeStore {
    existing: Option<ServingIdentity>,
    generated_at: Arc<Mutex<Vec<SystemTime>>>,
}

impl SelfSignedStore for FakeStore {
    async fn load_existing(
        &self,
        _dir: &Path,
    ) -> Result<Option<ServingIdentity>, CertificateError> {
        Ok(self.existing.clone())
    }

    async fn generate(
        &self,
        _dir: &Path,
        _names: &[String],
        now: SystemTime,
    ) -> Result<ServingIdentity, CertificateError> {
        self.generated_at.lock().unwrap().push(now);
        Ok(identity(b"generated", CertificateOrigin::SelfSigned, true))
    }
}

struct Fixture {
    provisioner: CertificateProvisioner<TestClock, FakeLoader, FakeStore>,
    clock: Arc<TestClock>,
    loads: Arc<AtomicUsize>,
    generated_at: Arc<Mutex<Vec<SystemTime>>>,
}

impl Fixture {
    fn new(operator: Option<ServingIdentity>, existing: Option<ServingIdentity>) -> Self {
        let clock = Arc::new(TestClock::new());
        clock.set_utc(epoch_plus(5));
        let loads = Arc::new(AtomicUsize::new(0));
        let generated_at = Arc::new(Mutex::new(Vec::new()));
        Self {
            provisioner: CertificateProvisioner::new(
                Arc::clone(&clock),
                FakeLoader {
                    serves: operator,
                    loads: Arc::clone(&loads),
                },
                FakeStore {
                    existing,
                    generated_at: Arc::clone(&generated_at),
                },
            ),
            clock,
            loads,
            generated_at,
        }
    }

    fn generations(&self) -> Vec<SystemTime> {
        self.generated_at.lock().unwrap().clone()
    }
}

fn config(operator_paths: bool) -> TlsConfig {
    let path = |name: &str| operator_paths.then(|| PathBuf::from(name));
    TlsConfig::new(TlsConfigParts {
        dot_listen_addrs: vec!["127.0.0.1:853".parse().unwrap()],
        doh_listen_addrs: Vec::new(),
        cert_path: path("fullchain.pem"),
        key_path: path("privkey.pem"),
        self_signed_dir: PathBuf::from("tls"),
        self_signed_names: vec!["localhost".into()],
        doh_path: DohResourcePath::new("/dns-query".into()).unwrap(),
        allow_http1: false,
        limits: EncryptedLimits::default(),
    })
    .unwrap()
}

/// One captured event: its level and its message.
#[derive(Debug, Clone)]
struct Logged {
    level: Level,
    message: String,
}

#[derive(Default)]
struct Message(String);

impl Visit for Message {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        }
    }
}

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<Logged>>>);

impl<S: Subscriber> Layer<S> for Capture {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut message = Message::default();
        event.record(&mut message);
        self.0.lock().unwrap().push(Logged {
            // Called as a path, not a method: arch-lint's no-sync-io matches a bare
            // `.metadata()` call as if it were `std::fs::metadata`.
            level: *Event::metadata(event).level(),
            message: message.0,
        });
    }
}

impl Capture {
    fn install(&self) -> tracing::subscriber::DefaultGuard {
        tracing::subscriber::set_default(tracing_subscriber::registry().with(self.clone()))
    }

    fn at(&self, level: Level) -> Vec<String> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|logged| logged.level == level)
            .map(|logged| logged.message.clone())
            .collect()
    }
}

#[tokio::test]
async fn a_configured_operator_certificate_serves_and_stale_material_is_noted() {
    let capture = Capture::default();
    let _guard = capture.install();
    let operator = identity(b"operator", CertificateOrigin::OperatorSupplied, false);
    let stale = identity(b"stale", CertificateOrigin::SelfSigned, false);
    let fixture = Fixture::new(Some(operator.clone()), Some(stale));

    let served = fixture.provisioner.resolve(&config(true)).await.unwrap();

    assert_eq!(served.pin(), operator.pin());
    assert!(fixture.generations().is_empty());
    let warnings = capture.at(Level::WARN);
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("self-signed material is present")),
        "{warnings:?}"
    );
}

#[tokio::test]
async fn configured_material_that_fails_to_load_never_falls_back_to_self_signed() {
    let existing = identity(b"existing", CertificateOrigin::SelfSigned, false);
    let fixture = Fixture::new(None, Some(existing));

    let error = fixture
        .provisioner
        .resolve(&config(true))
        .await
        .unwrap_err();

    assert!(error.to_string().contains("fullchain.pem"), "{error}");
    assert!(fixture.generations().is_empty());
}

#[tokio::test]
async fn first_boot_without_paths_generates_from_the_injected_clock() {
    let fixture = Fixture::new(None, None);

    let served = fixture.provisioner.resolve(&config(false)).await.unwrap();

    assert!(served.freshly_generated());
    assert_eq!(fixture.generations(), vec![epoch_plus(5)]);
    assert_eq!(fixture.loads.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn later_boots_reuse_persisted_material_without_generating() {
    let existing = identity(b"existing", CertificateOrigin::SelfSigned, false);
    let fixture = Fixture::new(None, Some(existing.clone()));

    let served = fixture.provisioner.resolve(&config(false)).await.unwrap();

    assert_eq!(served.pin(), existing.pin());
    assert!(fixture.generations().is_empty());
}

#[tokio::test]
async fn expired_and_not_yet_valid_certificates_warn_and_still_serve() {
    for (now, expect) in [
        (epoch_plus(11), "has expired"),
        (SystemTime::UNIX_EPOCH, "is not valid yet"),
    ] {
        let capture = Capture::default();
        let _guard = capture.install();
        let operator = identity(b"operator", CertificateOrigin::OperatorSupplied, false);
        let fixture = Fixture::new(Some(operator), None);
        fixture.clock.set_utc(now);

        assert!(fixture.provisioner.resolve(&config(true)).await.is_ok());
        let warnings = capture.at(Level::WARN);
        assert!(warnings.iter().any(|w| w.contains(expect)), "{warnings:?}");
    }
}

#[tokio::test]
async fn the_pin_is_logged_at_info_only_when_freshly_generated() {
    let fixture = Fixture::new(None, None);

    let capture = Capture::default();
    let guard = capture.install();
    let fresh = identity(b"fresh", CertificateOrigin::SelfSigned, true);
    fixture.provisioner.announce_pin(&fresh);
    drop(guard);
    let infos = capture.at(Level::INFO);
    assert_eq!(infos.len(), 1, "{infos:?}");
    assert!(infos[0].contains("Android Private DNS"), "{infos:?}");
    assert!(infos[0].contains("bring a certificate"), "{infos:?}");

    let capture = Capture::default();
    let _guard = capture.install();
    let reused = identity(b"reused", CertificateOrigin::SelfSigned, false);
    fixture.provisioner.announce_pin(&reused);
    assert!(capture.at(Level::INFO).is_empty());
    assert_eq!(capture.at(Level::DEBUG).len(), 1);
}

#[tokio::test]
async fn existing_pin_reports_absence_without_generating() {
    let fixture = Fixture::new(None, None);
    assert_eq!(
        fixture
            .provisioner
            .existing_pin(&config(false))
            .await
            .unwrap(),
        None
    );
    assert!(fixture.generations().is_empty());

    let existing = identity(b"existing", CertificateOrigin::SelfSigned, false);
    let fixture = Fixture::new(None, Some(existing.clone()));
    assert_eq!(
        fixture
            .provisioner
            .existing_pin(&config(false))
            .await
            .unwrap(),
        Some(existing.pin())
    );
}

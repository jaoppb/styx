//! Resolving the configured certificate source into the one serving identity.
//!
//! An operator path wins whenever it is configured. Self-signed material is used only when
//! no path is configured — never because configured material failed to load: falling back
//! would keep the daemon up while swapping a publicly-valid identity for one no client
//! trusts, turning a config typo into a silent DoT outage that looks like a client bug.

use std::sync::Arc;
use std::time::SystemTime;

use styx_core::Clock;
use time::OffsetDateTime;

use crate::domain::error::CertificateError;
use crate::domain::tls::{
    CertificateSource, OperatorCertificateLoader, SelfSignedStore, ServingIdentity,
    ServingIdentityProvider, SpkiPin, TlsConfig, ValidityState,
};

/// Selects the source, assesses validity, and announces the pin once.
pub struct CertificateProvisioner<C, R, G> {
    clock: Arc<C>,
    reader: R,
    store: G,
}

impl<C, R, G> CertificateProvisioner<C, R, G>
where
    C: Clock,
    R: OperatorCertificateLoader,
    G: SelfSignedStore,
{
    /// Builds a provisioner over the operator reader and the self-signed store.
    #[must_use]
    pub fn new(clock: Arc<C>, reader: R, store: G) -> Self {
        Self {
            clock,
            reader,
            store,
        }
    }

    /// The pin of the material `config` would serve, without generating anything.
    ///
    /// `Ok(None)` means the source is self-signed and nothing has been generated yet.
    ///
    /// # Errors
    /// Returns the [`CertificateError`] of a configured or persisted file that cannot be
    /// loaded.
    pub async fn existing_pin(
        &self,
        config: &TlsConfig,
    ) -> Result<Option<SpkiPin>, CertificateError> {
        let identity = match config.certificate_source() {
            CertificateSource::OperatorSupplied {
                cert_path,
                key_path,
            } => Some(self.reader.load(cert_path, key_path).await?),
            CertificateSource::SelfSigned { dir, .. } => self.store.load_existing(dir).await?,
        };
        Ok(identity.map(|identity| identity.pin()))
    }

    /// Logs the pin: at info level, with the plain-words caveat, only on the boot that
    /// generated the material; at debug level otherwise, so it does not scroll through the
    /// log forever.
    pub fn announce_pin(&self, identity: &ServingIdentity) {
        let pin = identity.pin().to_pin_directive();
        let names = identity.subject_names().join(",");
        if identity.freshly_generated() {
            tracing::info!(
                pin = %pin,
                source = identity.origin().name(),
                subject_names = %names,
                not_before = %utc(identity.validity().not_before),
                not_after = %utc(identity.validity().not_after),
                "generated a self-signed certificate for DoT/DoH; this pin is printed once \
                 (re-derive it with `styx pin`). It is adequate for curl and DoH clients \
                 that accept a pin, and inadequate for DoT clients such as Android Private \
                 DNS, which want a publicly-valid name: bring a certificate for those"
            );
        } else {
            tracing::debug!(
                pin = %pin,
                source = identity.origin().name(),
                subject_names = %names,
                "serving certificate pin"
            );
        }
    }

    async fn operator_identity(
        &self,
        config: &TlsConfig,
        cert_path: &std::path::Path,
        key_path: &std::path::Path,
    ) -> Result<ServingIdentity, CertificateError> {
        let identity = self.reader.load(cert_path, key_path).await?;
        let stale = self.store.load_existing(config.self_signed_dir()).await;
        if matches!(stale, Ok(Some(_)) | Err(_)) {
            tracing::warn!(
                dir = %config.self_signed_dir().display(),
                "self-signed material is present but the operator certificate is configured \
                 and serves; the self-signed pin is not in use"
            );
        }
        Ok(identity)
    }

    async fn self_signed_identity(
        &self,
        dir: &std::path::Path,
        names: &[String],
    ) -> Result<ServingIdentity, CertificateError> {
        match self.store.load_existing(dir).await? {
            Some(identity) => Ok(identity),
            None => self.store.generate(dir, names, self.clock.now_utc()).await,
        }
    }

    fn warn_outside_validity(&self, identity: &ServingIdentity) {
        let window = identity.validity();
        let state = identity.validity_state(self.clock.now_utc());
        let reason = match state {
            ValidityState::Valid => return,
            ValidityState::NotYetValid => "is not valid yet",
            ValidityState::Expired => "has expired",
        };
        tracing::warn!(
            source = identity.origin().name(),
            not_before = %utc(window.not_before),
            not_after = %utc(window.not_after),
            "the serving certificate {reason}; clients will refuse it, and the symptom looks \
             like a network fault"
        );
    }
}

/// A validity bound as an operator reads it, in UTC.
fn utc(time: SystemTime) -> OffsetDateTime {
    OffsetDateTime::from(time)
}

impl<C, R, G> ServingIdentityProvider for CertificateProvisioner<C, R, G>
where
    C: Clock,
    R: OperatorCertificateLoader,
    G: SelfSignedStore,
{
    async fn resolve(&self, config: &TlsConfig) -> Result<ServingIdentity, CertificateError> {
        let identity = match config.certificate_source() {
            CertificateSource::OperatorSupplied {
                cert_path,
                key_path,
            } => self.operator_identity(config, cert_path, key_path).await?,
            CertificateSource::SelfSigned { dir, names } => {
                self.self_signed_identity(dir, names).await?
            }
        };
        self.warn_outside_validity(&identity);
        Ok(identity)
    }
}

//! Bringing up encrypted inbound, and recovering its pin.
//!
//! The serving certificate is resolved, its pin announced and the TLS configuration built
//! before any listener binds, so a certificate problem is one loud startup failure rather
//! than a resolver that starts and then fails every handshake. Everything comes from the
//! TOML file; no database participates in bringing a listener up.

use std::io::Write;
use std::sync::Arc;

use anyhow::{bail, Context};
use styx_core::SystemClock;
use styx_resolution::application::certificate::CertificateProvisioner;
use styx_resolution::domain::tls::{ServingIdentityProvider, TlsConfig};
use styx_resolution::infrastructure::cert_fs::{FilesystemCertificateReader, SelfSignedGenerator};
use styx_resolution::{EncryptedListeners, TlsServerSetup};

type Provisioner =
    CertificateProvisioner<SystemClock, FilesystemCertificateReader, SelfSignedGenerator>;

fn provisioner(clock: Arc<SystemClock>) -> Provisioner {
    CertificateProvisioner::new(
        clock,
        FilesystemCertificateReader::new(),
        SelfSignedGenerator::new(),
    )
}

/// Resolves the certificate, announces its pin and builds the TLS configuration.
///
/// # Errors
/// Fails, naming the file at fault, when the configured certificate cannot be loaded or
/// self-signed material cannot be generated, and when rustls refuses the pair.
pub async fn prepare(
    config: TlsConfig,
    clock: Arc<SystemClock>,
) -> anyhow::Result<EncryptedListeners> {
    let provisioner = provisioner(clock);
    let identity = provisioner
        .resolve(&config)
        .await
        .context("failed to load the [tls] serving certificate")?;
    provisioner.announce_pin(&identity);
    let setup = TlsServerSetup::build(&identity, config.allow_http1())
        .context("failed to build the TLS configuration")?;
    Ok(EncryptedListeners::new(config, setup))
}

/// `styx pin`: prints the pin of the certificate `config` would serve, to stdout.
///
/// Binds no socket and generates nothing: asked about self-signed material that does not
/// exist yet, it says so and fails rather than minting a certificate as a side effect of
/// a question. The pin is derived from a public key, so printing it again leaks nothing.
///
/// # Errors
/// Fails when encrypted inbound is not enabled, when no material exists yet, or when the
/// configured material cannot be loaded.
pub async fn print_pin(config: Option<TlsConfig>) -> anyhow::Result<()> {
    let Some(config) = config else {
        bail!("encrypted inbound is not enabled: [tls] needs enabled = true");
    };
    let pin = provisioner(Arc::new(SystemClock::new()))
        .existing_pin(&config)
        .await
        .context("failed to read the [tls] serving certificate")?;
    let Some(pin) = pin else {
        bail!(
            "no self-signed certificate in {} yet; start styx with [tls] enabled once to \
             generate it",
            config.self_signed_dir().display()
        );
    };
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{}", pin.to_pin_directive()).context("failed to write the pin")?;
    Ok(())
}

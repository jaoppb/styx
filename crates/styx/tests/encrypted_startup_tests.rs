//! The binary's side of encrypted inbound (issue #9): `styx pin` re-derives the pin without
//! generating anything, and a configured certificate that cannot be loaded stops startup
//! instead of falling back to self-signed.

#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::SystemTime;

use styx_resolution::domain::tls::SelfSignedStore;
use styx_resolution::infrastructure::cert_fs::{
    SelfSignedGenerator, SELF_SIGNED_CERT_FILE, SELF_SIGNED_KEY_FILE,
};

fn scratch() -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "styx-startup-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

async fn write_config(dir: &Path, tls: &str) -> PathBuf {
    tokio::fs::create_dir_all(dir).await.unwrap();
    let path = dir.join("styx.toml");
    let config = format!(
        "listen_addrs = [\"127.0.0.1:0\"]\n\n\
         [upstream]\nstrategy = \"ordered_failover\"\n\n\
         [[upstream.members]]\nname = \"local\"\nkind = \"forwarder\"\naddr = \"127.0.0.1:9\"\n\n\
         [tls]\nenabled = true\ndot_listen_addrs = [\"127.0.0.1:0\"]\ndoh_listen_addrs = []\n{tls}"
    );
    tokio::fs::write(&path, config).await.unwrap();
    path
}

async fn styx(args: Vec<String>) -> Output {
    tokio::task::spawn_blocking(move || {
        std::process::Command::new(env!("CARGO_BIN_EXE_styx"))
            .args(args)
            .env("RUST_LOG", "warn")
            .output()
            .unwrap()
    })
    .await
    .unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[tokio::test]
async fn pin_reports_missing_self_signed_material_without_generating_it() {
    let dir = scratch();
    let tls_dir = dir.join("tls");
    let config = write_config(&dir, &format!("self_signed_dir = {:?}\n", tls_dir)).await;

    let output = styx(vec!["pin".into(), config.display().to_string()]).await;

    assert!(!output.status.success());
    assert!(text(&output.stdout).is_empty(), "{}", text(&output.stdout));
    assert!(
        text(&output.stderr).contains("no self-signed certificate"),
        "{}",
        text(&output.stderr)
    );
    assert!(
        !tokio::fs::try_exists(&tls_dir).await.unwrap(),
        "pin must not generate"
    );
}

#[tokio::test]
async fn pin_prints_the_pin_of_the_persisted_self_signed_material() {
    let dir = scratch();
    let tls_dir = dir.join("tls");
    let identity = SelfSignedGenerator::new()
        .generate(&tls_dir, &["localhost".to_owned()], SystemTime::now())
        .await
        .unwrap();
    let config = write_config(&dir, &format!("self_signed_dir = {:?}\n", tls_dir)).await;

    let output = styx(vec!["pin".into(), config.display().to_string()]).await;

    assert!(output.status.success(), "{}", text(&output.stderr));
    assert_eq!(text(&output.stdout), format!("{}\n", identity.pin()));
}

#[tokio::test]
async fn pin_prints_the_pin_of_an_operator_certificate() {
    let dir = scratch();
    let material = dir.join("material");
    let identity = SelfSignedGenerator::new()
        .generate(&material, &["localhost".to_owned()], SystemTime::now())
        .await
        .unwrap();
    let tls = format!(
        "cert_path = {:?}\nkey_path = {:?}\n",
        material.join(SELF_SIGNED_CERT_FILE),
        material.join(SELF_SIGNED_KEY_FILE)
    );
    let config = write_config(&dir, &tls).await;

    let output = styx(vec!["pin".into(), config.display().to_string()]).await;

    assert!(output.status.success(), "{}", text(&output.stderr));
    assert_eq!(text(&output.stdout), format!("{}\n", identity.pin()));
}

#[tokio::test]
async fn a_configured_certificate_that_cannot_load_stops_startup_naming_the_file() {
    let dir = scratch();
    let tls_dir = dir.join("tls");
    let missing = dir.join("missing-fullchain.pem");
    let tls = format!(
        "cert_path = {:?}\nkey_path = {:?}\nself_signed_dir = {:?}\n",
        missing,
        dir.join("missing-privkey.pem"),
        tls_dir
    );
    let config = write_config(&dir, &tls).await;

    let output = styx(vec![config.display().to_string()]).await;

    assert!(!output.status.success());
    let stderr = text(&output.stderr);
    assert!(stderr.contains("missing-fullchain.pem"), "{stderr}");
    assert!(
        !tokio::fs::try_exists(&tls_dir).await.unwrap(),
        "no fallback to self-signed"
    );
}

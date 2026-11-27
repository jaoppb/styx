//! `styx health` (issue #100), the container healthcheck: it exits 0 when a styx listener
//! answers, and non-zero when nothing does, without depending on the upstreams.

// The helpers below sit outside `#[test]` functions, where clippy's allowances stop.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Every process here exits or is killed within this budget, so a hang fails instead of
/// stalling CI.
const RUN_BUDGET: Duration = Duration::from_secs(30);

fn scratch() -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "styx-health-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

/// A config whose only upstream is `silent`, a socket that never answers: a check that went
/// through an upstream would wait out the query timeout instead of passing.
async fn write_config(dir: &Path, silent: SocketAddr) -> PathBuf {
    tokio::fs::create_dir_all(dir).await.unwrap();
    let path = dir.join("styx.toml");
    tokio::fs::write(
        &path,
        format!(
            "listen_addrs = [\"127.0.0.1:0\"]\n\n\
             [upstream]\nstrategy = \"ordered_failover\"\n\n\
             [[upstream.members]]\nname = \"silent\"\nkind = \"forwarder\"\naddr = \"{silent}\"\n"
        ),
    )
    .await
    .unwrap();
    path
}

/// The port of the listener a `DNS listener active` log line names. The line may carry
/// ANSI colour codes around the field name, so the address is read after its host.
fn listener_port(line: &str) -> Option<u16> {
    let (_, rest) = line.split_once("DNS listener active")?;
    let (_, port) = rest.split_once("127.0.0.1:")?;
    let digits: String = port.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// A running resolver, killed when dropped.
struct Resolver {
    child: Child,
    address: SocketAddr,
}

impl Drop for Resolver {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_resolver(config: &Path) -> Resolver {
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_styx"))
        .arg(config)
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut lines = BufReader::new(stdout).lines().map_while(Result::ok);
        let port = lines.find_map(|line| listener_port(&line));
        let _ = tx.send(port);
        // Keep draining so the resolver never blocks on a full pipe.
        lines.for_each(drop);
    });
    let Ok(Some(port)) = rx.recv_timeout(RUN_BUDGET) else {
        let _ = child.kill();
        panic!("styx did not log a UDP/TCP listener within {RUN_BUDGET:?}");
    };
    Resolver {
        child,
        address: SocketAddr::from(([127, 0, 0, 1], port)),
    }
}

fn health(args: &[String]) -> Output {
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_styx"))
        .arg("health")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let started = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if started.elapsed() >= RUN_BUDGET {
            let _ = child.kill();
            panic!("styx health did not exit within {RUN_BUDGET:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    child.wait_with_output().unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[tokio::test]
async fn health_passes_against_a_running_resolver_whose_upstream_never_answers() {
    let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
    let resolver = start_resolver(&write_config(&scratch(), silent.local_addr().unwrap()).await);

    let started = Instant::now();
    let output = health(&[resolver.address.to_string()]);

    assert!(output.status.success(), "{}", text(&output.stderr));
    // The resolver answers the check itself; a check routed to the silent upstream would
    // only end at the five-second query timeout.
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn health_fails_naming_the_address_when_nothing_answers() {
    let free = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = free.local_addr().unwrap();
    drop(free);

    let output = health(&[address.to_string()]);

    assert!(!output.status.success());
    let stderr = text(&output.stderr);
    assert!(stderr.contains(&address.to_string()), "{stderr}");
}

#[test]
fn health_rejects_an_argument_that_is_not_a_socket_address() {
    let output = health(&["localhost".into()]);

    assert!(!output.status.success());
    assert!(text(&output.stderr).contains("localhost"));
}

#[test]
fn health_help_prints_its_usage() {
    for flag in ["-h", "--help"] {
        let output = health(&[flag.into()]);

        assert!(output.status.success(), "{flag}: {}", text(&output.stderr));
        assert_eq!(
            text(&output.stdout),
            "usage: styx health [address]\n",
            "{flag}"
        );
    }
}

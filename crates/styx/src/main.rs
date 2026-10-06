//! styx — the composition root.
//!
//! This binary is the **only** crate permitted to name every feature crate at
//! once. Cross-feature wiring happens here and nowhere else: a feature crate
//! declares a port in its `domain`, and this binary constructs the adapter and
//! injects it. There is no service locator and no reflection — collaborators
//! are passed to constructors by value at startup.
//!
//! Wires DNS listeners (UDP/TCP), server configuration, the resolution
//! pipeline, and graceful shutdown. The Leptos SSR handler is wired in
//! Phase 11.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use styx_core::SystemClock;
use styx_resolution::{
    default_socket_count, AllowAllFilter, ConcurrencyLimits, DiscardObserver, MaxResponseSize,
    NoLocalRecords, Pipeline, Server, ServerConfig,
};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::EnvFilter;

/// Log filter used when `RUST_LOG` is unset or unusable.
const DEFAULT_LOG_FILTER: LevelFilter = LevelFilter::INFO;

/// Starts the process and supervises server listeners.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    raise_descriptor_limit();

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        web = cfg!(feature = "web"),
        "styx starting"
    );

    let config = load_config().await?;
    let clock = Arc::new(SystemClock::new());
    let filter = Arc::new(AllowAllFilter::new());
    let local_records = Arc::new(NoLocalRecords::new());
    let observer = Arc::new(DiscardObserver::new());
    let pipeline = Arc::new(Pipeline::new(
        local_records,
        filter,
        observer,
        clock.clone(),
    ));

    let mut server = Server::bind(config, pipeline, clock)
        .await
        .context("failed to bind server listeners")?;

    for addr in server.local_addrs() {
        tracing::info!(%addr, "DNS listener active");
    }

    tokio::signal::ctrl_c()
        .await
        .context("failed to listen for shutdown signal")?;

    tracing::info!("shutdown signal received; closing listeners");
    server
        .shutdown()
        .await
        .context("failed to shut down server")?;
    Ok(())
}

async fn load_config() -> anyhow::Result<ServerConfig> {
    if let Some(path) = std::env::args().nth(1) {
        return ServerConfig::from_toml(&path)
            .await
            .with_context(|| format!("failed to read config from {path}"));
    }

    let has_default_toml = tokio::fs::try_exists("styx.toml").await.unwrap_or_default();

    if has_default_toml {
        return ServerConfig::from_toml("styx.toml")
            .await
            .context("failed to read default styx.toml config");
    }

    Ok(ServerConfig {
        listen_addrs: vec![SocketAddr::from(([127, 0, 0, 1], 1053))],
        udp_payload_size_default: MaxResponseSize::classic(),
        tcp_idle_timeout: Duration::from_secs(5),
        query_timeout: Duration::from_secs(2),
        limits: ConcurrencyLimits::default_limits()
            .with_udp_sockets_per_addr(default_socket_count()),
        supervisor: styx_resolution::SupervisorBackoffPolicy::default(),
    })
}

/// Raises the `RLIMIT_NOFILE` soft limit to the hard limit before any socket is bound.
///
/// The upstream forwarder binds a socket per query, so at the default caps peak
/// descriptor use exceeds the 1024 soft limit a systemd service starts with. Failure
/// is logged and boot continues: the accept loop already survives `EMFILE`.
#[cfg(target_os = "linux")]
fn raise_descriptor_limit() {
    use rustix::process::{getrlimit, setrlimit, Resource, Rlimit};

    let limit = getrlimit(Resource::Nofile);
    if limit.current == limit.maximum {
        tracing::info!(soft = ?limit.current, hard = ?limit.maximum, "descriptor limit unchanged");
        return;
    }
    let raised = Rlimit {
        current: limit.maximum,
        maximum: limit.maximum,
    };
    match setrlimit(Resource::Nofile, raised) {
        Ok(()) => tracing::info!(
            previous_soft = ?limit.current,
            soft = ?limit.maximum,
            "raised descriptor soft limit to the hard limit"
        ),
        Err(error) => tracing::warn!(
            %error,
            soft = ?limit.current,
            hard = ?limit.maximum,
            "could not raise descriptor soft limit"
        ),
    }
}

/// Descriptor limits are left to the operator off Linux.
#[cfg(not(target_os = "linux"))]
fn raise_descriptor_limit() {}

/// Installs the `tracing` subscriber, taking its filter from the environment.
fn init_tracing() {
    let builder = EnvFilter::builder().with_default_directive(DEFAULT_LOG_FILTER.into());

    let (filter, rejected) = match builder.from_env() {
        Ok(filter) => (filter, None),
        Err(error) => (EnvFilter::new(DEFAULT_LOG_FILTER.to_string()), Some(error)),
    };

    tracing_subscriber::fmt().with_env_filter(filter).init();

    if let Some(error) = rejected {
        tracing::warn!(
            %error,
            fallback = %DEFAULT_LOG_FILTER,
            "RUST_LOG could not be parsed; using the fallback filter"
        );
    }
}

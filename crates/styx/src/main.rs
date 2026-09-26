//! styx — the composition root.
//!
//! This binary is the **only** crate permitted to name every feature crate at
//! once. Cross-feature wiring happens here and nowhere else: a feature crate
//! declares a port in its `domain`, and this binary constructs the adapter and
//! injects it. There is no service locator and no reflection — collaborators
//! are passed to constructors by value at startup.
//!
//! Phase 0 delivers the crate, its `web` feature and the tracing convention.
//! DNS listeners, the resolver and the Leptos SSR handler are wired in from
//! phase 2 onward.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use styx_resolution::{
    AllowAllFilter, DiscardObserver, MaxResponseSize, NoLocalRecords, Pipeline, Server,
    ServerConfig, SystemClock,
};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::EnvFilter;

/// Log filter used when `RUST_LOG` is unset or unusable.
const DEFAULT_LOG_FILTER: LevelFilter = LevelFilter::INFO;

/// Starts the process and supervises server listeners.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

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
    })
}

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

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

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context};
use styx_core::{SystemClock, UpstreamId};
use styx_resolution::{
    AllowAllFilter, CacheStage, CanaryConfig, ConfiguredStrategy, DiscardObserver, Do53Forwarder,
    NoLocalRecords, Pipeline, PoolConfig, PoolMember, ProbePolicy, ProbeScheduler, Server,
    ServerConfig, ShardedAnswerCache, UpstreamPool,
};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::EnvFilter;

/// Log filter used when `RUST_LOG` is unset or unusable.
const DEFAULT_LOG_FILTER: LevelFilter = LevelFilter::INFO;

type ConcretePool = UpstreamPool<ConfiguredStrategy, Do53Forwarder<SystemClock>, SystemClock>;
type ConcreteCache = ShardedAnswerCache<SystemClock>;
type ConcreteStage =
    CacheStage<ConcreteCache, ConfiguredStrategy, Do53Forwarder<SystemClock>, SystemClock>;
type ConcretePipeline =
    Pipeline<NoLocalRecords, AllowAllFilter, DiscardObserver, SystemClock, ConcreteStage>;

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
    let pool_config = config
        .upstream
        .as_ref()
        .context("missing [upstream] configuration")?;

    let clock = Arc::new(SystemClock::new());
    let pool = build_pool(pool_config, clock.clone());
    let pipeline = build_pipeline(pool.clone(), clock.clone(), config.query_timeout);

    let probe_cancel = CancellationToken::new();
    let scheduler = ProbeScheduler::new(pool, clock.clone(), pool_config.probe.tick);
    let probe_token = probe_cancel.clone();
    tokio::spawn(async move {
        scheduler.run(probe_token).await;
    });

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
    probe_cancel.cancel();
    server
        .shutdown()
        .await
        .context("failed to shut down server")?;
    Ok(())
}

fn build_pool(pool_config: &PoolConfig, clock: Arc<SystemClock>) -> Arc<ConcretePool> {
    let mut members = Vec::with_capacity(pool_config.members.len());
    for member_cfg in &pool_config.members {
        let id = UpstreamId::new(member_cfg.name.as_str());
        let forwarder = Do53Forwarder::new(
            id.clone(),
            member_cfg.addr,
            member_cfg.edns_buffer,
            member_cfg.timeouts.udp,
            member_cfg.timeouts.tcp,
            clock.clone(),
        );
        let canary = member_cfg
            .canary
            .clone()
            .unwrap_or_else(|| CanaryConfig::for_kind(member_cfg.kind));
        members.push(PoolMember::new(id, forwarder, member_cfg.weight, canary));
    }
    let strategy = ConfiguredStrategy::from_name(pool_config.strategy);
    Arc::new(UpstreamPool::new(
        members,
        strategy,
        clock,
        pool_config.circuit.clone(),
        ProbePolicy::new(pool_config.probe.clone()),
    ))
}

fn build_pipeline(
    pool: Arc<ConcretePool>,
    clock: Arc<SystemClock>,
    query_timeout: Duration,
) -> Arc<ConcretePipeline> {
    let cache = Arc::new(ShardedAnswerCache::with_defaults(clock.clone()));
    let cache_stage = Arc::new(CacheStage::new(cache, pool, clock.clone(), query_timeout));
    Arc::new(
        Pipeline::new(
            Arc::new(NoLocalRecords::new()),
            Arc::new(AllowAllFilter::new()),
            Arc::new(DiscardObserver::new()),
            clock,
        )
        .with_terminal(cache_stage),
    )
}

async fn load_config() -> anyhow::Result<ServerConfig> {
    if let Some(path) = std::env::args().nth(1) {
        let config = ServerConfig::from_toml(&path)
            .await
            .with_context(|| format!("failed to read config from {path}"))?;
        if config.upstream.is_none() {
            bail!("configuration file '{path}' is missing required [upstream] section");
        }
        return Ok(config);
    }

    let has_default_toml = tokio::fs::try_exists("styx.toml").await.unwrap_or_default();

    if has_default_toml {
        let config = ServerConfig::from_toml("styx.toml")
            .await
            .context("failed to read default styx.toml config")?;
        if config.upstream.is_none() {
            bail!("default 'styx.toml' is missing required [upstream] section");
        }
        return Ok(config);
    }

    bail!("no configuration file found; please create 'styx.toml' or specify a configuration file path with [upstream] section")
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

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

mod upstream;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context};
use styx_core::{SystemClock, UpstreamId, UpstreamKind};
use styx_net::Do53Client;
use styx_recursion::application::config::RecursionConfig;
use styx_recursion::application::recursor::{Recursor, RecursorPorts, RecursorSettings};
use styx_recursion::domain::root_hints::RootHints;
use styx_recursion::infrastructure::do53_transport::{Do53Transport, DNS_PORT};
use styx_recursion::infrastructure::infra_cache::MemoryInfraCache;
use styx_recursion::infrastructure::sinks::{DiagnosticsStore, DiscardChainMaterial};
use styx_resolution::{
    AllowAllFilter, CacheStage, CanaryConfig, ConfiguredStrategy, DiscardObserver, Do53Forwarder,
    NoLocalRecords, Pipeline, PoolConfig, PoolMember, ProbePolicy, ProbeScheduler, Server,
    ServerConfig, ShardedAnswerCache, UpstreamConfig, UpstreamPool,
};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::EnvFilter;
use upstream::{PoolUpstream, ProductionRecursor};

/// Log filter used when `RUST_LOG` is unset or unusable.
const DEFAULT_LOG_FILTER: LevelFilter = LevelFilter::INFO;

type ConcretePool = UpstreamPool<ConfiguredStrategy, PoolUpstream, SystemClock>;
type ConcreteCache = ShardedAnswerCache<SystemClock>;
type ConcreteStage = CacheStage<ConcreteCache, ConfiguredStrategy, PoolUpstream, SystemClock>;
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

    let (config, recursion) = load_config().await?;
    let pool_config = config
        .upstream
        .as_ref()
        .context("missing [upstream] configuration")?;

    let clock = Arc::new(SystemClock::new());
    let recursion = match recursion {
        Some(recursion) => Some(RecursionWiring::load(recursion).await?),
        None => None,
    };
    let pool = build_pool(pool_config, recursion.as_ref(), &clock)?;
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

/// The `[recursion]` settings with their root hints loaded, and the diagnostics
/// store the admin/web layer will read (Phase 11).
struct RecursionWiring {
    config: RecursionConfig,
    hints: RootHints,
    diagnostics: Arc<DiagnosticsStore>,
}

impl RecursionWiring {
    /// Loads the root hints the section names. A missing or unparseable file is a
    /// startup error, like any other invalid configuration: failing loudly beats a
    /// pool that silently lost its recursor.
    async fn load(config: RecursionConfig) -> anyhow::Result<Self> {
        let hints = RootHints::from_config_path(&config.root_hints)
            .await
            .context("failed to load root hints for the recursor")?;
        Ok(Self {
            config,
            hints,
            diagnostics: Arc::new(DiagnosticsStore::new()),
        })
    }

    fn recursor(&self, id: UpstreamId, clock: &Arc<SystemClock>) -> ProductionRecursor {
        let client = Do53Client::new(
            self.config.udp_timeout,
            self.config.tcp_timeout,
            Arc::clone(clock),
        );
        Recursor::new(
            id,
            RecursorSettings {
                limits: self.config.limits,
                use_ipv6: self.config.use_ipv6,
            },
            &self.hints,
            RecursorPorts {
                clock: Arc::clone(clock),
                transport: Arc::new(Do53Transport::new(client, DNS_PORT)),
                diagnostics: Arc::clone(&self.diagnostics),
                chain_material: Arc::new(DiscardChainMaterial),
                infra: Arc::new(MemoryInfraCache::new(self.config.capacity)),
            },
        )
    }
}

fn build_upstream(
    member_cfg: &UpstreamConfig,
    id: &UpstreamId,
    recursion: Option<&RecursionWiring>,
    clock: &Arc<SystemClock>,
) -> anyhow::Result<PoolUpstream> {
    match member_cfg.kind {
        UpstreamKind::Forwarder => Ok(PoolUpstream::Forwarder(Do53Forwarder::new(
            id.clone(),
            member_cfg.addr,
            member_cfg.edns_buffer,
            member_cfg.timeouts.udp,
            member_cfg.timeouts.tcp,
            Arc::clone(clock),
        ))),
        UpstreamKind::Recursor => {
            let Some(recursion) = recursion else {
                bail!(
                    "pool member '{}' is a recursor, but the file has no [recursion] section",
                    member_cfg.name
                );
            };
            Ok(PoolUpstream::Recursor(Arc::new(
                recursion.recursor(id.clone(), clock),
            )))
        }
    }
}

fn build_pool(
    pool_config: &PoolConfig,
    recursion: Option<&RecursionWiring>,
    clock: &Arc<SystemClock>,
) -> anyhow::Result<Arc<ConcretePool>> {
    let mut members = Vec::with_capacity(pool_config.members.len());
    for member_cfg in &pool_config.members {
        let id = UpstreamId::new(member_cfg.name.as_str());
        let upstream = build_upstream(member_cfg, &id, recursion, clock)?;
        let canary = member_cfg
            .canary
            .clone()
            .unwrap_or_else(|| CanaryConfig::for_kind(member_cfg.kind));
        members.push(PoolMember::new(id, upstream, member_cfg.weight, canary));
    }
    let strategy = ConfiguredStrategy::from_name(pool_config.strategy);
    Ok(Arc::new(UpstreamPool::new(
        members,
        strategy,
        Arc::clone(clock),
        pool_config.circuit.clone(),
        ProbePolicy::new(pool_config.probe.clone()),
    )))
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

/// Reads the TOML file once and parses both sections it owns: the server and pool
/// (`styx-resolution`) and the optional `[recursion]` section (`styx-recursion`).
async fn load_config() -> anyhow::Result<(ServerConfig, Option<RecursionConfig>)> {
    let path = match std::env::args().nth(1) {
        Some(path) => path,
        None if tokio::fs::try_exists("styx.toml").await.unwrap_or_default() => {
            "styx.toml".to_string()
        }
        None => bail!(
            "no configuration file found; please create 'styx.toml' or specify a configuration file path with [upstream] section"
        ),
    };
    let content = tokio::fs::read_to_string(&path)
        .await
        .with_context(|| format!("failed to read config from {path}"))?;
    let config = ServerConfig::from_toml_str(&content)
        .with_context(|| format!("failed to parse config from {path}"))?;
    if config.upstream.is_none() {
        bail!("configuration file '{path}' is missing required [upstream] section");
    }
    let recursion = RecursionConfig::from_toml_str(&content)
        .with_context(|| format!("failed to parse [recursion] from {path}"))?;
    Ok((config, recursion))
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

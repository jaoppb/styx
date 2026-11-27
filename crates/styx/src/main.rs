//! styx — the composition root.
//!
//! This binary is the **only** crate permitted to name every feature crate at
//! once. Cross-feature wiring happens here and nowhere else: a feature crate
//! declares a port in its `domain`, and this binary constructs the adapter and
//! injects it. There is no service locator and no reflection — collaborators
//! are passed to constructors by value at startup.
//!
//! Wires DNS listeners (UDP/TCP, and DoT/DoH when `[tls]` is enabled), server
//! configuration, the resolution pipeline, and graceful shutdown. The Leptos SSR handler
//! is wired in Phase 11.
//!
//! Usage: `styx [config]` runs the resolver; `styx pin [config]` prints the SPKI pin of
//! the DoT/DoH certificate and exits.

mod encrypted;
mod pools;
mod upstream;

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context};
use pools::Pools;
use styx_core::{SystemClock, SystemSleeper, UpstreamId};
use styx_net::Do53Client;
use styx_recursion::application::config::RecursionConfig;
use styx_recursion::application::recursor::{Recursor, RecursorPorts, RecursorSettings};
use styx_recursion::domain::root_hints::RootHints;
use styx_recursion::infrastructure::do53_transport::{Do53Transport, DNS_PORT};
use styx_recursion::infrastructure::infra_cache::MemoryInfraCache;
use styx_recursion::infrastructure::sinks::{DiagnosticsStore, DiscardChainMaterial};
use styx_resolution::{
    AllowAllFilter, CacheConfig, CacheStage, CacheStatsLogger, ConfiguredStrategy, DiscardObserver,
    NoLocalRecords, Pipeline, ProbeScheduler, Server, ServerConfig, ShardedAnswerCache, TlsConfig,
};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::EnvFilter;
use upstream::{PoolUpstream, ProductionRecursor};

/// Log filter used when `RUST_LOG` is unset or unusable.
const DEFAULT_LOG_FILTER: LevelFilter = LevelFilter::INFO;

/// How often the answer cache's counters are logged at `debug`, so `[cache]` can be tuned
/// before the Phase 10 telemetry exists.
const CACHE_STATS_INTERVAL: Duration = Duration::from_secs(60);

type ConcreteCache = ShardedAnswerCache<SystemClock>;
type ConcreteStage = CacheStage<ConcreteCache, ConfiguredStrategy, PoolUpstream, SystemClock>;
type ConcretePipeline =
    Pipeline<NoLocalRecords, AllowAllFilter, DiscardObserver, SystemClock, ConcreteStage>;

/// The `pin` subcommand's name, the one argument that is not a config path: a config file
/// named `pin` is passed as `./pin`.
const PIN_COMMAND: &str = "pin";

const PIN_USAGE: &str = "usage: styx pin [config]";

/// Dispatches to the resolver or to `styx pin`.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next() {
        Some(command) if command == PIN_COMMAND => pin(args).await,
        path => run(path).await,
    }
}

/// Prints the SPKI pin of the DoT/DoH certificate named by the config, or the usage.
async fn pin(mut args: impl Iterator<Item = String>) -> anyhow::Result<()> {
    init_tracing(LogOutput::Stderr);
    let config = args.next();
    if args.next().is_some() {
        bail!("too many arguments; {PIN_USAGE}");
    }
    if matches!(config.as_deref(), Some("-h" | "--help")) {
        writeln!(std::io::stdout().lock(), "{PIN_USAGE}").context("failed to write the usage")?;
        return Ok(());
    }
    let path = config_path(config).await?;
    let content = read_config(&path).await?;
    let tls = TlsConfig::from_toml_str(&content)
        .with_context(|| format!("failed to parse [tls] from {path}"))?;
    encrypted::print_pin(tls).await
}

/// Starts the resolver and supervises its listeners until Ctrl-C.
async fn run(path: Option<String>) -> anyhow::Result<()> {
    init_tracing(LogOutput::Stdout);
    raise_descriptor_limit();

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        web = cfg!(feature = "web"),
        "styx starting"
    );

    let LoadedConfig {
        server: config,
        recursion,
        cache,
        tls,
    } = load_config(path).await?;
    let pool_config = config
        .upstream
        .as_ref()
        .context("missing [upstream] configuration")?;

    let clock = Arc::new(SystemClock::new());
    let encrypted = match tls {
        Some(tls) => Some(encrypted::prepare(tls, Arc::clone(&clock)).await?),
        None => None,
    };
    let recursion = match recursion {
        Some(recursion) => Some(RecursionWiring::load(recursion).await?),
        None => None,
    };
    let pools = Pools::build(pool_config, recursion.as_ref(), &clock)?;
    let answer_cache = build_cache(clock.clone(), &cache)?;
    let pipeline = build_pipeline(
        pools.clone(),
        clock.clone(),
        &config,
        answer_cache.clone(),
        &cache,
    );

    let sleeper = Arc::new(SystemSleeper::new());
    let background = BackgroundTasks::spawn(
        pools.probe_schedulers(&clock, pool_config.probe.tick),
        CacheStatsLogger::new(answer_cache, sleeper.clone(), CACHE_STATS_INTERVAL)?,
    );

    let mut server = Server::bind_with_encrypted(config, encrypted, pipeline, clock, sleeper)
        .await
        .context("failed to bind server listeners")?;

    log_listeners(&server);

    tokio::signal::ctrl_c()
        .await
        .context("failed to listen for shutdown signal")?;

    tracing::info!("shutdown signal received; closing listeners");
    let (server_stopped, background_stopped) = tokio::join!(server.shutdown(), background.stop());
    server_stopped.context("failed to shut down server")?;
    background_stopped
}

/// The tasks that run beside the listeners, sharing one shutdown token.
struct BackgroundTasks {
    shutdown: CancellationToken,
    probe_schedulers: Vec<JoinHandle<()>>,
    cache_stats: JoinHandle<()>,
}

impl BackgroundTasks {
    /// Starts one probe scheduler per pool: the main one and each conditional one.
    fn spawn(
        schedulers: Vec<ProbeScheduler<ConfiguredStrategy, PoolUpstream, SystemClock>>,
        stats_logger: CacheStatsLogger<ConcreteCache, SystemSleeper>,
    ) -> Self {
        let shutdown = CancellationToken::new();
        Self {
            probe_schedulers: schedulers
                .into_iter()
                .map(|scheduler| tokio::spawn(scheduler.run(shutdown.clone())))
                .collect(),
            cache_stats: tokio::spawn(stats_logger.run(shutdown.clone())),
            shutdown,
        }
    }

    /// Cancels every task and waits for all of them, even when one of them failed.
    async fn stop(self) -> anyhow::Result<()> {
        self.shutdown.cancel();
        let mut probe_schedulers = Vec::with_capacity(self.probe_schedulers.len());
        for probe_scheduler in self.probe_schedulers {
            probe_schedulers.push(probe_scheduler.await);
        }
        let cache_stats = self.cache_stats.await;
        for probe_scheduler in probe_schedulers {
            probe_scheduler.context("probe scheduler task failed")?;
        }
        cache_stats.context("cache stats logger task failed")
    }
}

/// Logs every bound listener address.
fn log_listeners<L, F, O, C, T>(server: &Server<L, F, O, C, T>) {
    for addr in server.local_addrs() {
        tracing::info!(%addr, "DNS listener active");
    }
    for addr in server.dot_addrs() {
        tracing::info!(%addr, "DNS-over-TLS listener active");
    }
    for addr in server.doh_addrs() {
        tracing::info!(%addr, "DNS-over-HTTPS listener active");
    }
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

fn build_cache(
    clock: Arc<SystemClock>,
    cache_config: &CacheConfig,
) -> anyhow::Result<Arc<ConcreteCache>> {
    let cache = ShardedAnswerCache::new(clock, cache_config.capacity, cache_config.shards)
        .context("failed to size the answer cache from [cache]")?;
    Ok(Arc::new(cache))
}

fn build_pipeline(
    pools: Pools,
    clock: Arc<SystemClock>,
    config: &ServerConfig,
    cache: Arc<ConcreteCache>,
    cache_config: &CacheConfig,
) -> Arc<ConcretePipeline> {
    let cache_stage = Arc::new(
        CacheStage::from_config(
            cache,
            pools.main,
            cache_config,
            clock.clone(),
            config.query_timeout,
        )
        .with_conditional(pools.conditional),
    );
    Arc::new(
        Pipeline::new(
            Arc::new(NoLocalRecords::new()),
            Arc::new(AllowAllFilter::new()),
            Arc::new(DiscardObserver::new()),
            clock,
        )
        .with_filter_aaaa(config.filter_aaaa)
        .with_terminal(cache_stage),
    )
}

/// What the TOML file holds, one parsed section per owner.
struct LoadedConfig {
    server: ServerConfig,
    recursion: Option<RecursionConfig>,
    cache: CacheConfig,
    tls: Option<TlsConfig>,
}

/// The config path named on the command line, or `styx.toml` in the current directory.
async fn config_path(arg: Option<String>) -> anyhow::Result<String> {
    match arg {
        Some(path) => Ok(path),
        None if tokio::fs::try_exists("styx.toml").await.unwrap_or_default() => {
            Ok("styx.toml".to_string())
        }
        None => bail!(
            "no configuration file found; please create 'styx.toml' or specify a configuration file path with [upstream] section"
        ),
    }
}

async fn read_config(path: &str) -> anyhow::Result<String> {
    tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("failed to read config from {path}"))
}

/// Reads the TOML file once and parses the sections it owns: the server and pool, the
/// `[cache]` and `[tls]` sections (`styx-resolution`), and the optional `[recursion]`
/// section (`styx-recursion`).
async fn load_config(arg: Option<String>) -> anyhow::Result<LoadedConfig> {
    let path = config_path(arg).await?;
    let content = read_config(&path).await?;
    let config = ServerConfig::from_toml_str(&content)
        .with_context(|| format!("failed to parse config from {path}"))?;
    if config.upstream.is_none() {
        bail!("configuration file '{path}' is missing required [upstream] section");
    }
    let recursion = RecursionConfig::from_toml_str(&content)
        .with_context(|| format!("failed to parse [recursion] from {path}"))?;
    let cache = CacheConfig::from_toml_str(&content)
        .with_context(|| format!("failed to parse [cache] from {path}"))?;
    let tls = TlsConfig::from_toml_str(&content)
        .with_context(|| format!("failed to parse [tls] from {path}"))?;
    Ok(LoadedConfig {
        server: config,
        recursion,
        cache,
        tls,
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

/// Where log lines go.
enum LogOutput {
    /// The resolver logs to stdout.
    Stdout,
    /// `styx pin` keeps stdout for the pin alone.
    Stderr,
}

/// Installs the `tracing` subscriber, taking its filter from the environment.
fn init_tracing(output: LogOutput) {
    let builder = EnvFilter::builder().with_default_directive(DEFAULT_LOG_FILTER.into());

    let (filter, rejected) = match builder.from_env() {
        Ok(filter) => (filter, None),
        Err(error) => (EnvFilter::new(DEFAULT_LOG_FILTER.to_string()), Some(error)),
    };

    let subscriber = tracing_subscriber::fmt().with_env_filter(filter);
    match output {
        LogOutput::Stdout => subscriber.init(),
        LogOutput::Stderr => subscriber.with_writer(std::io::stderr).init(),
    }

    if let Some(error) = rejected {
        tracing::warn!(
            %error,
            fallback = %DEFAULT_LOG_FILTER,
            "RUST_LOG could not be parsed; using the fallback filter"
        );
    }
}

#[cfg(test)]
#[path = "main_tests.rs"]
mod tests;

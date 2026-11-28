//! The upstream pools the cache stage sends its misses to: the main pool of
//! `[upstream].members` and one pool per `[[upstream.conditional]]` entry.

use std::sync::Arc;
use std::time::Duration;

use styx_core::{SystemClock, UpstreamId, UpstreamKind};
use styx_resolution::{
    CanaryConfig, ConditionalRoute, ConditionalRoutes, ConfiguredStrategy, Do53Forwarder,
    PoolConfig, PoolMember, ProbePolicy, ProbeScheduler, StrategyName, UpstreamConfig,
    UpstreamPool,
};

use crate::upstream::PoolUpstream;
use crate::RecursionWiring;

pub type ConcretePool = UpstreamPool<ConfiguredStrategy, PoolUpstream, SystemClock>;

/// The main pool and the conditional pools the cache stage sends its misses to.
#[derive(Clone)]
pub struct Pools {
    pub main: Arc<ConcretePool>,
    pub conditional: ConditionalRoutes<Arc<ConcretePool>>,
}

impl Pools {
    pub fn build(
        pool_config: &PoolConfig,
        recursion: &RecursionWiring,
        clock: &Arc<SystemClock>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            main: build_pool(
                pool_config,
                &pool_config.members,
                pool_config.strategy,
                recursion,
                clock,
            )?,
            conditional: build_conditional_routes(pool_config, recursion, clock)?,
        })
    }

    /// One probe scheduler per pool, so every member's health is measured.
    pub fn probe_schedulers(
        &self,
        clock: &Arc<SystemClock>,
        tick: Duration,
    ) -> Vec<ProbeScheduler<ConfiguredStrategy, PoolUpstream, SystemClock>> {
        std::iter::once(&self.main)
            .chain(self.conditional.targets())
            .map(|pool| ProbeScheduler::new(Arc::clone(pool), Arc::clone(clock), tick))
            .collect()
    }
}

fn build_upstream(
    member_cfg: &UpstreamConfig,
    id: &UpstreamId,
    recursion: &RecursionWiring,
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
        UpstreamKind::Recursor => Ok(PoolUpstream::Recursor(Arc::new(
            recursion.recursor(id.clone(), clock)?,
        ))),
    }
}

/// Builds a pool of `members` that shares `[upstream]`'s circuit and probe settings.
fn build_pool(
    pool_config: &PoolConfig,
    members_config: &[UpstreamConfig],
    strategy: StrategyName,
    recursion: &RecursionWiring,
    clock: &Arc<SystemClock>,
) -> anyhow::Result<Arc<ConcretePool>> {
    let mut members = Vec::with_capacity(members_config.len());
    for member_cfg in members_config {
        let id = UpstreamId::new(member_cfg.name.as_str());
        let upstream = build_upstream(member_cfg, &id, recursion, clock)?;
        let canary = member_cfg
            .canary
            .clone()
            .unwrap_or_else(|| CanaryConfig::for_kind(member_cfg.kind));
        members.push(PoolMember::new(id, upstream, member_cfg.weight, canary));
    }
    let strategy = ConfiguredStrategy::from_name(strategy);
    Ok(Arc::new(UpstreamPool::new(
        members,
        strategy,
        Arc::clone(clock),
        pool_config.circuit.clone(),
        ProbePolicy::new(pool_config.probe.clone()),
    )))
}

/// One ordered-failover pool per `[[upstream.conditional]]` entry. Its members are
/// forwarders only, which `PoolConfig` already checked, so `recursion` is never consulted.
fn build_conditional_routes(
    pool_config: &PoolConfig,
    recursion: &RecursionWiring,
    clock: &Arc<SystemClock>,
) -> anyhow::Result<ConditionalRoutes<Arc<ConcretePool>>> {
    let mut routes = Vec::with_capacity(pool_config.conditional.len());
    for entry in &pool_config.conditional {
        let target = build_pool(
            pool_config,
            &entry.members,
            StrategyName::OrderedFailover,
            recursion,
            clock,
        )?;
        routes.push(ConditionalRoute {
            domains: entry.domains.clone(),
            target,
        });
    }
    Ok(ConditionalRoutes::new(routes))
}

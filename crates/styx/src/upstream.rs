//! The pool's upstream type: a forwarder or a recursor, chosen per member by the
//! TOML file.
//!
//! The pool is generic over one upstream type, so a mixed pool needs a sum of the
//! kinds. An enum keeps dispatch static; the composition root is the one place
//! that may name both feature crates' upstreams at once.

use std::sync::Arc;
use std::time::Instant;

use styx_core::{SystemClock, Upstream, UpstreamError, UpstreamId, UpstreamKind, UpstreamResponse};
use styx_proto::Question;
use styx_recursion::application::recursor::Recursor;
use styx_recursion::infrastructure::do53_transport::Do53Transport;
use styx_recursion::infrastructure::infra_cache::MemoryInfraCache;
use styx_recursion::infrastructure::sinks::{DiagnosticsStore, DiscardChainMaterial};
use styx_resolution::Do53Forwarder;

/// The recursor as wired in production: system clock, Do53 transport, in-memory
/// infrastructure cache, diagnostics published to a store for the admin layer,
/// chain material discarded until the DNSSEC validator exists.
pub type ProductionRecursor = Recursor<
    SystemClock,
    Do53Transport<SystemClock>,
    DiagnosticsStore,
    DiscardChainMaterial,
    MemoryInfraCache,
>;

/// One pool member's upstream.
#[derive(Debug, Clone)]
pub enum PoolUpstream {
    /// A Do53 forwarder.
    Forwarder(Do53Forwarder<SystemClock>),
    /// An iterative recursor.
    Recursor(Arc<ProductionRecursor>),
}

impl Upstream for PoolUpstream {
    fn id(&self) -> UpstreamId {
        match self {
            Self::Forwarder(forwarder) => forwarder.id(),
            Self::Recursor(recursor) => recursor.id(),
        }
    }

    fn kind(&self) -> UpstreamKind {
        match self {
            Self::Forwarder(forwarder) => forwarder.kind(),
            Self::Recursor(recursor) => recursor.kind(),
        }
    }

    async fn resolve(
        &self,
        query: &Question,
        deadline: Instant,
    ) -> Result<UpstreamResponse, UpstreamError> {
        match self {
            Self::Forwarder(forwarder) => forwarder.resolve(query, deadline).await,
            Self::Recursor(recursor) => recursor.resolve(query, deadline).await,
        }
    }
}

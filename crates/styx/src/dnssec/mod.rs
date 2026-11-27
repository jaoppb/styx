//! DNSSEC validation on the resolution path: the composition root is the one place that
//! names `styx-dnssec`, `styx-recursion` and `styx-resolution` together.
//!
//! The recursor pushes the DS RRsets its referrals carried into [`PushedReferrals`]; the
//! cache stage hands every upstream answer to [`DnssecValidator`], whose chain source asks
//! the main pool for whatever was not pushed.

#[cfg(test)]
mod acceptance_tests;
mod material_cache;
mod pull;
mod pushed;
#[cfg(test)]
mod test_zone;
mod validator;

use std::sync::Arc;
use std::time::Duration;

use styx_core::SystemClock;
use styx_dnssec::{PinnedRootAnchor, TrustAnchorSource, ValidationPolicy};
use styx_resolution::ConfiguredStrategy;

pub use pull::PoolChainSource;
pub use pushed::PushedReferrals;
pub use validator::DnssecValidator;

use crate::pools::ConcretePool;
use crate::upstream::PoolUpstream;

/// The validator as wired in production.
pub type ProductionValidator =
    DnssecValidator<SystemClock, PoolChainSource<ConfiguredStrategy, PoolUpstream, SystemClock>>;

/// Builds the validator over the pinned IANA root anchors and the default policy, whose
/// failure mode stays `WarnOnly` until the differential run against `unbound` has been read
/// (Phase 06, 6d.8 and 6d.9). Chain material comes from `pushed` first, then from `pool`.
pub fn production_validator(
    pool: Arc<ConcretePool>,
    pushed: Arc<PushedReferrals<SystemClock>>,
    clock: &Arc<SystemClock>,
    query_timeout: Duration,
) -> ProductionValidator {
    let anchors = PinnedRootAnchor::new().anchors();
    let policy = ValidationPolicy::default();
    tracing::info!(failure_mode = ?policy.failure_mode, "DNSSEC validation enabled");
    let source = PoolChainSource::new(
        pool,
        pushed,
        Arc::clone(clock),
        query_timeout,
        &anchors,
        policy.nsec3_max_iterations,
    );
    DnssecValidator::new(SystemClock::new(), policy, anchors, source)
}

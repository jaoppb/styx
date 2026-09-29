//! Probe policy and canary configuration.
//!
//! Enforces probe traffic generation only where passive health is structurally blind:
//! idle-beyond-window standbys and currently down members attempting recovery.

use std::time::{Duration, Instant};

use styx_core::UpstreamKind;
use styx_proto::{Name, RecordType};

use crate::domain::circuit::CircuitState;
use crate::domain::health::HealthState;
use crate::domain::selection::MemberView;

/// Configuration for periodic background probing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeConfig {
    /// Maximum time an upstream may remain without observations before a probe is due.
    pub idle_window: Duration,
    /// Minimum interval between retry probes for a member whose circuit is Open.
    pub down_retry_interval: Duration,
    /// Periodic tick interval for the probe scheduler loop.
    pub tick: Duration,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            idle_window: Duration::from_secs(60),
            down_retry_interval: Duration::from_secs(10),
            tick: Duration::from_secs(1),
        }
    }
}

/// Canary question sent to probe upstream health.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanaryConfig {
    /// Domain name to query.
    pub qname: Name,
    /// Query type.
    pub qtype: RecordType,
    /// Resolution timeout budget for the probe query.
    pub timeout: Duration,
}

impl CanaryConfig {
    /// Generates the standard default canary for the given upstream kind.
    ///
    /// Forwarders receive a single-query canary, whereas recursors receive a
    /// canary that tests a full iterative root descent.
    #[must_use]
    pub fn for_kind(kind: UpstreamKind) -> Self {
        match kind {
            UpstreamKind::Forwarder => Self {
                qname: Name::from_ascii("probe.canary.invalid.").unwrap_or_else(|_| Name::root()),
                qtype: RecordType::A,
                timeout: Duration::from_secs(2),
            },
            UpstreamKind::Recursor => Self {
                qname: Name::from_ascii("root-canary.iana.org.").unwrap_or_else(|_| Name::root()),
                qtype: RecordType::NS,
                timeout: Duration::from_secs(5),
            },
        }
    }
}

/// Pure policy determining whether an upstream is due for an active probe.
///
/// # Invariant
/// Healthy, actively-used upstreams generate zero probe traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbePolicy {
    config: ProbeConfig,
}

impl ProbePolicy {
    /// Creates a new `ProbePolicy` from the provided configuration.
    #[must_use]
    pub const fn new(config: ProbeConfig) -> Self {
        Self { config }
    }

    /// Evaluates whether an upstream member is due for a probe query at `now`.
    #[must_use]
    pub fn due(&self, _view: &MemberView, health: &HealthState, now: Instant) -> bool {
        // Rule 1: Idle beyond configured window (including cold-start with no traffic)
        if health.is_idle_beyond(self.config.idle_window, now) {
            return true;
        }

        // Rule 2: Open circuit past retry interval
        if let CircuitState::Open { .. } = health.circuit() {
            let last_probe = health.last_probe_at();
            let due_for_retry = match last_probe {
                None => true,
                Some(last) => {
                    now.checked_duration_since(last).unwrap_or_default()
                        >= self.config.down_retry_interval
                }
            };
            if due_for_retry {
                return true;
            }
        }

        // Rule 3: Healthy with recent traffic is never due (unconditionally false)
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::circuit::CircuitConfig;
    use crate::domain::health::Outcome;
    use crate::domain::weight::Weight;
    use styx_core::UpstreamId;

    fn make_view(available: bool) -> MemberView {
        MemberView {
            id: UpstreamId::new("up1"),
            kind: UpstreamKind::Forwarder,
            weight: Weight::new(1),
            srtt: Some(Duration::from_millis(10)),
            circuit: if available {
                CircuitState::Closed
            } else {
                CircuitState::Open {
                    since: Instant::now(),
                }
            },
            available,
        }
    }

    #[test]
    fn test_healthy_recent_traffic_never_due() {
        let policy = ProbePolicy::new(ProbeConfig::default());
        let mut health = HealthState::new();
        let circuit_config = CircuitConfig::default();
        let now = Instant::now();

        // Fresh outcome within window
        health.observe(
            Outcome::Success {
                latency: Duration::from_millis(5),
                was_probe: false,
            },
            now,
            &circuit_config,
        );

        let view = make_view(true);
        // 5 seconds later (window is 60s): NOT DUE
        let check_time = now.checked_add(Duration::from_secs(5)).expect("valid add");
        assert!(!policy.due(&view, &health, check_time));
    }

    #[test]
    fn test_cold_start_and_idle_due() {
        let policy = ProbePolicy::new(ProbeConfig::default());
        let health = HealthState::new();
        let now = Instant::now();
        let view = make_view(true);

        // Cold-start is immediately due
        assert!(policy.due(&view, &health, now));
    }
}

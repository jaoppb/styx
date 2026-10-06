//! One shared exchange as its detached task runs it: send, time, and record what
//! the server showed about its health exactly once, however many descents wait.

use std::sync::Arc;
use std::time::Duration;

use styx_core::Clock;
use styx_proto::{Name, Question, ResponseCode};

use crate::application::diagnostics::DiagnosticsState;
use crate::application::single_flight::Outcome;
use crate::domain::metrics::{EdnsCapability, MetricEvent};
use crate::domain::ports::{EdnsObservation, InfraCache, Transport, TransportError};
use crate::domain::topology::NameserverAddr;

/// Longest one shared exchange may run, whoever started it. The transport's own
/// UDP and TCP timeouts apply inside it; this only bounds an exchange that outlives
/// every caller.
pub const EXCHANGE_DEADLINE: Duration = Duration::from_secs(2);

/// Everything one exchange needs, owned, so it can outlive the descent that began it.
pub(crate) struct ExchangeJob<C, T, I> {
    pub(crate) clock: Arc<C>,
    pub(crate) transport: Arc<T>,
    pub(crate) infra: Arc<I>,
    pub(crate) stats: Arc<DiagnosticsState>,
    pub(crate) server: NameserverAddr,
    pub(crate) sent: Question,
    pub(crate) zone: Name,
    pub(crate) edns: EdnsCapability,
}

impl<C: Clock, T: Transport, I: InfraCache> ExchangeJob<C, T, I> {
    /// Sends the question, then records the outcome once.
    pub(crate) async fn run(self) -> Outcome {
        let sent_at = self.clock.now_monotonic();
        let deadline = sent_at.checked_add(EXCHANGE_DEADLINE).unwrap_or(sent_at);
        let outcome = self
            .transport
            .query(self.server, &self.sent, self.edns, deadline)
            .await;
        let finished = self.clock.now_monotonic();
        let rtt = finished.saturating_duration_since(sent_at);
        self.record(&outcome, rtt, finished);
        outcome
    }

    fn record(&self, outcome: &Outcome, rtt: Duration, now: std::time::Instant) {
        let answered = outcome.is_ok();
        if self.zone.is_root() {
            self.stats
                .record_root_contact(self.server.ip(), answered.then_some(rtt), now);
        } else if self.zone.label_count() == 1 {
            self.stats.record_tld_contact(&self.zone, answered, now);
        }
        match outcome {
            Ok(reply) => {
                self.stats.note_reply(now);
                self.record_reply(reply.message.header.rcode, &reply.edns, rtt, now);
            }
            Err(failure) => {
                let unhealthy = matches!(
                    failure.error,
                    TransportError::Timeout | TransportError::Unreachable(_)
                );
                if unhealthy {
                    self.infra
                        .update_metrics(self.server, MetricEvent::Failure, now);
                }
            }
        }
    }

    /// A SERVFAIL is a failure of the server, not a sample of its speed.
    fn record_reply(
        &self,
        rcode: ResponseCode,
        edns: &EdnsObservation,
        rtt: Duration,
        now: std::time::Instant,
    ) {
        let health = if rcode == ResponseCode::SERVFAIL {
            MetricEvent::Failure
        } else {
            MetricEvent::Success(rtt)
        };
        self.infra.update_metrics(self.server, health, now);
        match edns {
            EdnsObservation::Supported(size) => {
                self.infra
                    .update_metrics(self.server, MetricEvent::EdnsSupported(*size), now);
            }
            EdnsObservation::Intolerant => {
                self.infra
                    .update_metrics(self.server, MetricEvent::EdnsIntolerant, now);
            }
            EdnsObservation::Inconclusive => {}
        }
    }
}

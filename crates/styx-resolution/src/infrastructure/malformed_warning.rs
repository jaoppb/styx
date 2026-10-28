//! The throttled warning every listener raises for a query it cannot decode.

use std::net::SocketAddr;
use std::sync::Arc;

use styx_core::{Clock, Sleeper};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::infrastructure::warn_gate::{FlushPlan, Verdict, WarnGate};

/// The transport a [`MalformedWarning`] speaks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ListenerKind {
    Udp,
    Tcp,
    Dot,
}

/// At most one `warn` per [`WARN_INTERVAL`](super::admission::WARN_INTERVAL) from one
/// listener for malformed queries, however many arrive.
///
/// Every malformed query still gets its FORMERR reply and its own `debug` event; only the
/// `warn` is throttled. The first line of a burst goes out at once. The rest of the burst is
/// counted and reported by a second line when the interval closes, so a flood costs two log
/// lines per interval and never an unbounded number.
///
/// One instance belongs to one socket or one listener. With `udp_sockets_per_addr` above one,
/// each socket throttles on its own, so the ceiling is one line per socket per interval.
pub(crate) struct MalformedWarning<C, S> {
    gate: WarnGate,
    kind: ListenerKind,
    addr: SocketAddr,
    clock: Arc<C>,
    sleeper: Arc<S>,
    tasks: TaskTracker,
    shutdown: CancellationToken,
    abort: CancellationToken,
}

impl<C, S> MalformedWarning<C, S>
where
    C: Clock,
    S: Sleeper,
{
    pub(crate) fn new(
        kind: ListenerKind,
        addr: SocketAddr,
        clock: Arc<C>,
        sleeper: Arc<S>,
        tasks: TaskTracker,
        shutdown: CancellationToken,
        abort: CancellationToken,
    ) -> Arc<Self> {
        Arc::new(Self {
            gate: WarnGate::default(),
            kind,
            addr,
            clock,
            sleeper,
            tasks,
            shutdown,
            abort,
        })
    }

    /// Records one malformed query, logging or scheduling the log line as the gate decides.
    pub(crate) fn record(self: &Arc<Self>) {
        match self.gate.record(self.clock.now_monotonic()) {
            Verdict::Emit { suppressed } => self.emit(suppressed),
            Verdict::Suppressed { flush: Some(plan) } => self.spawn_flush(plan),
            Verdict::Suppressed { flush: None } => {}
        }
    }

    /// Reports the interval's count once it closes, or at once if shutdown begins first.
    ///
    /// The task belongs to the listener's tracker, so shutdown waits for it; it ends on the
    /// shutdown signal rather than running out its sleep, and drops the count silently only
    /// when the drain grace period has expired.
    fn spawn_flush(self: &Arc<Self>, plan: FlushPlan) {
        let this = Arc::clone(self);
        self.tasks.spawn(async move {
            tokio::select! {
                () = this.abort.cancelled() => return,
                () = this.shutdown.cancelled() => {}
                () = this.sleeper.sleep(plan.after()) => {}
            }
            let closed = this.clock.now_monotonic();
            if let Some(suppressed) = this.gate.flush(plan.epoch(), closed) {
                this.emit(suppressed);
            }
        });
    }

    fn emit(&self, suppressed: u64) {
        match self.kind {
            ListenerKind::Udp => tracing::warn!(
                addr = %self.addr,
                suppressed,
                "malformed UDP datagrams; answering FORMERR (per-datagram detail at debug)"
            ),
            ListenerKind::Tcp => tracing::warn!(
                addr = %self.addr,
                suppressed,
                "malformed TCP queries; answering FORMERR (per-query detail at debug)"
            ),
            ListenerKind::Dot => tracing::warn!(
                addr = %self.addr,
                suppressed,
                "malformed DoT queries; answering FORMERR (per-query detail at debug)"
            ),
        }
    }
}

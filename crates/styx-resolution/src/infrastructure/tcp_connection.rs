//! One accepted stream connection — plaintext TCP or DNS over TLS: a reader that admits
//! pipelined queries, one task per query, and a single writer that owns the write half.

use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use styx_core::{Clock, Sleeper};

use crate::application::terminal::TerminalHandler;
use crate::domain::ports::filter::FilterPolicy;
use crate::domain::ports::local::LocalRecords;
use crate::domain::ports::observer::QueryObserver;
use crate::domain::request::Transport;
use crate::infrastructure::admission::{ListenerShared, QueryPermit};
pub use crate::infrastructure::connection_bounds::{ConnectionInFlight, InFlightSlot};
use crate::infrastructure::connection_bounds::{
    ConnectionLimiter, QueryCeiling, QueryLimit, Spend,
};
use crate::infrastructure::framing::{read_frame, send_frame, SendFrameError};
use crate::infrastructure::malformed_warning::MalformedWarning;
use crate::infrastructure::stream_query::{QueryTask, StreamOutcome};

/// An encoded response on its way to the writer, carrying its in-flight slot.
#[derive(Debug)]
pub struct OutboundFrame {
    body: Vec<u8>,
    _slot: InFlightSlot,
}

/// Per-connection settings fixed at accept time.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ConnectionSettings {
    pub(crate) idle_timeout: Duration,
    pub(crate) write_timeout: Duration,
    pub(crate) max_in_flight: NonZeroUsize,
    pub(crate) transport: Transport,
    pub(crate) query_limit: QueryLimit,
}

/// One accepted connection.
pub(crate) struct Connection<L, F, O, C, T, S> {
    shared: ListenerShared<L, F, O, C, T, S>,
    settings: ConnectionSettings,
    malformed_warning: Arc<MalformedWarning<C, S>>,
    closing: CancellationToken,
    peer: SocketAddr,
}

impl<L, F, O, C, T, S> Connection<L, F, O, C, T, S>
where
    L: LocalRecords + Send + Sync + 'static,
    F: FilterPolicy + Send + Sync + 'static,
    O: QueryObserver + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    T: TerminalHandler + Send + Sync + 'static,
    S: Sleeper + Send + Sync + 'static,
{
    pub(crate) fn new(
        shared: ListenerShared<L, F, O, C, T, S>,
        settings: ConnectionSettings,
        malformed_warning: Arc<MalformedWarning<C, S>>,
        closing: CancellationToken,
        peer: SocketAddr,
    ) -> Self {
        Self {
            shared,
            settings,
            malformed_warning,
            closing,
            peer,
        }
    }

    /// Serves a plaintext TCP connection using lock-free `TcpStream::into_split`.
    pub(crate) async fn run_tcp(self, stream: TcpStream) {
        let (read_half, write_half) = stream.into_split();
        self.run_halves(read_half, write_half).await;
    }

    /// Serves a stream (such as a TLS stream) that must be split via `tokio::io::split`.
    pub(crate) async fn run<St>(self, stream: St)
    where
        St: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (read_half, write_half) = tokio::io::split(stream);
        self.run_halves(read_half, write_half).await;
    }

    async fn run_halves<R, W>(self, read_half: R, write_half: W)
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let limiter = ConnectionLimiter::new(
            self.settings.max_in_flight,
            QueryCeiling::new(self.settings.query_limit),
            self.settings.idle_timeout,
        );
        let (frames, outbound) = mpsc::channel(self.settings.max_in_flight.get());
        tokio::join!(
            self.read_loop(read_half, frames, &limiter),
            self.write_loop(write_half, outbound),
        );
    }

    async fn read_loop<R: AsyncRead + Unpin>(
        &self,
        mut read_half: R,
        frames: mpsc::Sender<OutboundFrame>,
        limiter: &ConnectionLimiter,
    ) {
        loop {
            let frame = tokio::select! {
                () = self.closing.cancelled() => return,
                frame = self.next_frame(&mut read_half, limiter) => frame,
            };
            let Some(frame) = frame else {
                return;
            };
            if !self.admit(frame, &frames, limiter).await {
                return;
            }
            if limiter.spend() != Spend::Within {
                tracing::debug!(
                    peer = %self.peer,
                    transport = self.settings.transport.name(),
                    admitted = limiter.seen(),
                    "per-connection query ceiling reached; closing after the answers"
                );
                return;
            }
        }
    }

    /// Reads the next frame; the idle timer runs only while nothing is outstanding.
    async fn next_frame<R: AsyncRead + Unpin>(
        &self,
        read_half: &mut R,
        limiter: &ConnectionLimiter,
    ) -> Option<Vec<u8>> {
        tokio::select! {
            () = limiter.idle_expired() => {
                tracing::debug!(peer = %self.peer, transport = self.settings.transport.name(), "stream connection idle; closing");
                None
            }
            frame = read_frame(read_half, self.settings.idle_timeout) => match frame {
                Ok(frame) => frame,
                Err(err) => {
                    tracing::debug!(peer = %self.peer, transport = self.settings.transport.name(), %err, "stream closed or timed out");
                    None
                }
            },
        }
    }

    /// Takes a slot, then a query permit, then spawns the query; `false` ends the reader.
    async fn admit(
        &self,
        frame: Vec<u8>,
        frames: &mpsc::Sender<OutboundFrame>,
        limiter: &ConnectionLimiter,
    ) -> bool {
        let received_at = self.shared.clock.now_monotonic();
        let slot = tokio::select! {
            () = self.closing.cancelled() => None,
            slot = limiter.track() => slot,
        };
        let Some(slot) = slot else {
            return false;
        };
        let permit = tokio::select! {
            () = self.closing.cancelled() => None,
            permit = self.shared.budget.acquire() => permit,
        };
        let Some(permit) = permit else {
            return false;
        };

        let query = QueryTask::new(
            self.shared.clone(),
            Arc::clone(&self.malformed_warning),
            self.peer,
            self.settings.transport,
            received_at,
        );
        let frames = frames.clone();
        let abort = self.shared.abort.clone();
        self.shared.tasks.spawn(async move {
            tokio::select! {
                () = abort.cancelled() => {}
                () = answer_frame(query, frame, permit, slot, frames) => {}
            }
        });
        true
    }

    /// Writes frames in completion order until every sender is gone or a write fails.
    async fn write_loop<W: AsyncWrite + Unpin>(
        &self,
        mut write_half: W,
        mut outbound: mpsc::Receiver<OutboundFrame>,
    ) {
        while let Some(frame) = outbound.recv().await {
            match send_frame(&mut write_half, &frame.body, self.settings.write_timeout).await {
                Ok(()) => {}
                Err(SendFrameError::TimedOut) => {
                    tracing::debug!(peer = %self.peer, transport = self.settings.transport.name(), "response write timed out; closing");
                    self.closing.cancel();
                    return;
                }
                Err(err) => {
                    tracing::debug!(peer = %self.peer, transport = self.settings.transport.name(), %err, "failed to write response frame");
                    self.closing.cancel();
                    return;
                }
            }
        }
        // Every answer is written: close our side, which over TLS sends close_notify so
        // the client sees a clean end rather than a truncated stream.
        let closed = tokio::time::timeout(self.settings.write_timeout, write_half.shutdown()).await;
        if !matches!(closed, Ok(Ok(()))) {
            tracing::debug!(peer = %self.peer, transport = self.settings.transport.name(), "stream did not close cleanly");
        }
    }
}

/// Answers one framed query; the global permit is released as soon as the response is
/// encoded, before it is queued, so a slow reader cannot pin the budget.
async fn answer_frame<L, F, O, C, T, S>(
    query: QueryTask<L, F, O, C, T, S>,
    frame: Vec<u8>,
    permit: QueryPermit,
    slot: InFlightSlot,
    frames: mpsc::Sender<OutboundFrame>,
) where
    L: LocalRecords + Send + Sync + 'static,
    F: FilterPolicy + Send + Sync + 'static,
    O: QueryObserver + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    T: TerminalHandler + Send + Sync + 'static,
    S: Sleeper + Send + Sync + 'static,
{
    let peer = query.peer();
    let transport = query.transport().name();
    let outcome = query.respond(&frame).await;
    drop(permit);
    let StreamOutcome::Answered(answer) = outcome else {
        return;
    };
    if frames
        .send(OutboundFrame {
            body: answer.wire,
            _slot: slot,
        })
        .await
        .is_err()
    {
        tracing::debug!(%peer, transport, "connection writer gone; dropping response");
    }
}

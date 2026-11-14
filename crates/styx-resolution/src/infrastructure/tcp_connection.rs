//! One accepted stream connection — plaintext TCP or DNS over TLS: a reader that admits
//! pipelined queries, one task per query, and a single writer that owns the write half.

use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use styx_proto::application::Decoder;
use styx_proto::{DecodeError, Message, MessageKind};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use styx_core::{Clock, Sleeper};

use crate::application::terminal::TerminalHandler;
use crate::domain::client_reply::error_reply;
use crate::domain::ports::filter::FilterPolicy;
use crate::domain::ports::local::LocalRecords;
use crate::domain::ports::observer::QueryObserver;
use crate::domain::request::{ClientId, MaxResponseSize, RequestContext, Transport};
use crate::infrastructure::admission::{ListenerShared, QueryPermit};
pub use crate::infrastructure::connection_bounds::{ConnectionInFlight, InFlightSlot};
use crate::infrastructure::connection_bounds::{ConnectionLimiter, QueryLimit, Spend};
use crate::infrastructure::early_reply::{badvers_reply, formerr_reply};
use crate::infrastructure::framing::read_frame;
use crate::infrastructure::malformed_warning::MalformedWarning;
use crate::infrastructure::response::ResponseWriter;
use styx_net::write_framed;

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

    /// Serves the connection until it is closed, idles out, or the server shuts down.
    ///
    /// The reader and the writer run as two halves of this one task. Once the reader
    /// stops, outstanding queries still finish and the writer drains their responses
    /// before the connection closes.
    pub(crate) async fn run<St>(self, stream: St)
    where
        St: AsyncRead + AsyncWrite + Send + 'static,
    {
        let (read_half, write_half) = tokio::io::split(stream);
        let limiter = ConnectionLimiter::new(
            self.settings.max_in_flight,
            self.settings.query_limit.ceiling(),
            self.settings.idle_timeout,
        );
        let (frames, outbound) = mpsc::channel(self.settings.max_in_flight.get());
        tokio::join!(
            self.read_loop(read_half, frames, &limiter),
            self.write_loop(write_half, outbound),
        );
    }

    async fn read_loop<R: AsyncRead>(
        &self,
        mut read_half: ReadHalf<R>,
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
                    transport = ?self.settings.transport,
                    admitted = limiter.seen(),
                    "per-connection query ceiling reached; closing after the answers"
                );
                return;
            }
        }
    }

    /// Reads the next frame; the idle timer runs only while nothing is outstanding.
    async fn next_frame<R: AsyncRead>(
        &self,
        read_half: &mut ReadHalf<R>,
        limiter: &ConnectionLimiter,
    ) -> Option<Vec<u8>> {
        tokio::select! {
            () = limiter.idle_expired() => {
                tracing::debug!(peer = %self.peer, transport = ?self.settings.transport, "stream connection idle; closing");
                None
            }
            frame = read_frame(read_half, self.settings.idle_timeout) => match frame {
                Ok(frame) => frame,
                Err(err) => {
                    tracing::debug!(peer = %self.peer, transport = ?self.settings.transport, %err, "stream closed or timed out");
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
                () = query.answer(frame, permit, slot, frames) => {}
            }
        });
        true
    }

    /// Writes frames in completion order until every sender is gone or a write fails.
    async fn write_loop<W: AsyncWrite>(
        &self,
        mut write_half: WriteHalf<W>,
        mut outbound: mpsc::Receiver<OutboundFrame>,
    ) {
        while let Some(frame) = outbound.recv().await {
            let written = tokio::time::timeout(
                self.settings.write_timeout,
                write_framed(&mut write_half, &frame.body),
            )
            .await;
            match written {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    tracing::debug!(peer = %self.peer, transport = ?self.settings.transport, %err, "failed to write response frame");
                    self.closing.cancel();
                    return;
                }
                Err(_) => {
                    tracing::debug!(peer = %self.peer, transport = ?self.settings.transport, "response write timed out; closing");
                    self.closing.cancel();
                    return;
                }
            }
        }
        // Every answer is written: close our side, which over TLS sends close_notify so
        // the client sees a clean end rather than a truncated stream.
        let closed = tokio::time::timeout(self.settings.write_timeout, write_half.shutdown()).await;
        if !matches!(closed, Ok(Ok(()))) {
            tracing::debug!(peer = %self.peer, transport = ?self.settings.transport, "stream did not close cleanly");
        }
    }
}

/// One query, answered on its own task: decoded, run through the pipeline and encoded the
/// same way for every stream transport, DoH included.
pub(crate) struct QueryTask<L, F, O, C, T, S> {
    shared: ListenerShared<L, F, O, C, T, S>,
    malformed_warning: Arc<MalformedWarning<C, S>>,
    peer: SocketAddr,
    transport: Transport,
    received_at: Instant,
}

impl<L, F, O, C, T, S> QueryTask<L, F, O, C, T, S>
where
    L: LocalRecords + Send + Sync + 'static,
    F: FilterPolicy + Send + Sync + 'static,
    O: QueryObserver + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    T: TerminalHandler + Send + Sync + 'static,
    S: Sleeper + Send + Sync + 'static,
{
    /// Answers the query; the global permit is released as soon as the response is
    /// encoded, before it is queued, so a slow reader cannot pin the budget.
    async fn answer(
        self,
        frame: Vec<u8>,
        permit: QueryPermit,
        slot: InFlightSlot,
        frames: mpsc::Sender<OutboundFrame>,
    ) {
        let body = self.respond(&frame).await;
        drop(permit);
        let Some(body) = body else {
            return;
        };
        if frames
            .send(OutboundFrame { body, _slot: slot })
            .await
            .is_err()
        {
            tracing::debug!(peer = %self.peer, transport = ?self.transport, "connection writer gone; dropping response");
        }
    }

    /// A query task for `peer` on `transport`, received at `received_at`.
    pub(crate) fn new(
        shared: ListenerShared<L, F, O, C, T, S>,
        malformed_warning: Arc<MalformedWarning<C, S>>,
        peer: SocketAddr,
        transport: Transport,
        received_at: Instant,
    ) -> Self {
        Self {
            shared,
            malformed_warning,
            peer,
            transport,
            received_at,
        }
    }

    /// The encoded answer to `bytes`, or `None` when the message gets no answer at all.
    pub(crate) async fn respond(&self, bytes: &[u8]) -> Option<Vec<u8>> {
        let mut decoder = Decoder::new(bytes);
        let query = match decoder.decode_message() {
            Ok(msg) => msg,
            Err(DecodeError::UnsupportedEdnsVersion(rejected)) => {
                tracing::debug!(peer = %self.peer, version = rejected.version(), "unsupported EDNS version; answering BADVERS");
                return self.reply_early(badvers_reply(&rejected));
            }
            Err(err) => {
                tracing::debug!(peer = %self.peer, transport = ?self.transport, %err, "malformed stream query; responding FORMERR");
                self.malformed_warning.record();
                return self.reply_early(formerr_reply(bytes));
            }
        };

        if query.header.kind == MessageKind::Response {
            tracing::debug!(peer = %self.peer, transport = ?self.transport, "silently dropping inbound response (QR=1)");
            return None;
        }

        let client = ClientId::from_socket_addr(self.peer);
        let max_size = MaxResponseSize::tcp_ceiling();
        let ctx = RequestContext::new(
            query,
            client,
            self.transport,
            max_size,
            self.shared.udp_payload_size_default,
            self.received_at,
        );
        let pipeline = &self.shared.pipeline;
        let response = match pipeline
            .handle_within(&ctx, self.shared.query_timeout)
            .await
        {
            Ok(msg) => msg,
            Err(crate::domain::error::PipelineError::InboundResponse) => return None,
            Err(err) => error_reply(&ctx.query, err.response_code()),
        };
        self.encode(response, &ctx)
    }

    /// Encodes `reply` to a query that never reached the pipeline, or drops it when there is
    /// no reply to give.
    fn reply_early(&self, reply: Option<Message>) -> Option<Vec<u8>> {
        let Some(reply) = reply else {
            tracing::debug!(peer = %self.peer, transport = ?self.transport, "silently dropping unanswerable message");
            return None;
        };
        self.encode_error_reply(reply)
    }

    /// Encodes a reply to a query that never reached the pipeline.
    fn encode_error_reply(&self, resp: Message) -> Option<Vec<u8>> {
        let client = ClientId::from_socket_addr(self.peer);
        let ctx = RequestContext::new(
            resp.clone(),
            client,
            self.transport,
            MaxResponseSize::tcp_ceiling(),
            self.shared.udp_payload_size_default,
            self.received_at,
        );
        self.encode(resp, &ctx)
    }

    fn encode(&self, message: Message, ctx: &RequestContext) -> Option<Vec<u8>> {
        match ResponseWriter::new().write(message, ctx) {
            Ok(body) => Some(body),
            Err(err) => {
                tracing::error!(peer = %self.peer, transport = ?self.transport, %err, "failed to serialize stream response");
                None
            }
        }
    }
}

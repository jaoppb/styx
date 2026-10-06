//! One accepted TCP connection: a reader that admits pipelined queries, one task per
//! query, and a single writer that owns the write half.

use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use styx_proto::application::Decoder;
use styx_proto::{Header, Message, MessageKind, ResponseCode};
use tokio::io::AsyncReadExt;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Notify, OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;

use styx_core::Clock;

use crate::application::terminal::TerminalHandler;
use crate::domain::error::ListenerError;
use crate::domain::ports::filter::FilterPolicy;
use crate::domain::ports::local::LocalRecords;
use crate::domain::ports::observer::QueryObserver;
use crate::domain::request::{ClientId, MaxResponseSize, RequestContext, Transport};
use crate::infrastructure::admission::{ListenerShared, QueryPermit};
use crate::infrastructure::response::ResponseWriter;
use styx_net::write_framed;

/// The outstanding queries of one connection, counted by semaphore slots.
///
/// A query holds its slot from admission until its response is written, so the
/// connection is idle exactly when every slot is free.
#[derive(Debug)]
pub struct ConnectionInFlight {
    slots: Arc<Semaphore>,
    capacity: NonZeroUsize,
    released: Arc<Notify>,
}

impl ConnectionInFlight {
    /// Creates a tracker allowing `capacity` outstanding queries.
    #[must_use]
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            slots: Arc::new(Semaphore::new(capacity.get())),
            capacity,
            released: Arc::new(Notify::new()),
        }
    }

    /// Waits for a free slot; `None` only if the tracker has been closed.
    pub async fn track(&self) -> Option<InFlightSlot> {
        let permit = Arc::clone(&self.slots).acquire_owned().await.ok()?;
        Some(InFlightSlot {
            permit: Some(permit),
            released: Arc::clone(&self.released),
        })
    }

    /// Returns `true` when no query is outstanding.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        self.slots.available_permits() == self.capacity.get()
    }

    /// Resolves once no query is outstanding.
    pub async fn idle(&self) {
        loop {
            let notified = self.released.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_idle() {
                return;
            }
            notified.await;
        }
    }
}

/// One outstanding query on a connection; frees its slot when dropped.
#[derive(Debug)]
pub struct InFlightSlot {
    permit: Option<OwnedSemaphorePermit>,
    released: Arc<Notify>,
}

impl Drop for InFlightSlot {
    fn drop(&mut self) {
        // Release before notifying, so a woken `idle()` sees the freed slot.
        drop(self.permit.take());
        self.released.notify_waiters();
    }
}

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
}

/// One accepted connection.
pub(crate) struct Connection<L, F, O, C, T> {
    shared: ListenerShared<L, F, O, C, T>,
    settings: ConnectionSettings,
    closing: CancellationToken,
    peer: SocketAddr,
}

impl<L, F, O, C, T> Connection<L, F, O, C, T>
where
    L: LocalRecords + Send + Sync + 'static,
    F: FilterPolicy + Send + Sync + 'static,
    O: QueryObserver + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    T: TerminalHandler + Send + Sync + 'static,
{
    pub(crate) fn new(
        shared: ListenerShared<L, F, O, C, T>,
        settings: ConnectionSettings,
        closing: CancellationToken,
        peer: SocketAddr,
    ) -> Self {
        Self {
            shared,
            settings,
            closing,
            peer,
        }
    }

    /// Serves the connection until it is closed, idles out, or the server shuts down.
    ///
    /// The reader and the writer run as two halves of this one task. Once the reader
    /// stops, outstanding queries still finish and the writer drains their responses
    /// before the connection closes.
    pub(crate) async fn run(self, stream: TcpStream) {
        let (read_half, write_half) = stream.into_split();
        let in_flight = ConnectionInFlight::new(self.settings.max_in_flight);
        let (frames, outbound) = mpsc::channel(self.settings.max_in_flight.get());
        tokio::join!(
            self.read_loop(read_half, frames, &in_flight),
            self.write_loop(write_half, outbound),
        );
    }

    async fn read_loop(
        &self,
        mut read_half: OwnedReadHalf,
        frames: mpsc::Sender<OutboundFrame>,
        in_flight: &ConnectionInFlight,
    ) {
        loop {
            let frame = tokio::select! {
                () = self.closing.cancelled() => return,
                frame = self.next_frame(&mut read_half, in_flight) => frame,
            };
            let Some(frame) = frame else {
                return;
            };
            if !self.admit(frame, &frames, in_flight).await {
                return;
            }
        }
    }

    /// Reads the next frame; the idle timer runs only while nothing is outstanding.
    async fn next_frame(
        &self,
        read_half: &mut OwnedReadHalf,
        in_flight: &ConnectionInFlight,
    ) -> Option<Vec<u8>> {
        let idle_timeout = self.settings.idle_timeout;
        let idle_timer = async {
            in_flight.idle().await;
            tokio::time::sleep(idle_timeout).await;
        };
        tokio::select! {
            () = idle_timer => {
                tracing::debug!(peer = %self.peer, "TCP connection idle; closing");
                None
            }
            frame = read_frame(read_half, idle_timeout) => match frame {
                Ok(frame) => frame,
                Err(err) => {
                    tracing::debug!(peer = %self.peer, %err, "TCP stream closed or timed out");
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
        in_flight: &ConnectionInFlight,
    ) -> bool {
        let received_at = self.shared.clock.now_monotonic();
        let slot = tokio::select! {
            () = self.closing.cancelled() => None,
            slot = in_flight.track() => slot,
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

        let query = QueryTask {
            shared: self.shared.clone(),
            peer: self.peer,
            received_at,
        };
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
    async fn write_loop(
        &self,
        mut write_half: OwnedWriteHalf,
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
                    tracing::debug!(peer = %self.peer, %err, "failed to write TCP response frame");
                    self.closing.cancel();
                    return;
                }
                Err(_) => {
                    tracing::debug!(peer = %self.peer, "TCP response write timed out; closing");
                    self.closing.cancel();
                    return;
                }
            }
        }
    }
}

/// Reads one length-prefixed frame. The prefix read has no timeout of its own — the
/// caller races it against the idle timer — but the payload must follow promptly.
async fn read_frame(
    read_half: &mut OwnedReadHalf,
    payload_timeout: Duration,
) -> Result<Option<Vec<u8>>, ListenerError> {
    let mut prefix = [0u8; 2];
    match read_half.read_exact(&mut prefix).await {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(ListenerError::Io(err)),
    }

    let len = usize::from(u16::from_be_bytes(prefix));
    if len == 0 {
        return Err(ListenerError::Framing(
            "zero-length TCP frame received".into(),
        ));
    }

    let mut payload = vec![0u8; len];
    let read_payload = tokio::time::timeout(payload_timeout, read_half.read_exact(&mut payload));
    match read_payload.await {
        Ok(Ok(_)) => Ok(Some(payload)),
        Ok(Err(err)) => Err(ListenerError::Io(err)),
        Err(_) => Err(ListenerError::Framing(
            "timeout reading TCP frame payload".into(),
        )),
    }
}

/// One pipelined query, answered on its own task.
struct QueryTask<L, F, O, C, T> {
    shared: ListenerShared<L, F, O, C, T>,
    peer: SocketAddr,
    received_at: Instant,
}

impl<L, F, O, C, T> QueryTask<L, F, O, C, T>
where
    L: LocalRecords + Send + Sync + 'static,
    F: FilterPolicy + Send + Sync + 'static,
    O: QueryObserver + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    T: TerminalHandler + Send + Sync + 'static,
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
            tracing::debug!(peer = %self.peer, "TCP writer gone; dropping response");
        }
    }

    async fn respond(&self, bytes: &[u8]) -> Option<Vec<u8>> {
        let mut decoder = Decoder::new(bytes);
        let query = match decoder.decode_message() {
            Ok(msg) => msg,
            Err(err) => {
                tracing::warn!(peer = %self.peer, %err, "malformed TCP query; responding FORMERR");
                return self.formerr(bytes);
            }
        };

        if query.header.kind == MessageKind::Response {
            tracing::debug!(peer = %self.peer, "silently dropping inbound TCP response (QR=1)");
            return None;
        }

        let client = ClientId::from_socket_addr(self.peer);
        let max_size = MaxResponseSize::tcp_ceiling();
        let ctx = RequestContext::new(
            query,
            client,
            Transport::Tcp,
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
            Err(err) => error_response(&ctx, err.response_code()),
        };
        self.encode(response, &ctx)
    }

    fn formerr(&self, bytes: &[u8]) -> Option<Vec<u8>> {
        if bytes.get(2).is_some_and(|&b| (b & 0x80) != 0) {
            tracing::debug!(peer = %self.peer, "silently dropping malformed TCP response (QR=1)");
            return None;
        }
        let (Some(&b0), Some(&b1)) = (bytes.first(), bytes.get(1)) else {
            return None;
        };
        let id = u16::from_be_bytes([b0, b1]);
        let mut resp = Message::new(Header::new_query(id, styx_proto::Opcode::Query, false));
        resp.header.kind = MessageKind::Response;
        resp.header.rcode = ResponseCode::FORMERR;

        let client = ClientId::from_socket_addr(self.peer);
        let ctx = RequestContext::new(
            resp.clone(),
            client,
            Transport::Tcp,
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
                tracing::error!(peer = %self.peer, %err, "failed to serialize TCP response");
                None
            }
        }
    }
}

fn error_response(ctx: &RequestContext, rcode: ResponseCode) -> Message {
    let mut resp = Message::new(Header::new_query(
        ctx.query.header.id,
        ctx.query.header.opcode,
        false,
    ));
    resp.header.kind = MessageKind::Response;
    resp.header.rcode = rcode;
    resp.questions = ctx.query.questions.clone();
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn idle_tracks_outstanding_slots() {
        let in_flight = ConnectionInFlight::new(NonZeroUsize::new(2).unwrap());
        assert!(in_flight.is_idle());
        let slot = in_flight.track().await.unwrap();
        assert!(!in_flight.is_idle());

        let waiter = async { in_flight.idle().await };
        let release = async {
            tokio::task::yield_now().await;
            drop(slot);
        };
        tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(waiter, release);
        })
        .await
        .unwrap();
        assert!(in_flight.is_idle());
    }

    #[tokio::test]
    async fn track_blocks_at_capacity() {
        let in_flight = ConnectionInFlight::new(NonZeroUsize::MIN);
        let _held = in_flight.track().await.unwrap();
        let blocked = tokio::time::timeout(Duration::from_millis(50), in_flight.track()).await;
        assert!(blocked.is_err());
    }
}

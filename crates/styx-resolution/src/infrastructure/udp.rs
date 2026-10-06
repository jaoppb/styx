//! UDP DNS transport listener.

use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use styx_proto::application::Decoder;
use styx_proto::{Header, Message, MessageKind, ResponseCode};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use styx_core::Clock;

use crate::application::terminal::{RefusedTerminal, TerminalHandler};
use crate::application::Pipeline;
use crate::domain::error::ListenerError;
use crate::domain::ports::filter::FilterPolicy;
use crate::domain::ports::local::LocalRecords;
use crate::domain::ports::observer::QueryObserver;
use crate::domain::request::{ClientId, MaxResponseSize, RequestContext, Transport};
use crate::infrastructure::admission::{ListenerShared, QueryPermit, WarnLimiter};
use crate::infrastructure::response::ResponseWriter;
use crate::infrastructure::udp_socket::bind_reuseport_group;

/// Fixed receive buffer capacity (4096 bytes, large enough for EDNS UDP datagrams).
const RECV_BUFFER_SIZE: usize = 4096;

/// UDP DNS listener dispatching each datagram to its own task.
///
/// The receive loop takes a query permit *before* reading, so at the budget's cap it
/// stops reading and the kernel drops the excess: overload costs styx no extra work.
pub struct UdpListener<L, F, O, C, T = RefusedTerminal> {
    socket: Arc<UdpSocket>,
    shared: ListenerShared<L, F, O, C, T>,
    bound_addr: SocketAddr,
    exhausted_warning: WarnLimiter,
}

impl<L, F, O, C, T> UdpListener<L, F, O, C, T>
where
    L: LocalRecords + Send + Sync + 'static,
    F: FilterPolicy + Send + Sync + 'static,
    O: QueryObserver + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    T: TerminalHandler + Send + Sync + 'static,
{
    /// Binds a single UDP listener to the target address.
    ///
    /// # Errors
    /// Returns [`ListenerError::Io`] if socket binding fails.
    pub async fn bind(
        addr: SocketAddr,
        shared: ListenerShared<L, F, O, C, T>,
    ) -> Result<Self, ListenerError> {
        let group = Self::bind_group(addr, NonZeroUsize::MIN, shared).await?;
        group
            .into_iter()
            .next()
            .ok_or_else(|| ListenerError::Io(std::io::Error::other("UDP bind produced no socket")))
    }

    /// Binds `count` listeners sharing `addr` (one socket each, `SO_REUSEPORT` on Linux).
    ///
    /// # Errors
    /// Returns [`ListenerError::Io`] if any socket fails to bind.
    pub async fn bind_group(
        addr: SocketAddr,
        count: NonZeroUsize,
        shared: ListenerShared<L, F, O, C, T>,
    ) -> Result<Vec<Self>, ListenerError> {
        let sockets = bind_reuseport_group(addr, count).await?;
        let mut listeners = Vec::with_capacity(sockets.len());
        for socket in sockets {
            let bound_addr = socket.local_addr()?;
            listeners.push(Self {
                socket: Arc::new(socket),
                shared: shared.clone(),
                bound_addr,
                exhausted_warning: WarnLimiter::default(),
            });
        }
        Ok(listeners)
    }

    /// Returns the OS-assigned local bound address (allowing port 0 binding).
    #[must_use]
    pub fn bound_addr(&self) -> SocketAddr {
        self.bound_addr
    }

    /// Runs the UDP listener loop until cancellation is signaled.
    ///
    /// # Errors
    /// Returns [`ListenerError::Io`] on fatal socket receive errors.
    pub async fn run(&self, cancel: CancellationToken) -> Result<(), ListenerError> {
        let mut buf = [0u8; RECV_BUFFER_SIZE];

        while let Some(permit) = self.admit(&cancel).await {
            let received = tokio::select! {
                () = cancel.cancelled() => return Ok(()),
                received = self.socket.recv_from(&mut buf) => received,
            };
            self.dispatch(received, &buf, permit)?;
        }

        Ok(())
    }

    async fn admit(&self, cancel: &CancellationToken) -> Option<QueryPermit> {
        if cancel.is_cancelled() {
            return None;
        }
        if self.shared.budget.is_exhausted()
            && self
                .exhausted_warning
                .allow(self.shared.clock.now_monotonic())
        {
            tracing::warn!(
                addr = %self.bound_addr,
                budget = self.shared.budget.capacity().get(),
                "query budget exhausted; UDP listener waiting before reading"
            );
        }
        tokio::select! {
            () = cancel.cancelled() => None,
            permit = self.shared.budget.acquire() => permit,
        }
    }

    fn dispatch(
        &self,
        received: Result<(usize, SocketAddr), std::io::Error>,
        buf: &[u8; RECV_BUFFER_SIZE],
        permit: QueryPermit,
    ) -> Result<(), ListenerError> {
        let (len, peer) = match received {
            Ok(pair) => pair,
            Err(err) => {
                tracing::error!(%err, addr = %self.bound_addr, "UDP socket recv error");
                return Err(ListenerError::Io(err));
            }
        };
        let Some(slice) = buf.get(..len) else {
            return Ok(());
        };

        let responder = DatagramResponder {
            socket: Arc::clone(&self.socket),
            pipeline: Arc::clone(&self.shared.pipeline),
            clock: Arc::clone(&self.shared.clock),
            query_timeout: self.shared.query_timeout,
            udp_payload_size_default: self.shared.udp_payload_size_default,
        };
        let bytes = slice.to_vec();
        let abort = self.shared.abort.clone();
        self.shared.tasks.spawn(async move {
            let _permit = permit;
            tokio::select! {
                () = abort.cancelled() => {}
                () = responder.handle_datagram(&bytes, peer) => {}
            }
        });
        Ok(())
    }
}

/// Everything one per-datagram task needs to answer its query.
struct DatagramResponder<L, F, O, C, T> {
    socket: Arc<UdpSocket>,
    pipeline: Arc<Pipeline<L, F, O, C, T>>,
    clock: Arc<C>,
    query_timeout: Duration,
    udp_payload_size_default: MaxResponseSize,
}

impl<L, F, O, C, T> DatagramResponder<L, F, O, C, T>
where
    L: LocalRecords + Send + Sync + 'static,
    F: FilterPolicy + Send + Sync + 'static,
    O: QueryObserver + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    T: TerminalHandler + Send + Sync + 'static,
{
    async fn handle_datagram(&self, bytes: &[u8], peer: SocketAddr) {
        let received_at = self.clock.now_monotonic();
        let mut decoder = Decoder::new(bytes);

        let query = match decoder.decode_message() {
            Ok(msg) => msg,
            Err(err) => {
                tracing::warn!(%peer, %err, "malformed UDP datagram; attempting FORMERR");
                self.try_send_formerr(bytes, peer).await;
                return;
            }
        };

        if query.header.kind == MessageKind::Response {
            tracing::debug!(%peer, "silently dropping inbound UDP response datagram (QR=1)");
            return;
        }

        let client = ClientId::from_socket_addr(peer);
        let max_size = RequestContext::derive_max_response_size(
            Transport::Udp,
            &query,
            self.udp_payload_size_default,
        );
        let ctx = RequestContext::new(
            query,
            client,
            Transport::Udp,
            max_size,
            self.udp_payload_size_default,
            received_at,
        );

        let response = match self.pipeline.handle_within(&ctx, self.query_timeout).await {
            Ok(resp) => resp,
            Err(crate::domain::error::PipelineError::InboundResponse) => return,
            Err(err) => {
                let mut resp = Message::new(Header::new_query(
                    ctx.query.header.id,
                    ctx.query.header.opcode,
                    false,
                ));
                resp.header.kind = MessageKind::Response;
                resp.header.rcode = err.response_code();
                resp.questions = ctx.query.questions.clone();
                resp
            }
        };
        if let Err(err) = self.send_message(response, &ctx, peer).await {
            tracing::debug!(%peer, %err, "failed to send UDP response");
        }
    }

    async fn try_send_formerr(&self, bytes: &[u8], peer: SocketAddr) {
        if bytes.get(2).is_some_and(|&b| (b & 0x80) != 0) {
            tracing::debug!(%peer, "silently dropping malformed UDP response datagram (QR=1)");
            return;
        }
        let (Some(&b0), Some(&b1)) = (bytes.first(), bytes.get(1)) else {
            return;
        };
        let id = u16::from_be_bytes([b0, b1]);
        let mut resp = Message::new(Header::new_query(id, styx_proto::Opcode::Query, false));
        resp.header.kind = MessageKind::Response;
        resp.header.rcode = ResponseCode::FORMERR;

        let received_at = self.clock.now_monotonic();
        let client = ClientId::from_socket_addr(peer);
        let max_size = crate::domain::request::MaxResponseSize::classic();
        let ctx = RequestContext::new(
            resp.clone(),
            client,
            Transport::Udp,
            max_size,
            self.udp_payload_size_default,
            received_at,
        );
        if let Err(err) = self.send_message(resp, &ctx, peer).await {
            tracing::debug!(%peer, %err, "failed to send UDP formerr");
        }
    }

    async fn send_message(
        &self,
        message: Message,
        ctx: &RequestContext,
        peer: SocketAddr,
    ) -> Result<(), ListenerError> {
        let writer = ResponseWriter::new();
        let bytes = writer.write(message, ctx)?;
        self.socket.send_to(&bytes, peer).await?;
        Ok(())
    }
}

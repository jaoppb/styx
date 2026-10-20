//! UDP DNS transport listener.

use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use styx_proto::application::Decoder;
use styx_proto::{DecodeError, Message, MessageKind};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use styx_core::{Clock, Sleeper, SystemSleeper};

use crate::application::terminal::{RefusedTerminal, TerminalHandler};
use crate::application::Pipeline;
use crate::domain::client_reply::error_reply;
use crate::domain::error::ListenerError;
use crate::domain::ports::filter::FilterPolicy;
use crate::domain::ports::local::LocalRecords;
use crate::domain::ports::observer::QueryObserver;
use crate::domain::request::{ClientId, MaxResponseSize, RequestContext, Transport};
use crate::infrastructure::admission::{ListenerShared, QueryPermit, WarnLimiter};
use crate::infrastructure::early_reply::{badvers_reply, formerr_reply};
use crate::infrastructure::malformed_warning::{ListenerKind, MalformedWarning};
use crate::infrastructure::response::ResponseWriter;
use crate::infrastructure::udp_socket::bind_reuseport_group;

/// Fixed receive buffer capacity (4096 bytes, large enough for EDNS UDP datagrams).
const RECV_BUFFER_SIZE: usize = 4096;

/// UDP DNS listener dispatching each datagram to its own task.
///
/// The receive loop takes a query permit *before* reading, so at the budget's cap it
/// stops reading and the kernel drops the excess: overload costs styx no extra work.
pub struct UdpListener<L, F, O, C, T = RefusedTerminal, S = SystemSleeper> {
    socket: Arc<UdpSocket>,
    shared: ListenerShared<L, F, O, C, T, S>,
    bound_addr: SocketAddr,
    exhausted_warning: WarnLimiter,
    malformed_warning: Arc<MalformedWarning<C, S>>,
}

impl<L, F, O, C, T, S> UdpListener<L, F, O, C, T, S>
where
    L: LocalRecords + Send + Sync + 'static,
    F: FilterPolicy + Send + Sync + 'static,
    O: QueryObserver + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    T: TerminalHandler + Send + Sync + 'static,
    S: Sleeper + Send + Sync + 'static,
{
    /// Binds a single UDP listener to the target address.
    ///
    /// # Errors
    /// Returns [`ListenerError::Io`] if socket binding fails.
    pub async fn bind(
        addr: SocketAddr,
        shared: ListenerShared<L, F, O, C, T, S>,
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
        shared: ListenerShared<L, F, O, C, T, S>,
    ) -> Result<Vec<Self>, ListenerError> {
        let sockets = bind_reuseport_group(addr, count).await?;
        let mut listeners = Vec::with_capacity(sockets.len());
        for socket in sockets {
            let bound_addr = socket.local_addr()?;
            let malformed_warning = MalformedWarning::new(
                ListenerKind::Udp,
                bound_addr,
                Arc::clone(&shared.clock),
                Arc::clone(&shared.sleeper),
                shared.tasks.clone(),
                shared.shutdown.clone(),
                shared.abort.clone(),
            );
            listeners.push(Self {
                socket: Arc::new(socket),
                shared: shared.clone(),
                bound_addr,
                exhausted_warning: WarnLimiter::default(),
                malformed_warning,
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
            malformed_warning: Arc::clone(&self.malformed_warning),
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
struct DatagramResponder<L, F, O, C, T, S> {
    socket: Arc<UdpSocket>,
    pipeline: Arc<Pipeline<L, F, O, C, T>>,
    clock: Arc<C>,
    malformed_warning: Arc<MalformedWarning<C, S>>,
    query_timeout: Duration,
    udp_payload_size_default: MaxResponseSize,
}

impl<L, F, O, C, T, S> DatagramResponder<L, F, O, C, T, S>
where
    L: LocalRecords + Send + Sync + 'static,
    F: FilterPolicy + Send + Sync + 'static,
    O: QueryObserver + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    T: TerminalHandler + Send + Sync + 'static,
    S: Sleeper + Send + Sync + 'static,
{
    async fn handle_datagram(&self, bytes: &[u8], peer: SocketAddr) {
        let received_at = self.clock.now_monotonic();
        let mut decoder = Decoder::new(bytes);

        let query = match decoder.decode_message() {
            Ok(msg) => msg,
            Err(DecodeError::UnsupportedEdnsVersion(rejected)) => {
                tracing::debug!(%peer, version = rejected.version(), "unsupported EDNS version; answering BADVERS");
                self.reply_early(badvers_reply(&rejected), peer).await;
                return;
            }
            Err(err) => {
                tracing::debug!(%peer, %err, "malformed UDP datagram; attempting FORMERR");
                self.malformed_warning.record();
                self.reply_early(formerr_reply(bytes), peer).await;
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
            Err(err) => error_reply(&ctx.query, err.response_code()),
        };
        if let Err(err) = self.send_message(response, &ctx, peer).await {
            tracing::debug!(%peer, %err, "failed to send UDP response");
        }
    }

    /// Sends `reply` to a query that never reached the pipeline, or drops the datagram when
    /// there is no reply to give.
    async fn reply_early(&self, reply: Option<Message>, peer: SocketAddr) {
        let Some(reply) = reply else {
            tracing::debug!(%peer, "silently dropping unanswerable UDP datagram");
            return;
        };
        self.send_error_reply(reply, peer).await;
    }

    /// Sends a reply to a query that never reached the pipeline, within the classic 512-octet
    /// budget because no EDNS buffer size was negotiated.
    async fn send_error_reply(&self, resp: Message, peer: SocketAddr) {
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
            tracing::debug!(%peer, %err, "failed to send UDP error reply");
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

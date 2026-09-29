//! UDP DNS transport listener.

use std::net::SocketAddr;
use std::sync::Arc;

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
use crate::domain::request::{ClientId, RequestContext, Transport};
use crate::infrastructure::response::ResponseWriter;

/// Fixed receive buffer capacity (4096 bytes, large enough for EDNS UDP datagrams).
const RECV_BUFFER_SIZE: usize = 4096;

/// UDP DNS listener dispatching datagrams to the resolution pipeline.
pub struct UdpListener<L, F, O, C, T = RefusedTerminal> {
    socket: Arc<UdpSocket>,
    pipeline: Arc<Pipeline<L, F, O, C, T>>,
    clock: Arc<C>,
    bound_addr: SocketAddr,
}

impl<L, F, O, C, T> UdpListener<L, F, O, C, T>
where
    L: LocalRecords + Send + Sync + 'static,
    F: FilterPolicy + Send + Sync + 'static,
    O: QueryObserver + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    T: TerminalHandler + Send + Sync + 'static,
{
    /// Binds a UDP listener to the target address.
    ///
    /// # Errors
    /// Returns [`ListenerError::Io`] if socket binding fails.
    pub async fn bind(
        addr: SocketAddr,
        pipeline: Arc<Pipeline<L, F, O, C, T>>,
        clock: Arc<C>,
    ) -> Result<Self, ListenerError> {
        let socket = UdpSocket::bind(addr).await?;
        let bound_addr = socket.local_addr()?;
        Ok(Self {
            socket: Arc::new(socket),
            pipeline,
            clock,
            bound_addr,
        })
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

        while !cancel.is_cancelled() {
            tokio::select! {
                _ = cancel.cancelled() => break,
                recv_res = self.socket.recv_from(&mut buf) => {
                    self.handle_recv_result(recv_res, &buf).await?;
                }
            }
        }

        Ok(())
    }

    async fn handle_recv_result(
        &self,
        recv_res: Result<(usize, SocketAddr), std::io::Error>,
        buf: &[u8; RECV_BUFFER_SIZE],
    ) -> Result<(), ListenerError> {
        let (len, peer) = match recv_res {
            Ok(pair) => pair,
            Err(err) => {
                tracing::error!(%err, addr = %self.bound_addr, "UDP socket recv error");
                return Err(ListenerError::Io(err));
            }
        };
        if let Some(slice) = buf.get(..len) {
            self.handle_datagram(slice, peer).await;
        }
        Ok(())
    }

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

        let client = ClientId::from_socket_addr(peer);
        let max_size = RequestContext::derive_max_response_size(Transport::Udp, &query);
        let ctx = RequestContext::new(query, client, Transport::Udp, max_size, received_at);

        match self.pipeline.handle(ctx.clone()).await {
            Ok(resp) => {
                if let Err(err) = self.send_message(resp, &ctx, peer).await {
                    tracing::debug!(%peer, %err, "failed to send UDP response");
                }
            }
            Err(err) => {
                let rcode = err.response_code();
                let mut resp = Message::new(Header::new_query(
                    ctx.query.header.id,
                    ctx.query.header.opcode,
                    false,
                ));
                resp.header.kind = MessageKind::Response;
                resp.header.rcode = rcode;
                resp.questions = ctx.query.questions.clone();
                if let Err(err) = self.send_message(resp, &ctx, peer).await {
                    tracing::debug!(%peer, %err, "failed to send UDP error response");
                }
            }
        }
    }

    async fn try_send_formerr(&self, bytes: &[u8], peer: SocketAddr) {
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
        let ctx = RequestContext::new(resp.clone(), client, Transport::Udp, max_size, received_at);
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

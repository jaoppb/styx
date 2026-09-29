//! TCP DNS transport listener.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use styx_proto::application::Decoder;
use styx_proto::{Header, Message, MessageKind, ResponseCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use styx_core::Clock;

use crate::application::terminal::{RefusedTerminal, TerminalHandler};
use crate::application::Pipeline;
use crate::domain::error::ListenerError;
use crate::domain::ports::filter::FilterPolicy;
use crate::domain::ports::local::LocalRecords;
use crate::domain::ports::observer::QueryObserver;
use crate::domain::request::{ClientId, MaxResponseSize, RequestContext, Transport};
use crate::infrastructure::response::ResponseWriter;

/// Default idle timeout for idle TCP client connections (5 seconds).
const DEFAULT_TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(5);

/// TCP DNS listener handling framed stream connections and multiple queries.
pub struct TcpListener<L, F, O, C, T = RefusedTerminal> {
    listener: TokioTcpListener,
    pipeline: Arc<Pipeline<L, F, O, C, T>>,
    clock: Arc<C>,
    bound_addr: SocketAddr,
    idle_timeout: Duration,
}

impl<L, F, O, C, T> TcpListener<L, F, O, C, T>
where
    L: LocalRecords + Send + Sync + 'static,
    F: FilterPolicy + Send + Sync + 'static,
    O: QueryObserver + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    T: TerminalHandler + Send + Sync + 'static,
{
    /// Binds a TCP listener to the target address.
    ///
    /// # Errors
    /// Returns [`ListenerError::Io`] if socket binding fails.
    pub async fn bind(
        addr: SocketAddr,
        pipeline: Arc<Pipeline<L, F, O, C, T>>,
        clock: Arc<C>,
        idle_timeout: Option<Duration>,
    ) -> Result<Self, ListenerError> {
        let listener = TokioTcpListener::bind(addr).await?;
        let bound_addr = listener.local_addr()?;
        Ok(Self {
            listener,
            pipeline,
            clock,
            bound_addr,
            idle_timeout: match idle_timeout {
                Some(t) => t,
                None => DEFAULT_TCP_IDLE_TIMEOUT,
            },
        })
    }

    /// Returns the OS-assigned local bound address (allowing port 0 binding).
    #[must_use]
    pub fn bound_addr(&self) -> SocketAddr {
        self.bound_addr
    }

    /// Runs the TCP listener accept loop until cancellation is signaled.
    ///
    /// # Errors
    /// Returns [`ListenerError::Io`] on fatal accept failures.
    pub async fn run(&self, cancel: CancellationToken) -> Result<(), ListenerError> {
        while !cancel.is_cancelled() {
            tokio::select! {
                _ = cancel.cancelled() => break,
                accept_res = self.listener.accept() => {
                    self.handle_accept_result(accept_res, cancel.clone())?;
                }
            }
        }

        Ok(())
    }

    fn handle_accept_result(
        &self,
        accept_res: Result<(TcpStream, SocketAddr), std::io::Error>,
        cancel: CancellationToken,
    ) -> Result<(), ListenerError> {
        let (stream, peer) = match accept_res {
            Ok(pair) => pair,
            Err(err) => {
                tracing::error!(%err, addr = %self.bound_addr, "TCP accept error");
                return Err(ListenerError::Io(err));
            }
        };

        let pipeline = Arc::clone(&self.pipeline);
        let clock = Arc::clone(&self.clock);
        let timeout = self.idle_timeout;
        tokio::spawn(Self::handle_connection(
            stream, peer, pipeline, clock, timeout, cancel,
        ));
        Ok(())
    }

    async fn handle_connection(
        mut stream: TcpStream,
        peer: SocketAddr,
        pipeline: Arc<Pipeline<L, F, O, C, T>>,
        clock: Arc<C>,
        timeout: Duration,
        cancel: CancellationToken,
    ) {
        while !cancel.is_cancelled() {
            tokio::select! {
                _ = cancel.cancelled() => break,
                frame_res = Self::read_frame(&mut stream, timeout) => {
                    let should_continue = Self::handle_frame_step(
                        &mut stream,
                        peer,
                        &pipeline,
                        &clock,
                        frame_res,
                    ).await;
                    if !should_continue {
                        break;
                    }
                }
            }
        }
    }

    async fn handle_frame_step(
        stream: &mut TcpStream,
        peer: SocketAddr,
        pipeline: &Arc<Pipeline<L, F, O, C, T>>,
        clock: &Arc<C>,
        frame_res: Result<Option<Vec<u8>>, ListenerError>,
    ) -> bool {
        match frame_res {
            Ok(Some(frame)) => Self::process_query(stream, &frame, peer, pipeline, clock).await,
            Ok(None) => false,
            Err(err) => {
                tracing::debug!(%peer, %err, "TCP stream closed or timed out");
                false
            }
        }
    }

    async fn read_frame(
        stream: &mut TcpStream,
        timeout: Duration,
    ) -> Result<Option<Vec<u8>>, ListenerError> {
        let mut prefix = [0u8; 2];
        let read_prefix = tokio::time::timeout(timeout, stream.read_exact(&mut prefix));
        match read_prefix.await {
            Ok(Ok(_)) => {}
            Ok(Err(err)) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Ok(Err(err)) => return Err(ListenerError::Io(err)),
            Err(_) => {
                return Err(ListenerError::Framing(
                    "idle timeout reading frame length".into(),
                ))
            }
        }

        let len = usize::from(u16::from_be_bytes(prefix));
        if len == 0 {
            return Err(ListenerError::Framing(
                "zero-length TCP frame received".into(),
            ));
        }

        let mut payload = vec![0u8; len];
        let read_payload = tokio::time::timeout(timeout, stream.read_exact(&mut payload));
        match read_payload.await {
            Ok(Ok(_)) => Ok(Some(payload)),
            Ok(Err(err)) => Err(ListenerError::Io(err)),
            Err(_) => Err(ListenerError::Framing(
                "timeout reading TCP frame payload".into(),
            )),
        }
    }

    async fn process_query(
        stream: &mut TcpStream,
        bytes: &[u8],
        peer: SocketAddr,
        pipeline: &Arc<Pipeline<L, F, O, C, T>>,
        clock: &Arc<C>,
    ) -> bool {
        let received_at = clock.now_monotonic();
        let mut decoder = Decoder::new(bytes);

        let query = match decoder.decode_message() {
            Ok(msg) => msg,
            Err(err) => {
                tracing::warn!(%peer, %err, "malformed TCP query; responding FORMERR");
                return Self::send_formerr(stream, bytes, peer, received_at).await;
            }
        };

        let client = ClientId::from_socket_addr(peer);
        let max_size = MaxResponseSize::tcp_ceiling();
        let ctx = RequestContext::new(query, client, Transport::Tcp, max_size, received_at);

        let response = match pipeline.handle(ctx.clone()).await {
            Ok(msg) => msg,
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
                resp
            }
        };

        let writer = ResponseWriter::new();
        match writer.write(response, &ctx) {
            Ok(wire) => stream.write_all(&wire).await.is_ok(),
            Err(err) => {
                tracing::error!(%peer, %err, "failed to serialize TCP response");
                false
            }
        }
    }

    async fn send_formerr(
        stream: &mut TcpStream,
        bytes: &[u8],
        peer: SocketAddr,
        received_at: std::time::Instant,
    ) -> bool {
        let (Some(&b0), Some(&b1)) = (bytes.first(), bytes.get(1)) else {
            return false;
        };
        let id = u16::from_be_bytes([b0, b1]);
        let mut resp = Message::new(Header::new_query(id, styx_proto::Opcode::Query, false));
        resp.header.kind = MessageKind::Response;
        resp.header.rcode = ResponseCode::FORMERR;

        let client = ClientId::from_socket_addr(peer);
        let ctx = RequestContext::new(
            resp.clone(),
            client,
            Transport::Tcp,
            MaxResponseSize::tcp_ceiling(),
            received_at,
        );

        let writer = ResponseWriter::new();
        match writer.write(resp, &ctx) {
            Ok(wire) => stream.write_all(&wire).await.is_ok(),
            Err(_) => false,
        }
    }
}

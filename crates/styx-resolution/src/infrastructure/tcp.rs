//! TCP DNS transport listener.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use styx_proto::application::Decoder;
use styx_proto::{Header, Message, MessageKind, ResponseCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

use crate::application::Pipeline;
use crate::domain::clock::Clock;
use crate::domain::error::ListenerError;
use crate::domain::request::{ClientId, MaxResponseSize, RequestContext, Transport};
use crate::infrastructure::response::ResponseWriter;

/// Default idle timeout for idle TCP client connections (5 seconds).
const DEFAULT_TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(5);

/// TCP DNS listener handling framed stream connections and multiple queries.
pub struct TcpListener {
    listener: TokioTcpListener,
    pipeline: Arc<Pipeline>,
    clock: Arc<dyn Clock>,
    bound_addr: SocketAddr,
    idle_timeout: Duration,
}

impl TcpListener {
    /// Binds a TCP listener to the target address.
    ///
    /// # Errors
    /// Returns [`ListenerError::Io`] if socket binding fails.
    pub async fn bind(
        addr: SocketAddr,
        pipeline: Arc<Pipeline>,
        clock: Arc<dyn Clock>,
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
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                accept_res = self.listener.accept() => {
                    match accept_res {
                        Ok((stream, peer)) => {
                            let pipeline = Arc::clone(&self.pipeline);
                            let clock = Arc::clone(&self.clock);
                            let timeout = self.idle_timeout;
                            let conn_cancel = cancel.clone();
                            tokio::spawn(async move {
                                Self::handle_connection(
                                    stream,
                                    peer,
                                    pipeline,
                                    clock,
                                    timeout,
                                    conn_cancel,
                                ).await;
                            });
                        }
                        Err(err) => {
                            tracing::error!(%err, addr = %self.bound_addr, "TCP accept error");
                            return Err(ListenerError::Io(err));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn handle_connection(
        mut stream: TcpStream,
        peer: SocketAddr,
        pipeline: Arc<Pipeline>,
        clock: Arc<dyn Clock>,
        timeout: Duration,
        cancel: CancellationToken,
    ) {
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                frame_res = Self::read_frame(&mut stream, timeout) => {
                    match frame_res {
                        Ok(Some(frame)) => {
                            let keep_going = Self::process_query(
                                &mut stream,
                                &frame,
                                peer,
                                &pipeline,
                                &clock,
                            ).await;
                            if !keep_going {
                                break;
                            }
                        }
                        Ok(None) => break,
                        Err(err) => {
                            tracing::debug!(%peer, %err, "TCP stream closed or timed out");
                            break;
                        }
                    }
                }
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
        pipeline: &Arc<Pipeline>,
        clock: &Arc<dyn Clock>,
    ) -> bool {
        let received_at = clock.now_monotonic();
        let mut decoder = Decoder::new(bytes);

        let query = match decoder.decode_message() {
            Ok(msg) => msg,
            Err(err) => {
                tracing::warn!(%peer, %err, "malformed TCP query; responding FORMERR");
                return Self::send_formerr(stream, bytes, peer).await;
            }
        };

        let client = ClientId::from_socket_addr(peer);
        let max_size = MaxResponseSize::tcp_ceiling();
        let ctx = RequestContext::new(query, client, Transport::Tcp, max_size)
            .with_received_at(received_at);

        let response = match pipeline.handle(ctx.clone()) {
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

    async fn send_formerr(stream: &mut TcpStream, bytes: &[u8], peer: SocketAddr) -> bool {
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
        );

        let writer = ResponseWriter::new();
        match writer.write(resp, &ctx) {
            Ok(wire) => stream.write_all(&wire).await.is_ok(),
            Err(_) => false,
        }
    }
}

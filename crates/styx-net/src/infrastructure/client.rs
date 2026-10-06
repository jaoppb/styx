//! The outbound Do53 exchange: UDP first, TCP on truncation.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use styx_core::Clock;
use styx_proto::application::{Decoder, Encoder};
use styx_proto::{read_tcp_frame_length, Message, Question};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UdpSocket};

use crate::domain::exchange::{ExchangeError, Exchanged};
use crate::infrastructure::frame::{write_framed, FrameWriteError};

/// Encode budget for an outgoing query. A header, one question and an OPT record
/// total about 282 octets, so 512 never trips the budget and avoids reserving 4 KiB.
const QUERY_ENCODE_BUDGET: usize = 512;

/// UDP receive buffer size. Every caller advertises an EDNS payload of at most
/// 4096 octets, so a compliant response always fits; a larger datagram is cut
/// short, fails to decode, and is discarded like any other unusable datagram.
const UDP_RECEIVE_OCTETS: usize = 4096;

/// Sends DNS queries to a server and returns the matching response.
///
/// Holds no per-server state: the server is an argument of every exchange, so one
/// client serves a forwarder's single upstream and a recursor's many nameservers
/// alike.
#[derive(Debug)]
pub struct Do53Client<C> {
    udp_timeout: Duration,
    tcp_timeout: Duration,
    clock: Arc<C>,
}

impl<C> Clone for Do53Client<C> {
    fn clone(&self) -> Self {
        Self {
            udp_timeout: self.udp_timeout,
            tcp_timeout: self.tcp_timeout,
            clock: Arc::clone(&self.clock),
        }
    }
}

impl<C: Clock> Do53Client<C> {
    /// Creates a client with per-transport timeouts, each further capped by the
    /// deadline of the exchange it applies to.
    #[must_use]
    pub fn new(udp_timeout: Duration, tcp_timeout: Duration, clock: Arc<C>) -> Self {
        Self {
            udp_timeout,
            tcp_timeout,
            clock,
        }
    }

    /// Sends `query` to `server` and returns the first response whose transaction ID
    /// and question match it.
    ///
    /// The query's header ID is overwritten with a fresh random value; everything
    /// else — flags, the question, the OPT record — is sent exactly as given. A
    /// truncated UDP response is retried over TCP with the identical message.
    ///
    /// # Errors
    ///
    /// Returns [`ExchangeError::Timeout`] if no matching response arrives in time,
    /// [`ExchangeError::Transport`] if a socket operation fails,
    /// [`ExchangeError::Encode`] if `query` cannot be encoded,
    /// [`ExchangeError::OversizeFrame`] if it cannot be framed for TCP, and
    /// [`ExchangeError::Malformed`], [`ExchangeError::Mismatched`] or
    /// [`ExchangeError::Truncated`] if the TCP response is unusable.
    pub async fn exchange(
        &self,
        server: SocketAddr,
        mut query: Message,
        deadline: Instant,
    ) -> Result<Exchanged, ExchangeError> {
        let expected_id = rand::random::<u16>();
        query.header.id = expected_id;
        let bytes = encode(&query)?;
        let Some(question) = query.questions.first() else {
            return Err(ExchangeError::NoQuestion);
        };
        let expected = Expected {
            id: expected_id,
            question,
        };

        let udp = self.send_udp(server, &bytes, &expected, deadline).await?;
        if !udp.header.truncated {
            return Ok(Exchanged {
                message: udp,
                via_tcp: false,
            });
        }

        let tcp = self.send_tcp(server, &bytes, &expected, deadline).await?;
        Ok(Exchanged {
            message: tcp,
            via_tcp: true,
        })
    }

    /// The time left for one transport step: the smaller of its own timeout and what
    /// remains before the deadline on the injected clock.
    fn budget(&self, transport_timeout: Duration, deadline: Instant) -> Duration {
        let now = self.clock.now_monotonic();
        deadline
            .saturating_duration_since(now)
            .min(transport_timeout)
    }

    async fn send_udp(
        &self,
        server: SocketAddr,
        bytes: &[u8],
        expected: &Expected<'_>,
        deadline: Instant,
    ) -> Result<Message, ExchangeError> {
        let socket = match server {
            SocketAddr::V4(_) => UdpSocket::bind("0.0.0.0:0").await,
            SocketAddr::V6(_) => UdpSocket::bind("[::]:0").await,
        }
        .map_err(|error| ExchangeError::Transport(error.kind()))?;
        socket
            .connect(server)
            .await
            .map_err(|error| ExchangeError::Transport(error.kind()))?;
        socket
            .send(bytes)
            .await
            .map_err(|error| ExchangeError::Transport(error.kind()))?;

        let budget = self.budget(self.udp_timeout, deadline);
        tokio::time::timeout(budget, recv_until_matching(&socket, expected))
            .await
            .map_err(|_| ExchangeError::Timeout)?
    }

    async fn send_tcp(
        &self,
        server: SocketAddr,
        bytes: &[u8],
        expected: &Expected<'_>,
        deadline: Instant,
    ) -> Result<Message, ExchangeError> {
        let budget = self.budget(self.tcp_timeout, deadline);
        tokio::time::timeout(budget, tcp_round_trip(server, bytes, expected))
            .await
            .map_err(|_| ExchangeError::Timeout)?
    }
}

/// What a response must echo to be accepted as the answer to this query.
struct Expected<'a> {
    id: u16,
    question: &'a Question,
}

impl Expected<'_> {
    fn matches(&self, response: &Message) -> bool {
        response.header.id == self.id && response.questions.first() == Some(self.question)
    }
}

fn encode(query: &Message) -> Result<Vec<u8>, ExchangeError> {
    let mut encoder = Encoder::new(QUERY_ENCODE_BUDGET);
    encoder
        .encode_message(query)
        .map_err(ExchangeError::Encode)?;
    Ok(encoder.buf)
}

/// Reads datagrams until one decodes and matches. Anything else — a forgery, a late
/// answer to an earlier query, garbage — is discarded, and the caller's timeout
/// bounds the wait.
async fn recv_until_matching(
    socket: &UdpSocket,
    expected: &Expected<'_>,
) -> Result<Message, ExchangeError> {
    let mut buffer = [0u8; UDP_RECEIVE_OCTETS];
    loop {
        let received = socket
            .recv(&mut buffer)
            .await
            .map_err(|error| ExchangeError::Transport(error.kind()))?;
        let Some(datagram) = buffer.get(..received) else {
            continue;
        };
        let Ok(message) = Decoder::new(datagram).decode_message() else {
            continue;
        };
        if expected.matches(&message) {
            return Ok(message);
        }
    }
}

async fn tcp_round_trip(
    server: SocketAddr,
    bytes: &[u8],
    expected: &Expected<'_>,
) -> Result<Message, ExchangeError> {
    let mut stream = TcpStream::connect(server)
        .await
        .map_err(|error| ExchangeError::Transport(error.kind()))?;
    write_framed(&mut stream, bytes)
        .await
        .map_err(|error| match error {
            FrameWriteError::Io(kind) => ExchangeError::Transport(kind),
            FrameWriteError::BodyTooLong { length } => ExchangeError::OversizeFrame { length },
        })?;

    let mut length_prefix = [0u8; 2];
    stream
        .read_exact(&mut length_prefix)
        .await
        .map_err(|error| ExchangeError::Transport(error.kind()))?;
    let length = read_tcp_frame_length(&length_prefix).map_err(ExchangeError::Malformed)?;
    let mut body = vec![0u8; usize::from(length)];
    stream
        .read_exact(&mut body)
        .await
        .map_err(|error| ExchangeError::Transport(error.kind()))?;

    let message = Decoder::new(&body)
        .decode_message()
        .map_err(ExchangeError::Malformed)?;
    if !expected.matches(&message) {
        return Err(ExchangeError::Mismatched);
    }
    if message.header.truncated {
        return Err(ExchangeError::Truncated);
    }
    Ok(message)
}

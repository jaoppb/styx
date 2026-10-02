//! Classic Do53 DNS forwarder over UDP with TCP fallback.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use styx_proto::application::{Decoder, Encoder};
use styx_proto::{read_tcp_frame_length, Header, Message, Opcode, Opt, Question, ResponseCode};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UdpSocket};

use styx_core::{Clock, Upstream, UpstreamError, UpstreamId, UpstreamKind, UpstreamResponse};

use crate::domain::edns::EdnsBufferSize;
use crate::infrastructure::tcp_frame::{write_framed, FrameWriteError};

/// Encode budget for an outgoing query: a header, one question and an OPT record total
/// about 282 octets, so 512 never trips the budget and avoids reserving 4 KiB.
const QUERY_ENCODE_BUDGET: usize = 512;

/// UDP receive buffer size, matching the largest EDNS buffer the forwarder may advertise.
const UDP_RECEIVE_OCTETS: usize = EdnsBufferSize::MAX_CEILING as usize;

/// A classic DNS over UDP (Do53) forwarder with automatic TCP fallback on truncation.
#[derive(Debug)]
pub struct Do53Forwarder<C> {
    id: UpstreamId,
    addr: SocketAddr,
    edns_buffer: EdnsBufferSize,
    udp_timeout: Duration,
    tcp_timeout: Duration,
    clock: Arc<C>,
}

impl<C> Clone for Do53Forwarder<C> {
    fn clone(&self) -> Self {
        Self {
            id: self.id.clone(),
            addr: self.addr,
            edns_buffer: self.edns_buffer,
            udp_timeout: self.udp_timeout,
            tcp_timeout: self.tcp_timeout,
            clock: Arc::clone(&self.clock),
        }
    }
}

impl<C: Clock> Do53Forwarder<C> {
    /// Creates a new `Do53Forwarder`.
    #[must_use]
    pub fn new(
        id: UpstreamId,
        addr: SocketAddr,
        edns_buffer: EdnsBufferSize,
        udp_timeout: Duration,
        tcp_timeout: Duration,
        clock: Arc<C>,
    ) -> Self {
        Self {
            id,
            addr,
            edns_buffer,
            udp_timeout,
            tcp_timeout,
            clock,
        }
    }

    /// Returns the configured socket address.
    #[must_use]
    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }

    fn encode_query(&self, query: &Question) -> Result<(u16, Vec<u8>), UpstreamError> {
        let tx_id = rand::random::<u16>();
        let header = Header::new_query(tx_id, Opcode::Query, true);
        let mut msg = Message::new(header);
        msg.questions.push(query.clone());

        let opt = Opt::new(self.edns_buffer.octets(), 0, 0, false, Vec::new());
        msg.opt = Some(opt);

        let mut encoder = Encoder::new(QUERY_ENCODE_BUDGET);
        encoder
            .encode_message(&msg)
            .map_err(|e| UpstreamError::Malformed(e.to_string()))?;

        Ok((tx_id, encoder.buf))
    }

    async fn send_udp(
        &self,
        bytes: &[u8],
        query: &Question,
        expected_id: u16,
        deadline: Instant,
    ) -> Result<Message, UpstreamError> {
        let socket = match self.addr {
            SocketAddr::V4(_) => UdpSocket::bind("0.0.0.0:0").await,
            SocketAddr::V6(_) => UdpSocket::bind("[::]:0").await,
        }
        .map_err(|e| UpstreamError::Transport(e.kind()))?;

        socket
            .connect(self.addr)
            .await
            .map_err(|e| UpstreamError::Transport(e.kind()))?;

        socket
            .send(bytes)
            .await
            .map_err(|e| UpstreamError::Transport(e.kind()))?;

        let now = self.clock.now_monotonic();
        let remaining = deadline.checked_duration_since(now).unwrap_or_default();
        let timeout_budget = remaining.min(self.udp_timeout);

        tokio::time::timeout(
            timeout_budget,
            self.recv_until_valid(&socket, query, expected_id),
        )
        .await
        .map_err(|_| UpstreamError::Timeout)?
    }

    async fn recv_until_valid(
        &self,
        socket: &UdpSocket,
        query: &Question,
        expected_id: u16,
    ) -> Result<Message, UpstreamError> {
        let mut recv_buf = [0u8; UDP_RECEIVE_OCTETS];
        loop {
            let n = socket
                .recv(&mut recv_buf)
                .await
                .map_err(|e| UpstreamError::Transport(e.kind()))?;

            let Some(slice) = recv_buf.get(..n) else {
                continue;
            };

            if let Ok(msg) = self.validate_and_decode(slice, query, expected_id) {
                return Ok(msg);
            }
        }
    }

    fn validate_and_decode(
        &self,
        raw: &[u8],
        query: &Question,
        expected_id: u16,
    ) -> Result<Message, UpstreamError> {
        let mut decoder = Decoder::new(raw);
        let msg = decoder
            .decode_message()
            .map_err(|e| UpstreamError::Malformed(e.to_string()))?;

        if msg.header.id != expected_id {
            return Err(UpstreamError::Mismatched);
        }

        let Some(first_q) = msg.questions.first() else {
            return Err(UpstreamError::Mismatched);
        };

        if first_q != query {
            return Err(UpstreamError::Mismatched);
        }

        Ok(msg)
    }

    async fn retry_tcp(
        &self,
        query_bytes: &[u8],
        query: &Question,
        expected_id: u16,
        deadline: Instant,
    ) -> Result<Message, UpstreamError> {
        let now = self.clock.now_monotonic();
        let remaining = deadline.checked_duration_since(now).unwrap_or_default();
        let timeout_budget = remaining.min(self.tcp_timeout);

        let exchange = async {
            let mut stream = TcpStream::connect(self.addr)
                .await
                .map_err(|e| UpstreamError::Transport(e.kind()))?;

            write_framed(&mut stream, query_bytes)
                .await
                .map_err(|e| match e {
                    FrameWriteError::Io(kind) => UpstreamError::Transport(kind),
                    FrameWriteError::BodyTooLong { .. } => UpstreamError::Malformed(e.to_string()),
                })?;

            let mut len_buf = [0u8; 2];
            stream
                .read_exact(&mut len_buf)
                .await
                .map_err(|e| UpstreamError::Transport(e.kind()))?;
            let resp_len = usize::from(
                read_tcp_frame_length(&len_buf)
                    .map_err(|e| UpstreamError::Malformed(e.to_string()))?,
            );

            let mut resp_buf = vec![0u8; resp_len];

            stream
                .read_exact(&mut resp_buf)
                .await
                .map_err(|e| UpstreamError::Transport(e.kind()))?;

            let msg = self.validate_and_decode(&resp_buf, query, expected_id)?;
            if msg.header.truncated {
                return Err(UpstreamError::Truncated);
            }
            Ok(msg)
        };

        tokio::time::timeout(timeout_budget, exchange)
            .await
            .map_err(|_| UpstreamError::Timeout)?
    }

    fn map_response(message: Message) -> Result<Message, UpstreamError> {
        match message.header.rcode {
            ResponseCode::REFUSED => Err(UpstreamError::Refused),
            ResponseCode::SERVFAIL => Err(UpstreamError::ServerFailure { is_upstream: false }),
            _ => Ok(message),
        }
    }
}

impl<C: Clock> Upstream for Do53Forwarder<C> {
    fn id(&self) -> UpstreamId {
        self.id.clone()
    }

    fn kind(&self) -> UpstreamKind {
        UpstreamKind::Forwarder
    }

    async fn resolve(
        &self,
        query: &Question,
        deadline: Instant,
    ) -> Result<UpstreamResponse, UpstreamError> {
        let start = self.clock.now_monotonic();
        let (tx_id, query_bytes) = self.encode_query(query)?;

        let udp_message = self.send_udp(&query_bytes, query, tx_id, deadline).await?;
        let (message, via_tcp) = if udp_message.header.truncated {
            let tcp_message = self.retry_tcp(&query_bytes, query, tx_id, deadline).await?;
            (tcp_message, true)
        } else {
            (udp_message, false)
        };

        let mapped = Self::map_response(message)?;
        let elapsed = self
            .clock
            .now_monotonic()
            .checked_duration_since(start)
            .unwrap_or_default();

        Ok(UpstreamResponse {
            message: mapped,
            answered_by: self.id.clone(),
            kind: UpstreamKind::Forwarder,
            elapsed,
            via_tcp,
            raced_count: 1,
        })
    }
}

#[cfg(test)]
mod tests {
    use styx_core::test_util::TestClock;
    use styx_proto::{RecordClass, RecordType};

    use super::*;

    #[test]
    fn encode_query_roundtrips_through_decoder() {
        let forwarder = Do53Forwarder::new(
            UpstreamId::new("unit"),
            SocketAddr::from(([127, 0, 0, 1], 53)),
            EdnsBufferSize::default(),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Arc::new(TestClock::new()),
        );
        let name = styx_proto::Name::from_ascii("example.org.").expect("name");
        let question = Question::new(name, RecordType::A, RecordClass::In);

        let (tx_id, bytes) = forwarder.encode_query(&question).expect("encode");
        let message = Decoder::new(&bytes).decode_message().expect("decode");

        assert_eq!(message.header.id, tx_id);
        assert!(message.header.recursion_desired);
        assert_eq!(message.questions, vec![question]);
        let opt = message.opt.expect("opt record");
        assert_eq!(opt.udp_payload_size(), EdnsBufferSize::default().octets());
    }
}

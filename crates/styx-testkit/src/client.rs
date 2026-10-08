//! Test client driving real UDP and TCP sockets against servers.

use std::net::SocketAddr;
use std::time::Duration;

use styx_proto::application::Encoder;
use styx_proto::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::error::HarnessError;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);

/// DNS test client driving socket-level requests over loopback.
#[derive(Debug, Clone, Copy, Default)]
pub struct DnsClient;

impl DnsClient {
    /// Creates a new `DnsClient`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Sends a query over UDP and awaits the decoded response.
    ///
    /// # Errors
    /// Returns [`HarnessError`] on network timeout or invalid response.
    pub async fn query_udp(
        &self,
        server_addr: SocketAddr,
        query: &Message,
    ) -> Result<Message, HarnessError> {
        let mut encoder = Encoder::new(4096);
        encoder.encode_message(query)?;
        let raw = self.query_raw_udp(server_addr, &encoder.buf).await?;
        Ok(Message::decode(&raw)?)
    }

    /// Sends raw bytes over UDP and awaits the raw response bytes.
    ///
    /// # Errors
    /// Returns [`HarnessError`] on I/O or timeout failure.
    pub async fn query_raw_udp(
        &self,
        server_addr: SocketAddr,
        bytes: &[u8],
    ) -> Result<Vec<u8>, HarnessError> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        socket.send_to(bytes, server_addr).await?;

        let mut buf = [0u8; 4096];
        let recv_future = socket.recv_from(&mut buf);
        let (len, _) = tokio::time::timeout(DEFAULT_TIMEOUT, recv_future)
            .await
            .map_err(|_| HarnessError::Timeout("UDP receive timed out".into()))??;

        let slice = buf
            .get(..len)
            .ok_or_else(|| HarnessError::Protocol("invalid buffer bounds".into()))?;
        Ok(slice.to_vec())
    }

    /// Sends a query over TCP and awaits the decoded response.
    ///
    /// # Errors
    /// Returns [`HarnessError`] on framing, I/O, or timeout failure.
    pub async fn query_tcp(
        &self,
        server_addr: SocketAddr,
        query: &Message,
    ) -> Result<Message, HarnessError> {
        let mut encoder = Encoder::new(65535);
        encoder.encode_message(query)?;
        let raw = self.query_raw_tcp(server_addr, &encoder.buf).await?;
        Ok(Message::decode(&raw)?)
    }

    /// Sends raw message bytes framed over TCP and awaits the framed response payload.
    ///
    /// # Errors
    /// Returns [`HarnessError`] on connection or framing failure.
    pub async fn query_raw_tcp(
        &self,
        server_addr: SocketAddr,
        bytes: &[u8],
    ) -> Result<Vec<u8>, HarnessError> {
        let mut stream = TcpStream::connect(server_addr).await?;
        let framed = styx_proto::frame_tcp(bytes)?;
        stream.write_all(&framed).await?;

        let mut len_prefix = [0u8; 2];
        let read_len = stream.read_exact(&mut len_prefix);
        tokio::time::timeout(DEFAULT_TIMEOUT, read_len)
            .await
            .map_err(|_| HarnessError::Timeout("TCP read length prefix timed out".into()))??;

        let frame_len = usize::from(u16::from_be_bytes(len_prefix));
        let mut payload = vec![0u8; frame_len];
        let read_payload = stream.read_exact(&mut payload);
        tokio::time::timeout(DEFAULT_TIMEOUT, read_payload)
            .await
            .map_err(|_| HarnessError::Timeout("TCP read payload timed out".into()))??;

        Ok(payload)
    }
}

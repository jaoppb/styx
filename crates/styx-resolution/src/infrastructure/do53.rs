//! Classic Do53 DNS forwarder over UDP with TCP fallback.
//!
//! The exchange itself — transaction ID and source-port entropy, response matching,
//! the TC → TCP retry — belongs to `styx-net`'s [`Do53Client`], shared with the
//! recursor. This adapter owns only what is forwarder-specific: the query it builds
//! (RD=1, its configured EDNS buffer), and how a response's RCODE maps onto
//! [`UpstreamError`].

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use styx_net::{Do53Client, ExchangeError};
use styx_proto::{Header, Message, Opcode, Opt, Question, ResponseCode};

use styx_core::{Clock, Upstream, UpstreamError, UpstreamId, UpstreamKind, UpstreamResponse};

use crate::domain::edns::EdnsBufferSize;

/// A classic DNS over UDP (Do53) forwarder with automatic TCP fallback on truncation.
#[derive(Debug)]
pub struct Do53Forwarder<C> {
    id: UpstreamId,
    addr: SocketAddr,
    edns_buffer: EdnsBufferSize,
    client: Do53Client<C>,
    clock: Arc<C>,
}

impl<C> Clone for Do53Forwarder<C> {
    fn clone(&self) -> Self {
        Self {
            id: self.id.clone(),
            addr: self.addr,
            edns_buffer: self.edns_buffer,
            client: self.client.clone(),
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
            client: Do53Client::new(udp_timeout, tcp_timeout, Arc::clone(&clock)),
            clock,
        }
    }

    /// Returns the configured socket address.
    #[must_use]
    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Builds the outgoing query. Its transaction ID is a placeholder: the exchange
    /// stamps a fresh random one on every send.
    fn build_query(&self, query: &Question) -> Message {
        let header = Header::new_query(0, Opcode::Query, true);
        let mut msg = Message::new(header);
        msg.questions.push(query.clone());
        msg.opt = Some(Opt::new(self.edns_buffer.octets(), 0, 0, false, Vec::new()));
        msg
    }

    fn map_exchange_error(error: ExchangeError) -> UpstreamError {
        match error {
            ExchangeError::Timeout => UpstreamError::Timeout,
            ExchangeError::Transport(kind) => UpstreamError::Transport(kind),
            ExchangeError::Mismatched => UpstreamError::Mismatched,
            ExchangeError::Truncated => UpstreamError::Truncated,
            ExchangeError::Encode(_)
            | ExchangeError::Malformed(_)
            | ExchangeError::OversizeFrame { .. } => UpstreamError::Malformed(error.to_string()),
        }
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
        let exchanged = self
            .client
            .exchange(self.addr, self.build_query(query), deadline)
            .await
            .map_err(Self::map_exchange_error)?;

        let mapped = Self::map_response(exchanged.message)?;
        let elapsed = self.clock.now_monotonic().saturating_duration_since(start);

        Ok(UpstreamResponse {
            message: mapped,
            answered_by: self.id.clone(),
            kind: UpstreamKind::Forwarder,
            elapsed,
            via_tcp: exchanged.via_tcp,
            raced_count: 1,
        })
    }
}

#[cfg(test)]
mod tests {
    use styx_core::test_util::TestClock;
    use styx_proto::application::{Decoder, Encoder};
    use styx_proto::{RecordClass, RecordType};

    use super::*;

    #[test]
    fn built_query_roundtrips_through_decoder() {
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

        let mut encoder = Encoder::new(512);
        encoder
            .encode_message(&forwarder.build_query(&question))
            .expect("encode");
        let message = Decoder::new(&encoder.buf).decode_message().expect("decode");

        assert!(message.header.recursion_desired);
        assert_eq!(message.questions, vec![question]);
        let opt = message.opt.expect("opt record");
        assert_eq!(opt.udp_payload_size(), EdnsBufferSize::default().octets());
    }
}

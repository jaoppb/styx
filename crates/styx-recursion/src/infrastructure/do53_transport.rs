//! The Do53 transport adapter: one question to one nameserver over UDP, TCP on
//! truncation, through `styx-net`'s shared exchange.

use std::net::SocketAddr;
use std::time::Instant;

use styx_core::Clock;
use styx_net::{Do53Client, ExchangeError};
use styx_proto::{Header, Message, Opcode, Opt, Question, ResponseCode};

use crate::domain::metrics::EdnsCapability;
use crate::domain::ports::{EdnsObservation, Transport, TransportError, TransportReply};
use crate::domain::topology::NameserverAddr;

/// The port authoritative servers listen on.
pub const DNS_PORT: u16 = 53;

/// EDNS payload advertised to a server not yet measured: the DNS Flag Day 2020
/// value, small enough to avoid IP fragmentation on any path.
pub const ADVERTISED_PAYLOAD: u16 = 1232;

/// Sends descent queries: RD=0 (iterative), DO=1 so signed parents include DS in
/// referrals, and never an EDNS Client Subnet option — the same posture as QNAME
/// minimisation, one layer down.
#[derive(Debug, Clone)]
pub struct Do53Transport<C> {
    client: Do53Client<C>,
    port: u16,
}

impl<C: Clock> Do53Transport<C> {
    /// A transport sending through `client` to `port` on each nameserver — 53 in
    /// production; an ephemeral port shared by in-process fakes in tests.
    #[must_use]
    pub const fn new(client: Do53Client<C>, port: u16) -> Self {
        Self { client, port }
    }

    async fn send(
        &self,
        server: NameserverAddr,
        question: &Question,
        with_edns: bool,
        deadline: Instant,
    ) -> Result<(Message, bool), TransportError> {
        let mut query = Message::new(Header::new_query(0, Opcode::Query, false));
        query.questions.push(question.clone());
        if with_edns {
            query.opt = Some(Opt::new(ADVERTISED_PAYLOAD, 0, 0, true, Vec::new()));
        }
        let exchanged = self
            .client
            .exchange(SocketAddr::new(server.ip(), self.port), query, deadline)
            .await
            .map_err(map_exchange_error)?;
        Ok((exchanged.message, exchanged.via_tcp))
    }
}

impl<C: Clock> Transport for Do53Transport<C> {
    async fn query(
        &self,
        server: NameserverAddr,
        question: &Question,
        edns: EdnsCapability,
        deadline: Instant,
    ) -> Result<TransportReply, TransportError> {
        let with_edns = edns != EdnsCapability::Intolerant;
        let (message, via_tcp) = self.send(server, question, with_edns, deadline).await?;
        if !with_edns {
            return Ok(TransportReply {
                message,
                via_tcp,
                edns: EdnsObservation::Inconclusive,
            });
        }
        if rejects_edns(&message) {
            let (plain, via_tcp) = self.send(server, question, false, deadline).await?;
            let edns = if rejects_edns(&plain) {
                EdnsObservation::Inconclusive
            } else {
                EdnsObservation::Intolerant
            };
            return Ok(TransportReply {
                message: plain,
                via_tcp,
                edns,
            });
        }
        let edns = message
            .opt
            .as_ref()
            .map_or(EdnsObservation::Inconclusive, |opt| {
                EdnsObservation::Supported(opt.udp_payload_size())
            });
        Ok(TransportReply {
            message,
            via_tcp,
            edns,
        })
    }
}

/// A FORMERR or NOTIMP without an OPT record is how an EDNS-intolerant server
/// answers an EDNS query (RFC 6891 §7).
fn rejects_edns(message: &Message) -> bool {
    message.opt.is_none()
        && matches!(
            message.header.rcode,
            ResponseCode::FORMERR | ResponseCode::NOTIMP
        )
}

fn map_exchange_error(error: ExchangeError) -> TransportError {
    match error {
        ExchangeError::Timeout => TransportError::Timeout,
        ExchangeError::Transport(kind) => TransportError::Unreachable(kind),
        ExchangeError::Truncated => TransportError::Truncated,
        ExchangeError::Encode(_)
        | ExchangeError::Malformed(_)
        | ExchangeError::Mismatched
        | ExchangeError::OversizeFrame { .. } => TransportError::Malformed,
    }
}

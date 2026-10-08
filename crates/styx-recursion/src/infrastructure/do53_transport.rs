//! The Do53 transport adapter: one question to one nameserver over UDP, TCP on
//! truncation, through `styx-net`'s shared exchange.

use std::net::SocketAddr;
use std::time::Instant;

use styx_core::Clock;
use styx_net::{Do53Client, ExchangeError};
use styx_proto::{Header, Message, Opcode, Opt, Question, ResponseCode};

use crate::domain::metrics::EdnsCapability;
use crate::domain::ports::{
    EdnsObservation, Transport, TransportError, TransportFailure, TransportReply,
};
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

    /// One question to one server: UDP, and TCP if the reply was truncated.
    async fn send(
        &self,
        server: NameserverAddr,
        question: &Question,
        with_edns: bool,
        deadline: Instant,
    ) -> Result<Sent, TransportFailure> {
        let mut query = Message::new(Header::new_query(0, Opcode::Query, false));
        query.questions.push(question.clone());
        if with_edns {
            query.opt = Some(Opt::new(ADVERTISED_PAYLOAD, 0, 0, true, Vec::new()));
        }
        let exchanged = self
            .client
            .exchange(SocketAddr::new(server.ip(), self.port), query, deadline)
            .await
            .map_err(failure_of)?;
        Ok(Sent {
            message: exchanged.message,
            via_tcp: exchanged.via_tcp,
        })
    }
}

/// One answered exchange.
struct Sent {
    message: Message,
    via_tcp: bool,
}

impl Sent {
    /// Packets-worth of exchanges it took: UDP, plus TCP after a truncated reply.
    const fn wire_exchanges(&self) -> u8 {
        if self.via_tcp {
            2
        } else {
            1
        }
    }
}

impl<C: Clock> Transport for Do53Transport<C> {
    async fn query(
        &self,
        server: NameserverAddr,
        question: &Question,
        edns: EdnsCapability,
        deadline: Instant,
    ) -> Result<TransportReply, TransportFailure> {
        let with_edns = !matches!(edns, EdnsCapability::Intolerant(_));
        let first = self.send(server, question, with_edns, deadline).await?;
        if !with_edns {
            return Ok(reply(first, EdnsObservation::Inconclusive, 0));
        }
        if rejects_edns(&first.message) {
            let spent = first.wire_exchanges();
            let plain = self
                .send(server, question, false, deadline)
                .await
                .map_err(|failed| failed.after(spent))?;
            let edns = if rejects_edns(&plain.message) {
                EdnsObservation::Inconclusive
            } else {
                EdnsObservation::Intolerant
            };
            return Ok(reply(plain, edns, spent));
        }
        let edns = first
            .message
            .opt
            .as_ref()
            .map_or(EdnsObservation::Inconclusive, |opt| {
                EdnsObservation::Supported(opt.udp_payload_size())
            });
        Ok(reply(first, edns, 0))
    }
}

/// The reply for `sent`, charged for it and for the `earlier` exchanges of the same
/// query.
fn reply(sent: Sent, edns: EdnsObservation, earlier: u8) -> TransportReply {
    TransportReply {
        wire_exchanges: earlier.saturating_add(sent.wire_exchanges()),
        via_tcp: sent.via_tcp,
        message: sent.message,
        edns,
    }
}

impl TransportFailure {
    /// The same failure, charged for `earlier` exchanges already spent.
    const fn after(self, earlier: u8) -> Self {
        Self {
            error: self.error,
            wire_exchanges: earlier.saturating_add(self.wire_exchanges),
        }
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

/// What a failed exchange cost. A truncated reply was retried over TCP, so it cost
/// two; for every other failure the TCP leg, if reached, is not visible, so it is
/// counted as one.
fn failure_of(error: ExchangeError) -> TransportFailure {
    let wire_exchanges = if matches!(error, ExchangeError::Truncated) {
        2
    } else {
        1
    };
    TransportFailure {
        error: map_exchange_error(error),
        wire_exchanges,
    }
}

fn map_exchange_error(error: ExchangeError) -> TransportError {
    match error {
        ExchangeError::Timeout => TransportError::Timeout,
        ExchangeError::Transport(kind) => TransportError::Unreachable(kind),
        ExchangeError::Truncated => TransportError::Truncated,
        ExchangeError::Encode(_)
        | ExchangeError::NoQuestion
        | ExchangeError::Malformed(_)
        | ExchangeError::Mismatched
        | ExchangeError::OversizeFrame { .. } => TransportError::Malformed,
    }
}

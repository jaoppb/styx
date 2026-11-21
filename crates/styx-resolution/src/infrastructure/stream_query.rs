//! Shared query execution for every stream transport (plaintext TCP, DoT, and DoH):
//! decoding the wire query, answering early FORMERR/BADVERS, running the resolution
//! pipeline, and encoding the response.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use styx_proto::application::Decoder;
use styx_proto::{DecodeError, Message, MessageKind};

use styx_core::{Clock, Sleeper};

use crate::application::terminal::TerminalHandler;
use crate::domain::client_reply::error_reply;
use crate::domain::ports::filter::FilterPolicy;
use crate::domain::ports::local::LocalRecords;
use crate::domain::ports::observer::QueryObserver;
use crate::domain::request::{ClientId, MaxResponseSize, RequestContext, Transport};
use crate::infrastructure::admission::ListenerShared;
use crate::infrastructure::early_reply::{badvers_reply, formerr_reply};
use crate::infrastructure::malformed_warning::MalformedWarning;
use crate::infrastructure::response::ResponseWriter;

/// An encoded DNS response alongside its smallest answer/authority TTL.
pub(crate) struct EncodedAnswer {
    pub(crate) wire: Vec<u8>,
    pub(crate) min_ttl: Option<u32>,
}

/// One query, answered on its own task: decoded, run through the pipeline and encoded the
/// same way for every stream transport, DoH included.
pub(crate) struct QueryTask<L, F, O, C, T, S> {
    shared: ListenerShared<L, F, O, C, T, S>,
    malformed_warning: Arc<MalformedWarning<C, S>>,
    peer: SocketAddr,
    transport: Transport,
    received_at: Instant,
}

impl<L, F, O, C, T, S> QueryTask<L, F, O, C, T, S>
where
    L: LocalRecords + Send + Sync + 'static,
    F: FilterPolicy + Send + Sync + 'static,
    O: QueryObserver + Send + Sync + 'static,
    C: Clock + Send + Sync + 'static,
    T: TerminalHandler + Send + Sync + 'static,
    S: Sleeper + Send + Sync + 'static,
{
    /// A query task for `peer` on `transport`, received at `received_at`.
    pub(crate) fn new(
        shared: ListenerShared<L, F, O, C, T, S>,
        malformed_warning: Arc<MalformedWarning<C, S>>,
        peer: SocketAddr,
        transport: Transport,
        received_at: Instant,
    ) -> Self {
        Self {
            shared,
            malformed_warning,
            peer,
            transport,
            received_at,
        }
    }

    /// The encoded answer to `bytes`, or `None` when the message gets no answer at all.
    pub(crate) async fn respond(&self, bytes: &[u8]) -> Option<EncodedAnswer> {
        let mut decoder = Decoder::new(bytes);
        let query = match decoder.decode_message() {
            Ok(msg) => msg,
            Err(DecodeError::UnsupportedEdnsVersion(rejected)) => {
                tracing::debug!(peer = %self.peer, version = rejected.version(), "unsupported EDNS version; answering BADVERS");
                return self.reply_early(badvers_reply(&rejected));
            }
            Err(err) => {
                tracing::debug!(peer = %self.peer, transport = self.transport.name(), %err, "malformed stream query; responding FORMERR");
                self.malformed_warning.record();
                return self.reply_early(formerr_reply(bytes));
            }
        };

        if query.header.kind == MessageKind::Response {
            tracing::debug!(peer = %self.peer, transport = self.transport.name(), "silently dropping inbound response (QR=1)");
            return None;
        }

        let client = ClientId::from_socket_addr(self.peer);
        let max_size = MaxResponseSize::tcp_ceiling();
        let ctx = RequestContext::new(
            query,
            client,
            self.transport,
            max_size,
            self.shared.udp_payload_size_default,
            self.received_at,
        );
        let pipeline = &self.shared.pipeline;
        let response = match pipeline
            .handle_within(&ctx, self.shared.query_timeout)
            .await
        {
            Ok(msg) => msg,
            Err(crate::domain::error::PipelineError::InboundResponse) => return None,
            Err(err) => error_reply(&ctx.query, err.response_code()),
        };
        self.encode(response, &ctx)
    }

    /// Encodes `reply` to a query that never reached the pipeline, or drops it when there is
    /// no reply to give.
    fn reply_early(&self, reply: Option<Message>) -> Option<EncodedAnswer> {
        let Some(reply) = reply else {
            tracing::debug!(peer = %self.peer, transport = self.transport.name(), "silently dropping unanswerable message");
            return None;
        };
        self.encode_error_reply(reply)
    }

    /// Encodes a reply to a query that never reached the pipeline.
    fn encode_error_reply(&self, resp: Message) -> Option<EncodedAnswer> {
        let client = ClientId::from_socket_addr(self.peer);
        let ctx = RequestContext::new(
            resp.clone(),
            client,
            self.transport,
            MaxResponseSize::tcp_ceiling(),
            self.shared.udp_payload_size_default,
            self.received_at,
        );
        self.encode(resp, &ctx)
    }

    fn encode(&self, message: Message, ctx: &RequestContext) -> Option<EncodedAnswer> {
        let min_ttl = min_ttl_of(&message);
        match ResponseWriter::new().write(message, ctx) {
            Ok(wire) => Some(EncodedAnswer { wire, min_ttl }),
            Err(err) => {
                tracing::error!(peer = %self.peer, transport = self.transport.name(), %err, "failed to serialize stream response");
                None
            }
        }
    }
}

fn min_ttl_of(message: &Message) -> Option<u32> {
    let section = if message.answers.is_empty() {
        &message.authorities
    } else {
        &message.answers
    };
    section.iter().map(|record| record.ttl.seconds()).min()
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use styx_proto::{Header, Name, Opcode, RData, RecordClass, RecordType, ResourceRecord, Ttl};

    use super::*;

    fn a_record(ttl: u32) -> ResourceRecord {
        ResourceRecord::new(
            Name::root(),
            RecordType::A,
            RecordClass::In,
            Ttl::from_secs(ttl),
            RData::A(Ipv4Addr::LOCALHOST),
        )
    }

    #[test]
    fn min_ttl_prefers_answers_falls_back_to_authorities_and_none_when_empty() {
        let mut msg = Message::new(Header::new_query(1, Opcode::Query, false));
        assert_eq!(min_ttl_of(&msg), None);

        msg.authorities.push(a_record(120));
        msg.authorities.push(a_record(45));
        assert_eq!(min_ttl_of(&msg), Some(45));

        msg.answers.push(a_record(300));
        msg.answers.push(a_record(90));
        assert_eq!(min_ttl_of(&msg), Some(90));
    }
}

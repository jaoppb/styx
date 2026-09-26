//! DNS resolution outcome, provenance tracking, and forged answer synthesis.

use styx_proto::{Header, Message, MessageKind, RecordType, ResourceRecord, ResponseCode, Ttl};

use crate::domain::request::RequestContext;

/// Provenance of a resolved or forged answer.
///
/// Records which stage in the resolution pipeline produced the answer.
/// This is the sole provenance type in `styx-resolution`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnswerSource {
    /// Matched an operator-configured local record in storage.
    LocalRecord,
    /// Synthesized via block policy (e.g. adlist filter).
    Blocked,
    /// Retrieved from the in-memory answer cache.
    CacheHit,
    /// Forwarded to and answered by an upstream resolver.
    Upstream,
    /// Resolved iteratively via the recursion engine.
    Recursion,
    /// Synthesized as an error response (e.g. FORMERR, NOTIMP, REFUSED).
    Error,
}

/// Metadata and audit record of a resolution decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionOutcome {
    /// Which pipeline stage produced the answer.
    pub source: AnswerSource,
    /// The DNS response code returned to the client.
    pub rcode: ResponseCode,
    /// Whether the answer was invented/synthesized by styx rather than authoritative.
    pub forged: bool,
    /// Whether this answer is eligible for insertion into the global answer cache.
    pub cacheable: bool,
    /// Whether the authentic data (AD) bit was verified and set.
    pub authentic_data: bool,
}

/// A synthesized DNS answer produced inside styx.
///
/// **The forged-answer honesty rule**:
/// `ForgedAnswer::build` is the **only** mechanism to construct an answer
/// invented by styx. It unconditionally clears the AD bit, attaches no RRSIG
/// or DNSKEY records, applies a short TTL, and marks the outcome uncacheable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForgedAnswer {
    message: Message,
    source: AnswerSource,
}

impl ForgedAnswer {
    /// Constructs a forged answer for the given request context.
    ///
    /// # Invariants Enforced
    /// - Question section is preserved from incoming query.
    /// - Response QR bit is set to `MessageKind::Response`.
    /// - Recursion Available (RA) bit is set.
    /// - Authentic Data (AD) bit is unconditionally CLEARED (`false`).
    /// - No RRSIG or DNSKEY records are attached.
    /// - The supplied `ttl` is applied to all synthesized records.
    /// - Outcome is marked `forged: true, cacheable: false, authentic_data: false`.
    #[must_use]
    pub fn build(
        ctx: &RequestContext,
        records: Vec<ResourceRecord>,
        rcode: ResponseCode,
        ttl: Ttl,
    ) -> Self {
        let mut header = Header::new_query(ctx.query.header.id, ctx.query.header.opcode, false);
        header.kind = MessageKind::Response;
        header.rcode = rcode;
        header.recursion_available = true;
        header.recursion_desired = ctx.query.header.recursion_desired;
        header.authoritative = false;
        header.authentic_data = false;
        header.checking_disabled = ctx.query.header.checking_disabled;

        // Apply short TTL and filter out any accidental DNSSEC key/sig records
        let answers = records
            .into_iter()
            .filter(|rr| rr.rtype != RecordType::RRSIG && rr.rtype != RecordType::DNSKEY)
            .map(|mut rr| {
                rr.ttl = ttl;
                rr
            })
            .collect();

        let mut message = Message::new(header);
        message.questions = ctx.query.questions.clone();
        message.answers = answers;

        // Preserve EDNS OPT skeleton if the client requested EDNS
        if let Some(client_opt) = &ctx.query.opt {
            let opt = styx_proto::Opt::new(client_opt.udp_payload_size(), 0, 0, false, Vec::new());
            message.opt = Some(opt);
        }

        Self {
            message,
            source: AnswerSource::LocalRecord,
        }
    }

    /// Constructs a forged answer with a specific [`AnswerSource`].
    #[must_use]
    pub fn build_with_source(
        ctx: &RequestContext,
        records: Vec<ResourceRecord>,
        rcode: ResponseCode,
        ttl: Ttl,
        source: AnswerSource,
    ) -> Self {
        let mut forged = Self::build(ctx, records, rcode, ttl);
        forged.source = source;
        forged
    }

    /// Returns the resolution outcome audit descriptor for this forged answer.
    #[must_use]
    pub fn outcome(&self) -> ResolutionOutcome {
        ResolutionOutcome {
            source: self.source,
            rcode: self.message.header.rcode,
            forged: true,
            cacheable: false,
            authentic_data: false,
        }
    }

    /// Consumes the wrapper and returns the assembled [`Message`].
    #[must_use]
    pub fn into_response(self) -> Message {
        self.message
    }
}

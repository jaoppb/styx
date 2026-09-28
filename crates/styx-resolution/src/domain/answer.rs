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

/// Provenance of a forged answer synthesized by styx.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ForgedSource {
    /// Matched an operator-configured local record in storage.
    LocalRecord,
    /// Synthesized via block policy (e.g. adlist filter).
    Blocked,
}

impl From<ForgedSource> for AnswerSource {
    fn from(source: ForgedSource) -> Self {
        match source {
            ForgedSource::LocalRecord => Self::LocalRecord,
            ForgedSource::Blocked => Self::Blocked,
        }
    }
}

/// Provenance of an authentic or upstream resolved answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResolvedSource {
    /// Retrieved from the in-memory answer cache.
    CacheHit,
    /// Forwarded to and answered by an upstream resolver.
    Upstream,
    /// Resolved iteratively via the recursion engine.
    Recursion,
}

impl From<ResolvedSource> for AnswerSource {
    fn from(source: ResolvedSource) -> Self {
        match source {
            ResolvedSource::CacheHit => Self::CacheHit,
            ResolvedSource::Upstream => Self::Upstream,
            ResolvedSource::Recursion => Self::Recursion,
        }
    }
}

/// Metadata and audit record of a resolution decision.
///
/// Encoded as an enum to structurally forbid impossible states (such as
/// a forged or error answer being marked as cacheable or authentic).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolutionOutcome {
    /// Answer synthesized by styx. Never cacheable; authentic data is always false.
    Forged {
        /// Source that triggered the forged answer.
        source: ForgedSource,
        /// DNS response code.
        rcode: ResponseCode,
    },
    /// Resolved authoritative answer (from cache, upstream, or recursion).
    Resolved {
        /// Resolution path provenance.
        source: ResolvedSource,
        /// DNS response code.
        rcode: ResponseCode,
        /// Whether the answer is eligible for the global cache.
        cacheable: bool,
        /// Whether DNSSEC validation succeeded and authentic data is set.
        authentic_data: bool,
    },
    /// Synthesized protocol error response (FORMERR, NOTIMP, etc.). Never cacheable.
    Error {
        /// DNS response code.
        rcode: ResponseCode,
    },
}

impl ResolutionOutcome {
    /// Returns the DNS response code associated with this outcome.
    #[must_use]
    pub const fn rcode(&self) -> ResponseCode {
        match self {
            Self::Forged { rcode, .. } | Self::Resolved { rcode, .. } | Self::Error { rcode } => {
                *rcode
            }
        }
    }

    /// Returns `true` if the answer was synthesized/invented by styx.
    #[must_use]
    pub const fn is_forged(&self) -> bool {
        matches!(self, Self::Forged { .. })
    }

    /// Returns `true` if this answer is eligible for insertion into the answer cache.
    #[must_use]
    pub const fn is_cacheable(&self) -> bool {
        match self {
            Self::Resolved { cacheable, .. } => *cacheable,
            Self::Forged { .. } | Self::Error { .. } => false,
        }
    }

    /// Returns `true` if the authentic data (AD) flag is verified and valid.
    #[must_use]
    pub const fn authentic_data(&self) -> bool {
        match self {
            Self::Resolved { authentic_data, .. } => *authentic_data,
            Self::Forged { .. } | Self::Error { .. } => false,
        }
    }

    /// Returns the general provenance [`AnswerSource`] of this outcome.
    #[must_use]
    pub const fn source(&self) -> AnswerSource {
        match self {
            Self::Forged { source, .. } => match source {
                ForgedSource::LocalRecord => AnswerSource::LocalRecord,
                ForgedSource::Blocked => AnswerSource::Blocked,
            },
            Self::Resolved { source, .. } => match source {
                ResolvedSource::CacheHit => AnswerSource::CacheHit,
                ResolvedSource::Upstream => AnswerSource::Upstream,
                ResolvedSource::Recursion => AnswerSource::Recursion,
            },
            Self::Error { .. } => AnswerSource::Error,
        }
    }
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
    source: ForgedSource,
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
        Self::build_with_source(ctx, records, rcode, ttl, ForgedSource::LocalRecord)
    }

    /// Constructs a forged answer with a specific [`ForgedSource`].
    #[must_use]
    pub fn build_with_source(
        ctx: &RequestContext,
        records: Vec<ResourceRecord>,
        rcode: ResponseCode,
        ttl: Ttl,
        source: ForgedSource,
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

        Self { message, source }
    }

    /// Returns the resolution outcome audit descriptor for this forged answer.
    #[must_use]
    pub fn outcome(&self) -> ResolutionOutcome {
        ResolutionOutcome::Forged {
            source: self.source,
            rcode: self.message.header.rcode,
        }
    }

    /// Consumes the wrapper and returns the assembled [`Message`].
    #[must_use]
    pub fn into_response(self) -> Message {
        self.message
    }
}

/// A completed DNS resolution response paired with its audit outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionResponse {
    message: Message,
    outcome: ResolutionOutcome,
}

impl ResolutionResponse {
    /// Creates a new `ResolutionResponse`.
    #[must_use]
    pub const fn new(message: Message, outcome: ResolutionOutcome) -> Self {
        Self { message, outcome }
    }

    /// Returns a reference to the wire message.
    #[must_use]
    pub const fn message(&self) -> &Message {
        &self.message
    }

    /// Returns a reference to the resolution outcome.
    #[must_use]
    pub const fn outcome(&self) -> &ResolutionOutcome {
        &self.outcome
    }

    /// Decomposes the response into its wire message and outcome.
    #[must_use]
    pub fn into_parts(self) -> (Message, ResolutionOutcome) {
        (self.message, self.outcome)
    }
}

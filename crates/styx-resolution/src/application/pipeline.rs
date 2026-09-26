//! Request processing pipeline orchestrating stage order and outcome audit.

use std::sync::Arc;

use styx_proto::{Message, Opcode, Question, RecordClass, ResponseCode, Ttl};

use crate::application::terminal::{RefusedTerminal, TerminalHandler};
use crate::domain::answer::{AnswerSource, ForgedAnswer, ResolutionOutcome};
use crate::domain::clock::Clock;
use crate::domain::error::PipelineError;
use crate::domain::ports::filter::{FilterPolicy, FilterVerdict};
use crate::domain::ports::local::LocalRecords;
use crate::domain::ports::observer::{QueryDetail, QueryObserver};
use crate::domain::request::RequestContext;

/// Default TTL for blocked forged answers (2 seconds, anti-cache-pollution).
const BLOCKED_TTL: Ttl = Ttl::from_secs(2);

/// Default TTL for forged local record answers.
const LOCAL_RECORD_TTL: Ttl = Ttl::from_secs(60);

/// DNS resolution pipeline enforcing fixed stage execution order.
///
/// Order is a correctness property: Local Records -> Filter -> Cache -> Upstream.
pub struct Pipeline {
    local_records: Arc<dyn LocalRecords>,
    filter: Arc<dyn FilterPolicy>,
    observer: Arc<dyn QueryObserver>,
    clock: Arc<dyn Clock>,
    terminal: Arc<dyn TerminalHandler>,
}

impl Pipeline {
    /// Creates a new `Pipeline` with default refused terminal.
    #[must_use]
    pub fn new(
        local_records: Arc<dyn LocalRecords>,
        filter: Arc<dyn FilterPolicy>,
        observer: Arc<dyn QueryObserver>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            local_records,
            filter,
            observer,
            clock,
            terminal: Arc::new(RefusedTerminal::new()),
        }
    }

    /// Substitutes the terminal handler (used by test fixtures).
    #[must_use]
    pub fn with_terminal(mut self, terminal: Arc<dyn TerminalHandler>) -> Self {
        self.terminal = terminal;
        self
    }

    /// Handles an incoming DNS query through the fixed pipeline stages.
    ///
    /// # Errors
    /// Returns [`PipelineError`] mapped to DNS RCODEs on validation or resolution failure.
    pub fn handle(&self, ctx: RequestContext) -> Result<Message, PipelineError> {
        let question = match self.validate_input(&ctx.query) {
            Ok(q) => q.clone(),
            Err(err) => return self.handle_error(&ctx, err),
        };

        if let Some(forged) = self.try_local_records(&ctx, &question) {
            let outcome = forged.outcome();
            self.record_telemetry(&ctx, &question, &outcome);
            return Ok(forged.into_response());
        }

        if let Some(forged) = self.try_filter(&ctx, &question) {
            let outcome = forged.outcome();
            self.record_telemetry(&ctx, &question, &outcome);
            return Ok(forged.into_response());
        }

        self.run_terminal(&ctx, &question)
    }

    fn validate_input<'a>(&self, query: &'a Message) -> Result<&'a Question, PipelineError> {
        if query.questions.is_empty() {
            return Err(PipelineError::MalformedQuery);
        }
        if query.questions.len() > 1 {
            return Err(PipelineError::MultipleQuestions);
        }
        if query.header.opcode != Opcode::Query {
            return Err(PipelineError::UnsupportedOpcode(query.header.opcode));
        }

        let question = match query.questions.first() {
            Some(q) => q,
            None => return Err(PipelineError::MalformedQuery),
        };

        if question.qclass != RecordClass::In {
            return Err(PipelineError::UnsupportedClass(question.qclass));
        }

        Ok(question)
    }

    fn try_local_records(&self, ctx: &RequestContext, question: &Question) -> Option<ForgedAnswer> {
        let records = self.local_records.lookup(question)?;
        Some(ForgedAnswer::build_with_source(
            ctx,
            records,
            ResponseCode::NOERROR,
            LOCAL_RECORD_TTL,
            AnswerSource::LocalRecord,
        ))
    }

    fn try_filter(&self, ctx: &RequestContext, question: &Question) -> Option<ForgedAnswer> {
        match self.filter.evaluate(&ctx.client, question) {
            FilterVerdict::Allow => None,
            FilterVerdict::Block => Some(ForgedAnswer::build_with_source(
                ctx,
                Vec::new(),
                ResponseCode::NXDOMAIN,
                BLOCKED_TTL,
                AnswerSource::Blocked,
            )),
        }
    }

    fn run_terminal(
        &self,
        ctx: &RequestContext,
        question: &Question,
    ) -> Result<Message, PipelineError> {
        match self.terminal.handle_terminal(ctx) {
            Ok(message) => {
                let outcome = ResolutionOutcome {
                    source: AnswerSource::Error,
                    rcode: message.header.rcode,
                    forged: true,
                    cacheable: false,
                    authentic_data: false,
                };
                self.record_telemetry(ctx, question, &outcome);
                Ok(message)
            }
            Err(err) => self.handle_error(ctx, err),
        }
    }

    fn handle_error(
        &self,
        ctx: &RequestContext,
        err: PipelineError,
    ) -> Result<Message, PipelineError> {
        let rcode = err.response_code();
        let fallback_question = match ctx.query.questions.first() {
            Some(q) => q.clone(),
            None => Question::new(
                styx_proto::Name::root(),
                styx_proto::RecordType::A,
                RecordClass::In,
            ),
        };

        let outcome = ResolutionOutcome {
            source: AnswerSource::Error,
            rcode,
            forged: true,
            cacheable: false,
            authentic_data: false,
        };

        self.record_telemetry(ctx, &fallback_question, &outcome);
        Err(err)
    }

    fn record_telemetry(
        &self,
        ctx: &RequestContext,
        question: &Question,
        outcome: &ResolutionOutcome,
    ) {
        let now_mono = self.clock.now_monotonic();
        let now_utc = self.clock.now_utc();
        let elapsed = now_mono.saturating_duration_since(ctx.received_at);

        self.observer.record_outcome(&ctx.client, question, outcome);
        self.observer.offer_detail(QueryDetail {
            client: ctx.client,
            question: question.clone(),
            outcome: outcome.clone(),
            at: now_utc,
            elapsed,
        });
    }
}

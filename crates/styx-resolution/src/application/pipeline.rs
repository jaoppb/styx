//! Request processing pipeline orchestrating stage order and outcome audit.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use styx_core::Clock;
use styx_proto::{Message, Opcode, Question, RecordClass, ResponseCode, Ttl};

use crate::application::terminal::{RefusedTerminal, TerminalHandler};
use crate::domain::answer::{ForgedAnswer, ForgedSource, ResolutionOutcome, ResolutionResponse};
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
pub struct Pipeline<L, F, O, C, T = RefusedTerminal> {
    local_records: Arc<L>,
    filter: Arc<F>,
    observer: Arc<O>,
    clock: Arc<C>,
    terminal: Arc<T>,
}

impl<L, F, O, C> Pipeline<L, F, O, C, RefusedTerminal>
where
    L: LocalRecords,
    F: FilterPolicy,
    O: QueryObserver,
    C: Clock,
{
    /// Creates a new `Pipeline` with default refused terminal.
    #[must_use]
    pub fn new(local_records: Arc<L>, filter: Arc<F>, observer: Arc<O>, clock: Arc<C>) -> Self {
        Self {
            local_records,
            filter,
            observer,
            clock,
            terminal: Arc::new(RefusedTerminal::new()),
        }
    }
}

impl<L, F, O, C, T> Pipeline<L, F, O, C, T>
where
    L: LocalRecords,
    F: FilterPolicy,
    O: QueryObserver,
    C: Clock,
    T: TerminalHandler,
{
    /// Substitutes the terminal handler (used by test fixtures).
    #[must_use]
    pub fn with_terminal<T2: TerminalHandler>(self, terminal: Arc<T2>) -> Pipeline<L, F, O, C, T2> {
        Pipeline {
            local_records: self.local_records,
            filter: self.filter,
            observer: self.observer,
            clock: self.clock,
            terminal,
        }
    }

    /// Handles an incoming DNS query through the fixed pipeline stages.
    ///
    /// # Errors
    /// Returns [`PipelineError`] mapped to DNS RCODEs on validation or resolution failure.
    pub async fn handle(&self, ctx: &RequestContext) -> Result<Message, PipelineError> {
        self.handle_inner(ctx, None).await
    }

    /// Handles a query like [`Self::handle`], answering SERVFAIL once `deadline` has
    /// elapsed since the query was received.
    ///
    /// Only the terminal stage can exceed a deadline, so only it is raced. On expiry the
    /// terminal future is dropped and the outcome is still recorded exactly once, through
    /// the same telemetry funnel as every other path — which is why the deadline lives
    /// here rather than in a `timeout` wrapped around the pipeline by a caller.
    ///
    /// # Errors
    /// Returns [`PipelineError`] mapped to DNS RCODEs, including
    /// [`PipelineError::Internal`] (SERVFAIL) when the deadline expires.
    pub async fn handle_within(
        &self,
        ctx: &RequestContext,
        deadline: Duration,
    ) -> Result<Message, PipelineError> {
        self.handle_inner(ctx, Some(deadline)).await
    }

    async fn handle_inner(
        &self,
        ctx: &RequestContext,
        deadline: Option<Duration>,
    ) -> Result<Message, PipelineError> {
        let question = match self.validate_input(&ctx.query) {
            Ok(q) => q,
            Err(err) => return self.handle_error(ctx, err),
        };

        if let Some(forged) = self.try_local_records(ctx, question) {
            let outcome = forged.outcome();
            self.record_telemetry(ctx, question, &outcome);
            return Ok(forged.into_response());
        }

        if let Some(forged) = self.try_filter(ctx, question) {
            let outcome = forged.outcome();
            self.record_telemetry(ctx, question, &outcome);
            return Ok(forged.into_response());
        }

        self.run_terminal(ctx, question, deadline).await
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
            ForgedSource::LocalRecord,
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
                ForgedSource::Blocked,
            )),
        }
    }

    async fn run_terminal(
        &self,
        ctx: &RequestContext,
        question: &Question,
        deadline: Option<Duration>,
    ) -> Result<Message, PipelineError> {
        let terminal = self.terminal.handle_terminal(ctx);
        let result = match deadline {
            None => terminal.await,
            Some(deadline) => self.race_deadline(ctx, question, deadline, terminal).await,
        };
        match result {
            Ok(terminal_response) => {
                let (message, outcome) = terminal_response.into_parts();
                self.record_telemetry(ctx, question, &outcome);
                Ok(message)
            }
            Err(err) => self.handle_error(ctx, err),
        }
    }

    async fn race_deadline(
        &self,
        ctx: &RequestContext,
        question: &Question,
        deadline: Duration,
        terminal: impl Future<Output = Result<ResolutionResponse, PipelineError>>,
    ) -> Result<ResolutionResponse, PipelineError> {
        let elapsed = self
            .clock
            .now_monotonic()
            .saturating_duration_since(ctx.received_at);
        let remaining = deadline.saturating_sub(elapsed);
        if let Ok(result) = tokio::time::timeout(remaining, terminal).await {
            return result;
        }
        tracing::warn!(
            client = %ctx.client.addr,
            qname = %question.qname,
            deadline_ms = deadline.as_millis(),
            "query deadline exceeded; answering SERVFAIL"
        );
        Err(PipelineError::Internal("query deadline exceeded".into()))
    }

    fn handle_error(
        &self,
        ctx: &RequestContext,
        err: PipelineError,
    ) -> Result<Message, PipelineError> {
        let rcode = err.response_code();
        let fallback;
        let question = match ctx.query.questions.first() {
            Some(q) => q,
            None => {
                fallback = Question::new(
                    styx_proto::Name::root(),
                    styx_proto::RecordType::A,
                    RecordClass::In,
                );
                &fallback
            }
        };

        let outcome = ResolutionOutcome::Error { rcode };

        self.record_telemetry(ctx, question, &outcome);
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
        if self.observer.wants_detail() {
            self.observer.offer_detail(QueryDetail {
                client: ctx.client,
                question: question.clone(),
                outcome: outcome.clone(),
                at: now_utc,
                elapsed,
            });
        }
    }
}

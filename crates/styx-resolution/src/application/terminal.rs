//! Configurable terminal stage for the resolution pipeline.

use std::future::Future;

use styx_proto::{Message, ResponseCode};

use crate::domain::answer::{ResolutionOutcome, ResolutionResponse};
use crate::domain::error::PipelineError;
use crate::domain::request::RequestContext;

/// Trait for handling queries that reach the end of the resolution pipeline.
pub trait TerminalHandler: Send + Sync + 'static {
    /// Produces a DNS response and resolution outcome for queries reaching the end of the pipeline.
    ///
    /// # Errors
    /// Returns [`PipelineError`] if the query cannot be processed.
    fn handle_terminal(
        &self,
        ctx: &RequestContext,
    ) -> impl Future<Output = Result<ResolutionResponse, PipelineError>> + Send;
}

/// Default terminal implementation returning REFUSED with echoed questions.
#[derive(Debug, Clone, Copy, Default)]
pub struct RefusedTerminal;

impl RefusedTerminal {
    /// Creates a new `RefusedTerminal`.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl TerminalHandler for RefusedTerminal {
    async fn handle_terminal(
        &self,
        ctx: &RequestContext,
    ) -> Result<ResolutionResponse, PipelineError> {
        let question = ctx
            .query
            .questions
            .first()
            .cloned()
            .ok_or(PipelineError::MalformedQuery)?;

        let mut response = Message::response_to(ctx.query.header.id, question);
        response.header.opcode = ctx.query.header.opcode;
        response.header.rcode = ResponseCode::REFUSED;
        response.header.recursion_available = true;
        response.header.recursion_desired = ctx.query.header.recursion_desired;

        if let Some(opt) = &ctx.query.opt {
            let resp_opt = styx_proto::Opt::new(opt.udp_payload_size(), 0, 0, false, Vec::new());
            response.opt = Some(resp_opt);
        }

        let outcome = ResolutionOutcome::Error {
            rcode: ResponseCode::REFUSED,
        };

        Ok(ResolutionResponse::new(response, outcome))
    }
}

/// Standalone terminal stage that resolves directly through an [`UpstreamPool`].
pub struct PoolTerminal<S, U, C> {
    pool: std::sync::Arc<crate::application::pool::UpstreamPool<S, U, C>>,
    _clock: std::sync::Arc<C>,
    query_timeout: std::time::Duration,
}

impl<S, U, C> PoolTerminal<S, U, C> {
    /// Creates a new `PoolTerminal`.
    #[must_use]
    pub fn new(
        pool: std::sync::Arc<crate::application::pool::UpstreamPool<S, U, C>>,
        clock: std::sync::Arc<C>,
        query_timeout: std::time::Duration,
    ) -> Self {
        Self {
            pool,
            _clock: clock,
            query_timeout,
        }
    }

    /// Returns a reference to the inner pool.
    #[must_use]
    pub fn pool(&self) -> &std::sync::Arc<crate::application::pool::UpstreamPool<S, U, C>> {
        &self.pool
    }
}

impl<S, U, C> TerminalHandler for PoolTerminal<S, U, C>
where
    S: crate::domain::selection::SelectionStrategy + 'static,
    U: styx_core::Upstream + Clone + 'static,
    C: styx_core::Clock + 'static,
{
    async fn handle_terminal(
        &self,
        ctx: &RequestContext,
    ) -> Result<ResolutionResponse, PipelineError> {
        let question = ctx
            .query
            .questions
            .first()
            .ok_or(PipelineError::MalformedQuery)?;

        let deadline = ctx
            .received_at
            .checked_add(self.query_timeout)
            .unwrap_or(ctx.received_at);

        let upstream_resp = self.pool.resolve(question, deadline).await?;
        let mut message = upstream_resp.message;
        message.header.id = ctx.query.header.id;

        let source = match upstream_resp.kind {
            styx_core::UpstreamKind::Forwarder => crate::domain::answer::ResolvedSource::Upstream,
            styx_core::UpstreamKind::Recursor => crate::domain::answer::ResolvedSource::Recursion,
        };

        let outcome = ResolutionOutcome::Resolved {
            source,
            rcode: message.header.rcode,
            cacheable: true,
            authentic_data: message.header.authentic_data,
        };

        Ok(ResolutionResponse::new(message, outcome))
    }
}

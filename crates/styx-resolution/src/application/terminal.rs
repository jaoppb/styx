//! Configurable terminal stage for the resolution pipeline.

use std::future::Future;

use styx_proto::{Message, ResponseCode};

use crate::domain::answer::ResolutionOutcome;
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
    ) -> impl Future<Output = Result<(Message, ResolutionOutcome), PipelineError>> + Send;
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
    ) -> Result<(Message, ResolutionOutcome), PipelineError> {
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

        Ok((response, outcome))
    }
}

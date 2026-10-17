//! Cache pipeline stage handling lookup, upstream resolution on miss, and admission.

use std::sync::Arc;
use std::time::Duration;

use styx_core::{Clock, Upstream, UpstreamKind};

use crate::application::pool::UpstreamPool;
use crate::application::terminal::TerminalHandler;
use crate::domain::answer::{AnswerSource, ResolutionOutcome, ResolutionResponse, ResolvedSource};
use crate::domain::cache::admission::Admission;
use crate::domain::cache::admission_request::AdmissionRequest;
use crate::domain::cache::entry::CacheEntry;
use crate::domain::cache::error::CacheError;
use crate::domain::cache::key::CacheKey;
use crate::domain::cache::port::{AnswerCache, Lookup};
use crate::domain::cache::ttl::TtlPolicy;
use crate::domain::client_reply::conform_to_query;
use crate::domain::error::PipelineError;
use crate::domain::request::RequestContext;
use crate::domain::selection::SelectionStrategy;

/// Resolution terminal stage integrating the answer cache with the upstream pool.
pub struct CacheStage<A, S, U, C> {
    cache: Arc<A>,
    pool: Arc<UpstreamPool<S, U, C>>,
    admission: Admission,
    clock: Arc<C>,
    query_timeout: Duration,
}

impl<A, S, U, C> CacheStage<A, S, U, C>
where
    A: AnswerCache,
    S: SelectionStrategy,
    U: Upstream + Clone + 'static,
    C: Clock,
{
    /// Creates a new `CacheStage` with default admission TTL policies.
    #[must_use]
    pub fn new(
        cache: Arc<A>,
        pool: Arc<UpstreamPool<S, U, C>>,
        clock: Arc<C>,
        query_timeout: Duration,
    ) -> Self {
        Self {
            cache,
            pool,
            admission: Admission::new(TtlPolicy::default()),
            clock,
            query_timeout,
        }
    }

    /// Creates a new `CacheStage` with custom admission policy.
    #[must_use]
    pub fn with_admission(
        cache: Arc<A>,
        pool: Arc<UpstreamPool<S, U, C>>,
        admission: Admission,
        clock: Arc<C>,
        query_timeout: Duration,
    ) -> Self {
        Self {
            cache,
            pool,
            admission,
            clock,
            query_timeout,
        }
    }

    /// Returns a reference to the inner answer cache.
    #[must_use]
    pub fn cache(&self) -> &Arc<A> {
        &self.cache
    }

    /// Returns a reference to the upstream pool.
    #[must_use]
    pub fn pool(&self) -> &Arc<UpstreamPool<S, U, C>> {
        &self.pool
    }
    fn handle_cache_hit(
        &self,
        ctx: &RequestContext,
        question: &styx_proto::Question,
        entry: CacheEntry,
    ) -> Result<ResolutionResponse, PipelineError> {
        let now = self.clock.now_monotonic();
        let mut message = entry
            .to_response(question, now)
            .map_err(|e| PipelineError::Internal(e.to_string()))?;
        conform_to_query(&mut message, &ctx.query);

        let outcome = ResolutionOutcome::Resolved {
            source: ResolvedSource::CacheHit,
            rcode: message.header.rcode,
            cacheable: true,
            authentic_data: message.header.authentic_data,
        };

        Ok(ResolutionResponse::new(message, outcome))
    }

    async fn resolve_uncacheable(
        &self,
        ctx: &RequestContext,
        question: &styx_proto::Question,
        deadline: std::time::Instant,
    ) -> Result<ResolutionResponse, PipelineError> {
        let upstream_resp = self.pool.resolve(question, deadline).await?;
        let mut message = upstream_resp.message;
        conform_to_query(&mut message, &ctx.query);

        let source = match upstream_resp.kind {
            UpstreamKind::Forwarder => ResolvedSource::Upstream,
            UpstreamKind::Recursor => ResolvedSource::Recursion,
        };

        let outcome = ResolutionOutcome::Resolved {
            source,
            rcode: message.header.rcode,
            cacheable: false,
            authentic_data: message.header.authentic_data,
        };

        Ok(ResolutionResponse::new(message, outcome))
    }

    async fn resolve_and_admit(
        &self,
        ctx: &RequestContext,
        question: &styx_proto::Question,
        deadline: std::time::Instant,
    ) -> Result<ResolutionResponse, PipelineError> {
        let upstream_resp = self.pool.resolve(question, deadline).await?;
        let now = self.clock.now_monotonic();

        let answer_source = match upstream_resp.kind {
            UpstreamKind::Forwarder => AnswerSource::Upstream,
            UpstreamKind::Recursor => AnswerSource::Recursion,
        };

        let request = AdmissionRequest::new(question, &upstream_resp.message, answer_source, now)
            .map_err(|e| PipelineError::Internal(e.to_string()))?;
        let admission_outcome = self.admission.evaluate(request);

        let _ = self.cache.admit(admission_outcome);

        let mut message = upstream_resp.message;
        conform_to_query(&mut message, &ctx.query);

        let source = match upstream_resp.kind {
            UpstreamKind::Forwarder => ResolvedSource::Upstream,
            UpstreamKind::Recursor => ResolvedSource::Recursion,
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

impl<A, S, U, C> TerminalHandler for CacheStage<A, S, U, C>
where
    A: AnswerCache + 'static,
    S: SelectionStrategy + 'static,
    U: Upstream + Clone + 'static,
    C: Clock + 'static,
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

        let key = match CacheKey::from_question(question) {
            Ok(k) => k,
            Err(CacheError::UncacheableQuestion(_)) => {
                return self.resolve_uncacheable(ctx, question, deadline).await;
            }
            Err(other) => return Err(PipelineError::Internal(other.to_string())),
        };

        match self.cache.lookup(&key) {
            Lookup::Hit(entry) => self.handle_cache_hit(ctx, question, entry),
            Lookup::Miss | Lookup::Expired => self.resolve_and_admit(ctx, question, deadline).await,
        }
    }
}

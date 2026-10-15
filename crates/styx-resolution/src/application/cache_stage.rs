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
use crate::domain::cache::refusal::check_question;
use crate::domain::cache::ttl::TtlPolicy;
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
        query_id: u16,
        key: &CacheKey,
        entry: CacheEntry,
    ) -> Result<ResolutionResponse, PipelineError> {
        let now = self.clock.now_monotonic();
        let mut message = entry
            .to_response(key, now)
            .map_err(|e| PipelineError::Internal(e.to_string()))?;
        message.header.id = query_id;

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
        query_id: u16,
        question: &styx_proto::Question,
        deadline: std::time::Instant,
    ) -> Result<ResolutionResponse, PipelineError> {
        let upstream_resp = self.pool.resolve(question, deadline).await?;
        if let Some(refusal) = check_question(question, &upstream_resp.message) {
            tracing::debug!(
                expected = ?question,
                echoed = ?refusal.echoed(),
                "refused an uncacheable reply that does not answer the question"
            );
            return Err(PipelineError::UntrustedResponse(refusal.reason()));
        }
        let mut message = upstream_resp.message;
        message.header.id = query_id;

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
        query_id: u16,
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

        // A reply that does not answer the question is counted by the cache, which stores
        // nothing from it, and the client is not handed what the proxy cannot vouch for.
        let untrusted = admission_outcome
            .refusal_reason()
            .filter(|reason| reason.concerns_question());
        let _ = self.cache.admit(admission_outcome);
        if let Some(reason) = untrusted {
            return Err(PipelineError::UntrustedResponse(reason));
        }

        let mut message = upstream_resp.message;
        message.header.id = query_id;

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
                return self
                    .resolve_uncacheable(ctx.query.header.id, question, deadline)
                    .await;
            }
            Err(other) => return Err(PipelineError::Internal(other.to_string())),
        };

        match self.cache.lookup(&key) {
            Lookup::Hit(entry) => self.handle_cache_hit(ctx.query.header.id, &key, entry),
            Lookup::Miss | Lookup::Expired => {
                self.resolve_and_admit(ctx.query.header.id, question, deadline)
                    .await
            }
        }
    }
}

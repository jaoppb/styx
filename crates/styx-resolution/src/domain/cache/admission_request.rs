//! What admission is asked to judge: a response, the client question it answers, and the
//! provenance it arrived with.

use std::time::Instant;

use styx_proto::{Message, Question};

use crate::domain::answer::AnswerSource;
use crate::domain::cache::error::CacheError;
use crate::domain::cache::key::CacheKey;

/// A response offered to [`Admission::evaluate`](crate::domain::cache::Admission::evaluate)
/// for the client question it should answer.
///
/// The cache key is derived from the client's question here, once, so admission judges the
/// response against the question that was asked and the key it will be stored under cannot
/// disagree with it.
#[derive(Debug)]
pub struct AdmissionRequest<'a> {
    question: &'a Question,
    key: CacheKey,
    message: &'a Message,
    source: AnswerSource,
    now: Instant,
}

impl<'a> AdmissionRequest<'a> {
    /// Builds the request for `message`, the response to the client's `question`.
    ///
    /// # Errors
    /// Returns [`CacheError::UncacheableQuestion`] if the question asks for a meta-type
    /// (`ANY`, `AXFR`, `IXFR`, or `OPT`), which is never admitted.
    pub fn new(
        question: &'a Question,
        message: &'a Message,
        source: AnswerSource,
        now: Instant,
    ) -> Result<Self, CacheError> {
        Ok(Self {
            key: CacheKey::from_question(question)?,
            question,
            message,
            source,
            now,
        })
    }

    /// The client's question the response must answer.
    #[must_use]
    pub const fn question(&self) -> &'a Question {
        self.question
    }

    /// The key the response is admitted under, derived from the client's question.
    #[must_use]
    pub const fn key(&self) -> &CacheKey {
        &self.key
    }

    /// The response under judgement.
    #[must_use]
    pub const fn message(&self) -> &'a Message {
        self.message
    }

    /// Where the response came from.
    #[must_use]
    pub const fn source(&self) -> AnswerSource {
        self.source
    }

    /// The instant TTL deadlines are computed from.
    #[must_use]
    pub const fn now(&self) -> Instant {
        self.now
    }

    /// Gives up the key, so the outcome can take it without a copy.
    pub(crate) fn into_key(self) -> CacheKey {
        self.key
    }
}

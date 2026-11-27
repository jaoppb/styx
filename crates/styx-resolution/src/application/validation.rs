//! No-op implementation of [`ResponseValidator`], the cache stage's default.
//!
//! It sits here rather than in `infrastructure` with the other no-op adapters (ADR 0011)
//! because it is [`CacheStage`](crate::application::CacheStage)'s default type parameter, as
//! [`RefusedTerminal`](crate::application::RefusedTerminal) is the pipeline's, and this layer
//! may not name `infrastructure`.

use styx_proto::{Message, Question};

use crate::domain::ports::validation::{ResponseValidator, Validation};

/// A validator that validates nothing: every answer is [`Validation::UNVALIDATED`], so no
/// reply carries AD and none is refused.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoValidation;

impl ResponseValidator for NoValidation {
    async fn validate(&self, _question: &Question, _response: &Message) -> Validation {
        Validation::UNVALIDATED
    }
}

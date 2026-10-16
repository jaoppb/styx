//! Per-member tally of replies refused for not answering the question that was asked.

use styx_core::ReplyFault;

use crate::domain::circuit::FailureCount;

/// How many replies a member has sent that were refused, by the reason they were refused.
///
/// Each count saturates and never wraps. A refused reply also counts as an upstream fault
/// for the circuit breaker; this tally is the by-reason record an operator reads from
/// [`MemberView`](crate::domain::selection::MemberView).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RefusedReplies {
    question_mismatch: FailureCount,
    multiple_questions: FailureCount,
}

impl RefusedReplies {
    /// A tally with no refused reply.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            question_mismatch: FailureCount::zero(),
            multiple_questions: FailureCount::zero(),
        }
    }

    /// Returns this tally with one more reply refused for `reason`.
    #[must_use]
    pub const fn with(self, reason: ReplyFault) -> Self {
        match reason {
            ReplyFault::QuestionMismatch => Self {
                question_mismatch: self.question_mismatch.increment_saturating(),
                ..self
            },
            ReplyFault::MultipleQuestions => Self {
                multiple_questions: self.multiple_questions.increment_saturating(),
                ..self
            },
        }
    }

    /// How many replies were refused for `reason`.
    #[must_use]
    pub const fn count(&self, reason: ReplyFault) -> u32 {
        match reason {
            ReplyFault::QuestionMismatch => self.question_mismatch.value(),
            ReplyFault::MultipleQuestions => self.multiple_questions.value(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_each_reason_is_counted_apart() {
        let tally = RefusedReplies::none()
            .with(ReplyFault::QuestionMismatch)
            .with(ReplyFault::QuestionMismatch)
            .with(ReplyFault::MultipleQuestions);
        assert_eq!(tally.count(ReplyFault::QuestionMismatch), 2);
        assert_eq!(tally.count(ReplyFault::MultipleQuestions), 1);
    }

    #[test]
    fn test_a_fresh_tally_is_empty() {
        assert_eq!(RefusedReplies::default(), RefusedReplies::none());
        assert_eq!(
            RefusedReplies::none().count(ReplyFault::QuestionMismatch),
            0
        );
    }
}

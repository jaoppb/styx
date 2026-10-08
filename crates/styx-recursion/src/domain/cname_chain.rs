//! The alias chain a descent has followed.

use styx_proto::Name;

use crate::domain::error::{BudgetExceeded, RecursionError};

/// The names a descent has been redirected to by CNAME or DNAME, in order.
/// Changed only through [`CnameChain::push`], which is where a repeat becomes a
/// loop and a long chain becomes a spent budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CnameChain {
    seen: Vec<Name>,
    max_length: u8,
}

impl CnameChain {
    /// Starts a chain at the client's qname, allowing `max_length` links.
    #[must_use]
    pub fn new(origin: Name, max_length: u8) -> Self {
        Self {
            seen: vec![origin],
            max_length,
        }
    }

    /// Follows one link to `target`.
    ///
    /// # Errors
    ///
    /// Returns [`RecursionError::CnameLoop`] if `target` was already visited, and
    /// [`RecursionError::BudgetExceeded`] once `max_length` links have been followed.
    pub fn push(&mut self, target: Name) -> Result<(), RecursionError> {
        if self.seen.contains(&target) {
            return Err(RecursionError::CnameLoop);
        }
        if self.length() >= usize::from(self.max_length) {
            return Err(RecursionError::BudgetExceeded(BudgetExceeded::CnameChain));
        }
        self.seen.push(target);
        Ok(())
    }

    /// Links followed so far.
    #[must_use]
    pub fn length(&self) -> usize {
        self.seen.len().saturating_sub(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(text: &str) -> Name {
        Name::from_ascii(text).unwrap()
    }

    #[test]
    fn a_revisit_is_a_loop_and_a_long_chain_is_a_spent_budget() {
        let mut chain = CnameChain::new(name("a.example."), 2);
        assert_eq!(chain.push(name("b.example.")), Ok(()));
        assert_eq!(
            chain.push(name("A.example.")),
            Err(RecursionError::CnameLoop)
        );
        assert_eq!(chain.push(name("c.example.")), Ok(()));
        assert_eq!(
            chain.push(name("d.example.")),
            Err(RecursionError::BudgetExceeded(BudgetExceeded::CnameChain))
        );
    }
}

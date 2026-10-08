//! The four denial-of-service bounds on a descent, and their accounting.
//!
//! An unbounded recursor is an amplifier: one client question could make it send
//! an unbounded number of queries to third parties. Every descent therefore runs
//! inside a [`DescentBudget`], and a glue-resolving sub-descent spends from its
//! parent's budget rather than getting a fresh one — otherwise nesting would
//! defeat every limit.

use std::time::{Duration, Instant};

use crate::domain::error::{BudgetExceeded, ConfigError};

/// Default maximum zone cuts per client question. The deepest real delegation
/// chains are well under 10 levels; 16 leaves room for glue sub-descents, which
/// draw from the same count, while still stopping a malicious delegation ladder.
pub const DEFAULT_MAX_DEPTH: u8 = 16;

/// Default maximum outbound queries per client question. A cold descent with
/// minimisation costs roughly one query per label plus glue lookups; 64 covers a
/// cold, glue-less, CNAME-crossing descent with retries, and caps how much
/// traffic one client question can make styx send to third parties.
pub const DEFAULT_MAX_OUTBOUND_QUERIES: u16 = 64;

/// Default maximum CNAME/DNAME links. Real chains rarely exceed 4 (CDNs); 8 is
/// the conventional resolver bound and stops alias ladders.
pub const DEFAULT_MAX_CNAME_CHAIN: u8 = 8;

/// Default wall-clock limit per client question. Clients typically retry after
/// 1–2 s and give up near 5 s; spending longer serves nobody.
pub const DEFAULT_WALL_CLOCK: Duration = Duration::from_secs(4);

/// The four bounds, validated: none may be zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DescentLimits {
    max_depth: u8,
    max_outbound_queries: u16,
    max_cname_chain: u8,
    wall_clock: Duration,
}

impl DescentLimits {
    /// Validates and bundles the four bounds.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::ZeroLimit`] naming the first limit that is zero.
    pub fn new(
        max_depth: u8,
        max_outbound_queries: u16,
        max_cname_chain: u8,
        wall_clock: Duration,
    ) -> Result<Self, ConfigError> {
        if max_depth == 0 {
            return Err(ConfigError::ZeroLimit("max_depth"));
        }
        if max_outbound_queries == 0 {
            return Err(ConfigError::ZeroLimit("max_outbound_queries"));
        }
        if max_cname_chain == 0 {
            return Err(ConfigError::ZeroLimit("max_cname_chain"));
        }
        if wall_clock.is_zero() {
            return Err(ConfigError::ZeroLimit("wall_clock"));
        }
        Ok(Self {
            max_depth,
            max_outbound_queries,
            max_cname_chain,
            wall_clock,
        })
    }

    /// Maximum zone cuts descended.
    #[must_use]
    pub const fn max_depth(&self) -> u8 {
        self.max_depth
    }

    /// Maximum outbound queries sent.
    #[must_use]
    pub const fn max_outbound_queries(&self) -> u16 {
        self.max_outbound_queries
    }

    /// Maximum alias links followed.
    #[must_use]
    pub const fn max_cname_chain(&self) -> u8 {
        self.max_cname_chain
    }

    /// Maximum wall-clock time spent.
    #[must_use]
    pub const fn wall_clock(&self) -> Duration {
        self.wall_clock
    }
}

impl Default for DescentLimits {
    fn default() -> Self {
        Self {
            max_depth: DEFAULT_MAX_DEPTH,
            max_outbound_queries: DEFAULT_MAX_OUTBOUND_QUERIES,
            max_cname_chain: DEFAULT_MAX_CNAME_CHAIN,
            wall_clock: DEFAULT_WALL_CLOCK,
        }
    }
}

/// What one client question has spent so far. Spent only through its methods, so
/// no caller can reset consumption or swap the limits partway through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescentBudget {
    limits: DescentLimits,
    started_at: Instant,
    queries_sent: u16,
    cuts_descended: u8,
}

impl DescentBudget {
    /// Starts a budget at `started_at`, read from the injected clock.
    #[must_use]
    pub const fn new(limits: DescentLimits, started_at: Instant) -> Self {
        Self {
            limits,
            started_at,
            queries_sent: 0,
            cuts_descended: 0,
        }
    }

    /// The limits this budget enforces.
    #[must_use]
    pub const fn limits(&self) -> &DescentLimits {
        &self.limits
    }

    /// Accounts for one outbound query.
    ///
    /// # Errors
    ///
    /// Returns [`BudgetExceeded::OutboundQueries`] once the limit is spent.
    pub fn charge_query(&mut self) -> Result<(), BudgetExceeded> {
        if self.queries_sent >= self.limits.max_outbound_queries {
            return Err(BudgetExceeded::OutboundQueries);
        }
        self.queries_sent = self.queries_sent.saturating_add(1);
        Ok(())
    }

    /// Accounts for `extra` outbound exchanges beyond the one already charged: a TCP
    /// retry after truncation, or a plain retry after an EDNS rejection. The packets
    /// are already sent, so a descent that overspends is ended, not refused.
    ///
    /// # Errors
    ///
    /// Returns [`BudgetExceeded::OutboundQueries`] if the limit is now exceeded.
    pub fn charge_extra(&mut self, extra: u8) -> Result<(), BudgetExceeded> {
        self.queries_sent = self.queries_sent.saturating_add(u16::from(extra));
        if self.queries_sent > self.limits.max_outbound_queries {
            return Err(BudgetExceeded::OutboundQueries);
        }
        Ok(())
    }

    /// Accounts for descending one zone cut.
    ///
    /// # Errors
    ///
    /// Returns [`BudgetExceeded::Depth`] once the limit is spent.
    pub fn descend(&mut self) -> Result<(), BudgetExceeded> {
        if self.cuts_descended >= self.limits.max_depth {
            return Err(BudgetExceeded::Depth);
        }
        self.cuts_descended = self.cuts_descended.saturating_add(1);
        Ok(())
    }

    /// Checks the wall-clock limit at `now`.
    ///
    /// # Errors
    ///
    /// Returns [`BudgetExceeded::WallClock`] once the limit has passed.
    pub fn elapsed(&self, now: Instant) -> Result<(), BudgetExceeded> {
        if now.saturating_duration_since(self.started_at) >= self.limits.wall_clock {
            return Err(BudgetExceeded::WallClock);
        }
        Ok(())
    }

    /// The instant the wall-clock limit runs out.
    #[must_use]
    pub fn wall_clock_deadline(&self) -> Instant {
        self.started_at
            .checked_add(self.limits.wall_clock)
            .unwrap_or(self.started_at)
    }

    /// Outbound queries sent so far.
    #[must_use]
    pub const fn queries_sent(&self) -> u16 {
        self.queries_sent
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(depth: u8, queries: u16) -> DescentLimits {
        DescentLimits::new(depth, queries, 2, Duration::from_secs(1)).unwrap()
    }

    #[test]
    fn zero_limits_are_rejected_by_name() {
        let second = Duration::from_secs(1);
        assert_eq!(
            DescentLimits::new(0, 1, 1, second),
            Err(ConfigError::ZeroLimit("max_depth"))
        );
        assert_eq!(
            DescentLimits::new(1, 0, 1, second),
            Err(ConfigError::ZeroLimit("max_outbound_queries"))
        );
        assert_eq!(
            DescentLimits::new(1, 1, 0, second),
            Err(ConfigError::ZeroLimit("max_cname_chain"))
        );
        assert_eq!(
            DescentLimits::new(1, 1, 1, Duration::ZERO),
            Err(ConfigError::ZeroLimit("wall_clock"))
        );
    }

    #[test]
    fn queries_and_depth_are_spent_to_the_limit_and_no_further() {
        let mut budget = DescentBudget::new(limits(1, 2), Instant::now());
        assert_eq!(budget.charge_query(), Ok(()));
        assert_eq!(budget.charge_query(), Ok(()));
        assert_eq!(budget.charge_query(), Err(BudgetExceeded::OutboundQueries));
        assert_eq!(budget.descend(), Ok(()));
        assert_eq!(budget.descend(), Err(BudgetExceeded::Depth));
    }

    #[test]
    fn extra_wire_exchanges_count_against_the_query_limit() {
        let mut budget = DescentBudget::new(limits(1, 4), Instant::now());
        assert_eq!(budget.charge_query(), Ok(()));
        assert_eq!(budget.charge_extra(3), Ok(()), "four packets of four");
        assert_eq!(budget.charge_extra(1), Err(BudgetExceeded::OutboundQueries));
        assert_eq!(budget.charge_query(), Err(BudgetExceeded::OutboundQueries));
    }

    #[test]
    fn the_wall_clock_runs_out_at_its_limit() {
        let start = Instant::now();
        let budget = DescentBudget::new(limits(1, 1), start);
        assert_eq!(budget.elapsed(start), Ok(()));
        let later = start + Duration::from_secs(1);
        assert_eq!(budget.elapsed(later), Err(BudgetExceeded::WallClock));
    }
}

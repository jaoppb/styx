//! TTL and expiry calculation primitives.

use std::time::{Duration, Instant};

use styx_proto::{RData, Ttl};

use crate::domain::cache::error::CacheError;
use crate::domain::cache::positive_entry::CachedRRset;

/// Default TTL floor (5 seconds).
pub const DEFAULT_TTL_FLOOR_SECS: u32 = 5;

/// Default TTL ceiling (24 hours / 86,400 seconds).
pub const DEFAULT_TTL_CEILING_SECS: u32 = 86_400;

/// Default negative TTL ceiling (5 minutes / 300 seconds, per RFC 2308).
pub const DEFAULT_NEGATIVE_TTL_CEILING_SECS: u32 = 300;

/// An absolute deadline at which a cached entry ceases to be fresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Deadline {
    at: Instant,
}

impl Deadline {
    /// Computes a deadline by adding a relative [`Ttl`] to the reference instant.
    ///
    /// # Errors
    /// Returns [`CacheError::TtlOverflow`] if the addition overflows the system `Instant`.
    pub fn from_ttl(now: Instant, ttl: Ttl) -> Result<Self, CacheError> {
        let duration = Duration::from_secs(u64::from(ttl.seconds()));
        let at = now.checked_add(duration).ok_or(CacheError::TtlOverflow)?;
        Ok(Self { at })
    }

    /// Computes the remaining time-to-live relative to `now`.
    ///
    /// Saturates at zero if `now` has reached or surpassed the deadline.
    ///
    /// # Errors
    /// Returns [`CacheError`] on arithmetic overflow.
    pub fn remaining(&self, now: Instant) -> Result<Ttl, CacheError> {
        if self.has_expired(now) {
            return Ok(Ttl::ZERO);
        }

        let duration = self
            .at
            .checked_duration_since(now)
            .unwrap_or(Duration::ZERO);
        let secs = u32::try_from(duration.as_secs()).unwrap_or(u32::MAX);
        Ok(Ttl::from_secs(secs))
    }

    /// Returns `true` if `now` is at or past the deadline.
    #[must_use]
    pub fn has_expired(&self, now: Instant) -> bool {
        now >= self.at
    }

    /// Returns the raw deadline [`Instant`].
    #[must_use]
    pub const fn at(&self) -> Instant {
        self.at
    }
}

/// Policy governing TTL limits and negative caching derivations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TtlPolicy {
    floor: Ttl,
    ceiling: Ttl,
    negative_ceiling: Ttl,
}

impl Default for TtlPolicy {
    fn default() -> Self {
        Self {
            floor: Ttl::from_secs(DEFAULT_TTL_FLOOR_SECS),
            ceiling: Ttl::from_secs(DEFAULT_TTL_CEILING_SECS),
            negative_ceiling: Ttl::from_secs(DEFAULT_NEGATIVE_TTL_CEILING_SECS),
        }
    }
}

impl TtlPolicy {
    /// Creates a new `TtlPolicy` with the given constraints.
    ///
    /// # Errors
    /// Returns [`CacheError::InvalidTtlBounds`] if `floor > ceiling`.
    pub fn new(floor: Ttl, ceiling: Ttl, negative_ceiling: Ttl) -> Result<Self, CacheError> {
        if floor.seconds() > ceiling.seconds() {
            return Err(CacheError::InvalidTtlBounds {
                floor: floor.seconds(),
                ceiling: ceiling.seconds(),
            });
        }
        Ok(Self {
            floor,
            ceiling,
            negative_ceiling,
        })
    }

    /// Minimum TTL clamp for positive responses.
    #[must_use]
    pub const fn floor(&self) -> Ttl {
        self.floor
    }

    /// Maximum TTL clamp for positive responses.
    #[must_use]
    pub const fn ceiling(&self) -> Ttl {
        self.ceiling
    }

    /// Maximum TTL clamp for RFC 2308 negative responses.
    #[must_use]
    pub const fn negative_ceiling(&self) -> Ttl {
        self.negative_ceiling
    }

    /// Clamps a TTL between the configured floor and ceiling.
    #[must_use]
    pub fn clamp(&self, ttl: Ttl) -> Ttl {
        let secs = ttl.seconds();
        let floor_secs = self.floor.seconds();
        let ceiling_secs = self.ceiling.seconds();

        let clamped = secs.max(floor_secs).min(ceiling_secs);
        Ttl::from_secs(clamped)
    }

    /// Computes the effective RFC 2308 negative TTL from an SOA record.
    ///
    /// Per RFC 2308 §5, the negative TTL is `min(soa.ttl, soa.minimum)`, clamped by
    /// `negative_ceiling`.
    ///
    /// # Errors
    /// Returns [`CacheError::MissingSoa`] if the record contains no SOA RDATA.
    pub fn effective_negative_ttl(&self, soa: &CachedRRset) -> Result<Ttl, CacheError> {
        let soa_rdata = soa
            .rdata()
            .first()
            .and_then(|r| match r {
                RData::Soa(s) => Some(s),
                _ => None,
            })
            .ok_or(CacheError::MissingSoa)?;

        let soa_minimum = soa_rdata.minimum();
        let effective = self.effective_negative_ttl_raw(soa.original_ttl(), soa_minimum);
        Ok(effective)
    }

    /// Computes the effective RFC 2308 negative TTL from raw SOA TTL and MINIMUM fields.
    #[must_use]
    pub fn effective_negative_ttl_raw(&self, soa_ttl: Ttl, soa_minimum: u32) -> Ttl {
        let min_ttl = soa_ttl.seconds().min(soa_minimum);
        let clamped = min_ttl.min(self.negative_ceiling.seconds());
        Ttl::from_secs(clamped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ttl_policy_invariants() {
        let valid = TtlPolicy::new(Ttl::from_secs(5), Ttl::from_secs(300), Ttl::from_secs(60));
        assert!(valid.is_ok());
        let policy = valid.expect("valid policy");
        assert_eq!(policy.floor(), Ttl::from_secs(5));
        assert_eq!(policy.ceiling(), Ttl::from_secs(300));
        assert_eq!(policy.negative_ceiling(), Ttl::from_secs(60));

        let invalid = TtlPolicy::new(Ttl::from_secs(500), Ttl::from_secs(100), Ttl::from_secs(60));
        assert_eq!(
            invalid,
            Err(CacheError::InvalidTtlBounds {
                floor: 500,
                ceiling: 100,
            })
        );
    }
}

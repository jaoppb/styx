//! DNSSEC validation metadata and security status.

use styx_proto::RrsigRdata;

use crate::domain::cache::bytes::HeapBytes;

/// Security validation status of a cached DNS record or response.
///
/// In Phase 4, validation logic is deferred to Phase 6 (DNSSEC), so every admitted
/// entry defaults to [`SecurityStatus::Indeterminate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum SecurityStatus {
    /// DNSSEC status cannot be determined or validation is not yet implemented.
    #[default]
    Indeterminate,
    /// Authoritatively proven insecure (unsigned zone with valid NSEC/NSEC3 proof of no DS).
    Insecure,
    /// Cryptographically verified with a complete, valid chain of trust to a root anchor.
    Secure,
    /// DNSSEC validation failed (signature mismatch, expired signature, or missing proof).
    Bogus,
}

/// DNSSEC metadata capturing validation status and associated cryptographic signatures.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum DnssecMetadata {
    /// DNSSEC status is indeterminate; validation has not been performed.
    #[default]
    Indeterminate,
    /// Proved insecure via unsigned delegation or validated NSEC/NSEC3 proofs.
    Insecure,
    /// Cryptographically verified with attached valid RRSIG signatures.
    Secure {
        /// Attached RRSIG signatures.
        signatures: Vec<RrsigRdata>,
    },
    /// Validation failed, retaining signatures if available for diagnostics.
    Bogus {
        /// Attached RRSIG signatures if available.
        signatures: Vec<RrsigRdata>,
    },
}

impl DnssecMetadata {
    /// Creates an indeterminate DNSSEC metadata instance.
    #[must_use]
    pub const fn indeterminate() -> Self {
        Self::Indeterminate
    }

    /// Creates an insecure DNSSEC metadata instance.
    #[must_use]
    pub const fn insecure() -> Self {
        Self::Insecure
    }

    /// Creates a secure DNSSEC metadata instance with attached signatures.
    #[must_use]
    pub fn secure(signatures: Vec<RrsigRdata>) -> Self {
        Self::Secure { signatures }
    }

    /// Creates a bogus DNSSEC metadata instance with attached signatures.
    #[must_use]
    pub fn bogus(signatures: Vec<RrsigRdata>) -> Self {
        Self::Bogus { signatures }
    }

    /// Returns the high-level security status verdict.
    #[must_use]
    pub fn status(&self) -> SecurityStatus {
        match self {
            Self::Indeterminate => SecurityStatus::Indeterminate,
            Self::Insecure => SecurityStatus::Insecure,
            Self::Secure { .. } => SecurityStatus::Secure,
            Self::Bogus { .. } => SecurityStatus::Bogus,
        }
    }

    /// Returns the attached RRSIG signatures if present.
    #[must_use]
    pub fn signatures(&self) -> Option<&[RrsigRdata]> {
        match self {
            Self::Secure { signatures } | Self::Bogus { signatures } => Some(signatures.as_slice()),
            Self::Indeterminate | Self::Insecure => None,
        }
    }

    /// Returns `true` if the entry has been cryptographically validated.
    #[must_use]
    pub const fn is_secure(&self) -> bool {
        matches!(self, Self::Secure { .. })
    }

    /// Returns the estimated heap size consumed by this DNSSEC metadata.
    #[must_use]
    pub fn heap_size(&self) -> HeapBytes {
        let base = std::mem::size_of::<Self>();
        let sig_count = match self {
            Self::Secure { signatures } | Self::Bogus { signatures } => signatures.len(),
            Self::Indeterminate | Self::Insecure => 0,
        };
        let sig_bytes = sig_count.saturating_mul(128);
        HeapBytes::new(base.saturating_add(sig_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dnssec_metadata_variants_and_status() {
        let indet = DnssecMetadata::indeterminate();
        assert_eq!(indet.status(), SecurityStatus::Indeterminate);
        assert!(!indet.is_secure());
        assert_eq!(indet.signatures(), None);

        let insec = DnssecMetadata::insecure();
        assert_eq!(insec.status(), SecurityStatus::Insecure);
        assert!(!insec.is_secure());

        let sec = DnssecMetadata::secure(vec![]);
        assert_eq!(sec.status(), SecurityStatus::Secure);
        assert!(sec.is_secure());
        assert_eq!(sec.signatures(), Some([].as_slice()));

        let bogus = DnssecMetadata::bogus(vec![]);
        assert_eq!(bogus.status(), SecurityStatus::Bogus);
        assert!(!bogus.is_secure());
        assert_eq!(bogus.signatures(), Some([].as_slice()));
    }
}

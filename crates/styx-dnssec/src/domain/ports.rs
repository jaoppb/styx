//! Port traits for DNSSEC validation dependencies.

use styx_proto::Name;

use crate::domain::chain::ZoneCutMaterial;
use crate::domain::error::{ChainSourceError, TrustAnchorError};
use crate::domain::trust_anchor::TrustAnchor;

/// Context passed when requesting chain material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainRequest {
    /// Question name that prompted the chain request.
    pub qname: Name,
}

impl ChainRequest {
    /// Creates a new [`ChainRequest`] for `qname`.
    #[must_use]
    pub fn new(qname: Name) -> Self {
        Self { qname }
    }
}

/// Port through which the validator obtains chain material (DS, DNSKEY, and DS-denial proofs).
pub trait ChainSource: Send + Sync {
    /// Obtains chain material for `zone`, including whether it is a zone cut at all.
    ///
    /// # Errors
    /// Returns [`ChainSourceError`] if material could not be retrieved. That is never
    /// a claim that `zone` is not a cut: report that as [`Delegation::NotACut`].
    ///
    /// [`Delegation::NotACut`]: crate::domain::chain::Delegation::NotACut
    fn material_for(
        &self,
        zone: &Name,
        context: &ChainRequest,
    ) -> Result<ZoneCutMaterial, ChainSourceError>;
}

/// Port supplying the configured cryptographic trust anchors.
pub trait TrustAnchorSource: Send + Sync {
    /// Returns the currently active trust anchors.
    ///
    /// # Errors
    /// Returns [`TrustAnchorError`] if the anchors could not be loaded or parsed.
    fn anchors(&self) -> Result<Vec<TrustAnchor>, TrustAnchorError>;
}

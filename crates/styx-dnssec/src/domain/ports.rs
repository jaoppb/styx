//! Port traits for DNSSEC validation dependencies.

use styx_proto::Name;

use crate::domain::chain::ChainMaterial;
use crate::domain::error::{ChainSourceError, TrustAnchorError};
use crate::domain::trust_anchor::TrustAnchor;

/// Context passed when requesting chain material.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ChainRequest {
    /// Optional question name that prompted the chain request.
    pub qname: Option<Name>,
}

impl ChainRequest {
    /// Creates a new [`ChainRequest`] with optional qname.
    #[must_use]
    pub fn new(qname: Option<Name>) -> Self {
        Self { qname }
    }
}

/// Port through which the validator obtains chain material (DS, DNSKEY, and DS-denial proofs).
pub trait ChainSource: Send + Sync {
    /// Obtains chain material for the given zone cut.
    ///
    /// # Errors
    /// Returns [`ChainSourceError`] if material could not be retrieved.
    fn material_for(
        &self,
        zone: &Name,
        context: &ChainRequest,
    ) -> Result<ChainMaterial, ChainSourceError>;
}

/// Port supplying the configured cryptographic trust anchors.
pub trait TrustAnchorSource: Send + Sync {
    /// Returns the currently active trust anchors.
    ///
    /// # Errors
    /// Returns [`TrustAnchorError`] if the anchors could not be loaded or parsed.
    fn anchors(&self) -> Result<Vec<TrustAnchor>, TrustAnchorError>;
}

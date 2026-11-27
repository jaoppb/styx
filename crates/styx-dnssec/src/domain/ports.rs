//! Port traits for DNSSEC validation dependencies.

use std::future::Future;

use styx_proto::Name;

use crate::domain::chain::ZoneCutMaterial;
use crate::domain::error::ChainSourceError;
use crate::domain::trust_anchor::TrustAnchors;

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
    ) -> impl Future<Output = Result<ZoneCutMaterial, ChainSourceError>> + Send;
}

/// Port supplying the configured cryptographic trust anchors, read once at startup and
/// handed to [`Validator::new`](crate::application::validator::Validator::new).
///
/// Loading can fail (a missing or malformed file); that happens when the adapter is
/// built, so once it exists its anchors are always there.
pub trait TrustAnchorSource: Send + Sync {
    /// Returns the configured trust anchors.
    fn anchors(&self) -> TrustAnchors;
}

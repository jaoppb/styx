//! Adapters implementing the [`ChainSource`] port for pushed and pulled strategies.

use std::collections::HashMap;
use std::sync::RwLock;

use styx_proto::Name;

use crate::domain::chain::{Delegation, MaterialOrigin, ZoneCutMaterial};
use crate::domain::error::ChainSourceError;
use crate::domain::ports::{ChainRequest, ChainSource};

/// In-memory accumulator collecting referrals observed during recursive descent.
///
/// A name the descent never saw a referral for is reported as not being a zone cut.
#[derive(Debug, Default)]
pub struct PushedChainSource {
    observed: RwLock<HashMap<Name, Delegation>>,
}

impl PushedChainSource {
    /// Creates an empty [`PushedChainSource`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the delegation material observed in a referral for `zone`.
    pub fn record_referral(&self, zone: Name, delegation: Delegation) {
        if let Ok(mut map) = self.observed.write() {
            map.insert(zone, delegation);
        }
    }
}

impl ChainSource for PushedChainSource {
    fn material_for(
        &self,
        zone: &Name,
        _context: &ChainRequest,
    ) -> Result<ZoneCutMaterial, ChainSourceError> {
        let map = self
            .observed
            .read()
            .map_err(|_| ChainSourceError::Unavailable(zone.clone()))?;
        let delegation = map.get(zone).cloned().unwrap_or(Delegation::NotACut);
        Ok(ZoneCutMaterial::new(
            zone.clone(),
            delegation,
            MaterialOrigin::PushedFromDescent,
        ))
    }
}

/// On-demand chain material store, populated with the cuts fetched for a zone.
///
/// A name with no inserted cut is reported as not being a zone cut.
#[derive(Debug, Default)]
pub struct PullChainSource {
    cuts: RwLock<HashMap<Name, ZoneCutMaterial>>,
}

impl PullChainSource {
    /// Creates a new [`PullChainSource`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Populates material for a zone.
    pub fn insert_cut(&self, cut: ZoneCutMaterial) {
        if let Ok(mut map) = self.cuts.write() {
            map.insert(cut.zone.clone(), cut);
        }
    }
}

impl ChainSource for PullChainSource {
    fn material_for(
        &self,
        zone: &Name,
        _context: &ChainRequest,
    ) -> Result<ZoneCutMaterial, ChainSourceError> {
        let map = self
            .cuts
            .read()
            .map_err(|_| ChainSourceError::Unavailable(zone.clone()))?;
        Ok(map.get(zone).cloned().unwrap_or_else(|| {
            ZoneCutMaterial::new(
                zone.clone(),
                Delegation::NotACut,
                MaterialOrigin::PulledOnDemand,
            )
        }))
    }
}

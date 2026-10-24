//! Adapters implementing the [`ChainSource`] port for pushed and pulled strategies.

use std::collections::HashMap;
use std::sync::RwLock;

use styx_proto::{Name, ResourceRecord};

use crate::domain::chain::{ChainMaterial, MaterialOrigin, ZoneCutMaterial};
use crate::domain::denial::DenialProof;
use crate::domain::error::ChainSourceError;
use crate::domain::ports::{ChainRequest, ChainSource};

/// In-memory accumulator collecting referrals observed during recursive descent.
#[derive(Debug, Default)]
pub struct PushedChainSource {
    observed: RwLock<HashMap<Name, ZoneCutMaterial>>,
}

impl PushedChainSource {
    /// Creates an empty [`PushedChainSource`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            observed: RwLock::new(HashMap::new()),
        }
    }

    /// Records an observed referral for `zone`.
    pub fn record_referral(
        &self,
        zone: Name,
        ds: Option<Vec<ResourceRecord>>,
        ds_denial: Option<DenialProof>,
        dnskey: Option<Vec<ResourceRecord>>,
        dnskey_signatures: Vec<ResourceRecord>,
    ) {
        let cut = ZoneCutMaterial::new(
            zone.clone(),
            ds,
            ds_denial,
            dnskey,
            dnskey_signatures,
            MaterialOrigin::PushedFromDescent,
        );
        if let Ok(mut map) = self.observed.write() {
            map.insert(zone, cut);
        }
    }
}

impl ChainSource for PushedChainSource {
    fn material_for(
        &self,
        zone: &Name,
        _context: &ChainRequest,
    ) -> Result<ChainMaterial, ChainSourceError> {
        let map = self
            .observed
            .read()
            .map_err(|_| ChainSourceError::Unavailable(zone.clone()))?;
        let cuts = map.values().cloned().collect();
        Ok(ChainMaterial::with_cuts(cuts))
    }
}

/// On-demand chain material resolver fetching cuts as requested.
#[derive(Debug, Default)]
pub struct PullChainSource {
    cuts: RwLock<HashMap<Name, ZoneCutMaterial>>,
}

impl PullChainSource {
    /// Creates a new [`PullChainSource`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            cuts: RwLock::new(HashMap::new()),
        }
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
    ) -> Result<ChainMaterial, ChainSourceError> {
        let map = self
            .cuts
            .read()
            .map_err(|_| ChainSourceError::Unavailable(zone.clone()))?;
        let cut = map
            .get(zone)
            .cloned()
            .ok_or_else(|| ChainSourceError::Unavailable(zone.clone()))?;
        Ok(ChainMaterial::with_cuts(vec![cut]))
    }
}

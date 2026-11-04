//! In-memory [`ChainSource`] implementation for testing and referral accumulation.

use std::collections::HashMap;
use std::sync::RwLock;

use styx_proto::Name;

use crate::domain::chain::{Delegation, ZoneCutMaterial};
use crate::domain::error::ChainSourceError;
use crate::domain::ports::ChainSource;

/// In-memory store for zone cuts and delegation material.
///
/// Can be pre-populated for forwarder lookups or fed referrals as recursive descent proceeds.
/// A name with no recorded cut is reported as not being a zone cut ([`Delegation::NotACut`]).
#[derive(Debug, Default)]
pub struct InMemoryChainSource {
    cuts: RwLock<HashMap<Name, ZoneCutMaterial>>,
}

impl InMemoryChainSource {
    /// Creates an empty [`InMemoryChainSource`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts chain material for a zone cut.
    pub fn insert_cut(&self, cut: ZoneCutMaterial) {
        let mut map = match self.cuts.write() {
            Ok(guard) => guard,
            Err(poison) => poison.into_inner(),
        };
        map.insert(cut.zone.clone(), cut);
    }

    /// Records delegation material observed in a referral for `zone`.
    pub fn record_referral(&self, zone: Name, delegation: Delegation) {
        self.insert_cut(ZoneCutMaterial::new(zone, delegation));
    }
}

impl ChainSource for InMemoryChainSource {
    fn material_for(&self, zone: &Name) -> Result<ZoneCutMaterial, ChainSourceError> {
        let map = match self.cuts.read() {
            Ok(guard) => guard,
            Err(poison) => poison.into_inner(),
        };
        Ok(map
            .get(zone)
            .cloned()
            .unwrap_or_else(|| ZoneCutMaterial::new(zone.clone(), Delegation::NotACut)))
    }
}

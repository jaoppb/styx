//! Trust anchor domain representation.

use styx_proto::domain::rdata::DsRdata;
use styx_proto::Name;

use crate::domain::policy::{DigestType, DnssecAlgorithm};

/// A cryptographic trust anchor establishing the root of a DNSSEC chain of trust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustAnchor {
    owner: Name,
    ds: DsRdata,
}

impl TrustAnchor {
    /// Constructs a new [`TrustAnchor`] from an owner zone name and its [`DsRdata`].
    #[must_use]
    pub fn new(owner: Name, ds: DsRdata) -> Self {
        Self { owner, ds }
    }

    /// Owner name of the anchor (normally the root name `.`).
    #[must_use]
    pub fn owner(&self) -> &Name {
        &self.owner
    }

    /// Underlying DS record representation of this trust anchor.
    #[must_use]
    pub fn ds(&self) -> &DsRdata {
        &self.ds
    }

    /// Key tag of the DNSKEY referred to by this anchor.
    #[must_use]
    pub fn key_tag(&self) -> u16 {
        self.ds.key_tag()
    }

    /// Cryptographic signature algorithm.
    #[must_use]
    pub fn algorithm(&self) -> DnssecAlgorithm {
        DnssecAlgorithm::new(self.ds.algorithm())
    }

    /// Digest algorithm type (e.g. SHA-256).
    #[must_use]
    pub fn digest_type(&self) -> DigestType {
        DigestType::new(self.ds.digest_type())
    }

    /// Cryptographic digest octets.
    #[must_use]
    pub fn digest(&self) -> &[u8] {
        self.ds.digest()
    }
}

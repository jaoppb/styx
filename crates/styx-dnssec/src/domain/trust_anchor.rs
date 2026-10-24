//! Trust anchor domain representation.

use styx_proto::Name;

/// A cryptographic trust anchor establishing the root of a DNSSEC chain of trust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustAnchor {
    owner: Name,
    key_tag: u16,
    algorithm: u8,
    digest_type: u8,
    digest: Vec<u8>,
}

impl TrustAnchor {
    /// Constructs a new [`TrustAnchor`].
    #[must_use]
    pub fn new(owner: Name, key_tag: u16, algorithm: u8, digest_type: u8, digest: Vec<u8>) -> Self {
        Self {
            owner,
            key_tag,
            algorithm,
            digest_type,
            digest,
        }
    }

    /// Owner name of the anchor (normally the root name `.`).
    #[must_use]
    pub fn owner(&self) -> &Name {
        &self.owner
    }

    /// Key tag of the DNSKEY referred to by this anchor.
    #[must_use]
    pub fn key_tag(&self) -> u16 {
        self.key_tag
    }

    /// Cryptographic algorithm number.
    #[must_use]
    pub fn algorithm(&self) -> u8 {
        self.algorithm
    }

    /// Digest algorithm type (e.g. SHA-256 = 2).
    #[must_use]
    pub fn digest_type(&self) -> u8 {
        self.digest_type
    }

    /// Cryptographic digest octets.
    #[must_use]
    pub fn digest(&self) -> &[u8] {
        &self.digest
    }
}

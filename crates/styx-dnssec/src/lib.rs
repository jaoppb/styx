//! `styx-dnssec` — DNSSEC validation feature crate for the styx resolver.
//!
//! Provides cryptographic verification of DNSSEC chains, RFC 4034 canonical serialization,
//! RRSIG signature validation, DS-to-DNSKEY authentication, and denial of existence proofs
//! (NSEC and NSEC3).
//!
//! Follows the port-and-adapter architecture: external dependencies (trust anchors,
//! chain material, clock) are consumed via traits declared in the [`domain`] module.

pub mod application;
pub mod domain;
pub mod infrastructure;

pub use application::validator::Validator;
pub use domain::chain::{ChainMaterial, MaterialOrigin, ZoneCutMaterial};
pub use domain::denial::{DenialProof, Nsec3Flags, Nsec3Params, Nsec3Proof, NsecProof};
pub use domain::error::{ChainSourceError, DenialError, TrustAnchorError, ValidationError};
pub use domain::ports::{ChainRequest, ChainSource, TrustAnchorSource};
pub use domain::trust_anchor::TrustAnchor;
pub use domain::verdict::{
    AlgorithmSet, AlgorithmSupport, FailureMode, Nsec3IterationsCap, ValidationOutcome,
    ValidationPolicy, ValidationVerdict, VerdictReason,
};
pub use infrastructure::chain_source::{PullChainSource, PushedChainSource};
pub use infrastructure::trust_anchor::{FileTrustAnchor, PinnedRootAnchor};

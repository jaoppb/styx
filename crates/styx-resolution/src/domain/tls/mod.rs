//! Encrypted inbound: DNS over TLS and DNS over HTTPS, as pure values.
//!
//! No I/O, no async, and no TLS- or HTTP-library type in any public signature, so the TLS
//! implementation can be replaced without touching this module.

pub mod certificate;
pub mod config;

pub use certificate::{
    CertificateOrigin, OperatorCertificateLoader, PrivateKeyEncoding, PrivateKeyMaterial,
    SelfSignedStore, ServingIdentity, ServingIdentityParts, ServingIdentityProvider, SpkiPin,
    ValidityState, ValidityWindow,
};
pub use config::{
    CertificateSource, DohResourcePath, EncryptedLimits, StreamMessageLimit, TlsConfig,
    TlsConfigParts,
};

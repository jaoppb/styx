//! Certificate provisioning error taxonomy.
//!
//! Every variant aborts startup, before any listener binds. The messages are deliberately
//! verbose and name the file at fault, because the operator reading them is the person who
//! set the path; none of them ever reaches a client.

use std::path::PathBuf;

use thiserror::Error;

/// Errors resolving the serving certificate and key.
#[derive(Debug, Error)]
pub enum CertificateError {
    /// A configured or persisted file could not be read.
    #[error("cannot read {path}: {reason}")]
    PathUnreadable {
        /// The file at fault.
        path: PathBuf,
        /// What the operating system reported.
        reason: String,
    },

    /// The file holds no PEM certificate.
    #[error("{path} holds no PEM certificate")]
    NoCertificateInFile {
        /// The file at fault.
        path: PathBuf,
    },

    /// A certificate in the file could not be parsed.
    #[error("{path} holds a malformed certificate: {reason}")]
    MalformedCertificate {
        /// The file at fault.
        path: PathBuf,
        /// What the parser reported.
        reason: String,
    },

    /// The file holds no usable private key.
    #[error("{path} holds no usable private key: {reason}")]
    MalformedKey {
        /// The file at fault.
        path: PathBuf,
        /// What the parser reported.
        reason: String,
    },

    /// The private key is not the one the leaf certificate was issued for.
    #[error("the key in {key_path} does not match the leaf certificate in {cert_path}")]
    KeyMismatch {
        /// The certificate file.
        cert_path: PathBuf,
        /// The key file.
        key_path: PathBuf,
    },

    /// A serving identity was assembled with no certificate.
    #[error("the certificate chain is empty")]
    EmptyChain,

    /// Self-signed material could not be generated.
    #[error("failed to generate a self-signed certificate: {0}")]
    GenerationFailed(String),

    /// Self-signed material could not be written.
    #[error("failed to persist {path}: {reason}")]
    PersistFailed {
        /// The file or directory at fault.
        path: PathBuf,
        /// What the operating system reported.
        reason: String,
    },

    /// Only one of the self-signed certificate and key exists.
    #[error("{present} exists but {missing} does not; remove {present} to regenerate")]
    IncompleteMaterial {
        /// The file that exists.
        present: PathBuf,
        /// The file that is missing.
        missing: PathBuf,
    },

    /// A persisted private key is readable by group or others.
    #[error("{path} is readable by group or others; restrict it to the owner (chmod 600)")]
    InsecurePermissions {
        /// The key file.
        path: PathBuf,
    },

    /// The SPKI pin could not be derived.
    #[error("failed to derive the SPKI pin")]
    PinDerivationFailed,
}

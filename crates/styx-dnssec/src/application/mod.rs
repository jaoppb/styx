//! Application orchestration for DNSSEC validation.

pub(crate) mod authenticator;
pub(crate) mod denial_verifier;
pub(crate) mod descent;
pub mod validator;

pub use validator::Validator;

//! Application orchestration for DNSSEC validation.

pub(crate) mod authenticator;
pub mod denial_verifier;
pub mod descent;
pub mod validator;

pub use validator::Validator;

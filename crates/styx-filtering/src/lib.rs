//! styx filtering: per-client blocking policy and the adlist matcher.
//!
//! A **feature crate**, same three-module shape as `styx-resolution`.
//!
//! In phase 0 its job is to be the *other* crate in a cross-feature violation,
//! so that `[[restrict-use]]` and the link-graph gate can both be proven live
//! rather than merely configured. The matcher itself arrives in phase 8.

pub mod application;
pub mod domain;
pub mod infrastructure;

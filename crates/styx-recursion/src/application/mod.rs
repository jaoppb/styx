//! Application layer: the descent driver, server selection, single-flight,
//! priming, diagnostics assembly, configuration, and the `Upstream`
//! implementation.

pub mod config;
pub mod diagnostics;
pub mod driver;
pub mod exchange;
pub mod prime;
pub mod priming;
pub mod recursor;
pub mod selection;
pub mod single_flight;

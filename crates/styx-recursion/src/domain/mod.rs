//! Domain layer: the descent state machine, minimisation, topology, bailiwick
//! predicates, budgets, errors and the ports. No I/O, no `async`, no clock reads —
//! time arrives as a parameter.

pub mod bailiwick;
pub mod budget;
pub mod chain_material;
pub mod classify;
pub mod cname_chain;
pub mod descent;
pub mod diagnostics;
pub mod error;
pub mod metrics;
pub mod minimisation;
pub mod names;
pub mod ports;
pub mod root_hints;
pub mod topology;

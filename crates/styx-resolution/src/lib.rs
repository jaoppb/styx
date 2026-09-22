//! styx resolution: forwarding, the upstream pool, caching and recursion.
//!
//! A **feature crate**. Its layer structure is exactly three modules — no
//! other top-level module belongs here. Later phases fill these in; they do
//! not reshape them.
//!
//! This crate will declare the `FilterPolicy` port in [`domain`], which the
//! `styx` binary wires `styx-filtering` into. It must never name
//! `styx-filtering` directly: that is the cross-feature edge
//! `[[restrict-use]]` and the link-graph gate both exist to reject.

pub mod application;
pub mod domain;
pub mod infrastructure;

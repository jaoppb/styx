//! styx recursion: an iterative resolver that walks the delegation chain from the
//! root to an authoritative answer, behind the same `Upstream` port the Do53
//! forwarder implements.
//!
//! A **feature crate**, with two structural commitments:
//!
//! - **QNAME minimisation is built in, not bolted on.** Every outbound question is
//!   composed by [`domain::minimisation::MinimisationState`], which sends each
//!   server one label more than it needs to see (RFC 9156, relaxed). There is no
//!   code path that puts the client's full qname on the wire without it.
//! - **The infrastructure cache is private to this crate.** Delegations, NS sets
//!   and per-nameserver RTT, EDNS and minimisation verdicts live here, keyed by zone
//!   and address, and share nothing with the global answer cache.
//!
//! This crate names no other feature crate: it depends on `styx-proto`, `styx-core`
//! and `styx-net` only, and the `styx` binary wires it into the pool.

pub mod application;
pub mod domain;
pub mod infrastructure;

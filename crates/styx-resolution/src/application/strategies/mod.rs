//! Selection strategy implementations for upstream pools.

pub mod ordered_failover;
pub mod race_all;
pub mod round_robin;
pub mod weighted;

pub use ordered_failover::OrderedFailover;
pub use race_all::RaceAll;
pub use round_robin::RoundRobin;
pub use weighted::Weighted;

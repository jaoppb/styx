//! Sharded memory cache and eviction infrastructure.

pub mod eviction;
pub mod sharded;

pub use eviction::{Eviction, EvictionReport};
pub use sharded::{ShardedAnswerCache, DEFAULT_SHARDS};

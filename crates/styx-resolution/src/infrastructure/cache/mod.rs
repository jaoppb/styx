//! Sharded memory cache and eviction infrastructure.

pub mod eviction;
mod ring;
pub mod shard;
pub mod sharded;

pub use eviction::{Eviction, EvictionReport};
pub use shard::Shard;
pub use sharded::{ShardedAnswerCache, DEFAULT_SHARDS};

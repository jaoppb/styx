//! Issue #82: the `[cache]` table reaches the cache the binary builds, not just the parsed
//! struct.

// The helper below sits outside `#[test]` functions, where clippy's expect allowance stops.
#![allow(clippy::expect_used)]

use std::sync::Arc;

use styx_core::TestClock;
use styx_proto::Ttl;
use styx_resolution::{CacheConfig, ShardedAnswerCache};

fn cache_from(content: &str) -> ShardedAnswerCache<TestClock> {
    let config = CacheConfig::from_toml_str(content).expect("valid [cache]");
    ShardedAnswerCache::new(
        Arc::new(TestClock::new()),
        config.capacity,
        config.ttl,
        config.shards,
    )
    .expect("sized cache")
}

#[test]
fn max_entries_from_the_file_bounds_the_built_cache() {
    let cache = cache_from("[cache]\nmax_entries = 500\n");
    assert_eq!(cache.capacity().max_entries(), 500);
}

#[test]
fn ttl_bounds_from_the_file_reach_the_built_cache() {
    let cache = cache_from("[cache]\nttl_floor_secs = 30\nttl_ceiling_secs = 600\n");
    assert_eq!(cache.ttl_policy().floor(), Ttl::from_secs(30));
    assert_eq!(cache.ttl_policy().ceiling(), Ttl::from_secs(600));
}

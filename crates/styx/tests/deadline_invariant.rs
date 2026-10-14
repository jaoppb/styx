//! The default whole-query deadline must outlast the recursor's default wall clock, or a
//! recursive query that spends its full budget is cut off by the deadline instead of
//! failing on its own. The two defaults live in different feature crates, so only the
//! composition root can see both.

use styx_recursion::domain::budget::DEFAULT_WALL_CLOCK;
use styx_resolution::ServerConfig;

#[test]
fn default_query_deadline_outlasts_the_default_recursor_wall_clock() {
    let config = ServerConfig::from_toml_str("").unwrap();
    assert!(
        config.query_timeout > DEFAULT_WALL_CLOCK,
        "query_timeout {:?} must exceed the recursor wall clock {:?}",
        config.query_timeout,
        DEFAULT_WALL_CLOCK
    );
}

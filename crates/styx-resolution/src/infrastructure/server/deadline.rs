//! The cross-check between the whole-query deadline and the pool's member timeouts.

use crate::domain::config::PoolConfig;
use crate::domain::error::ConfigError;

use super::ServerConfig;

impl ServerConfig {
    /// Checks that `query_timeout` outlasts every pool member's own timeout, so the
    /// pool always settles its health accounting before the pipeline deadline fires.
    ///
    /// # Errors
    /// Returns [`ConfigError::Invalid`] naming the member with the longest timeout and both
    /// durations when some member's UDP or TCP timeout is not strictly shorter than
    /// `query_timeout`.
    pub fn check_deadline_covers(&self, pool: &PoolConfig) -> Result<(), ConfigError> {
        let slowest = pool
            .members
            .iter()
            .max_by_key(|member| member.timeouts.udp.max(member.timeouts.tcp));
        let Some(member) = slowest else {
            return Ok(());
        };
        let member_timeout = member.timeouts.udp.max(member.timeouts.tcp);
        if member_timeout < self.query_timeout {
            return Ok(());
        }
        Err(ConfigError::Invalid(format!(
            "query_timeout ({}ms) must exceed the longest upstream member timeout, but \
             member `{}` allows {}ms; raise query_timeout_secs or lower that member's \
             udp_timeout_ms and tcp_timeout_ms",
            self.query_timeout.as_millis(),
            member.name,
            member_timeout.as_millis()
        )))
    }
}

//! Each recursor member of the pool gets its own recursion settings: its
//! `[recursion.members.<name>]` overrides, then the shared `[recursion]` section, then the
//! built-in defaults. The pool's member list belongs to `styx-resolution` and the overrides
//! to `styx-recursion`, so only the composition root can pair the two.

// The helper below sits outside `#[test]` functions, where clippy's expect allowance stops.
#![allow(clippy::expect_used)]

use std::time::Duration;

use styx_recursion::application::config::{
    InfraCapacity, RecursionConfig, RecursionSection, DEFAULT_MAX_SERVERS, DEFAULT_TCP_TIMEOUT,
    DEFAULT_UDP_TIMEOUT,
};
use styx_recursion::application::recursor::RecursorSettings;
use styx_recursion::domain::budget::{
    DescentLimits, DEFAULT_MAX_CNAME_CHAIN, DEFAULT_MAX_DEPTH, DEFAULT_MAX_OUTBOUND_QUERIES,
};
use styx_recursion::domain::error::{ConfigError, MemberConfigError};
use styx_resolution::ServerConfig;

const POOL: &str = r#"
query_timeout_secs = 5

[upstream]
strategy = "ordered_failover"

[[upstream.members]]
name = "recursor-v4"
kind = "recursor"
addr = "0.0.0.0:0"

[[upstream.members]]
name = "recursor-tight"
kind = "recursor"
addr = "0.0.0.0:0"

[[upstream.members]]
name = "quad9"
kind = "forwarder"
addr = "9.9.9.9:53"
"#;

const SHARED: &str = r#"
[recursion]
root_hints = "config/named.root"
wall_clock_ms = 3000
"#;

/// The merged settings of every recursor member, in pool order, the way the binary
/// builds them at startup.
fn recursors(recursion: &str) -> Result<Vec<RecursionConfig>, ConfigError> {
    let text = format!("{POOL}{recursion}");
    let server = ServerConfig::from_toml_str(&text).expect("the pool parses");
    let pool = server.upstream.expect("the file has a pool");
    let names = pool.recursor_names();
    let section = RecursionSection::from_toml_str(&text)?;
    let mut configs = section.validate(&names, server.query_timeout)?;
    Ok(names
        .iter()
        .map(|name| {
            configs
                .remove(*name)
                .expect("validated recursor missing from map")
        })
        .collect())
}

#[test]
fn two_recursors_with_different_overrides_get_their_own_settings() {
    let configs = recursors(&format!(
        "{SHARED}
[recursion.members.recursor-v4]
use_ipv6 = false
max_delegations = 500

[recursion.members.recursor-tight]
max_outbound_queries = 16
udp_timeout_ms = 300
tcp_timeout_ms = 2000
"
    ))
    .expect("both members resolve");

    let [v4, tight] = configs.as_slice() else {
        panic!("expected two recursors, got {configs:?}");
    };
    let shared_wall_clock = Duration::from_secs(3);
    assert_eq!(
        v4.settings(),
        RecursorSettings {
            limits: DescentLimits::new(
                DEFAULT_MAX_DEPTH,
                DEFAULT_MAX_OUTBOUND_QUERIES,
                DEFAULT_MAX_CNAME_CHAIN,
                shared_wall_clock,
            )
            .expect("valid limits"),
            use_ipv6: false,
        }
    );
    assert_eq!(v4.udp_timeout, DEFAULT_UDP_TIMEOUT);
    assert_eq!(v4.tcp_timeout, DEFAULT_TCP_TIMEOUT);
    assert_eq!(
        v4.capacity,
        InfraCapacity {
            max_delegations: 500,
            max_servers: DEFAULT_MAX_SERVERS,
        }
    );

    assert_eq!(
        tight.settings(),
        RecursorSettings {
            limits: DescentLimits::new(
                DEFAULT_MAX_DEPTH,
                16,
                DEFAULT_MAX_CNAME_CHAIN,
                shared_wall_clock,
            )
            .expect("valid limits"),
            use_ipv6: true,
        }
    );
    assert_eq!(tight.udp_timeout, Duration::from_millis(300));
    assert_eq!(tight.tcp_timeout, Duration::from_millis(2000));
    assert_eq!(tight.capacity, InfraCapacity::default());
}

#[test]
fn an_unknown_key_in_an_override_fails_naming_the_member() {
    let error = recursors(&format!(
        "{SHARED}[recursion.members.recursor-tight]\nmax_outbound = 16\n"
    ))
    .expect_err("a typo must not fall back to the default");
    let message = error.to_string();
    assert!(message.contains("recursor-tight"), "{message}");
}

#[test]
fn a_zero_limit_in_an_override_fails_naming_the_member() {
    let error = recursors(&format!(
        "{SHARED}[recursion.members.recursor-v4]\nmax_cname_chain = 0\n"
    ))
    .expect_err("a zero limit is rejected");
    assert_eq!(
        error,
        ConfigError::member(
            "recursor-v4",
            MemberConfigError::ZeroLimit("max_cname_chain")
        )
    );
}

#[test]
fn an_override_for_a_forwarder_or_a_misspelt_member_fails() {
    for name in ["quad9", "recursor-4v"] {
        let error = recursors(&format!(
            "{SHARED}[recursion.members.{name}]\nuse_ipv6 = false\n"
        ))
        .expect_err("an override nothing uses is rejected");
        assert_eq!(error, ConfigError::UnknownMember(name.to_owned()));
    }
}

#[test]
fn without_a_shared_section_every_recursor_must_name_its_own_root_hints() {
    let error = recursors("[recursion.members.recursor-v4]\nroot_hints = \"config/named.root\"\n")
        .expect_err("recursor-tight has no root hints");
    assert_eq!(
        error,
        ConfigError::member("recursor-tight", MemberConfigError::MissingRootHints)
    );
}

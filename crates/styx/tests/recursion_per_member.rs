//! Each recursor member of the pool gets its own recursion settings: its
//! `[recursion.members.<name>]` overrides, then the shared `[recursion]` section, then the
//! built-in defaults. The pool's member list belongs to `styx-resolution` and the overrides
//! to `styx-recursion`, so only the composition root can pair the two.

use std::time::Duration;

use styx_core::UpstreamKind;
use styx_recursion::application::config::{RecursionConfig, RecursionSection};
use styx_recursion::domain::error::ConfigError;
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
    let server = ServerConfig::from_toml_str(&text)
        .map_err(|error| ConfigError::Toml(format!("the pool does not parse: {error}")))?;
    let pool = server
        .upstream
        .ok_or_else(|| ConfigError::Toml("the file has no pool".to_owned()))?;
    let names: Vec<&str> = pool
        .members
        .iter()
        .filter(|member| member.kind == UpstreamKind::Recursor)
        .map(|member| member.name.as_str())
        .collect();
    let section = RecursionSection::from_toml_str(&text)?;
    section.check_overrides(&names)?;
    names
        .iter()
        .map(|name| section.for_member(name, server.query_timeout))
        .collect()
}

#[test]
fn two_recursors_with_different_overrides_get_their_own_settings() {
    let configs = recursors(&format!(
        "{SHARED}
[recursion.members.recursor-v4]
use_ipv6 = false

[recursion.members.recursor-tight]
max_outbound_queries = 16
udp_timeout_ms = 300
"
    ))
    .expect("both members resolve");

    let [v4, tight] = configs.as_slice() else {
        panic!("expected two recursors, got {configs:?}");
    };
    assert!(!v4.settings().use_ipv6);
    assert_eq!(v4.settings().limits.max_outbound_queries(), 64);
    assert_eq!(v4.udp_timeout, Duration::from_millis(800));

    assert!(tight.settings().use_ipv6);
    assert_eq!(tight.settings().limits.max_outbound_queries(), 16);
    assert_eq!(tight.udp_timeout, Duration::from_millis(300));

    for config in [v4, tight] {
        assert_eq!(
            config.settings().limits.wall_clock(),
            Duration::from_secs(3)
        );
    }
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
        ConfigError::member("recursor-v4", ConfigError::ZeroLimit("max_cname_chain"))
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
fn a_member_wall_clock_past_the_query_deadline_fails_naming_the_member() {
    let error = recursors(&format!(
        "{SHARED}[recursion.members.recursor-tight]\nwall_clock_ms = 5000\n"
    ))
    .expect_err("the deadline would cut the descent off");
    assert!(
        matches!(&error, ConfigError::Member { member, .. } if member == "recursor-tight"),
        "{error:?}"
    );
}

#[test]
fn without_a_shared_section_every_recursor_must_name_its_own_root_hints() {
    let error = recursors("[recursion.members.recursor-v4]\nroot_hints = \"config/named.root\"\n")
        .expect_err("recursor-tight has no root hints");
    assert_eq!(
        error,
        ConfigError::member("recursor-tight", ConfigError::MissingRootHints)
    );
}

use crate::domain::budget::{
    DEFAULT_MAX_CNAME_CHAIN, DEFAULT_MAX_DEPTH, DEFAULT_MAX_OUTBOUND_QUERIES,
};

use super::*;

const QUERY_TIMEOUT: Duration = Duration::from_secs(5);

const TWO_RECURSORS: &str = r#"
[recursion]
root_hints = "/etc/named.root"
wall_clock_ms = 3000
udp_timeout_ms = 700

[recursion.members.recursor-v4]
use_ipv6 = false
max_outbound_queries = 32

[recursion.members.recursor-far]
root_hints = "/srv/other.root"
wall_clock_ms = 4500
tcp_timeout_ms = 2500
max_servers = 50
"#;

fn section(text: &str) -> RecursionSection {
    RecursionSection::from_toml_str(text).unwrap()
}

#[test]
fn each_member_merges_its_overrides_over_the_shared_section_and_the_defaults() {
    let section = section(TWO_RECURSORS);

    let v4 = section.for_member("recursor-v4", QUERY_TIMEOUT).unwrap();
    assert_eq!(v4.root_hints, PathBuf::from("/etc/named.root"));
    assert_eq!(
        v4.settings(),
        RecursorSettings {
            limits: DescentLimits::new(
                DEFAULT_MAX_DEPTH,
                32,
                DEFAULT_MAX_CNAME_CHAIN,
                Duration::from_millis(3000),
            )
            .unwrap(),
            use_ipv6: false,
        }
    );
    assert_eq!(v4.udp_timeout, Duration::from_millis(700));
    assert_eq!(v4.tcp_timeout, DEFAULT_TCP_TIMEOUT);
    assert_eq!(v4.capacity, InfraCapacity::default());

    let far = section.for_member("recursor-far", QUERY_TIMEOUT).unwrap();
    assert_eq!(far.root_hints, PathBuf::from("/srv/other.root"));
    assert_eq!(
        far.settings(),
        RecursorSettings {
            limits: DescentLimits::new(
                DEFAULT_MAX_DEPTH,
                DEFAULT_MAX_OUTBOUND_QUERIES,
                DEFAULT_MAX_CNAME_CHAIN,
                Duration::from_millis(4500),
            )
            .unwrap(),
            use_ipv6: true,
        }
    );
    assert_eq!(far.udp_timeout, Duration::from_millis(700));
    assert_eq!(far.tcp_timeout, Duration::from_millis(2500));
    assert_eq!(far.capacity.max_servers, 50);
    assert_eq!(far.capacity.max_delegations, DEFAULT_MAX_DELEGATIONS);
}

#[test]
fn a_member_without_overrides_takes_the_shared_section() {
    let section = section("[recursion]\nroot_hints = \"/etc/named.root\"\n");
    let config = section.for_member("recursor", QUERY_TIMEOUT).unwrap();
    assert_eq!(config.limits, DescentLimits::default());
    assert!(config.use_ipv6);
}

#[test]
fn a_member_naming_its_own_root_hints_needs_no_shared_section() {
    let section = section("[recursion.members.solo]\nroot_hints = \"/etc/named.root\"\n");
    assert!(section.for_member("solo", QUERY_TIMEOUT).is_ok());
    assert_eq!(
        section.for_member("other", QUERY_TIMEOUT),
        Err(ConfigError::member("other", ConfigError::MissingRootHints))
    );
}

#[test]
fn without_any_recursion_section_a_recursor_has_no_root_hints() {
    let section = section("listen_addrs = []");
    assert_eq!(section, RecursionSection::default());
    assert_eq!(
        section.for_member("recursor", QUERY_TIMEOUT),
        Err(ConfigError::member(
            "recursor",
            ConfigError::MissingRootHints
        ))
    );
}

#[test]
fn an_unknown_key_in_a_member_override_names_the_member() {
    let typo =
        "[recursion]\nroot_hints = \"x\"\n[recursion.members.recursor-v4]\nuse_ip6 = false\n";
    let error = RecursionSection::from_toml_str(typo).unwrap_err();
    assert!(
        matches!(&error, ConfigError::Member { member, reason }
            if member == "recursor-v4" && matches!(**reason, ConfigError::Toml(_))),
        "{error:?}"
    );
    let message = error.to_string();
    assert!(
        message.contains("recursor-v4") && message.contains("use_ip6"),
        "{message}"
    );
}

#[test]
fn a_zero_limit_in_a_member_override_names_the_member() {
    let zero = "[recursion]\nroot_hints = \"x\"\n[recursion.members.recursor-v4]\nmax_depth = 0\n";
    assert_eq!(
        section(zero).for_member("recursor-v4", QUERY_TIMEOUT),
        Err(ConfigError::member(
            "recursor-v4",
            ConfigError::ZeroLimit("max_depth")
        ))
    );
}

#[test]
fn zero_limits_and_unknown_keys_in_the_shared_section_are_rejected() {
    let zero = "[recursion]\nroot_hints = \"x\"\nmax_depth = 0\n";
    assert_eq!(
        RecursionSection::from_toml_str(zero),
        Err(ConfigError::ZeroLimit("max_depth"))
    );
    let typo = "[recursion]\nroot_hints = \"x\"\nmax_dept = 3\n";
    assert!(matches!(
        RecursionSection::from_toml_str(typo),
        Err(ConfigError::Toml(_))
    ));
}

#[test]
fn an_override_for_a_name_that_is_not_a_recursor_is_rejected() {
    let section = section(TWO_RECURSORS);
    assert_eq!(
        section.check_overrides(&["recursor-v4", "recursor-far", "quad9"]),
        Ok(())
    );
    assert_eq!(
        section.check_overrides(&["recursor-v4"]),
        Err(ConfigError::UnknownMember("recursor-far".to_owned()))
    );
}

#[test]
fn a_wall_clock_that_outlasts_the_query_deadline_names_the_member() {
    let section = section(TWO_RECURSORS);
    let deadline = Duration::from_millis(4000);
    assert!(section.for_member("recursor-v4", deadline).is_ok());
    assert_eq!(
        section.for_member("recursor-far", deadline),
        Err(ConfigError::member(
            "recursor-far",
            ConfigError::WallClockOutlastsDeadline {
                wall_clock: Duration::from_millis(4500),
                query_timeout: deadline,
            }
        ))
    );
    assert!(
        section
            .for_member("recursor-v4", Duration::from_millis(3000))
            .is_err(),
        "a wall clock equal to the deadline is cut off by it too"
    );
}

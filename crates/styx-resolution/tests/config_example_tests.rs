//! `config/styx.example.toml` stays parseable, and every default it states equals the
//! default the code applies.

use styx_core::UpstreamKind;
use styx_resolution::{
    CanaryConfig, CircuitConfig, ConfigError, EdnsBufferSize, PoolConfig, ProbeConfig,
    ServerConfig, SupervisorBackoffPolicy, Timeouts, Weight,
};
use styx_testkit::ExampleDocument;

const EXAMPLE_CONFIG: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../config/styx.example.toml"
));

const MINIMAL_CONFIG: &str = r#"
[upstream]
strategy = "ordered_failover"

[[upstream.members]]
name = "a"
kind = "forwarder"
addr = "9.9.9.9:53"
"#;

fn switched_on() -> Result<ServerConfig, ConfigError> {
    ServerConfig::from_toml_str(&ExampleDocument::parse(EXAMPLE_CONFIG).enabled())
}

fn switched_on_pool() -> Result<PoolConfig, ConfigError> {
    switched_on()?
        .upstream
        .ok_or_else(|| ConfigError::Invalid("the example configures no upstream pool".into()))
}

#[test]
fn example_config_parses_as_written() {
    let config = ServerConfig::from_toml_str(EXAMPLE_CONFIG).expect("example config parses");
    assert!(config.upstream.is_some());
}

#[test]
fn switched_on_example_yields_a_canary_for_a_forwarder_and_a_recursor() {
    let pool = switched_on_pool().expect("the commented keys parse once switched on");
    let kinds: Vec<UpstreamKind> = pool
        .members
        .iter()
        .filter(|member| member.canary.is_some())
        .map(|member| member.kind)
        .collect();
    assert!(kinds.contains(&UpstreamKind::Forwarder), "{kinds:?}");
    assert!(kinds.contains(&UpstreamKind::Recursor), "{kinds:?}");
}

#[test]
fn switched_on_example_members_equal_the_type_defaults() {
    let pool = switched_on_pool().expect("the commented keys parse once switched on");
    assert!(!pool.members.is_empty(), "the example configures members");
    for member in &pool.members {
        let name = &member.name;
        assert_eq!(member.weight, Weight::default(), "weight of {name}");
        assert_eq!(
            member.edns_buffer,
            EdnsBufferSize::default(),
            "edns_buffer of {name}"
        );
        assert_eq!(member.timeouts, Timeouts::default(), "timeouts of {name}");
    }
}

#[test]
fn switched_on_example_canaries_equal_the_default_of_their_kind() {
    let pool = switched_on_pool().expect("the commented keys parse once switched on");
    for member in &pool.members {
        let Some(canary) = &member.canary else {
            continue;
        };
        assert_eq!(
            canary,
            &CanaryConfig::for_kind(member.kind),
            "canary of {}",
            member.name
        );
    }
}

#[test]
fn switched_on_example_probe_and_circuit_equal_the_type_defaults() {
    let pool = switched_on_pool().expect("the commented keys parse once switched on");
    assert_eq!(pool.probe, ProbeConfig::default());
    assert_eq!(pool.circuit, CircuitConfig::default());
}

#[test]
fn switched_on_example_server_values_equal_those_of_a_minimal_config() {
    let config = switched_on().expect("the commented keys parse once switched on");
    let minimal = ServerConfig::from_toml_str(MINIMAL_CONFIG).expect("minimal config");
    assert_eq!(
        config.udp_payload_size_default, minimal.udp_payload_size_default,
        "udp_payload_size_default"
    );
    assert_eq!(
        config.tcp_idle_timeout, minimal.tcp_idle_timeout,
        "tcp_idle_timeout_secs"
    );
    assert_eq!(config.limits, minimal.limits, "concurrency caps");
    assert_eq!(config.query_timeout, minimal.query_timeout);
}

#[test]
fn switched_on_example_supervisor_equals_the_default_policy() {
    let config = switched_on().expect("the commented keys parse once switched on");
    assert_eq!(config.supervisor, SupervisorBackoffPolicy::default());
}

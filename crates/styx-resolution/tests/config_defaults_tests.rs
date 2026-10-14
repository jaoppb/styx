//! First-run configuration: a minimal config is accepted with every default left alone,
//! and every omitted value takes the default its own type states.

use std::time::Duration;

use styx_resolution::{
    CircuitConfig, ConfigError, EdnsBufferSize, PoolConfig, ProbeConfig, ServerConfig, Timeouts,
    UpstreamConfig, Weight,
};

const MINIMAL_CONFIG: &str = r#"
[upstream]
strategy = "ordered_failover"

[[upstream.members]]
name = "a"
kind = "forwarder"
addr = "9.9.9.9:53"
"#;

fn pool_with_one_member(kind: &str, extra: &str) -> String {
    format!(
        "strategy = \"ordered_failover\"\n\
         [[members]]\nname = \"a\"\nkind = \"{kind}\"\naddr = \"9.9.9.9:53\"\n{extra}\n"
    )
}

fn only_member(pool: &str) -> Result<UpstreamConfig, ConfigError> {
    let pool = PoolConfig::from_toml_str(pool)?;
    pool.members
        .into_iter()
        .next()
        .ok_or(ConfigError::EmptyPool)
}

#[test]
fn minimal_config_with_one_member_and_no_timeout_keys_is_accepted() {
    let config = ServerConfig::from_toml_str(MINIMAL_CONFIG)
        .expect("one member with only name, kind and addr is a valid config");
    assert_eq!(config.upstream.map(|pool| pool.members.len()), Some(1));
}

#[test]
fn default_query_timeout_outlasts_every_default_member_timeout() {
    let config = ServerConfig::from_toml_str(MINIMAL_CONFIG).expect("minimal config");
    let defaults = Timeouts::default();
    assert!(config.query_timeout > defaults.udp.max(defaults.tcp));
    assert_eq!(config.query_timeout, Duration::from_secs(5));
}

#[test]
fn member_without_weight_edns_or_timeouts_takes_the_type_defaults() {
    let member = only_member(&pool_with_one_member("forwarder", "")).expect("a valid member");
    assert_eq!(member.weight, Weight::default());
    assert_eq!(member.edns_buffer, EdnsBufferSize::default());
    assert_eq!(member.timeouts, Timeouts::default());
}

#[test]
fn pool_without_probe_or_circuit_tables_takes_the_type_defaults() {
    let pool =
        PoolConfig::from_toml_str(&pool_with_one_member("forwarder", "")).expect("a valid pool");
    assert_eq!(pool.probe, ProbeConfig::default());
    assert_eq!(pool.circuit, CircuitConfig::default());
}

#[test]
fn probe_table_setting_one_key_keeps_the_defaults_of_the_others() {
    let pool = PoolConfig::from_toml_str(&format!(
        "{}\n[probe]\ntick_secs = 7\n",
        pool_with_one_member("forwarder", "")
    ))
    .expect("a valid pool");
    let defaults = ProbeConfig::default();
    assert_eq!(pool.probe.tick, Duration::from_secs(7));
    assert_eq!(pool.probe.idle_window, defaults.idle_window);
    assert_eq!(pool.probe.down_retry_interval, defaults.down_retry_interval);
}

#[test]
fn circuit_table_setting_one_key_keeps_the_defaults_of_the_others() {
    let pool = PoolConfig::from_toml_str(&format!(
        "{}\n[circuit]\nfailure_threshold = 9\n",
        pool_with_one_member("forwarder", "")
    ))
    .expect("a valid pool");
    let defaults = CircuitConfig::default();
    assert_eq!(pool.circuit.failure_threshold, 9);
    assert_eq!(pool.circuit.open_cooldown, defaults.open_cooldown);
    assert_eq!(
        pool.circuit.half_open_successes,
        defaults.half_open_successes
    );
}

const FORWARDER_CANARY: &str =
    "[members.canary]\nqname = \"probe.canary.invalid.\"\nqtype = \"A\"\n";
const RECURSOR_CANARY: &str =
    "[members.canary]\nqname = \"root-canary.iana.org.\"\nqtype = \"NS\"\n";

fn canary_timeout(kind: &str, canary: &str) -> Result<Duration, ConfigError> {
    only_member(&pool_with_one_member(kind, canary))?
        .canary
        .map(|canary| canary.timeout)
        .ok_or_else(|| ConfigError::Invalid("the member sets no canary table".into()))
}

#[test]
fn forwarder_canary_without_timeout_takes_two_seconds() {
    assert_eq!(
        canary_timeout("forwarder", FORWARDER_CANARY).expect("the member sets a canary table"),
        Duration::from_secs(2)
    );
}

#[test]
fn recursor_canary_without_timeout_takes_five_seconds() {
    assert_eq!(
        canary_timeout("recursor", RECURSOR_CANARY).expect("the member sets a canary table"),
        Duration::from_secs(5)
    );
}

#[test]
fn explicit_canary_timeout_wins_for_both_kinds() {
    let forwarder = format!("{FORWARDER_CANARY}timeout_ms = 750\n");
    let recursor = format!("{RECURSOR_CANARY}timeout_ms = 750\n");
    assert_eq!(
        canary_timeout("forwarder", &forwarder).expect("the member sets a canary table"),
        Duration::from_millis(750)
    );
    assert_eq!(
        canary_timeout("recursor", &recursor).expect("the member sets a canary table"),
        Duration::from_millis(750)
    );
}

#[test]
fn recursor_canary_naming_the_root_or_one_label_is_still_rejected() {
    for qname in [".", "com."] {
        let canary = format!("[members.canary]\nqname = \"{qname}\"\nqtype = \"NS\"\n");
        let result = PoolConfig::from_toml_str(&pool_with_one_member("recursor", &canary));
        assert!(
            matches!(result, Err(ConfigError::CanaryNotDescending)),
            "{qname} must not be accepted as a recursor canary"
        );
    }
}

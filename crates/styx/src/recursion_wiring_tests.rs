//! `RecursionWiring::load` is the startup step that pairs the pool's recursor members with
//! their merged `[recursion]` settings and reads each root-hints file from disk.

use std::sync::Arc;
use std::time::Duration;

use styx_core::{SystemClock, UpstreamId};
use styx_recursion::application::config::{
    InfraCapacity, RecursionSection, DEFAULT_TCP_TIMEOUT, DEFAULT_UDP_TIMEOUT,
};
use styx_recursion::application::recursor::RecursorSettings;
use styx_recursion::domain::budget::{
    DescentLimits, DEFAULT_MAX_CNAME_CHAIN, DEFAULT_MAX_DEPTH, DEFAULT_WALL_CLOCK,
};
use styx_resolution::ServerConfig;

use super::RecursionWiring;

const ROOT_HINTS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../config/named.root");

fn config_text(query_timeout_secs: u64, recursion: &str) -> String {
    format!(
        r#"
query_timeout_secs = {query_timeout_secs}

[upstream]
strategy = "ordered_failover"

[[upstream.members]]
name = "recursor-a"
kind = "recursor"
addr = "0.0.0.0:0"

[[upstream.members]]
name = "recursor-b"
kind = "recursor"
addr = "0.0.0.0:0"

[recursion]
root_hints = "{ROOT_HINTS}"
{recursion}
"#
    )
}

async fn load_with(query_timeout_secs: u64, recursion: &str) -> anyhow::Result<RecursionWiring> {
    let text = config_text(query_timeout_secs, recursion);
    let server = ServerConfig::from_toml_str(&text).expect("the pool parses");
    let pool = server.upstream.expect("the file has a pool");
    let section = RecursionSection::from_toml_str(&text).expect("[recursion] parses");
    RecursionWiring::load(section, &pool, server.query_timeout).await
}

async fn load(recursion: &str) -> anyhow::Result<RecursionWiring> {
    load_with(5, recursion).await
}

/// Builds both recursor members from `wiring`, as the pool does at startup. A member whose
/// validated config or loaded root hints `load` failed to key under the same path fails here.
fn build_every_recursor(wiring: &RecursionWiring) {
    let clock = Arc::new(SystemClock::new());
    for name in ["recursor-a", "recursor-b"] {
        if let Err(error) = wiring.recursor(UpstreamId::new(name), &clock) {
            panic!("{name} could not be built from the wiring: {error:#}");
        }
    }
}

#[tokio::test]
async fn a_forwarder_only_pool_needs_no_recursion_section() {
    let server = ServerConfig::from_toml_str(
        r#"
[upstream]
strategy = "ordered_failover"

[[upstream.members]]
name = "quad9"
kind = "forwarder"
addr = "9.9.9.9:53"
"#,
    )
    .expect("the pool parses");
    let pool = server.upstream.expect("the file has a pool");

    let wiring = RecursionWiring::load(RecursionSection::default(), &pool, server.query_timeout)
        .await
        .expect("nothing to validate or load");

    assert!(wiring.configs.is_empty());
    assert!(wiring.hints.is_empty());
}

#[tokio::test]
async fn recursors_naming_the_same_root_hints_share_one_loaded_copy() {
    let wiring = load("").await.expect("both recursors load");

    assert_eq!(wiring.configs.len(), 2);
    assert_eq!(wiring.hints.len(), 1);
    build_every_recursor(&wiring);
}

#[tokio::test]
async fn recursors_naming_equivalent_paths_share_one_loaded_copy() {
    let dot_path = format!("{}/./../../config/named.root", env!("CARGO_MANIFEST_DIR"));
    let wiring = load(&format!(
        "[recursion.members.recursor-b]\nroot_hints = \"{dot_path}\"\n"
    ))
    .await
    .expect("both recursors load");

    assert_eq!(wiring.configs.len(), 2);
    assert_eq!(wiring.hints.len(), 1);
    build_every_recursor(&wiring);
}

#[tokio::test]
async fn recursors_naming_distinct_root_hints_load_separate_entries() {
    let copy_path = std::env::temp_dir().join(format!(
        "styx-wiring-distinct-hints-{}.root",
        std::process::id()
    ));
    let _ = tokio::fs::copy(ROOT_HINTS, &copy_path)
        .await
        .expect("copy root hints");
    let wiring = load(&format!(
        "[recursion.members.recursor-b]\nroot_hints = \"{}\"\n",
        copy_path.display()
    ))
    .await;
    let _ = tokio::fs::remove_file(&copy_path).await;
    let wiring = wiring.expect("both recursors load distinct hint files");

    assert_eq!(wiring.configs.len(), 2);
    assert_eq!(wiring.hints.len(), 2);
    build_every_recursor(&wiring);
}

#[tokio::test]
async fn wiring_keeps_each_members_merged_config_separate() {
    let wiring = load(
        r#"
[recursion.members.recursor-a]
use_ipv6 = false
max_delegations = 500

[recursion.members.recursor-b]
max_outbound_queries = 16
udp_timeout_ms = 300
tcp_timeout_ms = 2000
"#,
    )
    .await
    .expect("both recursors load");

    let a = &wiring.configs["recursor-a"];
    assert_eq!(
        a.settings(),
        RecursorSettings {
            limits: DescentLimits::default(),
            use_ipv6: false,
        }
    );
    assert_eq!(a.udp_timeout, DEFAULT_UDP_TIMEOUT);
    assert_eq!(a.tcp_timeout, DEFAULT_TCP_TIMEOUT);
    assert_eq!(
        a.capacity,
        InfraCapacity {
            max_delegations: 500,
            ..InfraCapacity::default()
        }
    );

    let b = &wiring.configs["recursor-b"];
    assert_eq!(
        b.settings(),
        RecursorSettings {
            limits: DescentLimits::new(
                DEFAULT_MAX_DEPTH,
                16,
                DEFAULT_MAX_CNAME_CHAIN,
                DEFAULT_WALL_CLOCK,
            )
            .expect("valid limits"),
            use_ipv6: true,
        }
    );
    assert_eq!(b.udp_timeout, Duration::from_millis(300));
    assert_eq!(b.tcp_timeout, Duration::from_millis(2000));
    assert_eq!(b.capacity, InfraCapacity::default());
}

#[tokio::test]
async fn an_unreadable_root_hints_file_fails_startup_naming_the_member() {
    let error = load("[recursion.members.recursor-b]\nroot_hints = \"/nonexistent/named.root\"\n")
        .await
        .err()
        .expect("a missing root-hints file is a startup error");

    let message = format!("{error:#}");
    assert!(message.contains("recursor-b"), "{message}");
}

#[tokio::test]
async fn recursor_timeouts_must_be_shorter_than_query_timeout() {
    assert!(load_with(2, "").await.is_ok());

    let member_error = load_with(2, "[recursion.members.recursor-b]\ntcp_timeout_ms = 2000\n")
        .await
        .err()
        .expect("tcp_timeout_ms == query_timeout must fail");
    let message = format!("{member_error:#}");
    assert!(message.contains("recursor-b"), "{message}");
    assert!(
        message.contains("per-exchange") && message.contains("wall_clock_ms"),
        "{message}"
    );

    let shared_error = load_with(
        2,
        "udp_timeout_ms = 2500\n[recursion.members.recursor-b]\nudp_timeout_ms = 500\n",
    )
    .await
    .err()
    .expect("recursor-a inherits shared 2500ms > 2000ms");
    let message = format!("{shared_error:#}");
    assert!(message.contains("recursor-a"), "{message}");

    let _ = load_with(
        3,
        "tcp_timeout_ms = 4000\n\
         [recursion.members.recursor-a]\ntcp_timeout_ms = 1200\n\
         [recursion.members.recursor-b]\ntcp_timeout_ms = 1200\n",
    )
    .await
    .expect("member overrides below query_timeout succeed");
}

#[tokio::test]
async fn dotted_member_name_is_quoted_in_recursor_deadline_error() {
    let text = format!(
        r#"
query_timeout_secs = 2

[upstream]
strategy = "ordered_failover"

[[upstream.members]]
name = "rec.v4"
kind = "recursor"
addr = "0.0.0.0:0"

[recursion]
root_hints = "{ROOT_HINTS}"

[recursion.members."rec.v4"]
tcp_timeout_ms = 2000
"#
    );
    let server = ServerConfig::from_toml_str(&text).expect("the pool parses");
    let pool = server.upstream.expect("the file has a pool");
    let section = RecursionSection::from_toml_str(&text).expect("[recursion] parses");
    let error = RecursionWiring::load(section, &pool, server.query_timeout)
        .await
        .err()
        .expect("tcp_timeout_ms == query_timeout must fail");

    let message = format!("{error:#}");
    assert!(
        message.contains(r#"[recursion.members."rec.v4"]"#),
        "{message}"
    );
}

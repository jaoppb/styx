//! `RecursionWiring::load` is the startup step that pairs the pool's recursor members with
//! their merged `[recursion]` settings and reads each root-hints file from disk.

use styx_recursion::application::config::RecursionSection;
use styx_resolution::ServerConfig;

use super::RecursionWiring;

const ROOT_HINTS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../config/named.root");

fn config_text(recursion: &str) -> String {
    format!(
        r#"
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

async fn load(recursion: &str) -> anyhow::Result<RecursionWiring> {
    let text = config_text(recursion);
    let server = ServerConfig::from_toml_str(&text).expect("the pool parses");
    let pool = server.upstream.expect("the file has a pool");
    let section = RecursionSection::from_toml_str(&text).expect("[recursion] parses");
    RecursionWiring::load(section, &pool).await
}

#[tokio::test]
async fn recursors_naming_the_same_root_hints_share_one_loaded_copy() {
    let wiring = load("").await.expect("both recursors load");

    assert_eq!(wiring.configs.len(), 2);
    assert_eq!(wiring.hints.len(), 1);
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

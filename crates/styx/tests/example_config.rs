//! The example configuration is one file read by two crates' parsers: `styx-resolution`
//! takes the server, supervisor, upstream and `[tls]` tables and `styx-recursion` takes
//! `[recursion]`. Only the composition root may name both, so only it can prove the whole
//! file parses.

use styx_core::UpstreamKind;
use styx_recursion::application::config::RecursionConfig;
use styx_resolution::{tls_config_from_toml_str, ServerConfig};
use styx_testkit::ExampleDocument;

const EXAMPLE_CONFIG: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../config/styx.example.toml"
));

struct Parsed {
    server: ServerConfig,
    recursion: Option<RecursionConfig>,
    tls_enabled: bool,
}

fn parse_through_both(text: &str) -> Result<Parsed, String> {
    Ok(Parsed {
        server: ServerConfig::from_toml_str(text).map_err(|error| error.to_string())?,
        recursion: RecursionConfig::from_toml_str(text).map_err(|error| error.to_string())?,
        tls_enabled: tls_config_from_toml_str(text)
            .map_err(|error| error.to_string())?
            .is_some(),
    })
}

/// What is wrong with `text` as a whole config file, or `None` when both parsers accept it
/// and it still configures a recursor member together with its `[recursion]` section.
fn problem_with(text: &str) -> Option<String> {
    let parsed = match parse_through_both(text) {
        Ok(parsed) => parsed,
        Err(problem) => return Some(problem),
    };
    let Some(pool) = parsed.server.upstream else {
        return Some("the example configures no pool".to_owned());
    };
    let has_recursor = pool
        .members
        .iter()
        .any(|member| member.kind == UpstreamKind::Recursor);
    if !has_recursor {
        return Some("the example keeps no recursor member".to_owned());
    }
    if parsed.tls_enabled {
        return Some("the example turns encrypted inbound on by default".to_owned());
    }
    parsed
        .recursion
        .is_none()
        .then(|| "a recursor member needs the [recursion] section".to_owned())
}

#[test]
fn example_parses_through_the_server_and_the_recursion_parser() {
    assert_eq!(problem_with(EXAMPLE_CONFIG), None);
}

#[test]
fn example_with_every_commented_key_switched_on_parses_through_both() {
    assert_eq!(
        problem_with(&ExampleDocument::parse(EXAMPLE_CONFIG).enabled()),
        None
    );
}

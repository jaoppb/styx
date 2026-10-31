//! The example configuration is one file read by two parsers: `styx-resolution` takes the
//! server, supervisor and upstream tables and `styx-recursion` takes `[recursion]`. Only
//! the composition root may name both, so only it can prove the whole file parses.

use styx_core::UpstreamKind;
use styx_recursion::application::config::RecursionSection;
use styx_resolution::ServerConfig;
use styx_testkit::ExampleDocument;

const EXAMPLE_CONFIG: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../config/styx.example.toml"
));

struct Parsed {
    server: ServerConfig,
    recursion: RecursionSection,
}

fn parse_through_both(text: &str) -> Result<Parsed, String> {
    Ok(Parsed {
        server: ServerConfig::from_toml_str(text).map_err(|error| error.to_string())?,
        recursion: RecursionSection::from_toml_str(text).map_err(|error| error.to_string())?,
    })
}

/// What is wrong with `text` as a whole config file, or `None` when both parsers accept it
/// and it still configures a recursor member whose merged recursion settings are valid.
fn problem_with(text: &str) -> Option<String> {
    let parsed = match parse_through_both(text) {
        Ok(parsed) => parsed,
        Err(problem) => return Some(problem),
    };
    let Some(pool) = parsed.server.upstream else {
        return Some("the example configures no pool".to_owned());
    };
    let recursors: Vec<&str> = pool
        .members
        .iter()
        .filter(|member| member.kind == UpstreamKind::Recursor)
        .map(|member| member.name.as_str())
        .collect();
    if recursors.is_empty() {
        return Some("the example keeps no recursor member".to_owned());
    }
    if let Err(error) = parsed.recursion.check_overrides(&recursors) {
        return Some(error.to_string());
    }
    recursors.iter().find_map(|name| {
        parsed
            .recursion
            .for_member(name, parsed.server.query_timeout)
            .err()
            .map(|error| error.to_string())
    })
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

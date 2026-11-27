//! `packaging/styx.toml` (issue #100) is the config the container image starts with when
//! none is mounted, so it must load as-is, listen where the image exposes, and find its
//! root hints where the Dockerfile puts them.

use std::net::SocketAddr;
use std::path::Path;

use styx_recursion::application::config::RecursionSection;
use styx_resolution::ServerConfig;

const PACKAGED_CONFIG: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../packaging/styx.toml"
));

const DOCKERFILE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../packaging/docker/Dockerfile"
));

#[test]
fn the_packaged_config_listens_on_every_address_on_the_exposed_port() {
    let server = ServerConfig::from_toml_str(PACKAGED_CONFIG).unwrap();

    assert_eq!(
        server.listen_addrs,
        vec!["0.0.0.0:53".parse::<SocketAddr>().unwrap()]
    );
    assert!(DOCKERFILE.contains("EXPOSE 53/udp 53/tcp"));
}

#[test]
fn the_packaged_config_resolves_through_the_recursor_alone() {
    let server = ServerConfig::from_toml_str(PACKAGED_CONFIG).unwrap();
    let pool = server.upstream.unwrap();

    let recursors = pool.recursor_names();
    assert_eq!(recursors, vec!["recursor"]);
    assert_eq!(pool.members.len(), 1, "no third-party forwarder");
    assert!(pool.conditional.is_empty());

    let recursion = RecursionSection::from_toml_str(PACKAGED_CONFIG).unwrap();
    recursion
        .validate(&recursors, server.query_timeout)
        .unwrap();
}

#[test]
fn the_packaged_root_hints_are_where_the_image_copies_them() {
    let recursion = RecursionSection::from_toml_str(PACKAGED_CONFIG).unwrap();
    let root_hints = recursion.for_member("recursor").unwrap().root_hints;

    assert_eq!(root_hints, Path::new("/etc/styx/named.root"));
    assert!(DOCKERFILE.contains("COPY named.root /etc/styx/named.root"));
    assert!(DOCKERFILE.contains("COPY styx.toml /etc/styx/styx.toml"));
}

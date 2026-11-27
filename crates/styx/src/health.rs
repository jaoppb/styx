//! `styx health [address]`: the container healthcheck. It sends one query to a running
//! resolver and exits 0 when any response comes back, whatever its RCODE.
//!
//! The query asks the root name in class CH. The pipeline refuses every class but IN with
//! NOTIMP before it reaches the cache or an upstream, so the answer proves the listener and
//! the pipeline are serving without waiting on, or depending on, the upstreams.

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context};
use styx_core::{Clock, SystemClock};
use styx_net::Do53Client;
use styx_proto::{Header, Message, Name, Opcode, Question, RecordClass, RecordType};
use styx_recursion::infrastructure::do53_transport::DNS_PORT;

/// The `health` subcommand's name: a config file named `health` is passed as `./health`.
pub const HEALTH_COMMAND: &str = "health";

const HEALTH_USAGE: &str = "usage: styx health [address]";

/// Where the check is sent when no address is given: the resolver's default port, on the
/// loopback a container's own healthcheck reaches it through.
const DEFAULT_ADDRESS: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), DNS_PORT);

/// The whole check's budget. The resolver answers it without an upstream, so a healthy
/// one replies in well under a millisecond on loopback.
const HEALTH_TIMEOUT: Duration = Duration::from_secs(2);

/// Queries the resolver at the given address, or the default one, or prints the usage.
pub async fn health(mut args: impl Iterator<Item = String>) -> anyhow::Result<()> {
    let argument = args.next();
    if args.next().is_some() {
        bail!("too many arguments; {HEALTH_USAGE}");
    }
    let address = match argument.as_deref() {
        None => DEFAULT_ADDRESS,
        Some("-h" | "--help") => {
            writeln!(std::io::stdout().lock(), "{HEALTH_USAGE}")
                .context("failed to write the usage")?;
            return Ok(());
        }
        Some(text) => text
            .parse()
            .with_context(|| format!("'{text}' is not a socket address; {HEALTH_USAGE}"))?,
    };

    let clock = Arc::new(SystemClock::new());
    let deadline = clock
        .now_monotonic()
        .checked_add(HEALTH_TIMEOUT)
        .context("the health check deadline overflows the clock")?;
    let client = Do53Client::new(HEALTH_TIMEOUT, HEALTH_TIMEOUT, clock);
    client
        .exchange(address, query(), deadline)
        .await
        .with_context(|| format!("no DNS answer from {address}"))?;
    Ok(())
}

/// The check's query. Its transaction ID is a placeholder: the exchange stamps a fresh
/// random one.
fn query() -> Message {
    let mut message = Message::new(Header::new_query(0, Opcode::Query, false));
    message
        .questions
        .push(Question::new(Name::root(), RecordType::NS, RecordClass::Ch));
    message
}

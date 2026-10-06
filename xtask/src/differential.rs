//! The Phase 5 gate: a differential run of styx's recursor against a local
//! `unbound` over a curated corpus of real names.
//!
//! In-process fakes only prove the resolver does what *we think* delegation
//! means; a fake built from the same misreading of the RFCs agrees with the
//! resolver enthusiastically. `unbound` was written by other people reading those
//! RFCs independently, so this run is the only gate that catches a shared
//! misreading.
//!
//! **Recorded properties, which must not be quietly dropped:** it depends on the
//! live internet, it is flaky by nature because real DNS changes underneath the
//! corpus, it therefore gates a phase and never a push — and a genuine regression
//! can consequently hide behind a shrug. Every disagreement must be triaged to a
//! named cause before the phase is called done.
//!
//! Compared per name: the RCODE, and the answer section as a set of
//! `owner TYPE rdata` (TTLs and RRSIGs excluded — TTLs differ by cache age, and
//! there is no validator yet). The AD bit is the next phase's criterion.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use styx_core::{Clock, SystemClock, UpstreamId};
use styx_net::Do53Client;
use styx_proto::{Header, Message, Name, Opcode, Opt, Question, RecordClass, RecordType};
use styx_recursion::application::recursor::{Recursor, RecursorPorts, RecursorSettings};
use styx_recursion::domain::budget::DescentLimits;
use styx_recursion::domain::root_hints::RootHints;
use styx_recursion::infrastructure::do53_transport::{Do53Transport, DNS_PORT};
use styx_recursion::infrastructure::infra_cache::MemoryInfraCache;
use styx_recursion::infrastructure::sinks::{DiagnosticsStore, DiscardChainMaterial};

type RunRecursor = Recursor<
    SystemClock,
    Do53Transport<SystemClock>,
    DiagnosticsStore,
    DiscardChainMaterial,
    MemoryInfraCache,
>;

/// Per-name time allowance for either resolver.
const PER_NAME_DEADLINE: Duration = Duration::from_secs(8);

/// Where the run's inputs are.
pub(crate) struct Inputs<'a> {
    pub(crate) corpus: &'a Path,
    pub(crate) root_hints: &'a Path,
    pub(crate) unbound: SocketAddr,
}

/// One resolver's view of one name.
#[derive(Debug, PartialEq, Eq)]
struct Observed {
    rcode: String,
    answers: BTreeSet<String>,
}

/// Runs the corpus through both resolvers and reports every disagreement.
///
/// # Errors
///
/// Returns an error if the corpus or root hints cannot be read, or the runtime
/// cannot start.
pub(crate) fn run(inputs: &Inputs<'_>) -> Result<bool> {
    let runtime = tokio::runtime::Runtime::new().context("starting the tokio runtime")?;
    runtime.block_on(compare_all(inputs))
}

async fn compare_all(inputs: &Inputs<'_>) -> Result<bool> {
    let corpus = tokio::fs::read_to_string(inputs.corpus)
        .await
        .with_context(|| format!("reading corpus {}", inputs.corpus.display()))?;
    let questions = parse_corpus(&corpus)?;
    let hints = RootHints::from_config_path(inputs.root_hints)
        .await
        .context("loading root hints")?;
    let clock = Arc::new(SystemClock::new());
    let recursor = build_recursor(&hints, &clock);
    let client = Do53Client::new(PER_NAME_DEADLINE, PER_NAME_DEADLINE, Arc::clone(&clock));

    let mut disagreements = 0usize;
    for question in &questions {
        let deadline = deadline(clock.as_ref());
        let styx = observe_styx(&recursor, question, deadline).await;
        let unbound = observe_unbound(&client, inputs.unbound, question, deadline).await;
        let label = format!("{} {}", question.qname, question.qtype);
        match (styx, unbound) {
            (Ok(ours), Ok(theirs)) if ours == theirs => println!("AGREE   {label}  {}", ours.rcode),
            (Ok(ours), Ok(theirs)) => {
                disagreements = disagreements.saturating_add(1);
                report(&label, &ours, &theirs);
            }
            (ours, theirs) => {
                disagreements = disagreements.saturating_add(1);
                println!("ERROR   {label}\n        styx: {ours:?}\n        unbound: {theirs:?}");
            }
        }
    }
    println!(
        "\ndifferential: {} name(s), {disagreements} disagreement(s)",
        questions.len()
    );
    if disagreements > 0 {
        eprintln!(
            "Every disagreement must be triaged to a named cause before the phase is done.\n\
             \"DNS moved\" is a cause only once the movement itself has been confirmed."
        );
    }
    Ok(disagreements == 0)
}

fn build_recursor(hints: &RootHints, clock: &Arc<SystemClock>) -> RunRecursor {
    let client = Do53Client::new(
        Duration::from_millis(800),
        Duration::from_millis(1500),
        Arc::clone(clock),
    );
    Recursor::new(
        UpstreamId::new("differential"),
        RecursorSettings {
            limits: DescentLimits::default(),
            use_ipv6: false,
        },
        hints,
        RecursorPorts {
            clock: Arc::clone(clock),
            transport: Arc::new(Do53Transport::new(client, DNS_PORT)),
            diagnostics: Arc::new(DiagnosticsStore::new()),
            chain_material: Arc::new(DiscardChainMaterial),
            infra: Arc::new(MemoryInfraCache::default()),
        },
    )
}

fn deadline(clock: &SystemClock) -> Instant {
    let now = clock.now_monotonic();
    now.checked_add(PER_NAME_DEADLINE).unwrap_or(now)
}

async fn observe_styx(
    recursor: &RunRecursor,
    question: &Question,
    deadline: Instant,
) -> Result<Observed, String> {
    recursor
        .resolve_iteratively(question, deadline)
        .await
        .map(|message| observed(&message))
        .map_err(|error| error.to_string())
}

async fn observe_unbound(
    client: &Do53Client<SystemClock>,
    unbound: SocketAddr,
    question: &Question,
    deadline: Instant,
) -> Result<Observed, String> {
    let mut query = Message::new(Header::new_query(0, Opcode::Query, true));
    query.questions.push(question.clone());
    query.opt = Some(Opt::new(1232, 0, 0, true, Vec::new()));
    client
        .exchange(unbound, query, deadline)
        .await
        .map(|exchanged| observed(&exchanged.message))
        .map_err(|error| error.to_string())
}

fn observed(message: &Message) -> Observed {
    let answers = message
        .answers
        .iter()
        .filter(|record| record.rtype != RecordType::RRSIG)
        .map(|record| {
            format!(
                "{} {} {:?}",
                record.owner.to_canonical(),
                record.rtype,
                record.rdata
            )
        })
        .collect();
    Observed {
        rcode: message.header.rcode.to_string(),
        answers,
    }
}

fn report(label: &str, ours: &Observed, theirs: &Observed) {
    println!("DIFFER  {label}");
    if ours.rcode != theirs.rcode {
        println!(
            "        rcode: styx {} / unbound {}",
            ours.rcode, theirs.rcode
        );
    }
    for only in ours.answers.difference(&theirs.answers) {
        println!("        only styx:    {only}");
    }
    for only in theirs.answers.difference(&ours.answers) {
        println!("        only unbound: {only}");
    }
}

fn parse_corpus(text: &str) -> Result<Vec<Question>> {
    let mut questions = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let number = index.saturating_add(1);
        let [name, rtype] = line.split_whitespace().collect::<Vec<_>>()[..] else {
            bail!("corpus line {number}: expected `name TYPE`");
        };
        let qname =
            Name::from_ascii(name).with_context(|| format!("corpus line {number}: bad name"))?;
        let qtype = record_type(rtype)
            .with_context(|| format!("corpus line {number}: unknown type {rtype}"))?;
        questions.push(Question::new(qname, qtype, RecordClass::In));
    }
    Ok(questions)
}

fn record_type(mnemonic: &str) -> Option<RecordType> {
    let known = [
        RecordType::A,
        RecordType::NS,
        RecordType::CNAME,
        RecordType::SOA,
        RecordType::PTR,
        RecordType::MX,
        RecordType::TXT,
        RecordType::AAAA,
        RecordType::SRV,
        RecordType::DS,
        RecordType::DNSKEY,
    ];
    if mnemonic.eq_ignore_ascii_case("HINFO") {
        return Some(RecordType::from_u16(13));
    }
    known
        .into_iter()
        .find(|rtype| rtype.to_string().eq_ignore_ascii_case(mnemonic))
}

//! Reads an example TOML configuration the way a user edits it.
//!
//! An example file documents optional keys by commenting them out: `# weight = 1`.
//! Telling those lines from prose by pattern is guesswork, so this scanner asks the TOML
//! parser instead. With its leading `#` removed, a line is a table header or a
//! `key = value` pair exactly when it parses as one; prose does not parse and is dropped.
//!
//! Values that span several lines are not supported.

mod schema;

pub use schema::{SchemaMismatch, SchemaTable};

use toml::{Table, Value};

/// One `key = value` line of an example file, live or commented out.
#[derive(Debug, Clone, PartialEq)]
pub struct ExampleEntry {
    /// One-based line number in the file.
    pub line: usize,
    /// The table header in force, as written (`[[upstream.members]]`), or empty for the
    /// top level of the file.
    pub table: String,
    /// The `name` of the array-of-tables element this entry sits in, if it has one.
    pub owner: Option<String>,
    /// The key, without its value.
    pub key: String,
    /// The value, parsed.
    pub value: Value,
    /// Whether the line is commented out in the file.
    pub commented: bool,
}

#[derive(Debug, Clone)]
enum ExampleLine {
    /// Anything that is neither a header nor an entry, kept as written.
    Prose(String),
    /// A table header, live or commented, as its uncommented text.
    Header(String),
    /// A `key = value` line, with its uncommented text.
    Entry {
        entry: ExampleEntry,
        uncommented: String,
    },
}

enum Candidate {
    Header(String),
    Entry { key: String, value: Value },
    Prose,
}

/// An example configuration file, classified line by line.
#[derive(Debug, Clone)]
pub struct ExampleDocument {
    lines: Vec<ExampleLine>,
}

impl ExampleDocument {
    /// Classifies every line of `text`. Parsing never fails as a whole: a line that is not
    /// a header or a `key = value` pair is prose.
    #[must_use]
    pub fn parse(text: &str) -> Self {
        let mut table = String::new();
        let mut lines = Vec::new();
        for (index, raw) in text.lines().enumerate() {
            let trimmed = raw.trim();
            let stripped = trimmed.strip_prefix('#');
            let commented = stripped.is_some();
            let candidate = stripped.unwrap_or(trimmed).trim();
            lines.push(match classify(candidate) {
                Candidate::Header(text) => {
                    table.clone_from(&text);
                    ExampleLine::Header(text)
                }
                Candidate::Entry { key, value } => ExampleLine::Entry {
                    entry: ExampleEntry {
                        line: index.saturating_add(1),
                        table: table.clone(),
                        owner: None,
                        key,
                        value,
                        commented,
                    },
                    uncommented: candidate.to_owned(),
                },
                Candidate::Prose => ExampleLine::Prose(raw.to_owned()),
            });
        }
        assign_owners(&mut lines);
        Self { lines }
    }

    /// The entries of the file, live and commented, in file order.
    pub fn entries(&self) -> impl Iterator<Item = &ExampleEntry> {
        self.lines.iter().filter_map(|line| match line {
            ExampleLine::Entry { entry, .. } => Some(entry),
            ExampleLine::Prose(_) | ExampleLine::Header(_) => None,
        })
    }

    /// The file with every commented header and entry switched on, all other lines
    /// unchanged.
    #[must_use]
    pub fn enabled(&self) -> String {
        let lines: Vec<&str> = self
            .lines
            .iter()
            .map(|line| match line {
                ExampleLine::Prose(raw) => raw.as_str(),
                ExampleLine::Header(text) => text.as_str(),
                ExampleLine::Entry { uncommented, .. } => uncommented.as_str(),
            })
            .collect();
        lines.join("\n")
    }
}

fn classify(candidate: &str) -> Candidate {
    if candidate.starts_with('[') {
        return header_of(candidate).map_or(Candidate::Prose, Candidate::Header);
    }
    let Ok(table) = toml::from_str::<Table>(candidate) else {
        return Candidate::Prose;
    };
    let mut pairs = table.into_iter();
    match (pairs.next(), pairs.next()) {
        (Some(pair), None) if !pair.1.is_table() => Candidate::Entry {
            key: pair.0,
            value: pair.1,
        },
        _ => Candidate::Prose,
    }
}

/// The header text, without any trailing comment, when `candidate` is a table header.
fn header_of(candidate: &str) -> Option<String> {
    let text = candidate.split('#').next().unwrap_or(candidate).trim();
    let parsed = toml::from_str::<Table>(text).ok()?;
    parsed
        .values()
        .all(holds_only_tables)
        .then(|| text.to_owned())
}

fn holds_only_tables(value: &Value) -> bool {
    match value {
        Value::Table(table) => table.values().all(holds_only_tables),
        Value::Array(items) => items.iter().all(holds_only_tables),
        _ => false,
    }
}

/// The dotted path a header names: `[[a.b]]` and `[a.b]` both give `a.b`.
fn header_path(text: &str) -> &str {
    text.trim_start_matches('[').trim_end_matches(']')
}

fn extends(path: &str, parent: &str) -> bool {
    path.strip_prefix(parent)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('.'))
}

/// Tags every entry inside an array-of-tables element with that element's `name`.
///
/// An element runs from its `[[...]]` header to the next header that is not one of its
/// own sub-tables.
fn assign_owners(lines: &mut [ExampleLine]) {
    let mut span: Option<(String, usize)> = None;
    for index in 0..lines.len() {
        let Some(ExampleLine::Header(text)) = lines.get(index) else {
            continue;
        };
        let path = header_path(text).to_owned();
        let opens_element = text.starts_with("[[");
        let continues = span
            .as_ref()
            .is_some_and(|(parent, _)| !opens_element && extends(&path, parent));
        if continues {
            continue;
        }
        if let Some((_, start)) = span.take() {
            tag_owner(lines, start, index);
        }
        if opens_element {
            span = Some((path, index));
        }
    }
    if let Some((_, start)) = span {
        tag_owner(lines, start, lines.len());
    }
}

fn tag_owner(lines: &mut [ExampleLine], start: usize, end: usize) {
    let owner = lines
        .iter()
        .take(end)
        .skip(start)
        .find_map(|line| match line {
            ExampleLine::Entry { entry, .. } if !entry.commented && entry.key == "name" => {
                entry.value.as_str().map(str::to_owned)
            }
            _ => None,
        });
    for line in lines.iter_mut().take(end).skip(start) {
        if let ExampleLine::Entry { entry, .. } = line {
            entry.owner.clone_from(&owner);
        }
    }
}

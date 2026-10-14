//! The key manifest an example file is checked against, and what a mismatch looks like.

use thiserror::Error;

use super::ExampleDocument;

/// The keys one table of a configuration schema accepts.
#[derive(Debug, Clone, Copy)]
pub struct SchemaTable {
    /// The table header exactly as the example writes it (`[upstream.probe]`), or empty
    /// for the top level of the file.
    pub header: &'static str,
    /// The leaf keys the table accepts. Keys whose value is itself a table are not listed.
    pub keys: &'static [&'static str],
}

/// A way the example and the schema disagree.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SchemaMismatch {
    /// The example has a key the table does not accept.
    #[error("example line {line}: {key} is not a key of {table}")]
    UnknownKey {
        /// Line of the offending entry.
        line: usize,
        /// Header of the table it sits in.
        table: String,
        /// The key the schema does not know.
        key: String,
    },
    /// The schema accepts a key the example never mentions, live or commented.
    #[error("example never mentions {key} under {table}")]
    MissingKey {
        /// Header of the table that accepts the key.
        table: String,
        /// The key the example leaves out.
        key: String,
    },
}

impl ExampleDocument {
    /// Compares the example with `schema`.
    ///
    /// Entries in tables the schema does not name are ignored: they belong to another
    /// crate. Unknown keys come first, in line order, then missing keys in schema order.
    #[must_use]
    pub fn check(&self, schema: &[SchemaTable]) -> Vec<SchemaMismatch> {
        let mut mismatches = self.unknown_keys(schema);
        mismatches.extend(self.missing_keys(schema));
        mismatches
    }

    fn unknown_keys(&self, schema: &[SchemaTable]) -> Vec<SchemaMismatch> {
        self.entries()
            .filter(|entry| {
                schema
                    .iter()
                    .find(|table| table.header == entry.table)
                    .is_some_and(|table| !table.keys.contains(&entry.key.as_str()))
            })
            .map(|entry| SchemaMismatch::UnknownKey {
                line: entry.line,
                table: entry.table.clone(),
                key: entry.key.clone(),
            })
            .collect()
    }

    fn missing_keys(&self, schema: &[SchemaTable]) -> Vec<SchemaMismatch> {
        schema
            .iter()
            .flat_map(|table| table.keys.iter().map(move |key| (table.header, *key)))
            .filter(|(header, key)| {
                !self
                    .entries()
                    .any(|entry| entry.table == *header && entry.key == *key)
            })
            .map(|(header, key)| SchemaMismatch::MissingKey {
                table: header.to_owned(),
                key: key.to_owned(),
            })
            .collect()
    }
}

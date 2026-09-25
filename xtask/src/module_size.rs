//! The module-size check: turns "small, single-purpose modules over
//! god-modules" into a verdict, at the only granularity no clippy lint
//! covers — the file.
//!
//! Walks every `.rs` file under `crates/*/src/` and `xtask/src/`, relative to
//! a root (default: the current directory, i.e. the workspace root when run
//! through `just`). The `--root` flag exists so Fixture I can point this
//! check at a fixture directory; it changes where the check looks, never what
//! it allows. There is no other configuration and no per-file exemption: a
//! file over the cap is split by concept.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

/// The cap, in counted lines. One named constant, not a flag — the self-test
/// proves the real number rather than a copy of it.
pub(crate) const MAX_MODULE_LINES: usize = 400;

/// Runs the check rooted at `root` (default: the current directory).
///
/// # Errors
///
/// Returns an error if a directory cannot be read, a file cannot be read as
/// UTF-8, or the scan finds zero `.rs` files — an empty scan is never a pass.
pub(crate) fn run(root: Option<&str>) -> Result<bool> {
    let root = Path::new(root.unwrap_or("."));
    let files = collect_rs_files(root)?;
    if files.is_empty() {
        bail!(
            "module-size: found no .rs files under {}/crates/*/src or {}/xtask/src",
            root.display(),
            root.display()
        );
    }

    let mut violations: Vec<(PathBuf, usize)> = Vec::new();
    for file in &files {
        let count = count_file(file)?;
        if is_over_cap(count) {
            violations.push((file.clone(), count));
        }
    }

    report(&files, &violations)
}

/// Prints the verdict and returns whether the scan passed.
fn report(files: &[PathBuf], violations: &[(PathBuf, usize)]) -> Result<bool> {
    if violations.is_empty() {
        println!(
            "module-size: OK — {} file(s) scanned, none over {MAX_MODULE_LINES} counted lines.",
            files.len()
        );
        return Ok(true);
    }

    eprintln!("module-size: FAILED\n");
    for (path, count) in violations {
        eprintln!(
            "  {} — {count} counted lines (cap {MAX_MODULE_LINES})",
            path.display()
        );
    }
    eprintln!(
        "\nInvariant: a .rs file holds at most {MAX_MODULE_LINES} lines that are neither\n\
         blank nor only a comment. There is no per-file exemption and no marker comment\n\
         to raise it — split the file by concept, the way domain/rdata/basic.rs and\n\
         domain/rdata/dnssec.rs are split out of a single rdata catch-all."
    );
    Ok(false)
}

/// A count strictly greater than [`MAX_MODULE_LINES`] is a violation.
fn is_over_cap(count: usize) -> bool {
    count > MAX_MODULE_LINES
}

/// Collects every `.rs` file under `<root>/crates/*/src/` and
/// `<root>/xtask/src/`.
fn collect_rs_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();

    if let Ok(entries) = fs::read_dir(root.join("crates")) {
        for entry in entries {
            let entry = entry.context("reading the crates directory")?;
            walk(&entry.path().join("src"), &mut files)?;
        }
    }

    walk(&root.join("xtask/src"), &mut files)?;

    Ok(files)
}

/// Walks `path`, collecting `.rs` files into `files`.
///
/// Tries to open `path` as a directory rather than asking whether it is one
/// first: one `read_dir` per path, and it doubles as the existence check —
/// a path that is not a directory (including one that does not exist at all)
/// takes the `Err` branch and is treated as a candidate file instead.
fn walk(path: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    match fs::read_dir(path) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry.with_context(|| format!("reading {}", path.display()))?;
                walk(&entry.path(), files)?;
            }
            Ok(())
        }
        Err(_) => {
            if path.extension().is_some_and(|extension| extension == "rs") {
                files.push(path.to_path_buf());
            }
            Ok(())
        }
    }
}

/// Reads `path` and counts its non-blank, non-comment-only lines.
fn count_file(path: &Path) -> Result<usize> {
    let contents =
        fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(count_lines(&contents))
}

/// Counts the lines in `contents` that are neither blank nor made up only of
/// a comment (`//`, `///`, `//!`, or a line inside a `/* */` block).
fn count_lines(contents: &str) -> usize {
    let mut count: usize = 0;
    let mut in_block_comment = false;

    for line in contents.lines() {
        let trimmed = line.trim();

        if in_block_comment {
            if trimmed.contains("*/") {
                in_block_comment = false;
            }
            continue;
        }
        if trimmed.is_empty() || trimmed.starts_with("//") {
            continue;
        }
        if trimmed.starts_with("/*") {
            in_block_comment = !trimmed.contains("*/");
            continue;
        }

        count = count.saturating_add(1);
    }

    count
}

#[cfg(test)]
mod tests {
    use super::{count_lines, is_over_cap, MAX_MODULE_LINES};

    fn code_lines(count: usize) -> String {
        "let x = 1;\n".repeat(count)
    }

    #[test]
    fn exactly_at_cap_is_counted_and_passes() {
        let contents = code_lines(MAX_MODULE_LINES);
        assert_eq!(count_lines(&contents), MAX_MODULE_LINES);
        assert!(!is_over_cap(count_lines(&contents)));
    }

    #[test]
    fn one_over_cap_is_counted_and_fails() {
        let contents = code_lines(MAX_MODULE_LINES.saturating_add(1));
        assert_eq!(count_lines(&contents), MAX_MODULE_LINES.saturating_add(1));
        assert!(is_over_cap(count_lines(&contents)));
    }

    #[test]
    fn blank_and_comment_only_lines_are_not_counted() {
        let contents = "let a = 1;\n\
                         \n\
                         // a line comment\n\
                         /// a doc comment\n\
                         //! an inner doc comment\n\
                         /* a single-line block comment */\n\
                         /* a block comment\n\
                            spanning several lines\n\
                            of pure prose */\n\
                         let b = 2;\n";
        assert_eq!(count_lines(contents), 2);
    }
}

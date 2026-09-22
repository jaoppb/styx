//! styx shared foundation.
//!
//! `styx-proto` is **not a feature crate**. It is the shared foundation every
//! other crate parses through, and it is the *sole* exemption from the
//! feature-isolation rule: everyone may name it, and it names no one.
//!
//! That exemption is a dependency *target* exemption only. `styx-proto` is
//! still bound by the rule as a *source* — it must never name a feature crate.
//! Phrasing the restriction as "no crate may name another workspace crate"
//! would break the entire build, which is why the rule in `arch-lint.toml`
//! denies specific feature crates rather than workspace membership in general.
//!
//! Unlike a feature crate, this crate has no `domain` / `application` /
//! `infrastructure` split: it is a codec, not a feature.
//!
//! The DNS wire format — header, question, resource record, name compression —
//! arrives in **Phase 1**. Phase 0 delivers the crate and its place in the
//! layering rules, and nothing else. See `docs/adr/0001-layering-and-arch-lint.md`.

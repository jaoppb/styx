# ADR 0008 — Centralized checked slice traversal via Cursor primitive

- **Status**: accepted
- **Date**: 2026-09-26
- **Phase**: 1 — Wire codec

## Context

`styx` enforces panic-freedom across all production code via workspace-level lints and
architectural rules:

- `#![deny(clippy::indexing_slicing)]` forbids raw indexing like `&buf[start..end]` or
  `buf[i]`.
- `#![deny(clippy::arithmetic_side_effects)]` forbids bare `+`, `-`, `*` arithmetic that
  could overflow.
- `arch-lint` rule `no-unwrap-expect` forbids `.unwrap()` and `.expect()`.

DNS wire protocol parsing is intrinsically variable-length and heavily offset-driven.
Scattering defensive `get()`, `checked_add()`, and range boundary checks across every
individual header, question, label, and record parser function produces excessive
ceremony, obscures domain logic, and increases the likelihood that a subtler boundary check
is missed.

## Decision

**All slice access and offset arithmetic during wire decoding is centralized in a single
audited primitive: `styx_proto::application::cursor::Cursor`.**

- `Cursor` wraps a contiguous byte slice, tracks the current read position, and provides
  bounds-checked primitives (`read_u8`, `read_u16`, `read_u32`, `read_bytes`, `slice`,
  `checkpoint`).
- Every cursor operation returns a `Result<T, DecodeError>` where an out-of-bounds attempt
  yields `DecodeError::UnexpectedEndOfInput`.
- Direct slice indexing is prohibited throughout `domain` and `application`; all wire
  traversal must route through `Cursor`.

## Consequences

- Out-of-bounds panics and arithmetic overflow in decoding are structurally prevented by
  construction.
- Parser code remains concise and readable without repetitive manual boundary checks.
- Any future wire parsing requirements must either use existing `Cursor` methods or add
  new audited, tested primitives to `Cursor` rather than introducing ad-hoc slicing.

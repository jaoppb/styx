---
name: /spdd-generate
id: spdd-generate
category: Development
description: Generate Rust code from a structured SPDD prompt file following the REASONS Canvas methodology
---

Generate Rust implementation code from a structured SPDD (Structured Prompt-Driven
Development) prompt file, strictly following the Operations sequence and coding norms
defined in the prompt.

**Input**: The argument after `/spdd-generate` is the path to the structured prompt file
(e.g., `@spdd/prompt/202602271430-[Feat]-api-create-agent-endpoint.md`).

**Steps**

1. **If no input provided, ask for the prompt file**

   Use the **AskUserQuestion tool** to ask:
   > "Please provide the path to the structured prompt file (e.g.,
   > `@spdd/prompt/xxx.md`)."

   **IMPORTANT**: Do NOT proceed without a valid prompt file path.

2. **Read and parse the structured prompt file**

   Read the prompt file and extract the REASONS Canvas sections:

   | Section | Purpose | Usage |
   |---------|---------|-------|
   | **R** - Requirements | Overall goal and DoD | Understand the business context |
   | **E** - Entities | Type model and relationships | Reference for struct/enum/trait design |
   | **A** - Approach | Implementation strategy | Guide architectural decisions |
   | **S** - Structure | Crates, modules and dependencies | Verify layering and relationships |
   | **O** - Operations | Concrete implementation tasks | **Execute in defined order** |
   | **N** - Norms | Engineering standards | Apply to all generated code |
   | **S** - Safeguards | Non-negotiable constraints | Enforce strictly |

   **IMPORTANT**: Read the ENTIRE file carefully. Each section provides critical guidance.

3. **Analyze project context**

   Before generating code:
   - Read the workspace root `Cargo.toml` and the target crate's `Cargo.toml` — edition,
     MSRV (`rust-version`), `[features]`, available dependencies, `[workspace.lints]`
   - Confirm every crate the Operations section references is already a dependency. If one
     is missing, add it to the correct `Cargo.toml` with the right features before writing
     code that imports it
   - Locate existing similar patterns in the codebase for reference
   - Identify the correct module path and where the new `mod` declarations must be added
   - Read `clippy.toml`, `rustfmt.toml` and any crate-level `#![deny(...)]` attributes —
     these bind the generated code
   - Check for existing error types, newtypes, traits, or helpers to reuse rather than
     duplicate

   **IMPORTANT**: Generated code MUST align with existing project conventions.

4. **Validate the Operations sequence**

   Review the **Operations** section to verify:

   a. **Dependency order is correct**:
      - Types with no dependencies come first (error enums, newtypes, plain enums, consts)
      - Then traits, then their implementors, then wiring, then tests
      - Types depend only on previously defined types
      - No circular module dependencies exist (Rust permits cycles between modules in a
        crate, but not between crates — check crate edges especially)

   b. **Task decomposition is complete**:
      - Each operation is atomic and testable
      - No logical gaps between operations
      - All components mentioned in Structure are covered

   c. **Consistency with Structure section**:
      - Trait implementations match
      - Dependencies match
      - Layering is respected: no domain module importing infrastructure, no crate edge
        the Structure section forbids

   **If issues are found**: Report to user and suggest prompt modifications before
   proceeding.

   **IMPORTANT**: Do NOT re-plan the sequence. The Operations order is the designed
   execution order from the Abstraction phase.

5. **Generate code following Operations sequence**

   For each operation in the **Operations** section (in order):

   a. **Read the operation specification**:
      - Responsibility: What the component does
      - Fields/Methods: Exact fields, types, and full signatures including
        `&self`/`&mut self`/`self` and borrows
      - Derives: The required derive set
      - Invariants: What must always hold, and where it is enforced
      - Error paths: Which error variant each failure returns
      - Business logic: Step-by-step implementation details

   b. **Apply Norms**:
      - Naming: `snake_case` items, `UpperCamelCase` types, no stutter
      - Visibility: the narrowest that satisfies the stated callers — `pub(crate)` unless
        the API surface calls for `pub`
      - Error handling: `thiserror` enums in library code, `anyhow` with `.context(...)`
        at binary boundaries, propagation via `?`
      - Construction: explicit constructor injection — a type takes its collaborators as
        `new` parameters
      - Logging: `tracing`, structured fields, `#[instrument]` on meaningful operations
      - Documentation: `///` on public items, with `# Errors` on fallible functions and
        `# Panics` where applicable

   c. **Enforce Safeguards**:
      - Invariants enforced at construction rather than checked at use
      - **Exact error messages** (do not modify)
      - No `unwrap`/`expect`/`panic!`/`todo!`/`unimplemented!` on any non-test path
      - Checked arithmetic and indexing on untrusted input where the lint config demands
        it
      - `Send`/`Sync` bounds where specified; no lock held across an `.await` unless
        explicitly sanctioned
      - No `unsafe` unless the prompt justifies it, with a `# Safety` comment

   d. **Generate the code**:
      - Place the file at the module path Structure specifies
      - **Add the `mod` declaration to the parent module** — a new file that nothing
        declares is silently not compiled
      - Include all required `use` statements
      - Implement exact signatures as specified
      - Follow the exact error messages from Safeguards

   **IMPORTANT**:
   - Do NOT deviate from the specifications in Operations
   - Do NOT add features or methods not specified
   - Do NOT change error messages from Safeguards
   - Do NOT silence a compiler or clippy complaint with `#[allow]` to make it build — fix
     the cause, or report it as a prompt defect
   - DO reference existing project patterns for consistency

6. **Batch validation after generation**

   After ALL code is generated, perform unified validation:

   a. **Build and lint gate** — run these in order and fix what they report:
      - `cargo fmt --all` — formatting is not a matter of taste
      - `cargo check --all-targets` — resolve every type and borrow error
      - `cargo clippy --all-targets --all-features -- -D warnings` — clippy findings are
        defects, not suggestions
      - `cargo test` — unit, integration and doc tests
      - `cargo build --no-default-features` if the crate has optional features, plus any
        feature combination Safeguards names
      - Prefer the project's own aggregate target (`just gate`, `make check`, a CI script)
        if one exists — it encodes gates these commands miss

   b. **Acceptance Criteria verification**:
      - Cross-check with the **Acceptance Criteria Traceability** table (if present)
      - Ensure each AC is addressed by the implementation
      - Verify error variants and messages match exactly

   c. **Structure verification**:
      - Verify layering is respected — no domain module importing infrastructure, no
        forbidden crate edge
      - Confirm collaborators are injected through constructors rather than constructed
        internally
      - Check trait implementations match those specified
      - Confirm every new file is reachable through a `mod` declaration

   d. **Fix any issues found**:
      - Fix compilation and borrow-checker errors at the cause, not by cloning to silence
        them
      - Correct `use` statements
      - If a fix requires deviating from the prompt, stop and report it as a prompt defect
        rather than diverging silently

7. **Report generation summary**

   Provide a summary to the user:
   - List of created files with their responsibilities
   - Any deviations or assumptions made
   - Validation results (pass/fail for each check)

**Review & Iteration Loop**

If issues are discovered after generation (during testing or code review), follow the SPDD
principle:

> **"When reality diverges, fix the prompt first — then update the code."**

1. **Identify the issue**: What behavior is incorrect or missing?

2. **Trace to prompt section**: Which part of the prompt caused this?
   - Wrong requirement interpretation → Update **Requirements**
   - Missing entity/relationship → Update **Entities**
   - Flawed strategy → Update **Approach**
   - Incorrect component design → Update **Structure**
   - Wrong implementation detail → Update **Operations**
   - Missing standard → Update **Norms**
   - Missing constraint → Update **Safeguards**

3. **Update the prompt first**: Modify the relevant section in the prompt file

4. **Regenerate affected code**: Only regenerate the components affected by the prompt
   change

5. **Commit together**: Commit the updated prompt and code together to maintain
   traceability

**Example iteration**:

```text
Issue: "The Resolver port isn't object-safe, so Arc<dyn Resolver> won't compile"

1. Trace: Operations defines Resolver with a generic method, which makes it non-object-safe
2. Update prompt: Approach picks static dispatch, or Operations moves the generic to the
   trait's type parameters — decide in the prompt, not in the code
3. Regenerate: Only regenerate Resolver and its implementors
4. Commit: Commit prompt change + code change together
```

**Markdown Output Norms** (any prompt file this command updates is linted)

A prompt file you update is checked by the repository's markdown gate.
Every rule below is one that real generated output has actually tripped — these
are not style preferences recovered from a manual. **Emit a clean document on
the first write.** A document that has to be repaired after generation means the
next run reintroduces the same defect, and the repair becomes a permanent tax on
the workflow.

- **Wrap prose at 90 columns**, not 80. Tables, long URLs and fenced blocks are
  exempt — never contort a table to fit a width it is exempt from.
- **Every fenced block carries a language.** Use `text` for ASCII diagrams, directory
  trees and console output, and `mermaid` for diagrams. A bare ``` is a defect.
- **Headings never end in punctuation.** Write `### GROUP 6a — Positive chain` and put
  the qualifying sentence in the body, not in the heading.
- **Emphasis style**: use `*emphasis*` and `**strong**`, never the `_underscore_` forms.
- **A heading is a heading.** Never leave a standalone bold line standing in for one:
  if it introduces a section, give it a real `###` or `####` level. If it is an aside
  rather than a section, write it as ordinary prose instead of emphasising the whole
  line.
- **Consecutive blockquotes**: separate the paragraphs with a `>` line, not a blank
  line — a blank line reads as a gap *inside* one quote rather than a break between
  two.
- **One blank line between blocks**, never two or more.
- **Keep every table row adjacent to its table.** A blank line before a trailing row
  orphans it from the header that gives it meaning.

**Verify before you finish**: if the repository has a markdown linter configured
(`just md`, `rumdl`, `markdownlint`), run it against the file you just wrote and fix
what it reports. Do not hand the document to the gate to be rejected.

**Output**

- All generated source files following the project structure
- Summary of created files and their responsibilities
- Validation results
- Any issues requiring prompt modification

**Guardrails**

- Emitted markdown MUST satisfy the **Markdown Output Norms** above: wrapped at 90
  columns, every fence carrying a language, real headings rather than bold lines,
  and no trailing punctuation in a heading
- Do NOT generate code without first reading the entire prompt file
- Do NOT re-plan the Operations sequence — execute in the defined order
- Do NOT skip any operation defined in the Operations section
- Do NOT change method signatures, field names, or error messages from the specification
- Do NOT add extra public items, methods, or fields not specified
- Do NOT patch code directly when issues are found — update prompt first
- Do NOT add `#[allow(...)]`, `unwrap()`, `clone()` or `unsafe` to make something compile
  — each is a design answer and belongs in the prompt
- Do NOT add a dependency without recording it in the prompt's Structure section
- Always use the exact error messages from Safeguards
- Always follow Norms for coding style and patterns
- Always verify against Acceptance Criteria after generation
- Always run the full build/lint/test gate after batch generation and fix what it reports
- Always commit prompt and code changes together

**Integration with /spdd-analysis and /spdd-reasons-canvas**

This command is the third phase of the SPDD workflow:

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                           SPDD Workflow                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Phase 1: /spdd-analysis                                               │
│  ┌────────────────────────────────────────────────────────────────┐    │
│  │ Requirement → Alignment → Abstraction → Enriched Context       │    │
│  │                                                                 │    │
│  │ Output: Strategic context (business + domain + risks)          │    │
│  └────────────────────────────────────────────────────────────────┘    │
│                              │                                          │
│                              ▼                                          │
│  Phase 2: /spdd-reasons-canvas                                         │
│  ┌────────────────────────────────────────────────────────────────┐    │
│  │ Enriched Context → REASONS Canvas → Structured Prompt          │    │
│  │                                                                 │    │
│  │ Output: spdd/prompt/*.md (REASONS Canvas)                      │    │
│  └────────────────────────────────────────────────────────────────┘    │
│                              │                                          │
│                              ▼                                          │
│  Phase 3: /spdd-generate                                               │
│  ┌────────────────────────────────────────────────────────────────┐    │
│  │ Structured Prompt → Validate → Generate → Verify → Code        │    │
│  │                                                                 │    │
│  │ Output: Implementation code following Operations sequence       │    │
│  └────────────────────────────────────────────────────────────────┘    │
│                              │                                          │
│                              ▼                                          │
│  Phase 4: Review & Iteration                                            │
│  ┌────────────────────────────────────────────────────────────────┐    │
│  │ Issue Found → Update Prompt → Regenerate → Commit Together     │    │
│  │                                                                 │    │
│  │ Principle: "Fix prompt first, then update code"                │    │
│  └────────────────────────────────────────────────────────────────┘    │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

The structured prompt serves as the **contract** between design and implementation, and
must stay in sync with the code throughout the lifecycle.

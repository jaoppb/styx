---
name: /spdd-reasons-canvas
id: spdd-reasons-canvas
category: Development
description: Generate REASONS-Canvas structured prompts for Rust codebases from business context without external template
---

Generate implementation-ready structured prompts using the built-in REASONS-Canvas
framework (Requirements, Entities, Approach, Structure, Operations, Norms, Safeguards),
targeting **Rust** codebases and their conventions.

**Input**: Business context/requirement description after `/spdd-reasons-canvas`

Input can be provided in two ways:

1. **Text description**: Direct text describing the requirement
2. **File/folder reference**: Using `@` to reference files or folders containing
   requirements

**Examples**:

```text
# Text description
/spdd-reasons-canvas Implement a bounded work queue with backpressure and a drop counter

# File reference
/spdd-reasons-canvas @spdd/analysis/202609212118-[Analysis]-phase-04-answer-cache.md

# Combined (text + file reference)
/spdd-reasons-canvas @docs/requirements/cache.md additionally requires negative caching

# Multiple file references
/spdd-reasons-canvas @docs/requirements/cache.md @docs/rfc-notes.md
```

**Steps**

1. **Validate and consolidate business context**

   a. **If business context is missing**, use the **AskUserQuestion tool** (open-ended, no
   preset options) to ask:
   - "Please provide the business context or requirement description (you can use text,
     @file references, or both)"

   **IMPORTANT**: Do NOT proceed without business context input.

   b. **If input contains `@` file/folder references**:
   - Read ALL referenced files completely using the Read tool
   - For folder references, read all relevant files within the folder (`.md`, `.txt`,
     `.toml`, `.rs`, etc.)
   - Consolidate all file contents into a unified business context

   c. **Combine all context sources**:
   - Merge text descriptions with file contents
   - Preserve the complete information from all sources
   - Do NOT summarize or truncate - maintain full context integrity

   **Context Integrity Check**:
   - Verify all `@` references were successfully read
   - If any file cannot be read, report the error and ask user to provide alternative
   - Confirm the consolidated context contains sufficient information to proceed

2. **Read relevant Rust codebase context**

   - Read the workspace root `Cargo.toml` — workspace members, shared
     `[workspace.dependencies]`, `[workspace.lints]`, resolver version, `rust-version`
     (MSRV)
   - Read the `Cargo.toml` of each crate the requirement touches — its dependencies,
     `[features]`, and whether it is a lib, bin, or both
   - Locate the relevant modules by reading `lib.rs` / `main.rs` / `mod.rs` and following
     the `mod` tree
   - Read the existing traits (ports), domain types, and error enums in scope
   - Note the conventions actually in use: error crate (`thiserror` / `anyhow` /
     hand-rolled), async runtime, logging (`tracing` vs `log`), dispatch style (generics
     vs `Arc<dyn Trait>`), interior mutability choices, test layout
   - Read `clippy.toml`, `rustfmt.toml`, `deny.toml` and any `#![deny(...)]` /
     `#![warn(...)]` crate attributes — these are binding constraints on generated code
   - If the area is greenfield with no existing code, say so explicitly and derive
     conventions from the workspace manifests and lint configuration instead of guessing

3. **Apply the REASONS-Canvas Framework**

   Generate fully-populated content for each of the 7 stages using the built-in
   construction guidance:

   ***

   ### R - Requirements

   **Objective**: Extract core problem essence and fundamental goals

   **Output Format**:

   ```text
   ## Requirements
   [Use concise verb phrases to describe the essence of requirements]
   ```

   **Construction Guidance**:
   - **Essence Extraction**: Abstract what fundamental problem to solve and what value to
     create for whom
   - **Boundary Definition**: Clarify the applicable scope and limitations
   - **Value Focus**: Highlight business value and user benefits
   - **Use Verb Phrases**: "Implement...", "Create...", "Design..."
   - **Avoid Feature Stacking**: Don't list specific functions, abstract essential
     problems
   - **State non-goals**: What this explicitly does not do, and why — a non-goal prevents
     scope creep in the Operations phase

   **Quality Standards**:
   - Core requirements summarizable in one sentence
   - Reflect business value rather than technical implementation
   - Clear problem boundaries and constraints

   ***

   ### E - Entities

   **Objective**: Model the Rust type system for this requirement — structs, enums, and
   traits

   **Output Format**:

   ````text
   ## Entities
   ```mermaid
   classDiagram
   direction TB

   class CoreType {
       +FieldType field_name
       +method_name(param: ParamType) ReturnType
   }

   class SomeTrait {
       <<trait>>
       +required_method(param: ParamType) ReturnType
   }

   class StateEnum {
       <<enumeration>>
       VariantOne
       VariantTwo
   }

   class OperationError {
       <<enumeration>>
       NotFound
       Invalid
   }

   CoreType ..|> SomeTrait : implements
   CoreType "1" --> "0..*" RelatedType : owns
   CoreType --> OperationError : returns on failure
   ```
   ````

   **Construction Guidance**:
   - **Type identification**: Identify domain types (structs), closed sets of states
     (enums), and behavioural contracts (traits)
   - **Make invalid states unrepresentable**: Prefer an enum over a struct with mutually
     exclusive `Option` fields; prefer a newtype over a bare `String` or `u64` where a
     validated invariant exists
   - **Parse, don't validate**: Model validation as a fallible conversion producing a type
     that is correct by construction (`TryFrom`, a private constructor plus a
     `new() -> Result<Self, E>`), not as a check run against a permissive type
   - **Ownership and borrowing**: Note where a type owns its data versus borrows it, and
     where `Arc`/`Rc` shared ownership is deliberate. If a lifetime parameter is
     load-bearing, say what it ties to
   - **Traits are ports**: A trait in the `domain` layer is a seam an adapter implements.
     Mark trait classes with `<<trait>>` and use `..|>` for implementations
   - **Error types are entities**: Model the error enum explicitly. An operation's failure
     modes are part of its contract, not an afterthought
   - **Stereotypes**: use `<<trait>>`, `<<enumeration>>`, `<<newtype>>` so readers can
     tell a contract from a concrete type at a glance

   **Mermaid rendering constraints** (verify before shipping the diagram):
   - Mermaid's generic syntax is `~T~`, not `<T>`. `Vec~u8~` renders; `Vec<u8>` does not
   - **Nested generics mangle**: `Result~Vec~Rule~, Error~` renders incorrectly. Flatten
     to `ResultVecRule` or describe the signature in prose beneath the diagram
   - **The unit type inside a generic can drop the whole line**: `Result~(), Error~`
     collides with method-paren parsing. Write `Result~Unit, Error~` or omit the generic
     and state the real signature in Structure
   - Spell full signatures out in Structure and Operations; the diagram is a map, not the
     contract
   - If diagram fidelity matters, render it (`mmdc -i diagram.mmd -o out.svg`) and confirm
     every declared class appears in the output

   **Conservative Constraints** (CRITICAL):
   - **Prohibit unnecessary refactoring**: If an existing type meets the requirement, do
     not wrap it. A newtype must earn its place by enforcing an invariant
   - **Existing implementation priority**: If current types can satisfy the requirement,
     they stay unchanged
   - **Function-driven changes**: Only restructure when the requirement genuinely cannot
     be met through existing types
   - **Gradual improvement**: Extend existing types rather than rebuilding
   - **Semver awareness**: For a published crate, note whether a change to a public type
     is breaking

   **Quality Standards**:
   - Focus on current task flows
   - Clear and accurate type relationships
   - Maintain simplicity of existing implementations
   - Avoid over-abstraction: do not introduce a trait with exactly one implementation and
     no test double or planned second implementor

   ***

   ### A - Approach

   **Objective**: Provide high-level solution strategies and architectural approaches

   **Output Format**:

   ```text
   ## Approach
   1. [Solution Category]:
      - [High-level strategy description]
      - [Architecture pattern or approach]
      - [Key design decisions and rationale]

   2. [Technical Implementation]:
      - [Crate and module placement; which crate owns what]
      - [Dispatch strategy: generics/monomorphisation vs `dyn Trait` and why]
      - [Ownership and concurrency model: what is `Send`/`Sync`, what is shared, what is cloned]
      - [Error strategy: the error enum, its variants, and how it composes with callers]
      - [Performance and security considerations]

   3. [Business Logic]:
      - [Core business rules]
      - [Validation strategy and where invariants are enforced]
      - [Workflow and process design]
   ```

   **Construction Guidance**:
   - **Categorical Organization**: Organize by solution categories (API surface, data
     flow, error handling, concurrency)
   - **Architecture Decisions**: Provide key technical choices and the trade-off each one
     resolves
   - **Error strategy is architecture, not detail**: Decide and state whether this code
     returns a `thiserror` enum (library code, callers match on variants), propagates
     `anyhow::Error` with context (binary/top-level code), or both at a stated boundary.
     Decide what is a recoverable `Err` versus a genuine invariant violation
   - **Dispatch and ownership**: Static dispatch via generics costs compile time and code
     size but keeps calls inlinable; `Arc<dyn Trait>` costs a vtable hop but keeps types
     simple and enables runtime swapping. State which and why
   - **Concurrency**: If state is shared, state the mechanism (`Arc<Mutex<_>>`, `RwLock`,
     atomics, `ArcSwap`, channels) and what the contention profile is. If anything runs on
     a hot path, say what it must not do there (allocate, block, touch I/O)
   - **Async**: If async, state the runtime, whether futures must be cancellation-safe,
     and where `spawn`/`spawn_blocking` boundaries fall
   - **Best Practices**: Combine ecosystem idioms and experience summaries
   - **Decision Rationale**: Explain why specific solutions were chosen
   - **Risk Assessment**: Identify potential risks and response strategies

   **Quality Standards**:
   - Solutions have operability
   - Cover key technical decisions
   - Reflect architectural thinking

   ***

   ### S - Structure

   **Objective**: Define crate/module architecture and dependency relationships

   **Output Format**:

   ```text
   ## Structure

   ### Crate and Module Layout
   1. `crate-name/src/domain/` — [pure types, traits as ports, no I/O]
   2. `crate-name/src/application/` — [use cases orchestrating domain types]
   3. `crate-name/src/infrastructure/` — [adapters implementing domain ports]
   4. New modules to create, with their `mod` declarations and visibility

   ### Trait Implementations
   1. `ConcreteAdapter` implements `SomePort` — [what contract it satisfies]
   2. `DomainType` derives `Debug, Clone, PartialEq` — [and why each is needed]
   3. `OperationError` implements `std::error::Error` via `thiserror::Error`
   4. Blanket or generic impls, with their bounds

   ### Dependencies
   1. `ComponentA` calls `ComponentB` through trait `PortX`
   2. `UseCase` holds `Arc<dyn Repository>` and `Arc<dyn Clock>`
   3. Crate-level: which crates this one depends on, and which must NOT depend on it
   4. New third-party crates required, with justification and feature flags

   ### Layering Rules
   1. Domain layer: no I/O, no async runtime, no infrastructure imports
   2. Application layer: depends on domain only, orchestrates ports
   3. Infrastructure layer: implements domain ports, owns all I/O
   4. Binary/wiring layer: constructs concrete types and injects them
   5. Feature gates: what is conditionally compiled and what must still build with `--no-default-features`
   ```

   **Construction Guidance**:
   - **Module tree**: Give the real paths. A new module needs its `mod` declaration in the
     parent and a stated visibility (`pub`, `pub(crate)`, private)
   - **Visibility is design**: Default to the narrowest that works. `pub(crate)` for
     cross-module internals, `pub` only for the crate's intended API surface
   - **Dependency direction**: Inner layers must not know about outer ones. Dependency
     inversion is expressed as a trait defined in the consumer's layer and implemented
     outside it
   - **Derives are contracts**: `Clone` on a large type invites copies; `PartialEq` on a
     float-bearing type is a trap; `Default` can manufacture an invalid instance. Justify
     each derive
   - **Crate boundaries**: State which crate owns the type. Moving a type across a crate
     boundary later is a breaking change for downstream users
   - **Extension points**: Traits and feature flags that accommodate future work without
     restructuring

   **Quality Standards**:
   - Clear architectural hierarchy
   - Dependency direction is explicitly stated and acyclic
   - Support system extension

   ***

   ### O - Operations

   **Objective**: Transform abstract solutions into specific executable implementation
   tasks

   **Output Format**:

   ```text
   ## Operations

   ### Create/Update Type - `TypeName`
   1. Location: `crate-name/src/domain/module.rs`
   2. Responsibility: [Clear responsibility description]
   3. Definition: struct | enum | newtype, and its visibility
   4. Fields:
      - `field_name`: `FieldType` - [Description, and the invariant it carries]
   5. Derives: `Debug, Clone, PartialEq` - [why each]
   6. Methods:
      - `method_name(&self, param: ParamType) -> Result<ReturnType, ErrorType>`
        - Logic:
          - [Step-by-step implementation logic]
          - [Conditional logic and edge cases]
          - [Which error variant each failure path returns]
   7. Invariants: [What must always hold; where it is enforced]

   ### Define Trait - `PortName`
   1. Location: `crate-name/src/domain/ports.rs`
   2. Contract: [What the trait promises to callers]
   3. Required methods, with exact signatures and their `Result` types
   4. Bounds: `Send + Sync + 'static` - [why, or why not needed]
   5. Async: [whether methods are async, and any cancellation-safety requirement]
   6. Implementors: [which concrete types, in which layer, plus the test double]

   ### Implement Adapter - `AdapterName`
   1. Location: `crate-name/src/infrastructure/module.rs`
   2. Implements: `PortName`
   3. Construction: `new(deps) -> Self` or `try_new(deps) -> Result<Self, InitError>`
   4. Held state and its ownership/sharing strategy
   5. Per method: input handling, the real work, error mapping into the port's error type
   6. Resource handling: what it opens, and how `Drop` or explicit shutdown releases it

   ### Define Error Type - `OperationError`
   1. Location: [alongside the operations that return it]
   2. Derive: `thiserror::Error, Debug`
   3. Variants:
      - `VariantName { field: Type }` - `#[error("message")]` - [when returned]
   4. Source chaining: which variants carry `#[from]` or `#[source]`
   5. Boundary: whether callers match on variants (library) or add context and bubble (binary)

   ### Wire Into Composition Root
   1. Location: `src/main.rs` or the crate's builder
   2. Construction order and what each concrete type is injected as
   3. Configuration read and validated before construction
   4. Shutdown/teardown ordering

   ### Tests
   1. Unit tests: `#[cfg(test)] mod tests` beside the code, covering [specific cases]
   2. Integration tests: `tests/name.rs`, exercising the public API, covering [specific cases]
   3. Test doubles: [fakes implementing the ports; prefer hand-written fakes over mocks where behaviour matters]
   4. Property/fuzz targets, if the input is adversarial or the invariant is universal
   5. Each named test states the behaviour it pins, not just the function it calls
   ```

   **Construction Guidance**:
   - **Based on First Four Stages**: Strictly based on complete context of R, E, A, S
   - **Task Classification**: Group by module or component type
   - **Execution Order**: Order by dependency — types with no dependencies first (errors,
     newtypes, enums), then traits, then implementors, then wiring, then tests
   - **Exact signatures**: Give the real signature including `&self`/`&mut self`/`self`,
     borrows, and the full `Result` type. Ambiguity here is what produces code that does
     not compile
   - **Error paths are logic**: For each fallible step, name the error variant returned.
     "Handle errors appropriately" is not an instruction
   - **Single Responsibility**: Each task has clear responsibilities and boundaries
   - **Verifiability**: Each task has clear completion criteria
   - **Logical Rigor**: Ensure task orchestration is based on the type model, avoiding
     gaps

   **Quality Standards**:
   - Tasks can be executed directly
   - Cover complete implementation including wiring and tests
   - Accurate and specific details

   ***

   ### N - Norms

   **Objective**: Define unified Rust coding standards and common implementation patterns

   **Output Format**:

   ```text
   ## Norms
   1. Naming: `snake_case` for functions/modules/fields, `UpperCamelCase` for types/traits/variants,
      `SCREAMING_SNAKE_CASE` for consts. Avoid stutter (`cache::CacheEntry` → `cache::Entry`).
      Getters are `fn field()`, not `fn get_field()`. Conversions follow `as_`/`to_`/`into_` cost conventions.
   2. Error handling:
      - Library code: a `thiserror` enum per fallible boundary; variants carry the data a caller needs to act
      - Binary/top-level code: `anyhow::Result` with `.context(...)` at each layer crossing
      - Propagate with `?`; never swallow an error into a log line and return `Ok`
      - Error messages are lowercase, no trailing punctuation, and describe what failed
   3. Panics: no `unwrap()`/`expect()` in non-test code. Where a panic is genuinely correct
      (a violated internal invariant), use `expect("reason the invariant holds")` and document it
      under a `# Panics` heading. Indexing and arithmetic on untrusted input must be checked.
   4. Dependency construction: explicit constructor injection. A type takes its collaborators as
      parameters to `new`; it does not reach for globals or construct its own adapters.
   5. Logging: `tracing` — `#[instrument]` on meaningful operations, structured fields rather than
      formatted strings, `error!` only where the error is handled and not propagated.
   6. Documentation: `///` on every public item; `# Errors` for fallible functions, `# Panics`
      where applicable, `# Safety` for every `unsafe fn`. Doc examples compile and run under `cargo test`.
   7. Testing: unit tests in `#[cfg(test)] mod tests` beside the code; integration tests in `tests/`
      exercising only the public API. Test names state the behaviour. Time, randomness and I/O are
      injected, never ambient.
   8. Formatting and lints: `cargo fmt` is authoritative; `cargo clippy --all-targets -- -D warnings`
      must pass. Lints are configured in `[workspace.lints]` or crate-level attributes, not suppressed
      ad hoc — an `#[allow]` carries a comment giving the reason.
   9. Unsafe: forbidden unless justified in writing, isolated to the smallest possible module,
      and covered by a `# Safety` comment stating the invariant the caller must uphold.
   10. API surface: public items are deliberate. Prefer `pub(crate)` until an external caller exists.
   ```

   **Construction Guidance**:
   - **Standardization**: Define unified coding standards, derived from what the codebase
     already does
   - **Reusability**: Extract reusable patterns already present in the project
   - **Consistency**: Ensure all components follow the same standards
   - **Quality Assurance**: Prefer mechanisms the compiler or clippy can enforce over
     conventions a reviewer must remember
   - **Best Practices**: Reflect ecosystem idioms — but where the project's existing
     convention differs, the project wins

   **Quality Standards**:
   - Clear and specific standards
   - Easy to execute and check
   - Enforceable by tooling wherever possible

   ***

   ### S - Safeguards

   **Objective**: Define clear boundary conditions and quality standards

   **Output Format**:

   ```text
   ## Safeguards
   1. Functional Constraints: [Functional requirements and limitations with specific criteria]
   2. Type-Level Constraints: [Invariants the type system must enforce rather than runtime checks;
      which states must be unrepresentable]
   3. Error Handling Constraints:
      - Every fallible operation returns `Result`; no error is silently discarded
      - Error variants are specific enough for callers to branch on
      - No `unwrap`/`expect`/`panic!`/`todo!`/`unimplemented!` on any non-test path
      - Error messages expose no secrets, credentials, or internal paths
   4. Memory and Ownership Constraints: [Allocation limits, clone avoidance on hot paths,
      bounded buffers and what happens at the bound, `Send`/`Sync` requirements]
   5. Concurrency Constraints: [What may block, what must not; lock ordering; whether a lock may be
      held across an `.await`; cancellation safety requirements]
   6. Performance Constraints: [Measurable targets — latency, throughput, memory ceiling — and how
      each is measured]
   7. Security Constraints: [Input validation at trust boundaries, arithmetic overflow handling,
      no `unsafe` without written justification, dependency audit requirements]
   8. Compatibility Constraints: [MSRV, semver impact of public API changes, feature-flag
      combinations that must build, target platforms]
   9. Build and Lint Constraints: [`cargo fmt --check`, `cargo clippy -- -D warnings`,
      `cargo test`, `--no-default-features` build, plus any project-specific gate]
   10. Test Constraints: [What must be proven before this is considered done, expressed as
       assertions rather than aspirations]
   ```

   **Construction Guidance**:
   - **Clear Boundaries**: Clearly define what can and cannot be done
   - **Verifiability**: Each constraint should be checkable by a test, a lint, or a build
     command — name the check
   - **Completeness**: Cover functionality, types, errors, memory, concurrency,
     performance, security, compatibility
   - **Prefer compile-time to runtime**: A constraint the type system enforces cannot
     regress; a constraint a comment states can
   - **Quantified Standards**: Provide quantifiable standards and metrics whenever
     possible
   - **Exit criteria**: If the source requirement states acceptance or exit criteria,
     reproduce them verbatim here

   **Quality Standards**:
   - Clear constraint conditions
   - Verifiable
   - Complete coverage

4. **Construct the final structured prompt**

   Create a comprehensive, ready-to-implement prompt with:

   a. **Header Section**:

   ```text
   # [Derived Requirement Title]
   ```

   b. **All 7 REASONS Sections - Fully Populated**:
   - `## Requirements` - Fully populated
   - `## Entities` - With Mermaid class diagram
   - `## Approach` - With solution strategies
   - `## Structure` - With crate/module architecture
   - `## Operations` - With specific implementation tasks
   - `## Norms` - With Rust coding standards
   - `## Safeguards` - With constraints

   **DO NOT include**:
   - Business Context section (the original requirement text)
   - Framework metadata (Objective, Construction Guidance, Quality Standards)
   - Generation timestamp or framework name

   **ONLY include**: The structured content generated by analyzing the business context.

   c. **Implementation readiness**:
   - The final prompt should be immediately actionable
   - All sections should be fully populated with specific details
   - No placeholders or "TODO" items
   - Clear, executable implementation tasks in Operations section

5. **Save the fully-populated structured prompt to file**

   a. **Derive file name**: `{TIMESTAMP}-[{ACTION}]-{scope}-{description}.md`
   - **TIMESTAMP**: `YYYYMMDDHHmm` (current time)
   - **ACTION**: Infer from business context - `[Feat]`, `[Fix]`, `[Refactor]`, `[Perf]`,
     `[Test]`, `[Docs]`
   - **scope**: The crate or module the work lands in - e.g. `proto`, `domain`, `infra`,
     `cli`, `db`, `codec` (optional)
   - **description**: Derive from business context - kebab-case, < 10 words

   Examples:
   - `202603061530-[Feat]-codec-message-compression-pointers.md`
   - `202603061530-[Fix]-db-connection-pool-exhaustion.md`

   b. **Create directory and write file**:
   - Ensure directory `spdd/prompt/` exists under the project root (create if not)
   - Write the complete, fully-populated structured prompt to `spdd/prompt/<file-name>.md`

   c. **Show summary to user**:

   ```text
   ✅ REASONS-Canvas prompt generated and saved to `spdd/prompt/<file-name>.md`

   📋 Generated sections:
   - Requirements: [1-line summary]
   - Entities: [type count] types/traits with relationships
   - Approach: [main approach summary]
   - Structure: [crate/module layout]
   - Operations: [task count] implementation tasks
   - Norms: [key standards]
   - Safeguards: [constraint count] constraints defined
   ```

6. **Ask for confirmation to proceed**

   > "The REASONS-Canvas structured prompt is ready. Would you like me to proceed with the
   > implementation?"

**Markdown Output Norms** (the structured prompt this command writes is linted)

The structured prompt is checked by the repository's markdown gate.
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

A fully-populated, implementation-ready REASONS-Canvas structured prompt saved to
`spdd/prompt/<file-name>.md`, then implementation upon user confirmation.

**Guardrails**

- Emitted markdown MUST satisfy the **Markdown Output Norms** above: wrapped at 90
  columns, every fence carrying a language, real headings rather than bold lines,
  and no trailing punctuation in a heading
- **CRITICAL**: Do NOT just output section headers - you MUST analyze business context and
  generate fully-populated content for all 7 REASONS stages
- Do NOT proceed without business context input
- Do NOT include framework metadata (Objective, Construction Guidance, Quality Standards)
  in the final prompt
- Do NOT leave placeholders or TODO items - generate complete, specific content
- Do NOT implement code before user confirms the structured prompt
- File name MUST follow SPDD naming convention defined above
- Always create `spdd/prompt/` directory if it does not exist
- Read codebase context when needed to generate accurate type models and implementation
  tasks
- Ensure all sections are logically coherent and support the business requirement
- Operations section MUST contain specific, executable implementation tasks with exact
  Rust signatures and error paths
- **Conservative type design**: Respect existing types, avoid unnecessary newtypes and
  traits
- **No code blocks**: the prompt is a specification. Describe signatures and logic in
  prose; do not write ```rust blocks. Mermaid diagrams are permitted
- Never specify a type or trait from a crate that is not already a dependency without
  adding it explicitly to Structure with justification

**Context Integrity Guardrails**:

- **MUST read ALL `@` referenced files completely** - do NOT skip or partially read any
  referenced file
- **MUST read folder contents** when `@` references a folder - scan and read all relevant
  files
- **Do NOT summarize or truncate** referenced file contents - preserve full information
- **Verify all references resolved** - if any `@` reference fails to read, report error
  immediately
- **Combine all sources** - merge text descriptions with file contents into unified
  context
- **Preserve original intent** - do not interpret or modify the meaning of provided
  context

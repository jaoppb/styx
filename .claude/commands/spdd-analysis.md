---
name: /spdd-analysis
id: spdd-analysis
category: Development
description: Analyze business requirements against a Rust codebase at a strategic level, producing enriched context (business + domain concepts + strategic direction + risks) for REASONS Canvas generation
---

Analyze a business requirement document against the current **Rust** codebase, producing a
**strategic-level** enriched context that combines business information, domain concept
identification, high-level approach decisions, and risk analysis — serving as high-quality
input for `/spdd-reasons-canvas`. This phase focuses on the "What" and "Why", leaving the
"How" to the REASONS Canvas phase.

**Input**: The argument after `/spdd-analysis` is a business requirement description or
file reference.

Input can be provided in two ways:

1. **Text description**: Direct text describing the requirement
2. **File/folder reference**: Using `@` to reference files or folders containing
   requirements

**Examples**:

```text
# File reference
/spdd-analysis @requirements/token-usage-billing-story.md

# Text description
/spdd-analysis Implement monthly billing summary report for customers with usage breakdown

# Combined
/spdd-analysis @requirements/billing-report.md additionally needs CSV export support
```

**Steps**

1. **Validate and consolidate business input**

   a. **If no input provided**, use the **AskUserQuestion tool** (open-ended, no preset
   options) to ask:
   > "Please provide the business requirement document or description (you can use text,
   > @file references, or both)."

   **IMPORTANT**: Do NOT proceed without business input.

   b. **If input contains `@` file/folder references**:
    - Read ALL referenced files completely using the Read tool
    - For folder references, read all relevant files within the folder
    - Consolidate all file contents into a unified business context

   c. **Combine all context sources**:
    - Merge text descriptions with file contents
    - Preserve the complete information from all sources — do NOT summarize or truncate

   d. **Context Integrity Check**:
    - Verify all `@` references were successfully read
    - If any file cannot be read, report the error and ask user to provide alternative
    - Confirm the consolidated context contains sufficient information to proceed

2. **Concept-driven codebase exploration**

   Do NOT exhaustively read the entire codebase — this does not scale. Instead, use a
   **concept-driven** approach: first build a lightweight project fingerprint, then
   extract search concepts from the business requirement, and finally explore only the
   relevant parts of the codebase in depth.

   a. **Project fingerprint (lightweight bootstrap — always do first)**:
    - Read the **workspace root `Cargo.toml`** to detect workspace members, shared
      `[workspace.dependencies]`, `[workspace.lints]`, edition, and `rust-version` (MSRV)
    - List the crate directories and each crate's `src/` top level (names only, not file
      contents) to understand the layout and layering conventions
    - Read the lint and tooling configuration that constrains any generated code —
      `clippy.toml`, `rustfmt.toml`, `deny.toml`, and crate-level `#![deny(...)]` /
      `#![warn(...)]` attributes
    - This step should be fast and touch only 2–4 files

   b. **Extract search concepts from business input**: Before touching any domain code,
   analyze the business requirement from Step 1 to extract:
    - **Domain nouns**: concept names that likely map to structs, enums, or modules (e.g.,
      "cache entry", "upstream", "delegation", "rule set")
    - **Action verbs**: operations that likely map to methods or trait contracts (e.g.,
      "resolve", "evict", "reload")
    - **Surfaces**: explicit public API, CLI subcommands, wire formats, or channel/task
      names mentioned
    - **Technical hints**: mentioned crates, patterns, or domain-specific terms (e.g.,
      "bounded channel", "TTL", "backpressure")

   These extracted concepts become the **search scope** for all subsequent exploration.

   c. **Targeted type and data-model exploration (scoped by concepts)**:
    - Search for `struct`, `enum`, `trait`, and `type` declarations whose names match the
      extracted domain nouns — do NOT read every module
    - Read ONLY the matched definitions, plus the error enums the matched code returns
    - Follow type relationships **one hop outward**: if a matched struct holds another
      domain type or a `dyn Port`, read that definition too
    - If the project persists data, search migrations or schema files for the same concept
      names and read only the matched ones

   d. **Targeted code exploration (scoped by concepts)**:
    - Search module paths and type names for matches against the extracted concepts
    - Read matched files to understand existing logic, invariant enforcement, and error
      handling
    - Follow direct dependencies **one hop** (e.g., if a use case holds
      `Arc<dyn Repository>`, read that trait — but don't keep chaining)
    - From the matched files, observe the conventions actually in use: module layering,
      error crate (`thiserror` / `anyhow` / hand-rolled), dispatch style (generics vs
      `dyn Trait`), interior mutability and sharing choices, async runtime, logging
      (`tracing` vs `log`), and test layout
    - If no matching code exists (greenfield area), note this explicitly and derive
      conventions from the workspace manifests and lint configuration instead of guessing

   e. **Relevant SPDD context (scoped by concepts)**:
    - List files in `spdd/prompt/` and `spdd/analysis/` (if the directories exist)
    - Read ONLY those files whose filenames suggest relevance to the extracted concepts
    - If none are relevant or the directories are absent, skip this step

   f. **Controlled expansion (one additional hop only)**:
    - If during steps 2c–2e you discover a concept that is clearly essential to the
      requirement but was NOT in the initial extraction (e.g., an unexpected foreign key,
      a shared utility), add it to the concept list and do **one more** targeted search
      for it
    - Do NOT recursively expand beyond this single additional hop — stop and note the
      boundary

   **IMPORTANT**: Be targeted — explore deeply within the relevant scope, not broadly
   across the entire codebase. Read actual file contents for the scoped concepts; do not
   guess. If the scope turns out to be very large (e.g., the requirement touches 10+
   existing modules), explicitly list all identified concepts and prioritize the core
   ones, noting the peripheral ones as "boundary context" to be verified during REASONS
   Canvas.

3. **Domain Concept Identification**

   Identify the business concepts involved at a **conceptual level** — do NOT drill into
   specific attributes, data types, method signatures, or DTOs. The goal is to understand
   the domain landscape, not to design the implementation.

   a. **Concept inventory**:
    - What core business concepts does this requirement involve?
    - Which already exist in the codebase (as structs, enums, traits, modules, or
      persisted tables)?
    - Which are new and need to be introduced?

   b. **Conceptual relationships**:
    - How do these concepts relate to each other at a business level?
    - What are the ownership and lifecycle boundaries?

   c. **Key business rules**:
    - What invariants must be maintained?
    - What business rules are explicit in the requirement?
    - What business rules are **implicit** and need to be surfaced?

   Output this section as:

   ```text
   ### Domain Concept Identification

   #### Existing Concepts (from codebase)
   - [ConceptName]: [business purpose] — [relationship to other concepts]

   #### New Concepts Required
   - [ConceptName]: [business purpose] — [how it relates to existing concepts]

   #### Key Business Rules
   - [Rule]: [which concepts it governs]
   ```

4. **Strategic Approach & Trade-offs**

   Determine the **high-level solution direction** — do NOT specify implementation details
   like specific queries, annotations, JSON shapes, method signatures, or step-by-step
   logic. Those belong in the REASONS Canvas phase.

   a. **Solution direction**:
    - What is the overall approach to solving this requirement?
    - Which existing architectural patterns and conventions should be leveraged?
    - Which crate and layer should own this work, and why that one?
    - What is the general data flow direction (e.g., "listener → domain use case → port →
      adapter")?

   b. **Key design decisions**:
    - What strategic choices need to be made?
    - What are the trade-offs for each choice?
    - What is the recommended direction and why?

   At this stage name the decision and its trade-off, not the signature. Rust choices
   worth settling here because they shape everything downstream:
    - **Ownership model**: who owns the data, what is borrowed, where shared ownership
      (`Arc`) is warranted
    - **Dispatch**: generics/monomorphisation versus `dyn Trait` — inlinable and rigid, or
      uniform and swappable
    - **Error strategy**: a `thiserror` enum callers match on, or `anyhow` context
      propagation, and where the boundary between them falls
    - **Concurrency and blocking**: what is shared, by what mechanism, and what must never
      block or allocate on a hot path
    - **Crate placement**: which crate owns the new types, and whether that creates a
      dependency edge that should not exist

   c. **Alternatives considered** (if applicable):
    - What other approaches were considered?
    - Why were they rejected?

   Output this section as:

   ```text
   ### Strategic Approach

   #### Solution Direction
   - [High-level description of approach]

   #### Key Design Decisions
   - [Decision]: [trade-offs] → [recommendation and rationale]

   #### Alternatives Considered
   - [Alternative]: [why rejected]
   ```

5. **Risk & Gap Analysis**

   Surface everything that could cause problems or needs clarification **before** detailed
   design begins in the REASONS Canvas phase.

   a. **Requirement ambiguities**:
    - What is unclear, underspecified, or open to interpretation in the requirement?
    - What implicit assumptions has the requirement made?

   b. **Edge cases**:
    - What scenarios are not explicitly addressed by the requirement or ACs?
    - What boundary conditions need clarification?

   c. **Technical risks**:
    - What technical challenges or constraints could impact the implementation?
    - Are there concurrency, performance, or data integrity concerns?
    - Rust-specific risks worth surfacing before design: ownership or lifetime friction
      that would force an `Arc`/`clone` the design did not intend; a lock held across an
      `.await`; a trait that cannot be made object-safe if `dyn` dispatch is later needed;
      `Send`/`Sync` bounds that do not hold for a chosen dependency; a public API change
      that breaks semver; an MSRV or feature-flag combination that would stop building;
      arithmetic or indexing on untrusted input under deny-level lints; and any `unsafe`
      the approach would require

   d. **Acceptance Criteria coverage**:
    - Are all ACs addressable with the proposed approach?
    - Are there gaps between the ACs and the full scope of the requirement?

   Output this section as:

   ```text
   ### Risk & Gap Analysis

   #### Requirement Ambiguities
   - [Ambiguity]: [what needs clarification]

   #### Edge Cases
   - [Scenario]: [why it matters]

   #### Technical Risks
   - [Risk]: [potential impact and mitigation direction]

   #### Acceptance Criteria Coverage
   | AC# | Description | Addressable? | Gaps/Notes |
   |-----|-------------|--------------|------------|
   | [n] | [AC text]   | Yes/Partial  | [any gaps]  |
   ```

6. **Assemble the enriched context document**

   Combine all analysis results into a single, structured document:

   ```markdown
   # SPDD Analysis: [Derived Title]

   ## Original Business Requirement
   [Complete original requirement text — unmodified]

   ## Domain Concept Identification
   [Output from Step 3]

   ## Strategic Approach
   [Output from Step 4]

   ## Risk & Gap Analysis
   [Output from Step 5]
   ```

   **NOTE**: The codebase exploration from Step 2 is a **working process** — its findings
   are internalized and reflected through the Domain Concept Identification (which
   references existing vs. new concepts), Strategic Approach (which references existing
   patterns and conventions), and Risk & Gap Analysis (which surfaces technical
   constraints). Do NOT output a separate "Codebase Context Summary" section.

   **IMPORTANT**:
    - The original business requirement MUST be included verbatim — do NOT paraphrase
    - Every section must contain concrete, specific content — no placeholders
    - All analysis must be grounded in actual codebase exploration, not assumptions
    - Stay at a **conceptual/strategic** level — do NOT include implementation details
      (specific queries, JSON shapes, method signatures, annotations, component
      inventories). Those belong in the REASONS Canvas phase.

7. **Save the enriched context document**

   a. **Derive file name**: `{TIMESTAMP}-[Analysis]-{description}.md`
    - **TIMESTAMP**: `YYYYMMDDHHmm` (current time)
    - **description**: Derive from business context — kebab-case, < 10 words

   Examples:
    - `202603131530-[Analysis]-token-usage-billing.md`
    - `202603131530-[Analysis]-monthly-report-export.md`

   b. **Create directory and write file**:
    - Ensure directory `spdd/analysis/` exists under the project root (create if not)
    - Write the complete enriched context document to `spdd/analysis/<file-name>.md`

   c. **Show summary to user**:

   ```text
   ✅ Analysis complete. Enriched context saved to `spdd/analysis/<file-name>.md`

   📋 Analysis summary:
   - Crates touched: [crate names, and the layer within each]
   - Existing concepts identified: [count]
   - New concepts required: [count]
   - Key design decisions: [count]
   - Acceptance Criteria coverage: [count]/[total]
   - Open questions/risks: [count]

   🔗 Next step: Use this as input for REASONS Canvas generation:
      /spdd-reasons-canvas @spdd/analysis/<file-name>.md
   ```

8. **Offer to proceed with REASONS Canvas generation**

   > "The enriched context is ready. Would you like me to proceed with
   > `/spdd-reasons-canvas` using this analysis as input?"

   If the user confirms, invoke the `/spdd-reasons-canvas` workflow with the saved
   analysis file as input.

**Markdown Output Norms** (the analysis document this command writes is linted)

The analysis document is checked by the repository's markdown gate.
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

An enriched context document saved to `spdd/analysis/<file-name>.md` that transforms raw
business requirements into a **strategic-level** analysis containing:

- Original business requirements (preserved verbatim)
- Domain concept identification (existing and new concepts, conceptual relationships,
  business rules — grounded in codebase exploration)
- Strategic approach (solution direction, key design decisions, trade-offs, alternatives
  considered)
- Risk & gap analysis (ambiguities, edge cases, technical risks, AC coverage assessment)

**Guardrails**

- Emitted markdown MUST satisfy the **Markdown Output Norms** above: wrapped at 90
  columns, every fence carrying a language, real headings rather than bold lines,
  and no trailing punctuation in a heading
- Do NOT proceed without business requirement input
- Do NOT skip codebase exploration — analysis MUST be grounded in actual codebase state
- Do NOT exhaustively read the entire codebase — use concept-driven scoping from the
  business requirement to target only relevant areas
- Do NOT summarize or truncate the original business requirement — preserve it verbatim
- Do NOT make assumptions about codebase structure without reading actual files
- Do NOT assume conventions the codebase does not use — read the manifests and lint config
  first, and where the project's convention differs from ecosystem default, the project
  wins
- Do NOT generate code — this command produces analysis only
- Do NOT include implementation-level details (exact signatures, field lists, derive sets,
  error-variant enumerations, module inventories, step-by-step logic) — those belong in
  `/spdd-reasons-canvas`
- Do NOT leave placeholders or TODO items — generate complete, specific content
- Do NOT modify any existing files in the codebase
- Always read ALL `@` referenced files completely
- Always create `spdd/analysis/` directory if it does not exist
- File name MUST follow the naming convention defined above
- Acceptance Criteria coverage MUST assess every AC from the requirement
- Risk & Gap Analysis MUST surface any ambiguities — do NOT silently assume

**Context Integrity Guardrails**:

- **MUST read ALL `@` referenced files completely** — do NOT skip or partially read any
  referenced file
- **MUST read folder contents** when `@` references a folder — scan and read all relevant
  files
- **Do NOT summarize or truncate** referenced file contents — preserve full information
- **Verify all references resolved** — if any `@` reference fails to read, report error
  immediately
- **Combine all sources** — merge text descriptions with file contents into unified
  context
- **Preserve original intent** — do not interpret or modify the meaning of provided
  context

**Integration with SPDD Workflow**

This command is the **pre-processing phase** of the SPDD workflow, bridging raw business
requirements to implementation-ready structured prompts:

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                           SPDD Workflow                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Phase 0: /spdd-analysis                                                │
│  ┌────────────────────────────────────────────────────────────────┐    │
│  │ Business Requirement                                            │    │
│  │   + Concept-driven Codebase Exploration (targeted, not full)    │    │
│  │   + Domain Concept Identification (conceptual, not detailed)    │    │
│  │   + Strategic Approach & Trade-offs (direction, not specifics)  │    │
│  │   + Risk & Gap Analysis (ambiguities, edge cases, risks)        │    │
│  │   = Enriched Context (Business + Strategic + Risks)             │    │
│  │                                                                 │    │
│  │ Output: spdd/analysis/*-[Analysis]-*.md                         │    │
│  └────────────────────────────────────────────────────────────────┘    │
│                              │                                          │
│                              ▼                                          │
│  Phase 1: /spdd-reasons-canvas                                         │
│  ┌────────────────────────────────────────────────────────────────┐    │
│  │ Enriched Context → REASONS Canvas Structured Prompt             │    │
│  │                                                                 │    │
│  │ Output: spdd/prompt/*.md (REASONS Canvas)                      │    │
│  └────────────────────────────────────────────────────────────────┘    │
│                              │                                          │
│                              ▼                                          │
│  Phase 2: /spdd-generate                                               │
│  ┌────────────────────────────────────────────────────────────────┐    │
│  │ Structured Prompt → Validate → Generate → Verify → Code        │    │
│  │                                                                 │    │
│  │ Output: Implementation code following Operations sequence       │    │
│  └────────────────────────────────────────────────────────────────┘    │
│                              │                                          │
│                              ▼                                          │
│  Phase 3: /spdd-sync                                                   │
│  ┌────────────────────────────────────────────────────────────────┐    │
│  │ Code Changes → Analyze → Update Prompt → Consistency           │    │
│  └────────────────────────────────────────────────────────────────┘    │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

**Why This Phase Matters**

Raw business requirements describe **what** to build but lack the technical context needed
to produce high-quality REASONS Canvas prompts. `/spdd-analysis` bridges this gap by:

1. **Grounding in reality**: Analysis is based on actual codebase state, explored through
   concept-driven scoping rather than exhaustive reading
2. **Surfacing hidden complexity**: Business rules, edge cases, and ambiguities that are
   implicit in the requirement become explicit
3. **Setting strategic direction**: Key design decisions and trade-offs are resolved
   before detailed design begins
4. **Reducing hallucination risk**: By feeding `/spdd-reasons-canvas` enriched context
   with real codebase data, the generated REASONS Canvas is more accurate and
   implementable
5. **Identifying risks early**: Open questions and ambiguities are surfaced before design,
   not during implementation

**Separation of Concerns with REASONS Canvas**:

| Concern | `/spdd-analysis` (this phase) | `/spdd-reasons-canvas` (next phase) |
|---------|-------------------------------|--------------------------------------|
| Thinking level | Strategic — "What" & "Why" | Tactical — "How" |
| Domain | Conceptual identification | Concrete struct/enum/trait modeling (E) |
| Solution | Direction & trade-offs | Crate and module architecture (A, S) |
| Ownership & dispatch | Named as a decision with its trade-off | Settled per type and signature |
| Errors | "This boundary is fallible, and why" | The error enum, its variants and mapping |
| Implementation | Out of scope | Specific operations & tasks (O) |
| Standards | Out of scope | Rust coding norms & safeguards (N, S) |
| Risks | Identify & surface | Resolve via constraints |

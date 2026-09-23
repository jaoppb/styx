---
name: /spdd-prompt-update
id: spdd-prompt-update
category: Development
description: Update an existing Rust SPDD prompt file with new requirements or architectural changes while preserving the REASONS Canvas structure
---

Update an existing SPDD (Structured Prompt-Driven Development) prompt file for a Rust
codebase with new requirements, architectural changes, or refinements while maintaining
the REASONS Canvas structure and following all specification rules.

**Input**: The argument after `/spdd-prompt-update` includes the prompt file reference and
the update instructions.

**Examples**:

```text
# Update with architectural principles
/spdd-prompt-update @spdd/prompt/202603131758-[Feat]-cache-answer-cache.md
Invert the storage dependency behind a trait defined in the domain layer

# Update with new requirements
/spdd-prompt-update @spdd/prompt/202603131758-[Feat]-cache-answer-cache.md
Add negative caching with a separate TTL policy

# Update specific section
/spdd-prompt-update @spdd/prompt/202603131758-[Feat]-cache-answer-cache.md
Update Safeguards to add a memory ceiling and an eviction guarantee
```

**Steps**

1. **Validate input**

   a. **If no prompt file provided**, use the **AskUserQuestion tool** to ask:
   > "Please provide the path to the SPDD prompt file to update (e.g.,
   > `@spdd/prompt/xxx.md`)"

   b. **If no update instructions provided**, use the **AskUserQuestion tool** to ask:
   > "What changes would you like to make to this prompt? (e.g., new requirements,
   > architectural changes, constraint updates)"

   **IMPORTANT**: Do NOT proceed without both the file path and update instructions.

2. **Read and analyze the existing prompt**

   a. Read the entire SPDD prompt file
   b. Identify all existing REASONS sections:
    - Requirements
    - Entities
    - Approach
    - Structure
    - Operations
    - Norms
    - Safeguards
      c. Understand the current architecture, entities, and constraints

3. **Analyze the update request**

   Determine which sections need to be updated based on the change request:

   | Change Type | Affected Sections |
   |-------------|-------------------|
   | New functional requirement | R, E, A, S, O, possibly N, S |
   | Architectural change | A, S, O, N |
   | New type/relationship | E, S, O |
   | Ownership, dispatch or concurrency change | A, S, O, and usually Safeguards |
   | New error variant or changed error model | E, O, S (Safeguards) |
   | New dependency or feature flag | S (Structure), S (Safeguards) |
   | New constraint/safeguard | S (Safeguards), possibly O |
   | Coding standard change | N, O |
   | Bug fix in specification | Targeted section only |

4. **Read relevant codebase context (if needed)**

   If the update involves:
    - New types → Read existing structs, enums and their error types
    - New patterns → Read existing similar implementations
    - New integrations → Read the traits (ports) and their adapters
    - A new dependency → Check the target crate's `Cargo.toml` for whether it is already
      available and under which feature

5. **Apply updates to affected sections**

   For each affected section:

   a. **Preserve unchanged content** - Do NOT rewrite sections that don't need changes b.
   **Integrate changes coherently** - Ensure new content fits with existing content c.
   **Maintain consistency** - Cross-check that changes are reflected across related
   sections d. **Follow REASONS construction guidance** - Apply the same quality standards
   as initial generation

   **Section-specific guidance**:

    - **Requirements**: Update if business goal changes
    - **Entities**: Add/modify types, update the Mermaid diagram (generics are `~T~`;
      flatten nested generics)
    - **Approach**: Update strategies, add new architectural decisions — ownership,
      dispatch and error strategy belong here, not only in Operations
    - **Structure**: Update trait implementations, dependencies, module tree, crate edges,
      feature gates
    - **Operations**: Add new operations, modify existing specifications, keep signatures
      and error paths exact
    - **Norms**: Add new standards, update naming or lint conventions
    - **Safeguards**: Add new constraints, update existing rules, revisit
      MSRV/semver/feature impact

6. **Validate cross-section consistency**

   After updates, verify:
    - Types mentioned in Operations exist in the Entities section
    - Dependencies in Structure match what's described in Operations, and any new crate is
      recorded
    - Constraints in Safeguards are enforceable based on Operations, and each names its
      check
    - Norms are applied consistently across Operations
    - Error variants referenced in Operations exist in the error type defined in Entities
    - A layering rule in Structure is not contradicted by a module path in Operations

7. **Write the updated prompt file**

   a. Overwrite the existing file with the updated content
   b. Preserve the original filename (do NOT rename)

8. **Show update summary**

   ```text
   ✅ SPDD prompt updated: `spdd/prompt/<file-name>.md`

   📋 Changes made:
   - [Section]: [Summary of changes]
   - [Section]: [Summary of changes]

   🔍 Sections unchanged:
   - [List of sections that were not modified]

   ⚠️ Review recommendations:
   - [Any areas that may need manual review]
   ```

9. **Ask for confirmation**

   > "The SPDD prompt has been updated. Would you like me to regenerate the affected code
   > using `/spdd-generate`?"

**Markdown Output Norms** (the prompt file this command rewrites is linted)

The updated prompt is checked by the repository's markdown gate.
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

The updated SPDD prompt file with changes integrated while preserving the REASONS Canvas
structure.

**Guardrails**

- Emitted markdown MUST satisfy the **Markdown Output Norms** above: wrapped at 90
  columns, every fence carrying a language, real headings rather than bold lines,
  and no trailing punctuation in a heading
- **CRITICAL**: Do NOT rewrite the entire file - only modify sections that need changes
- Do NOT proceed without both file path and update instructions
- Do NOT change sections that are unaffected by the update request
- Do NOT break cross-section consistency - if you update Entities, check Operations too
- Do NOT leave placeholders or TODO items - generate complete, specific content
- Do NOT rename the file - preserve the original filename
- Preserve the REASONS Canvas structure (all 7 sections must remain)
- Validate that updates don't contradict existing unchanged content

**No Code Block Rules** (CRITICAL):

The SPDD prompt file is a **specification document**, not source code. It describes WHAT
to implement, leaving the HOW to the `/spdd-generate` phase.

- **Do NOT include language-specific code blocks** (e.g., ```rust, ```sql, ```toml)
- **Do NOT include implementation code** - no `impl` blocks, function bodies, SQL queries,
  or macro invocations in code form
- **Use natural language, with inline signatures** to describe:
  - Function signatures: "Method
    `find_by_id(&self, id: &EntryId) -> Result<Option<Entry>, StoreError>`"
  - Query logic: "Select entries whose zone matches and whose expiry is in the future,
    ordered by insertion time descending"
  - Trait contracts: "Trait `Store` requires
    `save(&self, entry: Entry) -> Result<(), StoreError>` and `find_by_id(...)`, bounded
    `Send + Sync + 'static`"
  - Derives: "Derives `Debug, Clone, PartialEq` — `Clone` because the cache hands out
    owned copies"
- **Allowed diagram blocks**: Mermaid diagrams for type relationships are permitted
  (```mermaid)
- **Describe, don't implement**:
  - ✅ "Adapter maps the stored row into the domain type via `TryFrom<Row>`, returning
    `StoreError::Corrupt` on a malformed column"
  - ❌ a ```rust block containing `impl TryFrom<Row> for Entry { ... }`
- **Exact signatures are specification, not implementation**: naming the receiver,
  borrows, bounds and the full `Result` type is what makes the prompt generatable.
  Withholding them is not abstraction, it is ambiguity
- **Specification vs Implementation boundary**:
  - SPDD prompt = specification (describes contracts, behaviors, constraints)
  - Generated code = implementation (actual source files created by `/spdd-generate`)

**Update-Specific Guardrails**:

- **Minimal change principle**: Only modify what's necessary to satisfy the update request
- **Preserve intent**: Do not change the original design intent unless explicitly
  requested
- **Backward compatibility**: Consider impact on any existing implementation
- **Traceability**: Changes should be clearly identifiable in the updated sections

**Integration with SPDD Workflow**

This command supports the iterative refinement cycle in SPDD:

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                    SPDD Prompt Lifecycle                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Create: /spdd-reasons-canvas                                           │
│  ┌────────────────────────────────────────────────────────────────┐    │
│  │ Business Context → REASONS Canvas → spdd/prompt/*.md            │    │
│  └────────────────────────────────────────────────────────────────┘    │
│                              │                                          │
│                              ▼                                          │
│  Update: /spdd-prompt-update  ◄────────────────────────┐               │
│  ┌────────────────────────────────────────────────────────────────┐    │
│  │ Existing Prompt + Change Request → Updated Prompt              │    │
│  │                                                                 │    │
│  │ Triggers:                                                       │    │
│  │ - New requirements from stakeholders                           │    │
│  │ - Architectural refinements                                    │    │
│  │ - Bug fixes in specification                                   │    │
│  │ - Constraint additions                                         │    │
│  └────────────────────────────────────────────────────────────────┘    │
│                              │                                          │
│                              ▼                                          │
│  Generate: /spdd-generate                                               │
│  ┌────────────────────────────────────────────────────────────────┐    │
│  │ Structured Prompt → Implementation Code                         │    │
│  └────────────────────────────────────────────────────────────────┘    │
│                              │                                          │
│                              ▼                                          │
│  Sync: /spdd-sync (if code changes first)                              │
│  ┌────────────────────────────────────────────────────────────────┐    │
│  │ Code Changes → Update Prompt → Maintain Consistency            │────┘
│  └────────────────────────────────────────────────────────────────┘    │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

**Common Update Scenarios**

1. **Adding Architectural Principles**
    - Affects: Approach, Structure, Operations, Norms, Safeguards
    - Example: "Invert the storage dependency behind a trait defined in the domain layer"

2. **Adding New Type**
    - Affects: Entities, Structure, Operations
    - Example: "Add an AuditEntry type for tracking changes"

3. **Adding New Constraint**
    - Affects: Safeguards, possibly Operations
    - Example: "Cap the cache at 50MB resident and prove eviction under load"

4. **Refining Business Logic**
    - Affects: Approach, Operations
    - Example: "Change eviction from LRU to a TTL-plus-LRU hybrid"

5. **Updating Coding Standards**
    - Affects: Norms, Operations (to align with new standards)
    - Example: "Adopt `thiserror` enums at every crate boundary and reserve `anyhow` for
      the binary"

6. **Changing Ownership or Dispatch**
    - Affects: Approach, Structure, Operations, Safeguards
    - Example: "Replace `Arc<Mutex<Matcher>>` with `ArcSwap` so readers never block on
      reload"

7. **Changing the Error Model**
    - Affects: Entities, Operations, Safeguards
    - Example: "Split `StoreError::Io` into `Io` and `Corrupt` so callers can distinguish
      retryable failures"

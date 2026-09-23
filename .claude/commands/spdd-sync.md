---
name: /spdd-sync
id: spdd-sync
category: Development
description: Sync Rust code changes back to the structured SPDD prompt file following the REASONS Canvas methodology
---

Synchronize implementation details from refactored or updated Rust code back to the
structured SPDD (Structured Prompt-Driven Development) prompt file, ensuring the prompt
remains the accurate source of truth for the system design.

**Input**: The argument after `/spdd-sync` is the path to the structured prompt file
(e.g., `@spdd/prompt/202602271430-[Feat]-api-create-agent-endpoint.md`).

**Steps**

1. **If no input provided, ask for the prompt file**

   Use the **AskUserQuestion tool** to ask:

   > "Please provide the path to the structured prompt file you want to sync (e.g.,
   > `@spdd/prompt/xxx.md`)."

   **IMPORTANT**: Do NOT proceed without a valid prompt file path.

2. **Read and parse the structured prompt file**

   Read the prompt file and identify the REASONS Canvas sections:

   | Section              | Purpose                        | Sync Priority                          |
   | -------------------- | ------------------------------ | -------------------------------------- |
   | **R** - Requirements | Overall goal and DoD           | Low (rarely changes from code)         |
   | **E** - Entities     | Type model and relationships   | High (type diagrams may change)        |
   | **A** - Approach     | Implementation strategy        | Medium (architectural decisions)       |
   | **S** - Structure    | Crates, modules, dependencies  | High (trait impls/dependencies change) |
   | **O** - Operations   | Concrete implementation tasks  | **Highest** (implementation details)   |
   | **N** - Norms        | Engineering standards          | Medium (patterns may evolve)           |
   | **S** - Safeguards   | Non-negotiable constraints     | Low (constraints rarely relax)         |

   **IMPORTANT**: Operations section typically requires the most updates as it contains
   implementation specifics.

3. **Identify affected components from user context**

   Ask the user (if not already specified):

   > "Which components were refactored? Please specify:
   >
   > - Specific files/classes that changed
   > - Type of change (renamed, restructured, logic changed, new components added)
   > - Brief description of what changed"

   Alternatively, analyze recent git changes or user-specified files to identify
   modifications.

4. **Analyze current implementation**

   For each affected component:

   a. **Read the current implementation**:
   - Locate the source file in the codebase
   - Extract type definitions (struct/enum/trait), their fields and variants, `impl`
     blocks, derives and attributes
   - Identify relationships and dependencies: which traits are implemented, what is held
     behind `Arc`/`Box`, which ports are injected
   - Check whether `Cargo.toml` changed — new dependencies, new features, an MSRV bump

   b. **Compare with prompt specification**:
   - Find corresponding Operation/Entity/Structure section
   - Note discrepancies in:
     - Type names and module paths
     - Function signatures, including `&self`/`&mut self`/`self`, borrows, lifetimes and
       generic bounds
     - Fields, variants and their types
     - Derives and attributes in use
     - Visibility (`pub`, `pub(crate)`, private) — a widened visibility is a change to the
       API surface
     - Error enum variants and their messages
     - Business logic steps
     - Invariants and where they are enforced

   c. **Categorize changes**:
   - **Structural**: trait implementations, module layout, crate dependencies, layering
   - **Behavioral**: function logic, invariant enforcement, error handling
   - **Naming**: type/function/field renames
   - **Additions**: new functions, fields, variants, or types
   - **Deletions**: removed functions, fields, variants, or types
   - **API surface**: visibility changes and anything semver-breaking for a published
     crate

5. **Generate prompt update plan**

   Create a detailed update plan showing:

   ```text
   ## Prompt Sync Plan

   ### Entities Section Updates
   - [ ] Update: TypeName - added/removed/changed fields or variants
   - [ ] Update: Relationship diagram - new trait implementation

   ### Structure Section Updates
   - [ ] Update: Trait implementations - AdapterX now implements PortY
   - [ ] Update: Dependencies - UseCaseA now holds Arc<dyn ValidatorB>
   - [ ] Update: Crate dependencies - new crate added to Cargo.toml

   ### Operations Section Updates
   - [ ] Update: "Create TypeName" operation - new signature
   - [ ] Update: "Create TypeName" operation - logic steps changed
   - [ ] Add: New operation for NewType
   - [ ] Remove: Obsolete operation description

   ### Norms Section Updates
   - [ ] Update: New pattern adopted (e.g., typestate for connection lifecycle)
   ```

   **Present this plan to the user for review before proceeding.**

6. **Apply updates to prompt file**

   For each approved update, modify the prompt file following these patterns:

   a. **Entities section updates**:
   - Update the Mermaid diagram to reflect actual type structure
   - Ensure fields and variants match actual names and types
   - Update relationship arrows to reflect actual trait implementations and ownership
   - Keep Mermaid's constraints in mind: generics are `~T~`, nested generics mangle, and
     `Result~(), E~` can drop its line — flatten and state the real signature in Structure

   b. **Structure section updates**:
   - Update the trait implementation list
   - Update dependencies, including any new crate added to `Cargo.toml` and why
   - Update the module tree if files moved, and confirm the `mod` declarations match
   - Ensure the layering description matches reality — if a layering rule was violated
     rather than changed, say so instead of rewriting the rule to match the code

   c. **Operations section updates** (most critical):
   - Update **Responsibility** if the component's purpose evolved
   - Update **Location** if the type moved to a different module or crate
   - Update **Fields** to match actual fields and variants
   - Update **Methods** to match actual signatures, including receivers, borrows and
     bounds
   - Update **Logic** steps to match actual implementation
   - Update **Derives** to match actual derives and attributes
   - Update **Invariants** and error paths to match what the code now enforces and returns
   - Add new operations for newly created types
   - Mark obsolete operations (or remove if no longer relevant)

   d. **Norms section updates**:
   - Add new patterns if adopted (e.g., typestate, newtype wrappers, a shared
     error-conversion idiom)
   - Update coding standards if conventions evolved
   - Record any new lint configuration or `#[allow]` convention established

   e. **Safeguards section updates**:
   - Update exact error messages to match implementation
   - Update invariants and constraints if they changed
   - Update MSRV, feature combinations, or semver notes if the public API surface moved

   **IMPORTANT**:
   - Preserve the existing section structure and formatting
   - Follow the existing pattern/style within each section
   - Use the same level of detail as existing content
   - Keep descriptions concise but complete

7. **Validate prompt consistency**

   After updates, verify:

   a. **Internal consistency**:
   - Entities diagram matches Structure section
   - Operations reference correct class names from Entities
   - Norms patterns are reflected in Operations logic
   - Safeguards constraints appear in relevant Operations

   b. **Traceability**:
   - Each Operation corresponds to a component in Structure
   - Each component in Structure has an Operation
   - Dependencies in Structure match import relationships in Operations

   c. **Completeness**:
   - No orphaned references to old class/method names
   - All new components have corresponding Operations
   - Error messages in Safeguards match Operations logic

8. **Report sync summary**

   Provide a summary to the user:
   - List of sections updated
   - Specific changes made in each section
   - Any manual review recommendations
   - Suggestions for further cleanup if needed

**Sync Patterns & Best Practices**

When syncing different types of changes:

1. **Type/Module Renames**:
   - Search and replace in all sections
   - Update module paths in Operations
   - Update type names in the Entities diagram
   - Update references in Structure section

2. **Signature Changes**:
   - Update Operations method specifications, including receiver, borrows, lifetimes and
     bounds
   - Update any Safeguards that reference return types or parameters
   - Verify the Entities diagram if the public API changed

3. **New Type Added**:
   - Add to Entities diagram with relationships
   - Add to Structure section (trait impls, dependencies, layer, `mod` declaration)
   - Add new Operation with full specification
   - Update related Operations that depend on the new type

4. **Type Removed**:
   - Remove from Entities diagram
   - Remove from Structure section
   - Remove corresponding Operation
   - Update Operations that referenced the removed type

5. **Logic/Behavior Changes**:
   - Update Logic steps in Operations section
   - Verify Safeguards still accurate
   - Update Approach section if the architectural pattern changed

6. **Error Model Changes**:
   - Update the error enum's variants and messages in Operations
   - Update Safeguards constraints and expected messages
   - Check every call site the variant change affects

7. **Ownership/Concurrency Changes**:
   - If sharing moved (owned → `Arc`, `Mutex` → `RwLock` → atomics → `ArcSwap`), update
     Approach as well as Operations — this is an architectural decision, not a detail
   - Update any `Send`/`Sync` bounds in Structure
   - Update Safeguards if what may block, allocate, or be held across an `.await` changed

8. **Dispatch Changes**:
   - A move between generics and `dyn Trait` changes object-safety requirements and the
     Structure section's dependency shape
   - Update Approach with the reason for the switch, not just the fact of it

9. **Dependency or Feature Changes**:
   - Record new crates in Structure with their justification and feature flags
   - Update Safeguards if MSRV, feature combinations, or the semver contract moved

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

- Updated structured prompt file with synced content
- Summary of all changes made to each section
- List of any inconsistencies found and resolved
- Recommendations for manual review if needed

**Guardrails**

- Emitted markdown MUST satisfy the **Markdown Output Norms** above: wrapped at 90
  columns, every fence carrying a language, real headings rather than bold lines,
  and no trailing punctuation in a heading
- Do NOT remove content from prompt without explicit user approval
- Do NOT change Requirements section unless user explicitly requests (business goals
  shouldn't change from code refactoring)
- Do NOT simplify or abbreviate existing detailed specifications
- Do NOT change error messages in Safeguards unless they actually changed in code
- Always preserve the existing formatting style within each section
- Always ask for confirmation before making destructive changes (deletions)
- Always maintain the same level of detail as existing content
- When in doubt, show the proposed change and ask user to confirm
- Never change the prompt's unique identifier or metadata

**Integration with SPDD Workflow**

This command completes the bidirectional sync in the SPDD workflow:

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                      SPDD Bidirectional Sync                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Forward Flow (Design → Code): /spdd-generate                          │
│  ┌────────────────────────────────────────────────────────────────┐    │
│  │ Structured Prompt → Validate → Generate → Verify → Code        │    │
│  └────────────────────────────────────────────────────────────────┘    │
│                              │                                          │
│                              │ Initial Implementation                   │
│                              ▼                                          │
│                    ┌─────────────────┐                                  │
│                    │  Implementation  │                                  │
│                    │     Codebase     │                                  │
│                    └─────────────────┘                                  │
│                              │                                          │
│                              │ Code Review / Refactoring                │
│                              ▼                                          │
│  Reverse Flow (Code → Design): /spdd-sync                              │
│  ┌────────────────────────────────────────────────────────────────┐    │
│  │ Analyze Changes → Compare → Plan Updates → Update Prompt       │    │
│  └────────────────────────────────────────────────────────────────┘    │
│                              │                                          │
│                              ▼                                          │
│  ┌────────────────────────────────────────────────────────────────┐    │
│  │              Prompt-Code Consistency Maintained                 │    │
│  │                                                                 │    │
│  │  - Prompt remains source of truth                              │    │
│  │  - Code changes are documented in prompt                       │    │
│  │  - Future generations use updated specifications               │    │
│  │  - Team alignment on actual vs planned implementation          │    │
│  └────────────────────────────────────────────────────────────────┘    │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

**When to Use /spdd-sync**

Use this command when:

- Code review led to refactoring changes
- Discovered better patterns during implementation
- Bug fixes required logic changes
- Performance optimization changed implementation details
- New types were added that were not in the original prompt
- Types or functions were renamed for clarity
- Modules or crate boundaries were restructured
- The borrow checker forced an ownership change the prompt did not anticipate
- A trait had to change shape to stay object-safe, or dispatch was switched
- The error enum gained, lost, or reworded variants

**Principle**: The structured prompt should always reflect the **actual** implementation,
not just the **planned** implementation. This ensures:

- New team members understand the real system from the prompt
- Future enhancements build on accurate specifications
- Prompt serves as living documentation
- Regeneration produces consistent code

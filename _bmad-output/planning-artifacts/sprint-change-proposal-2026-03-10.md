# Sprint Change Proposal — Epic 2 Retrospective Findings

**Date:** 2026-03-10
**Trigger:** Epic 2 Retrospective (2026-03-11)
**Change Scope:** Minor — Direct Adjustment
**Status:** Approved

---

## 1. Issue Summary

Epic 2 (Sync Framework & AWS Secrets Manager Integration) completed successfully with all 5 stories done and merged. During implementation and review, three patterns emerged that weren't captured in the original architecture or story specifications:

1. **`FetchResult` pattern** — `fetch_current()` needed to return both successful secrets AND per-key errors, not just a HashMap. The original trait signature was `Result<HashMap<String, String>, SyncError>`, but review of PR #83 revealed this silently dropped per-key failures. A new `FetchResult { secrets: HashMap, errors: Vec<(String, SyncError)> }` type was introduced.

2. **`DiffCommonArgs` split** — The original architecture defined a single `SyncCommonArgs` for all sync/diff commands. Review of PR #84 caught that read-only commands (`diff`) inherited write-only flags (`--dry-run`, `--force`). A separate `DiffCommonArgs` was created.

3. **Error classification specificity** — Broad substring matching (`"connection"`) for error classification misclassified API errors. Specific SDK error patterns (`"dispatch failure"`, `"timeout"`, `"connection refused"`, `"connection reset"`, `"connect error"`) replaced it.

These patterns are now proven in code but not reflected in the planning artifacts that future stories and agents will reference.

---

## 2. Impact Analysis

### Epic Impact

| Epic | Impact | Details |
|------|--------|---------|
| Epic 2 | None | Complete. Patterns already implemented. |
| Epic 3 (Fly) | **Moderate** | Stories 3.1 and 3.2 should reference `FetchResult` and `DiffCommonArgs` patterns from the start. |
| Epics 4-9 | **Low** | Stories not yet created. Patterns will be inherited via updated architecture doc. |

### Artifact Conflicts

| Artifact | Conflict | Action Needed |
|----------|----------|---------------|
| **Architecture** | `SyncTarget` trait signature outdated; missing `FetchResult` type, `DiffCommonArgs`, error classification rules | Update |
| **PRD** | No conflict | None |
| **UX Design** | No conflict | None |
| **Epics** | Epic 3 story specs don't exist yet (backlog) — no conflict, but patterns must be incorporated at creation time | Note for SM |
| **Sprint Status** | No conflict | None |

### Technical Impact

- No code changes needed — patterns are already implemented in main
- Architecture doc update is documentation-only
- Flaky test GH #85 (`test_cross_environment_isolation` server startup timeout) remains open — intermittent, not blocking

---

## 3. Recommended Approach

**Selected: Direct Adjustment**

Update the architecture document to reflect the three patterns that emerged during Epic 2 implementation. No story changes, no PRD changes, no scope adjustment.

**Rationale:**
- Effort: Low (documentation update only)
- Risk: Low (patterns are already proven in working code)
- Timeline impact: None — can be done before starting Epic 3
- The alternative (leaving docs outdated) risks future agents implementing the old pattern and requiring the same review fixes

**Effort estimate:** Low
**Risk level:** Low
**Timeline impact:** None

---

## 4. Detailed Change Proposals

### Change 1: Update Architecture — SyncTarget Trait Pattern

**File:** `_bmad-output/planning-artifacts/architecture.md`
**Section:** SyncTarget Trait Pattern (code block around line 267-283)

OLD:
```rust
#[async_trait]
pub trait SyncTarget {
    fn display_name(&self) -> &str;
    async fn fetch_current(&self) -> Result<HashMap<String, String>, SyncError>;
    async fn apply(&self, operations: &[DiffOperation]) -> Vec<SyncResult>;
}
```

NEW:
```rust
#[async_trait]
pub trait SyncTarget {
    fn display_name(&self) -> &str;
    async fn fetch_current(&self) -> Result<FetchResult, SyncError>;
    async fn apply(&self, operations: &[DiffOperation]) -> Vec<SyncResult>;
}
```

**Rationale:** `fetch_current()` returns `FetchResult` (containing both `secrets: HashMap<String, String>` and `errors: Vec<(String, SyncError)>`) instead of a bare HashMap. This ensures per-key errors are surfaced to the caller rather than silently dropped.

### Change 2: Add FetchResult Type to Architecture — Shared Types

**File:** `_bmad-output/planning-artifacts/architecture.md`
**Section:** After the SyncTarget trait code block, add:

ADD (new content):
```
#### FetchResult Type

When fetching collections with per-item potential failures, always return both successes AND errors:

```rust
pub struct FetchResult {
    /// Successfully fetched secrets
    pub secrets: HashMap<String, String>,
    /// Per-key errors (key name, error)
    pub errors: Vec<(String, SyncError)>,
}
```

**Rule:** Never silently discard errors from collection-fetching operations. Return both successes and failures — let the caller decide policy. This applies to `fetch_current()` and any future trait method that fetches collections.
```

**Rationale:** Team agreement from Epic 2 retro: "Return both successes AND errors from collection-fetching operations — never silently discard."

### Change 3: Add DiffCommonArgs to Architecture — CLI Command Pattern

**File:** `_bmad-output/planning-artifacts/architecture.md`
**Section:** CLI Command Pattern for Sync/Diff (around line 343-363)

OLD:
```rust
#[derive(Parser)]
pub struct SyncAwsArgs {
    #[command(flatten)]
    pub common: SyncCommonArgs,  // -w, -p, -e, --dry-run, --json, --no-color, etc.
    #[arg(long)]
    pub region: String,
    #[arg(long)]
    pub prefix: Option<String>,
}
```

NEW:
```rust
// Write commands (sync) use SyncCommonArgs
#[derive(Parser)]
pub struct SyncAwsArgs {
    #[command(flatten)]
    pub common: SyncCommonArgs,  // -w, -p, -e, --dry-run, --force, --json, --no-color, etc.
    #[arg(long)]
    pub region: String,
    #[arg(long)]
    pub prefix: Option<String>,
}

// Read-only commands (diff, status) use DiffCommonArgs
#[derive(Parser)]
pub struct DiffAwsArgs {
    #[command(flatten)]
    pub common: DiffCommonArgs,  // -w, -p, -e, --json, --no-color (NO --dry-run, --force)
    #[arg(long)]
    pub region: String,
    #[arg(long)]
    pub prefix: Option<String>,
}
```

ADD to rules:
- `DiffCommonArgs` is for read-only commands (`diff`, `status`) — excludes `--dry-run` and `--force`
- `SyncCommonArgs` is for write commands (`sync`) — includes `--dry-run` and `--force`
- Story specs must explicitly specify which args struct each command variant uses

**Rationale:** Discovered in PR #84 review — read-only commands should not accept write-only flags.

### Change 4: Add Error Classification Rule to Architecture

**File:** `_bmad-output/planning-artifacts/architecture.md`
**Section:** Error Handling Pattern for Sync (after the SyncError enum, around line 385)

ADD to rules:
- Error classification must use specific, documented SDK/API error patterns — never broad substring matching
- Example: classify connection errors by matching `"dispatch failure"`, `"timeout"`, `"connection refused"`, `"connection reset"`, `"connect error"` — not by checking if message contains `"connection"`
- When adding a new sync target, document the specific error patterns used for classification in the module's source

**Rationale:** Broad substring matching in Epic 2's initial AWS client misclassified API errors as connection errors. Specific patterns are more fragile to SDK changes but far less likely to misclassify.

### Change 5: Update Team Agreements in Architecture

**File:** `_bmad-output/planning-artifacts/architecture.md`
**Section:** Anti-Patterns to Avoid (after existing list, around line 422)

ADD new anti-patterns:
6. **Don't silently discard per-item errors in collection fetches.** When fetching multiple items (secrets, configs), return both successes and errors. Never return only the successful items.
7. **Don't share write-command args with read-only commands.** Use `DiffCommonArgs` for read-only commands and `SyncCommonArgs` for write commands. Don't let `diff` accept `--dry-run` or `--force`.
8. **Don't use broad substring matching for error classification.** Match specific, documented error patterns from the SDK/API. Broad matches like `"connection"` will misclassify unrelated errors.

**Rationale:** Codifies Epic 2 team agreements as anti-patterns for future agents to follow.

---

## 5. Implementation Handoff

**Change scope: Minor** — Direct implementation by dev team (documentation updates only).

| # | Action | Owner | Priority |
|---|--------|-------|----------|
| 1 | Apply Changes 1-5 to architecture.md | Dev (Amelia) | Before Epic 3 story creation |
| 2 | When creating Epic 3 stories via SM agent, ensure story specs reference `FetchResult` pattern and `DiffCommonArgs` split | SM (Bob) | During story creation |
| 3 | Address flaky test GH #85 if it recurs | Dev (Amelia) | Low priority |

**Success criteria:**
- Architecture doc reflects actual implemented `SyncTarget` trait signature
- Architecture doc includes `FetchResult` type documentation
- Architecture doc includes `DiffCommonArgs` vs `SyncCommonArgs` distinction
- Architecture doc includes error classification specificity rule
- Epic 3 Story 3.1 spec references these patterns when created

**No blocking dependencies.** Changes can be applied immediately.

---

## Approval

- [x] Change trigger identified and documented
- [x] Impact analysis complete
- [x] Path forward selected with rationale
- [x] Specific edit proposals with before/after
- [x] Implementation handoff defined

**Verdict:** Minor scope — apply architecture doc updates, then proceed to Epic 3 story creation.

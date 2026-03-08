# Story 2.3: Create CLI output component module

Status: ready-for-dev

## Story

As a user running sync commands,
I want consistent, well-formatted terminal output across all commands,
So that I can quickly scan results, understand errors, and take screenshots for compliance.

## Acceptance Criteria

1. **Given** the output module is created at `apps/zopp-cli/src/output/`
   **When** any sync or diff command runs
   **Then** output uses the shared components: OperationHeader, PerItemResult, SummaryLine, DiffSummary, StatusTable, ErrorBlock

2. **Given** the `--json` flag is passed
   **When** any command produces output
   **Then** a complete JSON object is emitted (not line-by-line JSON)
   **And** no ANSI color codes are included in JSON output

3. **Given** `NO_COLOR` environment variable is set or `--no-color` flag is passed
   **When** output is rendered
   **Then** no ANSI color codes are emitted
   **And** symbols (checkmark, cross, warning, +, -, ~) still convey meaning without color

4. **Given** the `--verbose` flag is passed
   **When** a sync operation runs
   **Then** additional detail is shown (API calls, timing)

5. **Given** the `--quiet` flag is passed
   **When** a sync operation runs
   **Then** only errors are displayed

6. **Given** any command completes
   **When** the exit code is set
   **Then** it follows the contract: 0 (success), 1 (partial failure), 2 (total failure), 3 (config error), 4 (connection error)

7. **Given** the terminal width is detected
   **When** table output is rendered
   **Then** columns adapt to available width with 80-column minimum
   **And** long values are truncated with `...` rather than wrapping

8. **Given** stdout is not a TTY (piped to another command or redirected to a file)
   **When** any command produces output
   **Then** all ANSI escape codes are stripped from the output
   **And** Unicode symbols downgrade to ASCII equivalents: checkmark->[ok], cross->[FAIL], warning->[WARN]
   **And** progress spinners are suppressed entirely

## Tasks / Subtasks

- [ ] Task 1: Create `OutputConfig` struct and initialization (AC: #2, #3, #4, #5, #8)
  - [ ] 1.1 Create `apps/zopp-cli/src/output/mod.rs` with module declarations
  - [ ] 1.2 Create `apps/zopp-cli/src/output/config.rs` with `OutputConfig` struct: `json`, `no_color`, `verbose`, `quiet`, `is_tty`, `terminal_width`
  - [ ] 1.3 Implement `OutputConfig::from_env()` — detect `NO_COLOR`, TTY, terminal width
  - [ ] 1.4 Add `console` (0.16.2) and `terminal_size` (0.4.3) to CLI Cargo.toml dependencies
  - [ ] 1.5 Wire `output` module into CLI `main.rs`

- [ ] Task 2: Create symbol and color utilities (AC: #3, #8)
  - [ ] 2.1 Define symbol constants: success (`✓`/`[ok]`), failure (`✗`/`[FAIL]`), warning (`⚠`/`[WARN]`), add (`+`), update (`~`), remove (`-`)
  - [ ] 2.2 Implement TTY-aware symbol selection (Unicode when TTY, ASCII when not)
  - [ ] 2.3 Implement color application functions using `console` crate: green, red, yellow, cyan, bold, dim — respecting `no_color` and TTY

- [ ] Task 3: Create OperationHeader component (AC: #1)
  - [ ] 3.1 Implement `header(verb: &str, source: &str, target: &str)` — outputs formatted header line
  - [ ] 3.2 Format: `{verb}: {source} -> {target}`  with cyan target name

- [ ] Task 4: Create PerItemResult component (AC: #1)
  - [ ] 4.1 Implement `per_item_success(key: &str, action: &str)` — checkmark + key + action
  - [ ] 4.2 Implement `per_item_failure(key: &str, error: &str, fix: Option<&str>)` — cross + key + error + optional fix on next line
  - [ ] 4.3 Pad key names to consistent column width

- [ ] Task 5: Create SummaryLine component (AC: #1)
  - [ ] 5.1 Implement `summary(total: usize, succeeded: usize, failed: usize, target: &str)` — outputs summary
  - [ ] 5.2 Three states: all success (green checkmark), partial (yellow warning), total failure (red cross)

- [ ] Task 6: Create DiffSummary component (AC: #1)
  - [ ] 6.1 Implement `diff_item(op_type: DiffSymbol, key: &str)` — single diff line with +/~/- symbol
  - [ ] 6.2 Implement `diff_summary(adds: usize, updates: usize, removes: usize)` — count summary or "No changes" message

- [ ] Task 7: Create StatusTable component (AC: #1, #7)
  - [ ] 7.1 Implement `status_table(entries: &[StatusEntry])` — formatted aligned table
  - [ ] 7.2 Define `StatusEntry` struct: target name, status, detail
  - [ ] 7.3 Truncate long values with `...` at terminal width boundary
  - [ ] 7.4 Adapt column widths based on terminal width (80 minimum)

- [ ] Task 8: Create ErrorBlock component (AC: #1)
  - [ ] 8.1 Implement `error_block(context: &str, problem: &str, fix: &str)` — structured error output
  - [ ] 8.2 Format: `Error: {context} — {problem}\n\n  Fix: {fix}`

- [ ] Task 9: Create JSON output support (AC: #2)
  - [ ] 9.1 Create `apps/zopp-cli/src/output/json.rs` with serialization types
  - [ ] 9.2 Define `SyncOutput`, `DiffOutput`, `StatusOutput` JSON structs (matching human-readable fields)
  - [ ] 9.3 Implement `output_json(value: &impl Serialize)` — outputs complete JSON, no ANSI codes

- [ ] Task 10: Create SyncCommonArgs struct (AC: #2, #3, #4, #5)
  - [ ] 10.1 Define `SyncCommonArgs` with clap derive: `-w`, `-p`, `-e`, `--dry-run`, `--json`, `--no-color`, `--verbose`, `--quiet`, `--force`
  - [ ] 10.2 Implement `SyncCommonArgs::to_output_config()` to build `OutputConfig`

- [ ] Task 11: Create exit code module (AC: #6)
  - [ ] 11.1 Define exit code constants: SUCCESS=0, PARTIAL=1, TOTAL_FAILURE=2, CONFIG_ERROR=3, CONNECTION_ERROR=4
  - [ ] 11.2 Implement `exit_code_from_results(total: usize, failed: usize) -> i32`

- [ ] Task 12: Write tests (AC: all)
  - [ ] 12.1 Unit test each component's output format
  - [ ] 12.2 Test NO_COLOR produces zero ANSI escape codes
  - [ ] 12.3 Test non-TTY uses ASCII fallback symbols
  - [ ] 12.4 Test JSON output is valid JSON with all expected fields
  - [ ] 12.5 Test exit code calculation for all scenarios
  - [ ] 12.6 Test summary line for all-success, partial, total-failure states

- [ ] Task 13: Verification
  - [ ] 13.1 `cargo build --package zopp-cli` compiles
  - [ ] 13.2 `cargo test --package zopp-cli` passes
  - [ ] 13.3 `cargo clippy --package zopp-cli --all-targets` zero warnings
  - [ ] 13.4 `cargo fmt --all -- --check` passes

## Dev Notes

### Architecture Compliance

**Module location:** `apps/zopp-cli/src/output/`

**File layout (from architecture):**
```
apps/zopp-cli/src/output/
  mod.rs          # Module root, re-exports, OutputConfig initialization
  config.rs       # OutputConfig struct (json, color, verbose, quiet, TTY, width)
  components.rs   # All output components: header, per_item, summary, diff, status_table, error_block
  json.rs         # JSON output serialization types and function
```

### Component Specifications

**OperationHeader:** `Syncing: zopp/workspace/project/env -> AWS Secrets Manager (us-east-1)`
- Verb in bold, target in cyan

**PerItemResult:**
```
  ✓ SECRET_NAME         synced
  ✗ SECRET_NAME         AccessDeniedException
                         Fix: Check IAM permissions
```

**SummaryLine:**
- `✓ 3/3 secrets synced to AWS Secrets Manager (us-east-1)` (all green)
- `⚠ 2/3 secrets synced, 1 failed | Target: AWS Secrets Manager` (yellow)
- `✗ 0/3 secrets synced | Target: AWS Secrets Manager` (red)

**DiffSummary:**
- `  + NEW_SECRET`, `  ~ UPDATED_SECRET`, `  - REMOVED_SECRET`
- Summary: `3 changes: 1 add, 1 update, 1 remove` or `No changes. Target is in sync.`

**StatusTable:**
```
  Target                     Status
  ──────────────────────────────────────
  AWS Secrets Manager        ✓ 12 in sync
  Fly (myapp)                ⚠ 2 drifted
```

**ErrorBlock:**
```
Error: [aws] sync failed — InvalidAccessKeyId

  Fix: Check AWS_ACCESS_KEY_ID is set correctly, or run `aws configure`.
```

### Color Semantics

| Color | Meaning | Usage |
|-------|---------|-------|
| Green bold | Success/Addition | `✓`, `+` |
| Red bold | Error/Removal | `✗`, `-` |
| Yellow | Warning/Change | `⚠`, `~` |
| Cyan | Informational | Headers, target names |
| White bold | Emphasis | Section headers, key names |
| Dim | Secondary | Timestamps, supplementary |

### Symbol Fallbacks (non-TTY)

| Unicode | ASCII Fallback |
|---------|---------------|
| `✓` | `[ok]` |
| `✗` | `[FAIL]` |
| `⚠` | `[WARN]` |

### New Dependencies

Add to `apps/zopp-cli/Cargo.toml`:
```toml
console = "0.16.2"     # Terminal styling + TTY detection
terminal_size = "0.4.3" # Terminal width detection
```

Both are already listed in the architecture doc as new dependencies.

Also add `zopp-sync` dependency for shared types (`DiffOperation`, `SyncResult`):
```toml
zopp-sync = { path = "../../crates/zopp-sync", version = "0.1.1" }
```

### SyncCommonArgs (from architecture)

```rust
#[derive(Parser)]
pub struct SyncCommonArgs {
    #[arg(short, long)]
    pub workspace: Option<String>,
    #[arg(short, long)]
    pub project: Option<String>,
    #[arg(short, long)]
    pub environment: Option<String>,
    #[arg(long)]
    pub dry_run: bool,
    #[arg(long)]
    pub json: bool,
    #[arg(long)]
    pub no_color: bool,
    #[arg(long)]
    pub verbose: bool,
    #[arg(long)]
    pub quiet: bool,
    #[arg(long)]
    pub force: bool,
}
```

### Exit Code Contract

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Partial failure |
| 2 | Total failure |
| 3 | Config error |
| 4 | Connection error |

### Testing Standards

- Unit test each component by capturing output and asserting format
- Test with `OutputConfig { no_color: true, .. }` to verify zero ANSI codes
- Test with `OutputConfig { is_tty: false, .. }` to verify ASCII fallback
- Test JSON output parses as valid JSON with expected structure
- Use `console` crate's `strip_ansi_codes()` for validation

### Anti-Patterns to Avoid

- Do NOT use `println!` directly for user-facing output — always use output module functions
- Do NOT hardcode ANSI escape sequences — use `console` crate
- Do NOT emit colors when `NO_COLOR` is set or when not a TTY
- Do NOT log plaintext secret values in any output component — only key names
- Do NOT create separate output functions per sync target — components are generic

### Previous Story Intelligence (Story 2.1)

- `zopp-sync` crate created with `DiffOperation`, `SyncResult`, `SyncOutcome`, `SyncError` types
- These types have `Serialize` derive — can be used directly in JSON output
- `DiffOperation::key()` accessor for getting the secret key name
- `SyncError::display_with_fix()` for formatted error output with fix instruction

### Project Structure Notes

- Module at `apps/zopp-cli/src/output/` — declared in CLI's `main.rs` or `lib.rs`
- `SyncCommonArgs` defined here but used by sync/diff commands in Story 2.4
- No changes to existing commands — new module is additive only
- `indicatif` (0.18.4) is listed in architecture for progress spinners but NOT needed in this story — spinners are only used during actual sync operations (Story 2.4)

### References

- [Source: _bmad-output/planning-artifacts/architecture.md#CLI Output Architecture]
- [Source: _bmad-output/planning-artifacts/architecture.md#CLI Output Pattern]
- [Source: _bmad-output/planning-artifacts/architecture.md#CLI Command Pattern for Sync/Diff]
- [Source: _bmad-output/planning-artifacts/ux-design-specification.md#Output Components]
- [Source: _bmad-output/planning-artifacts/epics.md#Story 2.3]
- [Source: _bmad-output/implementation-artifacts/2-1-*.md — Story 2.1 learnings]

### Pre-Submission Checklist

**Code Quality:**

- [ ] `cargo fmt --all` passes
- [ ] `cargo clippy --package zopp-cli --all-targets` zero warnings
- [ ] `cargo test --package zopp-cli` passes
- [ ] `cargo build --package zopp-cli` compiles

**Security:**

- [ ] No plaintext secret values in any output function
- [ ] Output functions only display key names, never values

## Dev Agent Record

### Agent Model Used

### Debug Log References

### Completion Notes List

### File List

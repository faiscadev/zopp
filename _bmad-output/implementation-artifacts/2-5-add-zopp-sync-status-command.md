# Story 2.5: Add zopp sync status command

Status: ready-for-dev

## Story

As a user,
I want to view the sync health of all my configured targets in one command,
so that I can quickly verify everything is in sync and capture compliance evidence.

## Acceptance Criteria

1. **Given** the user runs `zopp sync status --region us-east-1 --prefix /prod/`
   **When** AWS credentials are available in the environment
   **Then** it fetches secrets from zopp (encrypted), decrypts client-side
   **And** it queries AWS Secrets Manager via `fetch_current()`
   **And** it compares against current zopp secrets using `zopp_sync::diff()`
   **And** it displays a StatusTable showing: target name, sync state (in-sync/drifted), and counts
   **And** it shows the detail column with counts of drifted secrets (adds + updates + removes)

2. **Given** the user runs `zopp sync status` with AWS credentials missing
   **When** `AwsSyncTarget::new()` returns `SyncError::AuthError`
   **Then** the status entry for that target shows an error with fix instructions
   **And** the process exits with `PARTIAL_FAILURE` (1) or `TOTAL_FAILURE` (2)

3. **Given** the `--json` flag is passed
   **When** status is displayed
   **Then** a complete `StatusJsonOutput` JSON object is emitted with all target statuses
   **And** no ANSI color codes are included

4. **Given** the status output is displayed
   **When** the user reads the table
   **Then** the table is formatted with aligned columns via `status_table()` component
   **And** it uses the STATUS/DETAIL column pattern: e.g., "in-sync" / "12 secrets" or "drifted" / "2 added, 1 updated"

5. **Given** all secrets match between zopp and the target
   **When** the status is computed
   **Then** the status shows "in-sync" with the total secret count

6. **Given** `--quiet` flag is passed
   **When** status is displayed
   **Then** no table output is shown (only exit code communicates status)

7. **Given** the sync completes
   **When** results are displayed
   **Then** no plaintext secret values appear in the output, logs, or temporary files
   **And** only secret key names are shown in verbose mode (if ever added)

## Tasks / Subtasks

- [ ] Task 1: Add `Status` variant to `SyncCommand` enum (AC: #1, #3, #6)
  - [ ] 1.1 Add `Status` variant to `SyncCommand` enum in `cli.rs` with `#[command(flatten)] common: SyncCommonArgs`, `--region` (required), `--prefix` (optional)
  - [ ] 1.2 Add CLI parsing test for `zopp sync status --region us-east-1`

- [ ] Task 2: Create `cmd_sync_status` function (AC: #1, #2, #3, #4, #5, #6, #7)
  - [ ] 2.1 Create `apps/zopp-cli/src/commands/sync_status.rs`
  - [ ] 2.2 Resolve workspace/project/environment via `resolve_context()`
  - [ ] 2.3 Fetch and decrypt zopp secrets via `setup_client()` + `fetch_and_decrypt_secrets()`
  - [ ] 2.4 Create `AwsSyncTarget::new(region, prefix)` — if error, create error StatusEntry instead of aborting
  - [ ] 2.5 Call `target.fetch_current()` — if error, create error StatusEntry
  - [ ] 2.6 Compute diff via `zopp_sync::diff(zopp_map, aws_secrets)`
  - [ ] 2.7 Build `StatusEntry` from diff counts: status="in-sync" or "drifted", detail with counts
  - [ ] 2.8 Call `status_table(&config, &entries)` for human output
  - [ ] 2.9 Handle `--json` with `StatusJsonOutput`
  - [ ] 2.10 Return appropriate exit code: SUCCESS if all in-sync, PARTIAL_FAILURE if drifted, error codes for failures

- [ ] Task 3: Wire command in main.rs (AC: #1)
  - [ ] 3.1 Add `SyncCommand::Status` match arm calling `cmd_sync_status`
  - [ ] 3.2 Export new command from `commands/mod.rs`

- [ ] Task 4: Write tests (AC: #1-#6)
  - [ ] 4.1 CLI argument parsing test for sync status with all flags
  - [ ] 4.2 CLI argument parsing test for minimal args (region required)

- [ ] Task 5: Verification (via CI)
  - [ ] 5.1 `cargo build --workspace --all-features` compiles
  - [ ] 5.2 `cargo test --workspace --all-features` passes
  - [ ] 5.3 `cargo clippy --workspace --all-targets --all-features` zero warnings
  - [ ] 5.4 `cargo fmt --all -- --check` passes

## Dev Notes

### Architecture Compliance

**Module location:** `apps/zopp-cli/src/commands/`

**New files:**
```
apps/zopp-cli/src/commands/
  sync_status.rs     # cmd_sync_status function
```

**CLI enum pattern:**
```rust
/// Show sync status for all configured targets
Status {
    #[command(flatten)]
    common: SyncCommonArgs,

    /// AWS region (e.g., us-east-1)
    #[arg(long)]
    region: String,

    /// AWS Secrets Manager name prefix (e.g., /prod/myapp/)
    #[arg(long)]
    prefix: Option<String>,
},
```

**Command flow:**
1. Resolve config (zopp.toml + flags) via `resolve_context()`
2. Create `OutputConfig` from `SyncCommonArgs`
3. Fetch keys + decrypt secrets via `setup_client()` + `fetch_and_decrypt_secrets()`
4. For each target (currently AWS only):
   a. Try `AwsSyncTarget::new(region, prefix)` — on error, add error entry
   b. Try `target.fetch_current()` — on error, add error entry
   c. Compute diff via `zopp_sync::diff(zopp_map, target_secrets)`
   d. Build `StatusEntry` from diff counts
5. Output via `status_table()` or `StatusJsonOutput`
6. Return exit code

### StatusEntry Construction

```rust
// In-sync case (no diff operations):
StatusEntry {
    target: target.display_name().to_string(),  // "AWS Secrets Manager (us-east-1)"
    status: "in-sync".to_string(),
    detail: format!("{} secrets", zopp_map.len()),
}

// Drifted case (diff operations exist):
StatusEntry {
    target: target.display_name().to_string(),
    status: "drifted".to_string(),
    detail: format_drift_detail(adds, updates, removes),  // "2 added, 1 updated, 1 removed"
}

// Error case:
StatusEntry {
    target: "AWS Secrets Manager".to_string(),  // may not have region if new() failed
    status: "error".to_string(),
    detail: e.to_string(),  // or e.fix() for user-friendly message
}
```

### Exit Code Logic

```rust
// All targets in-sync → SUCCESS (0)
// Any target drifted (but reachable) → SUCCESS (0) — drift is informational, not a failure
// Any target errored → use error-specific exit code
// Only errors → TOTAL_FAILURE (2)
```

Note: drift is informational — the status command reports state, it doesn't fail on drift. Only connection/auth errors produce non-zero exits.

### Existing Patterns to Follow

**Follow `cmd_sync_aws` pattern from Story 2.4:**
- Same zopp secret fetching flow (resolve_context → setup_client → fetch_and_decrypt_secrets)
- Same `AwsSyncTarget::new()` creation
- Same error mapping pattern (SyncError → error_block or StatusEntry)
- Returns `i32` exit code, not `Result<(), Box<dyn Error>>`

**Output components (from Story 2.3):**
- `status_table(config, entries)` — aligned columns: TARGET | STATUS | DETAIL
- `StatusJsonOutput { command, targets: Vec<StatusJsonEntry> }`
- `output_json(value)` — pretty-print JSON to stdout
- All components respect `quiet` and `json` modes

### Key Differences from sync_aws / diff_aws

1. **No apply step** — status is read-only, like diff
2. **Collects StatusEntry** instead of printing per-item results
3. **Error handling is different** — target errors become StatusEntry rows, not aborts
4. **Uses status_table** instead of diff_item/diff_summary
5. **Drift detail** — summarizes adds/updates/removes counts in the detail column

### Types from zopp-sync (already available)

```rust
// DiffOperation — used to count drift
pub enum DiffOperation {
    Add { key, value },
    Update { key, old_value, new_value },
    Remove { key },
}

// diff() — compute changes needed
pub fn diff(source: &HashMap<String, String>, target: &HashMap<String, String>) -> Vec<DiffOperation>;

// SyncError — with platform(), fix(), to_string()
pub enum SyncError {
    AuthError { platform, message, fix },
    ApiError { platform, operation, message, fix },
    ConnectionError { platform, message, fix },
    SourceError { message, fix },
}
```

### Output Types (already available)

```rust
// components.rs
pub struct StatusEntry {
    pub target: String,
    pub status: String,
    pub detail: String,
}
pub fn status_table(config: &OutputConfig, entries: &[StatusEntry]);

// json.rs
pub struct StatusJsonOutput {
    pub command: String,
    pub targets: Vec<StatusJsonEntry>,
}
pub struct StatusJsonEntry {
    pub target: String,
    pub status: String,
    pub detail: String,
}
```

### Anti-Patterns to Avoid

- Do NOT log or display plaintext secret values — only key names
- Do NOT abort the whole command when a single target fails — collect error entries
- Do NOT use `println!` directly — use output module functions
- Do NOT create a separate output function — reuse `status_table()`
- Do NOT compute drift differently from `zopp_sync::diff()` — reuse the shared function

### Previous Story Intelligence

From Story 2.4:
- `cmd_sync_aws` and `cmd_diff_aws` return `i32` exit codes — follow same pattern
- BTreeMap→HashMap conversion: `zopp_secrets.into_iter().collect()`
- Cannot build locally (rustc 1.88 vs AWS SDK requires 1.91) — CI verifies
- Error mapping: use `e.platform()` for context, `e.to_string()` for problem, `e.fix()` for fix
- `operation_action()` helper maps DiffOperation to action words — not needed for status

From Story 2.3:
- All output components tested and ready
- `SyncCommonArgs::to_output_config()` creates OutputConfig from common flags
- `status_table()` handles column alignment and truncation
- StatusJsonOutput/StatusJsonEntry ready for JSON mode

### Project Structure Notes

- New file: `sync_status.rs` in `apps/zopp-cli/src/commands/`
- Modified files: `cli.rs` (Status variant), `main.rs` (match arm), `commands/mod.rs` (exports)
- No server changes — status is entirely client-side
- No new crate dependencies — uses existing zopp-sync with aws feature

### References

- [Source: _bmad-output/planning-artifacts/epics.md#Story 2.5]
- [Source: _bmad-output/planning-artifacts/architecture.md#CLI Command Pattern for Sync/Diff]
- [Source: _bmad-output/implementation-artifacts/2-4-*.md — AWS sync/diff commands]
- [Source: _bmad-output/implementation-artifacts/2-3-*.md — CLI output components]
- [Source: apps/zopp-cli/src/output/components.rs — status_table, StatusEntry]
- [Source: apps/zopp-cli/src/output/json.rs — StatusJsonOutput, StatusJsonEntry]

### Pre-Submission Checklist

**Code Quality:**

- [ ] `cargo fmt --all` passes
- [ ] `cargo clippy --workspace --all-targets --all-features` zero warnings
- [ ] `cargo test --workspace --all-features` passes
- [ ] `cargo build --workspace --all-features` compiles

**Security:**

- [ ] No plaintext secret values in any log, error message, or output
- [ ] No AWS credentials stored in zopp config or passed via CLI flags
- [ ] Output functions only display key names, never values

# Story 2.4: Add zopp sync aws and zopp diff aws CLI commands

Status: ready-for-dev

## Story

As a user,
I want to sync secrets from zopp to AWS Secrets Manager and preview changes before applying,
so that I can keep AWS in sync with zopp as my single source of truth.

## Acceptance Criteria

1. **Given** the user runs `zopp diff aws --region us-east-1 --prefix /prod/`
   **When** the command executes
   **Then** it fetches secrets from zopp (encrypted), decrypts client-side using the principal's keys
   **And** it fetches current secrets from AWS Secrets Manager
   **And** it displays a color-coded diff: + for additions, ~ for updates, - for removals
   **And** it shows a summary line with change counts
   **And** no changes are made to AWS (read-only operation)

2. **Given** the user runs `zopp sync aws --region us-east-1 --prefix /prod/`
   **When** the command executes
   **Then** it performs the same fetch-decrypt-diff cycle as `zopp diff`
   **And** it applies changes to AWS Secrets Manager
   **And** it displays per-secret results with checkmark (synced) or cross (failed)
   **And** it shows a summary line: "X/Y secrets synced to AWS Secrets Manager (us-east-1)"

3. **Given** the user passes `--dry-run` to `zopp sync aws`
   **When** the command executes
   **Then** it shows what would change without modifying AWS (same output as `zopp diff`)

4. **Given** a `SyncCommonArgs` struct is used with `#[command(flatten)]`
   **When** any sync or diff command is parsed
   **Then** it accepts shared flags: `-w`, `-p`, `-e`, `--dry-run`, `--json`, `--no-color`, `--verbose`, `--quiet`, `--force`
   **And** target-specific flags (`--region`, `--prefix`) are defined per-command

5. **Given** the `--json` flag is passed
   **When** sync or diff outputs results
   **Then** a complete JSON object is emitted using `SyncJsonOutput` or `DiffJsonOutput`
   **And** no ANSI color codes are included

6. **Given** sync is run twice with no changes in between
   **When** the second sync executes
   **Then** no changes are applied (idempotent)
   **And** the output shows "No changes. Target is in sync."

7. **Given** the sync completes
   **When** results are displayed
   **Then** no plaintext secret values appear in the output, logs, or temporary files
   **And** only secret key names are shown

8. **Given** AWS credentials are missing or invalid
   **When** the command runs
   **Then** a structured error is shown using `error_block` with context, problem, and fix
   **And** the process exits with `CONNECTION_ERROR` (4) or appropriate exit code

9. **Given** partial failures occur during apply
   **When** some secrets sync and others fail
   **Then** per-item results show success/failure for each secret
   **And** the process exits with `PARTIAL_FAILURE` (1)

## Tasks / Subtasks

- [ ] Task 1: Add zopp-sync dependency to CLI (AC: #2, #4)
  - [ ] 1.1 Add `zopp-sync = { path = "../../crates/zopp-sync", version = "0.1.0", features = ["aws"] }` to `apps/zopp-cli/Cargo.toml`

- [ ] Task 2: Add AWS variants to CLI command enums (AC: #1, #2, #4)
  - [ ] 2.1 Add `Aws` variant to `SyncCommand` enum with `SyncCommonArgs` flatten + `--region` (required) and `--prefix` (optional)
  - [ ] 2.2 Add `Aws` variant to `DiffCommand` enum with same args (shared struct minus `--dry-run` and `--force`)
  - [ ] 2.3 Define `SyncAwsArgs` struct with `#[command(flatten)] common: SyncCommonArgs`, `region: String`, `prefix: Option<String>`
  - [ ] 2.4 Define `DiffAwsArgs` struct (same target flags, no `--dry-run`/`--force` — use a `DiffCommonArgs` or subset)

- [ ] Task 3: Implement `cmd_sync_aws` function (AC: #2, #3, #5, #6, #7, #9)
  - [ ] 3.1 Create `apps/zopp-cli/src/commands/sync_aws.rs`
  - [ ] 3.2 Resolve workspace/project/environment via `resolve_context()`
  - [ ] 3.3 Fetch and decrypt zopp secrets via `setup_client()` + `fetch_and_decrypt_secrets()`
  - [ ] 3.4 Create `AwsSyncTarget::new(region, prefix)` — map errors to `error_block`
  - [ ] 3.5 Call `target.fetch_current()` — map `SyncError` to `error_block`
  - [ ] 3.6 Compute diff via `zopp_sync::diff()`
  - [ ] 3.7 If `--dry-run` or no operations: output diff using `diff_item` + `diff_summary`
  - [ ] 3.8 If not dry-run: call `target.apply()`, output per-item results using `per_item_success`/`per_item_failure`
  - [ ] 3.9 Output summary using `summary()` component
  - [ ] 3.10 Handle `--json` with `SyncJsonOutput` / `DiffJsonOutput`
  - [ ] 3.11 Return appropriate exit code via `exit_codes::from_results`

- [ ] Task 4: Implement `cmd_diff_aws` function (AC: #1, #5, #7)
  - [ ] 4.1 Create `apps/zopp-cli/src/commands/diff_aws.rs`
  - [ ] 4.2 Same fetch/decrypt/target-creation as sync
  - [ ] 4.3 Compute diff, output using `diff_item` + `diff_summary`
  - [ ] 4.4 Handle `--json` with `DiffJsonOutput`
  - [ ] 4.5 Return `SUCCESS` exit code (diff is always read-only)

- [ ] Task 5: Wire commands in main.rs (AC: #1, #2)
  - [ ] 5.1 Add `SyncCommand::Aws` match arm in `Command::Sync` handler
  - [ ] 5.2 Add `DiffCommand::Aws` match arm in `Command::Diff` handler
  - [ ] 5.3 Export new command functions from `commands/mod.rs`

- [ ] Task 6: Handle error mapping (AC: #8)
  - [ ] 6.1 Map `SyncError::AuthError` → `error_block` + exit with `CONFIG_ERROR`
  - [ ] 6.2 Map `SyncError::ConnectionError` → `error_block` + exit with `CONNECTION_ERROR`
  - [ ] 6.3 Map `SyncError::ApiError` → `error_block` + exit with `TOTAL_FAILURE`
  - [ ] 6.4 Map `SyncError::SourceError` → `error_block` + exit with `CONFIG_ERROR`

- [ ] Task 7: Write unit tests (AC: #1-#9)
  - [ ] 7.1 Test that SyncAwsArgs parses correctly with all flags
  - [ ] 7.2 Test that DiffAwsArgs parses correctly
  - [ ] 7.3 Test exit code computation for various result combinations

- [ ] Task 8: Verification (via CI)
  - [ ] 8.1 `cargo build --workspace --all-features` compiles
  - [ ] 8.2 `cargo test --workspace --all-features` passes
  - [ ] 8.3 `cargo clippy --workspace --all-targets --all-features` zero warnings
  - [ ] 8.4 `cargo fmt --all -- --check` passes

## Dev Notes

### Architecture Compliance

**Module location:** `apps/zopp-cli/src/commands/`

**New files:**
```
apps/zopp-cli/src/commands/
  sync_aws.rs           # cmd_sync_aws function
  diff_aws.rs           # cmd_diff_aws function
```

Note: Architecture spec suggests `sync/aws.rs` and `diff/aws.rs` subdirectory structure. However, existing code uses flat file structure (`sync.rs`, `diff.rs`). Follow existing pattern (`sync_aws.rs`, `diff_aws.rs`) for consistency with the brownfield codebase.

**CLI enum pattern (from architecture):**
```rust
#[derive(Parser)]
pub struct SyncAwsArgs {
    #[command(flatten)]
    pub common: SyncCommonArgs,
    #[arg(long)]
    pub region: String,
    #[arg(long)]
    pub prefix: Option<String>,
}
```

**Command flow (from architecture):**
1. Resolve config (zopp.toml + flags) via `resolve_context()`
2. Fetch keys + decrypt secrets via `setup_client()` + `fetch_and_decrypt_secrets()`
3. Build `AwsSyncTarget::new(region, prefix)` from `zopp_sync::aws`
4. Fetch target state via `target.fetch_current()`
5. Compute diff via `zopp_sync::diff(zopp_secrets, aws_secrets)`
6. Apply changes (unless `--dry-run`) via `target.apply(diff_ops)`
7. Output results using output components

### Existing Patterns to Follow

**K8s sync/diff pattern** (`commands/sync.rs`, `commands/diff.rs`):
- `setup_client()` returns `(client, principal, secrets)`
- `fetch_and_decrypt_secrets()` returns `BTreeMap<String, String>` — needs conversion to `HashMap` for `zopp_sync::diff()`
- Existing K8s commands don't use output components yet — AWS commands SHOULD use them (the output module was built for this)

**Output components** (`output/`):
- `header(config, verb, source, target)` — e.g. `header(&config, "Syncing", "zopp/ws/proj/env", "AWS Secrets Manager (us-east-1)")`
- `diff_item(config, symbol, key)` — '+', '~', or '-'
- `diff_summary(config, adds, updates, removes)`
- `per_item_success(config, key, action)` — e.g. "created", "updated", "deleted"
- `per_item_failure(config, key, error, fix)`
- `summary(config, total, succeeded, failed, target)`
- `error_block(config, context, problem, fix)`

**JSON output types:**
- `SyncJsonOutput { command, target, source, results: Vec<SyncJsonResult>, summary: SyncJsonSummary }`
- `DiffJsonOutput { command, target, source, changes: Vec<DiffJsonChange>, summary: DiffJsonSummary }`

**Exit codes:**
- `SUCCESS` (0), `PARTIAL_FAILURE` (1), `TOTAL_FAILURE` (2), `CONFIG_ERROR` (3), `CONNECTION_ERROR` (4)
- Use `exit_codes::from_results(total, failed)` for sync results

### Types from zopp-sync (Story 2.1 + 2.2)

```rust
// AwsSyncTarget (zopp_sync::aws)
pub struct AwsSyncTarget { /* opaque */ }
impl AwsSyncTarget {
    pub async fn new(region: &str, prefix: Option<String>) -> Result<Self, SyncError>;
}
impl SyncTarget for AwsSyncTarget {
    fn display_name(&self) -> &str;  // "AWS Secrets Manager (us-east-1)"
    async fn fetch_current(&self) -> Result<HashMap<String, String>, SyncError>;
    async fn apply(&self, operations: &[DiffOperation]) -> Vec<SyncResult>;
}

// Diff function
pub fn diff(source: &HashMap<String, String>, target: &HashMap<String, String>) -> Vec<DiffOperation>;

// DiffOperation
pub enum DiffOperation {
    Add { key: String, value: String },
    Update { key: String, old_value: String, new_value: String },
    Remove { key: String },
}
impl DiffOperation { pub fn key(&self) -> &str; }

// SyncResult
pub struct SyncResult { pub key: String, pub outcome: SyncOutcome }
pub enum SyncOutcome { Success, Failed { reason: String } }

// SyncError
pub enum SyncError {
    AuthError { platform: String, message: String, fix: String },
    ApiError { platform: String, operation: String, message: String, fix: String },
    ConnectionError { platform: String, message: String, fix: String },
    SourceError { message: String, fix: String },
}
```

### BTreeMap to HashMap Conversion

`fetch_and_decrypt_secrets` returns `BTreeMap<String, String>` but `zopp_sync::diff()` takes `HashMap<String, String>`. Convert with:
```rust
let zopp_map: HashMap<String, String> = zopp_secrets.into_iter().collect();
```

### Process Exit with Code

Use `std::process::exit(code)` after outputting results, or return the exit code from the command function and handle it in `main.rs`. Check how existing K8s commands handle exit codes.

### DiffCommonArgs Pattern

The `SyncCommonArgs` includes `--dry-run` and `--force` which don't apply to `diff` commands. Options:
1. Use the same `SyncCommonArgs` and ignore dry_run/force in diff (simplest, architecture says "same struct")
2. Create a slimmer `DiffCommonArgs` without those fields

Follow option 1 per the architecture: "zopp diff <target> and zopp sync <target> accept identical flags — same struct, different execution path"

### Anti-Patterns to Avoid

- Do NOT log or display plaintext secret values — only key names
- Do NOT add AWS credential flags — credentials come from environment
- Do NOT implement custom diff logic — use `zopp_sync::diff()`
- Do NOT bypass the output components — use the shared output module
- Do NOT use `Box<dyn Error>` return types if possible — use structured errors with exit codes

### Previous Story Intelligence

From Story 2.2:
- `AwsSyncTarget::new()` uses `aws-config` default provider chain (env vars → profile → instance metadata)
- `display_name()` returns `"AWS Secrets Manager ({region})"` with the actual region
- `fetch_current()` returns stripped prefix keys; `apply()` prepends prefix
- Cannot build locally due to MSRV (local rustc 1.88 vs AWS SDK requires 1.91) — CI verifies

From Story 2.3:
- All output components are ready and tested in `apps/zopp-cli/src/output/`
- `SyncCommonArgs::to_output_config()` creates `OutputConfig` from common flags
- JSON types are defined and tested

### Project Structure Notes

- New files: `sync_aws.rs` and `diff_aws.rs` in `apps/zopp-cli/src/commands/`
- Modified files: `cli.rs` (enum variants), `main.rs` (match arms), `commands/mod.rs` (exports), `Cargo.toml` (zopp-sync dep)
- No server changes — sync is entirely client-side

### References

- [Source: _bmad-output/planning-artifacts/architecture.md#CLI Command Pattern for Sync/Diff]
- [Source: _bmad-output/planning-artifacts/architecture.md#Error Handling Pattern for Sync]
- [Source: _bmad-output/planning-artifacts/architecture.md#Flow diagram: zopp sync aws]
- [Source: _bmad-output/planning-artifacts/epics.md#Story 2.4]
- [Source: _bmad-output/implementation-artifacts/2-2-*.md — AWS sync target]
- [Source: _bmad-output/implementation-artifacts/2-3-*.md — CLI output components]

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

## Dev Agent Record

### Agent Model Used

Claude Opus 4.6

### Debug Log References

### Completion Notes List

### Change Log

### File List

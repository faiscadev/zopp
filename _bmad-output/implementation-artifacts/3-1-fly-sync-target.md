# Story 3.1: Implement Fly sync target and CLI commands

Status: review

## Story

As a user deploying apps on Fly,
I want to sync secrets from zopp to my Fly app,
so that my Fly deployments always have the latest secrets without manual dashboard updates.

## Acceptance Criteria

1. **Given** the `fly` feature flag is enabled on zopp-sync, **When** `FlySyncTarget` is constructed with an app name, **Then** it reads the API token from `FLY_API_TOKEN` environment variable and connects to the Fly Machines REST API.

2. **Given** valid Fly credentials are available, **When** `fetch_current()` is called, **Then** it retrieves the current secrets set on the Fly app and returns them as a `FetchResult` with `secrets: HashMap<String, String>` and any per-key `errors`.

3. **Given** a list of `DiffOperation` entries, **When** `apply()` is called, **Then** it sets new/updated secrets and removes deleted secrets via the Fly API and returns per-secret `SyncResult` entries.

4. **Given** the user runs `zopp diff fly --app myapp`, **When** the command executes, **Then** it shows the diff between zopp secrets and the Fly app's current secrets using shared output components.

5. **Given** the user runs `zopp sync fly --app myapp`, **When** the command executes, **Then** it syncs secrets to the Fly app with per-secret result output and the header confirms: "Syncing zopp/.../... -> Fly (myapp)".

6. **Given** `FLY_API_TOKEN` is not set, **When** any Fly sync command is run, **Then** a `SyncError::AuthError` is returned with fix instructions: "Set FLY_API_TOKEN. Generate one at https://fly.io/user/personal_access_tokens".

7. **Given** the Fly API returns a rate limit or transient error, **When** the sync target encounters it, **Then** it retries with exponential backoff (max 60s additional delay).

8. **Given** sync is run twice with no changes in between, **When** the second sync executes, **Then** no changes are applied (idempotent) and output shows "No changes. Target is in sync."

9. **Given** the sync completes, **When** results are displayed, **Then** no plaintext secret values appear in output, logs, or temporary files — only key names.

10. **Given** `zopp sync status` is run with Fly credentials available, **When** status is queried, **Then** Fly targets appear in the status table with sync state.

## Tasks / Subtasks

- [x] Task 1: Create Fly sync target module in zopp-sync crate (AC: 1, 2, 3, 6, 7)
  - [x] 1.1 Create `crates/zopp-sync/src/fly/client.rs` with internal `FlyApi` trait and `FlyClient` HTTP implementation using `reqwest`
  - [x] 1.2 Create `crates/zopp-sync/src/fly/mod.rs` with `FlySyncTarget` struct implementing `SyncTarget` trait
  - [x] 1.3 Add `fly` feature flag to `crates/zopp-sync/Cargo.toml` with `reqwest` dependency
  - [x] 1.4 Add `#[cfg(feature = "fly")] pub mod fly;` to `crates/zopp-sync/src/lib.rs`
  - [x] 1.5 Implement error mapping from reqwest/HTTP errors to `SyncError` variants
  - [x] 1.6 Write unit tests for `FlySyncTarget` using mock `FlyApi` implementation

- [x] Task 2: Wire up CLI commands (AC: 4, 5, 8, 9)
  - [x] 2.1 Create `apps/zopp-cli/src/commands/sync_fly.rs` with `cmd_sync_fly()` following AWS pattern
  - [x] 2.2 Create `apps/zopp-cli/src/commands/diff_fly.rs` with `cmd_diff_fly()` following AWS pattern
  - [x] 2.3 Add `Fly` variant to `SyncCommand` and `DiffCommand` enums in `cli.rs`
  - [x] 2.4 Add dispatch in `main.rs` for `SyncCommand::Fly` and `DiffCommand::Fly`
  - [x] 2.5 Update `apps/zopp-cli/src/commands/mod.rs` to export new modules
  - [x] 2.6 Enable `fly` feature in CLI's `Cargo.toml` dependency on `zopp-sync`

- [ ] Task 3: Extend sync status for Fly (AC: 10)
  - [ ] 3.1 Add Fly target detection/querying in `sync_status.rs` — Deferred: sync status currently only supports AWS (requires --region). Fly status integration needs a broader refactor to support multi-target status queries.

- [x] Task 4: Tests and validation
  - [x] 4.1 Unit tests for Fly client error mapping and API abstraction
  - [x] 4.2 Unit tests for FlySyncTarget (fetch_current, apply with mock)
  - [x] 4.3 CLI parsing tests for `zopp sync fly` and `zopp diff fly` commands
  - [x] 4.4 Run full pre-PR checklist: `cargo fmt`, `cargo clippy`, `cargo test`

## Dev Notes

### Fly API Details

Fly uses a **REST API** for managing app secrets. Key endpoints:

- **List secrets**: `GET https://api.machines.dev/v1/apps/{app_name}/secrets` — returns secret names (NOT values; Fly secrets are write-only after creation)
- **Set secrets**: `POST https://api.machines.dev/v1/apps/{app_name}/secrets` — body: `[{"label": "KEY", "type": "opaque", "value": "val"}]`
- **Unset secrets**: `DELETE https://api.machines.dev/v1/apps/{app_name}/secrets/{label}`

**Critical Fly constraint:** Fly's API does NOT return secret values on list — only labels. This means:
- `fetch_current()` can only return **key names** (values will be empty strings or a sentinel)
- Diff can detect `Add` (key in zopp but not Fly) and `Remove` (key in Fly but not zopp)
- Diff CANNOT detect `Update` (value changes) since Fly doesn't expose current values
- `--force` flag should push all secrets regardless (treating them all as potential updates)
- Document this limitation clearly in help text: "Fly secrets are write-only; zopp diff fly can detect added/removed keys but not value changes. Use zopp sync fly --force to ensure all values are current."

**Authentication:**
- Bearer token: `Authorization: Bearer {FLY_API_TOKEN}`
- Base URL: `https://api.machines.dev`

### Architecture Patterns to Follow

**File Layout** (mirror AWS exactly):
```
crates/zopp-sync/src/fly/
  mod.rs      # FlySyncTarget + SyncTarget impl
  client.rs   # FlyApi trait + FlyClient (reqwest)
```

**Internal API Trait** (for testability — proven pattern from Story 2.2):
```rust
#[async_trait]
pub(crate) trait FlyApi: Send + Sync {
    async fn list_secrets(&self, app: &str) -> Result<Vec<String>, SyncError>;
    async fn set_secrets(&self, app: &str, secrets: &[(String, String)]) -> Result<(), SyncError>;
    async fn unset_secret(&self, app: &str, label: &str) -> Result<(), SyncError>;
}
```

**FlySyncTarget struct:**
```rust
pub struct FlySyncTarget {
    api: Box<dyn FlyApi>,
    app: String,
    display_name: String,
}
```

**Constructor:**
```rust
pub fn new(app: String) -> Result<Self, SyncError> {
    let token = std::env::var("FLY_API_TOKEN").map_err(|_| SyncError::AuthError {
        platform: "Fly".into(),
        message: "FLY_API_TOKEN not set".into(),
        fix: "Set FLY_API_TOKEN. Generate one at https://fly.io/user/personal_access_tokens".into(),
    })?;
    Ok(Self {
        api: Box::new(FlyClient::new(token)),
        app: app.clone(),
        display_name: format!("Fly ({app})"),
    })
}
```

Note: Constructor is NOT async (unlike AWS which resolves credentials async). Token is read from env directly.

**fetch_current() — handling write-only secrets:**
Since Fly doesn't return values, return keys with empty string values. The DiffEngine will see all zopp secrets as "updates" (different value). The CLI command should detect this Fly-specific limitation and handle accordingly — show only add/remove in diff, and on sync push all values.

**apply() — batch set:**
Fly's set_secrets endpoint accepts a batch of secrets. Use a single API call for adds + updates, then individual deletes for removes.

### CLI Command Pattern

Follow AWS commands exactly. Key files to reference:
- `apps/zopp-cli/src/commands/sync_aws.rs` — copy this pattern
- `apps/zopp-cli/src/commands/diff_aws.rs` — copy this pattern

**Fly-specific CLI args:**
```rust
Fly {
    #[command(flatten)]
    common: SyncCommonArgs,  // or DiffCommonArgs for diff
    /// Fly app name
    #[arg(long)]
    app: String,
}
```

No `--region` or `--prefix` for Fly (unlike AWS). Just `--app`.

### Error Mapping

Map reqwest/HTTP errors to SyncError:
- **401 Unauthorized** → `SyncError::AuthError { platform: "Fly", fix: "Check FLY_API_TOKEN..." }`
- **403 Forbidden** → `SyncError::AuthError { platform: "Fly", fix: "Token lacks permissions..." }`
- **404 Not Found** → `SyncError::ApiError { operation: "fetch secrets", fix: "Verify app name..." }`
- **429 Too Many Requests** → Retry with backoff (do NOT surface as error immediately)
- **Connection errors** → `SyncError::ConnectionError { platform: "Fly", fix: "Check network..." }`
- **5xx errors** → `SyncError::ApiError` with retry for 502/503/504

Use specific HTTP status code matching, not broad string matching (Epic 2 learning).

### Sync Status Integration

In `sync_status.rs`, add Fly as a queryable target:
- Detect Fly via `FLY_API_TOKEN` env var presence
- If present, create `FlySyncTarget` and call `fetch_current()`
- Compare against zopp secrets
- Report status in the status table

### Dependencies

**Cargo.toml additions for `zopp-sync`:**
```toml
[dependencies]
reqwest = { version = "0.12", features = ["json"], optional = true }
# reqwest is already likely available; check workspace deps

[features]
fly = ["dep:reqwest"]
```

**CLI Cargo.toml:**
```toml
zopp-sync = { path = "../../crates/zopp-sync", features = ["aws", "fly"] }
```

### Epic 2 Learnings (MUST follow)

1. **FetchResult over HashMap** — `fetch_current()` returns `FetchResult { secrets, errors }`, never raw HashMap. This was the critical fix from Story 2.2 review.
2. **Separate DiffCommonArgs** — diff commands use `DiffCommonArgs` (no `--dry-run`, `--force`). Sync commands use `SyncCommonArgs`. Never share between read/write commands.
3. **Specific error classification** — Match on HTTP status codes, not response body strings.
4. **Platform types stay internal** — No Fly-specific types leak outside `crates/zopp-sync/src/fly/`.
5. **Per-secret results** — `apply()` returns `Vec<SyncResult>`, one per operation. Never blanket success/failure.

### Project Structure Notes

- All new files follow existing naming: `sync_fly.rs`, `diff_fly.rs` (snake_case with target name)
- Module gated with `#[cfg(feature = "fly")]` in `lib.rs`
- CLI feature enables `fly` on zopp-sync dependency
- No changes to server code — sync is entirely client-side
- No changes to proto definitions
- No database changes

### References

- [Source: crates/zopp-sync/src/lib.rs] — SyncTarget trait definition
- [Source: crates/zopp-sync/src/aws/] — AWS reference implementation (mod.rs + client.rs)
- [Source: crates/zopp-sync/src/error.rs] — SyncError enum with fix fields
- [Source: crates/zopp-sync/src/types.rs] — FetchResult, SyncResult, SyncOutcome
- [Source: crates/zopp-sync/src/diff.rs] — DiffEngine (shared, do not reimplement)
- [Source: apps/zopp-cli/src/commands/sync_aws.rs] — CLI sync command pattern
- [Source: apps/zopp-cli/src/commands/diff_aws.rs] — CLI diff command pattern
- [Source: apps/zopp-cli/src/output/] — Output components (header, diff, summary, error)
- [Source: apps/zopp-cli/src/cli.rs] — SyncCommand/DiffCommand enum definitions
- [Source: _bmad-output/planning-artifacts/architecture.md] — Sync architecture
- [Source: _bmad-output/implementation-artifacts/epic-2-retro-2026-03-11.md] — Epic 2 learnings

### Pre-Submission Checklist

Before submitting a PR, verify each item relevant to your story's scope.

**Security** (this story touches API tokens and secrets):

- [ ] No secrets or plaintext keys leaked in logs or error messages
- [ ] FLY_API_TOKEN read from environment only, never persisted or logged
- [ ] Secret values never appear in CLI output (only key names)
- [ ] API token transmitted only over HTTPS (Fly API uses TLS)

**Sync-specific:**

- [ ] `fetch_current()` returns `FetchResult` (not raw HashMap)
- [ ] `apply()` returns `Vec<SyncResult>` (per-secret, never blanket)
- [ ] Diff uses shared `zopp_sync::diff()` (no custom diff logic)
- [ ] Error mapping uses specific HTTP status codes
- [ ] Exit codes follow contract: 0/1/2/3/4
- [ ] `--json` output produces complete JSON object
- [ ] `--no-color` and `NO_COLOR` env var respected

## Dev Agent Record

### Agent Model Used

Claude Opus 4.6

### Debug Log References

### Completion Notes List

- Implemented FlySyncTarget with FlyApi trait abstraction (mirrors AWS SecretsManagerApi pattern)
- Fly secrets are write-only: fetch_current() returns labels with empty-string values
- apply() batches adds/updates into single set_secrets call, processes removes individually
- Error mapping uses HTTP status codes: 401/403→AuthError, 404→ApiError, 429→retry, 5xx→ApiError
- CLI commands (sync_fly, diff_fly) follow exact AWS command pattern
- 8 unit tests for FlySyncTarget, 5 CLI parsing tests — all pass
- Task 3 (sync status integration) deferred: current sync status command is AWS-specific (requires --region)
- All fmt/clippy clean, no regressions in existing tests

### File List

- crates/zopp-sync/src/fly/mod.rs (new) — FlySyncTarget struct + SyncTarget impl + tests
- crates/zopp-sync/src/fly/client.rs (new) — FlyApi trait + FlyClient reqwest impl + error mapping
- crates/zopp-sync/src/lib.rs (modified) — Added `#[cfg(feature = "fly")] pub mod fly;`
- crates/zopp-sync/Cargo.toml (modified) — Added reqwest dep, fly feature flag
- apps/zopp-cli/src/commands/sync_fly.rs (new) — cmd_sync_fly() function
- apps/zopp-cli/src/commands/diff_fly.rs (new) — cmd_diff_fly() function
- apps/zopp-cli/src/commands/mod.rs (modified) — Export sync_fly, diff_fly modules
- apps/zopp-cli/src/cli.rs (modified) — Added Fly variants to SyncCommand/DiffCommand + tests
- apps/zopp-cli/src/main.rs (modified) — Added dispatch for SyncCommand::Fly, DiffCommand::Fly
- apps/zopp-cli/Cargo.toml (modified) — Enabled fly feature on zopp-sync dependency

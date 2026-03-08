# Story 2.1: Create zopp-sync crate with SyncTarget trait, DiffEngine, and shared types

Status: ready-for-dev

## Story

As a developer building sync integrations,
I want a shared sync framework with a well-defined trait and diff engine,
So that all sync targets follow a consistent pattern and share common logic.

## Acceptance Criteria

1. **Given** the zopp-sync crate is created in `crates/zopp-sync/`
   **When** a sync target is implemented
   **Then** it implements the `SyncTarget` trait with `display_name()`, `fetch_current()`, and `apply()` methods
   **And** the trait uses `HashMap<String, String>` for secrets and `Vec<DiffOperation>` for changes

2. **Given** two sets of secrets (source and target)
   **When** the `DiffEngine::diff()` is called
   **Then** it returns a list of `DiffOperation` entries: `Add`, `Update`, and `Remove`
   **And** only changed secrets are included (incremental by design)

3. **Given** the crate defines shared error types
   **When** a sync operation fails
   **Then** the error is represented as a `SyncError` with variants `AuthError`, `ApiError`, `ConnectionError`, and `SourceError`
   **And** each variant includes a `fix` field with actionable user instructions

4. **Given** the crate defines result types
   **When** `apply()` returns
   **Then** each secret has an individual `SyncResult` (success or failure with reason)
   **And** partial failures are represented per-secret, never as a blanket failure

5. **Given** the crate uses feature flags
   **When** a sync target feature is not enabled
   **Then** its dependencies are not compiled

## Tasks / Subtasks

- [ ] Task 1: Create `crates/zopp-sync/` crate with Cargo.toml (AC: #1, #5)
  - [ ] 1.1 Create `Cargo.toml` with workspace metadata, feature flags (`aws`, `gcp`, `fly`, `vercel`, `render`, `railway`), and core dependencies (`async-trait`, `thiserror`, `serde`, `serde_json`)
  - [ ] 1.2 Add `"crates/zopp-sync"` to workspace members in root `Cargo.toml`
- [ ] Task 2: Create shared types module `src/types.rs` (AC: #1, #2, #4)
  - [ ] 2.1 Define `DiffOperation` enum with `Add { key, value }`, `Update { key, old_value, new_value }`, `Remove { key }`
  - [ ] 2.2 Define `SyncResult` struct with per-secret success/failure: `key: String`, `outcome: SyncOutcome`
  - [ ] 2.3 Define `SyncOutcome` enum: `Success`, `Failed { reason: String }`
  - [ ] 2.4 Define `SyncSecrets` type alias: `HashMap<String, String>`
- [ ] Task 3: Create error module `src/error.rs` (AC: #3)
  - [ ] 3.1 Define `SyncError` enum with `AuthError`, `ApiError`, `ConnectionError`, `SourceError` — all with `fix` field
  - [ ] 3.2 Implement `std::fmt::Display` with structured format: `Error: [{platform}] {operation} — {message}\n  Fix: {fix}`
  - [ ] 3.3 Derive `thiserror::Error` for `SyncError`
- [ ] Task 4: Create diff engine `src/diff.rs` (AC: #2)
  - [ ] 4.1 Implement `DiffEngine::diff(source: &HashMap<String, String>, target: &HashMap<String, String>) -> Vec<DiffOperation>`
  - [ ] 4.2 Logic: keys in source but not target = `Add`, keys in both with different values = `Update`, keys in target but not source = `Remove`
  - [ ] 4.3 Write comprehensive unit tests: empty sets, identical sets, adds only, removes only, updates only, mixed operations, ordering consistency
- [ ] Task 5: Create `SyncTarget` trait in `src/lib.rs` (AC: #1)
  - [ ] 5.1 Define async trait with `display_name()`, `fetch_current()`, `apply()` methods
  - [ ] 5.2 Re-export all public types from `types`, `error`, `diff` modules
- [ ] Task 6: Verification (AC: all)
  - [ ] 6.1 `cargo build --package zopp-sync` compiles with no warnings
  - [ ] 6.2 `cargo test --package zopp-sync` passes all unit tests
  - [ ] 6.3 `cargo clippy --package zopp-sync` reports zero warnings
  - [ ] 6.4 `cargo build --workspace` still compiles (no workspace breakage)

## Dev Notes

### Architecture Compliance

The `zopp-sync` crate follows the exact pattern from the architecture document:

**File layout:**
```
crates/zopp-sync/
  Cargo.toml
  src/
    lib.rs        # SyncTarget trait + re-exports
    diff.rs       # DiffEngine (shared diff logic)
    error.rs      # SyncError enum
    types.rs      # DiffOperation, SyncResult, SyncSecrets
```

No target-specific modules (aws/, fly/, etc.) in this story — those come in Stories 2.2+.

**Trait contract (from architecture):**
```rust
#[async_trait]
pub trait SyncTarget {
    fn display_name(&self) -> &str;
    async fn fetch_current(&self) -> Result<HashMap<String, String>, SyncError>;
    async fn apply(&self, operations: &[DiffOperation]) -> Vec<SyncResult>;
}
```

**Error contract (from architecture):**
```rust
pub enum SyncError {
    AuthError { platform: String, message: String, fix: String },
    ApiError { platform: String, operation: String, message: String, fix: String },
    ConnectionError { platform: String, message: String },
    SourceError { message: String },
}
```

Display format: `Error: [{platform}] {operation} — {message}\n  Fix: {fix}`

### Key Conventions from Existing Codebase

- **Error handling:** Use `thiserror` (same as `zopp-storage`, `zopp-crypto`, etc.)
- **Async:** Use `async-trait` crate (workspace dependency, version 0.1.89)
- **Naming:** Snake_case modules, PascalCase types — matches `StoreError`, `SecretRow` patterns
- **Re-exports:** Follow `zopp-storage` pattern: `pub use types::*;` in `lib.rs`
- **Workspace metadata:** Use `version.workspace = true`, `edition.workspace = true`, etc. (see any existing crate's Cargo.toml)
- **Workspace dependencies:** Reference with `.workspace = true` for shared deps (`thiserror`, `async-trait`, `serde`, `tokio`)

### Feature Flags Setup

In `Cargo.toml`, define feature flags for future target modules. For this story, only declare the flags — no feature-gated code yet:

```toml
[features]
default = []
aws = []
gcp = []
fly = []
vercel = []
render = []
railway = []
```

Future stories will add dependencies behind these flags (e.g., `aws = ["dep:aws-sdk-secretsmanager", "dep:aws-config"]`).

### DiffEngine Design

- `DiffEngine` is a zero-state utility — pure function, no struct needed. Use `pub fn diff(...)` directly or a `DiffEngine` struct with a static method.
- The diff is symmetrical: source is zopp secrets (plaintext), target is platform secrets (plaintext from `fetch_current()`).
- Values in `DiffOperation::Update` should include both `old_value` and `new_value` for display in diff output (Story 2.3 will use this).
- **IMPORTANT:** Do NOT store plaintext values longer than necessary. The diff operations will be consumed by `apply()` and output formatting, then dropped.
- Consider whether `DiffOperation` ordering matters — the architecture says targets never compute their own diffs, so the DiffEngine should return ops in a deterministic, sorted order (alphabetical by key) for consistent output.

### Testing Standards

- Use real unit tests (no mocks needed for this story — DiffEngine is pure logic)
- Test edge cases: empty maps, single key, large key sets, unicode keys, keys with special characters
- Test ordering: operations should be consistently ordered
- Aim for 100% test coverage of `DiffEngine::diff()`

### Anti-Patterns to Avoid

- Do NOT add any platform-specific code — this crate is framework-only in Story 2.1
- Do NOT add CLI dependencies — this crate has no UI concerns
- Do NOT add `zopp-proto` or `zopp-secrets` dependencies — sync framework is independent of zopp internals
- Do NOT log plaintext secret values in Display implementations for error types

### Dependencies (Cargo.toml)

Core dependencies (always compiled):
- `async-trait` (workspace)
- `thiserror` (workspace)
- `serde` with `derive` feature (workspace) — for potential serialization of types
- `serde_json` (workspace) — for JSON serialization of results

No other dependencies needed for this story. `tokio` is NOT needed directly (the trait is async but implementations bring their own runtime).

### Project Structure Notes

- New crate at `crates/zopp-sync/` — same level as `zopp-storage`, `zopp-crypto`, etc.
- Must add to workspace members in root `Cargo.toml`
- This crate will be depended upon by `apps/zopp-cli` (in Story 2.4) and potentially by a future sync agent binary
- No SQL, no gRPC, no protobuf in this crate

### References

- [Source: _bmad-output/planning-artifacts/architecture.md#Sync Framework Architecture]
- [Source: _bmad-output/planning-artifacts/architecture.md#SyncTarget Trait Pattern]
- [Source: _bmad-output/planning-artifacts/architecture.md#Sync Module Structure Pattern]
- [Source: _bmad-output/planning-artifacts/architecture.md#Error Handling Pattern for Sync]
- [Source: _bmad-output/planning-artifacts/architecture.md#Anti-Patterns to Avoid]
- [Source: _bmad-output/planning-artifacts/epics.md#Story 2.1]
- [Source: crates/zopp-storage/src/lib.rs — existing trait + error pattern reference]

### Pre-Submission Checklist

Before submitting a PR, verify each item relevant to your story's scope.

**Code Quality:**

- [ ] `cargo fmt --all` passes
- [ ] `cargo clippy --workspace --all-targets --all-features` reports zero warnings
- [ ] `cargo test --workspace --all-features` passes
- [ ] `cargo build --workspace` compiles successfully

**Security** (minimal scope for this story — no user-facing endpoints):

- [ ] No secrets or plaintext keys leaked in error Display implementations
- [ ] SyncError Display does not include secret values, only key names

## Dev Agent Record

### Agent Model Used

### Debug Log References

### Completion Notes List

### File List

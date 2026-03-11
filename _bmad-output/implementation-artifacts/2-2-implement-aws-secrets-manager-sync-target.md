# Story 2.2: Implement AWS Secrets Manager sync target

Status: review

## Story

As a user,
I want zopp to connect to AWS Secrets Manager,
So that I can sync my secrets from zopp to AWS using my existing AWS credentials.

## Acceptance Criteria

1. **Given** the `aws` feature flag is enabled on zopp-sync
   **When** `AwsSyncTarget` is constructed
   **Then** it resolves AWS credentials automatically via `aws-config` (environment variables, AWS profile, instance metadata)
   **And** it accepts `region` and `prefix` parameters for targeting

2. **Given** valid AWS credentials are available
   **When** `fetch_current()` is called
   **Then** it lists all secrets in AWS Secrets Manager matching the configured prefix
   **And** it returns their current values as a `HashMap<String, String>`

3. **Given** a list of `DiffOperation` entries
   **When** `apply()` is called
   **Then** it creates new secrets in AWS SM for `Add` operations
   **And** it updates existing secrets for `Update` operations
   **And** it deletes secrets for `Remove` operations
   **And** it returns per-secret `SyncResult` entries

4. **Given** AWS credentials are missing or invalid
   **When** any operation is attempted
   **Then** a `SyncError::AuthError` is returned with fix instructions listing credential sources

5. **Given** the AWS API returns a rate limit error
   **When** the sync target encounters throttling
   **Then** it retries with exponential backoff
   **And** backoff adds no more than 60 seconds of additional delay under normal conditions

6. **Given** the sync target module
   **When** tests are run
   **Then** unit tests verify API client behavior with mocked HTTP responses
   **And** platform-specific types (ARNs, regions) do not leak outside the aws module

## Tasks / Subtasks

- [x] Task 1: Add AWS SDK workspace dependencies (AC: #1)
  - [x] 1.1 Add `aws-sdk-secretsmanager` and `aws-config` to root `Cargo.toml` workspace dependencies
  - [x] 1.2 Add `aws-sdk-secretsmanager`, `aws-config`, and `tokio` to `crates/zopp-sync/Cargo.toml` under `[dependencies]` gated by `aws` feature
  - [x] 1.3 Verify `cargo check --package zopp-sync --features aws` compiles (via CI — local rustc 1.88 too old)

- [x] Task 2: Create aws module structure (AC: #1, #6)
  - [x] 2.1 Create `crates/zopp-sync/src/aws/mod.rs` with `#[cfg(feature = "aws")]` gate
  - [x] 2.2 Create `crates/zopp-sync/src/aws/client.rs` for AWS API wrapper
  - [x] 2.3 Add `#[cfg(feature = "aws")] pub mod aws;` to `crates/zopp-sync/src/lib.rs`

- [x] Task 3: Implement AwsSyncTarget struct and constructor (AC: #1, #4)
  - [x] 3.1 Define `AwsSyncTarget` struct holding AWS SM client, region, and optional prefix
  - [x] 3.2 Implement `AwsSyncTarget::new(region: &str, prefix: Option<String>)` that resolves credentials via `aws-config` default chain
  - [x] 3.3 Map credential resolution failures to `SyncError::AuthError` with fix instructions

- [x] Task 4: Implement `fetch_current()` (AC: #2, #4, #5)
  - [x] 4.1 List all secrets using `list_secrets()` with pagination via `into_paginator()`
  - [x] 4.2 Filter secrets by prefix if configured
  - [x] 4.3 Fetch each secret's value using `get_secret_value()`
  - [x] 4.4 Strip prefix from key names before returning
  - [x] 4.5 Map API errors to appropriate `SyncError` variants (auth, connection, api)
  - [x] 4.6 Exponential backoff handled by AWS SDK's built-in RetryConfig

- [x] Task 5: Implement `apply()` (AC: #3, #5)
  - [x] 5.1 For `DiffOperation::Add`: call `create_secret()` with prefixed name and value
  - [x] 5.2 For `DiffOperation::Update`: call `put_secret_value()` with new value
  - [x] 5.3 For `DiffOperation::Remove`: call `delete_secret()` with `force_delete_without_recovery(true)`
  - [x] 5.4 Return `Vec<SyncResult>` with per-secret success/failure
  - [x] 5.5 Exponential backoff handled by AWS SDK's built-in RetryConfig

- [x] Task 6: Implement `SyncTarget` trait for `AwsSyncTarget` (AC: #1, #2, #3)
  - [x] 6.1 Implement `display_name()` returning `"AWS Secrets Manager"` (static &str)
  - [x] 6.2 Wire `fetch_current()` and `apply()` through the trait

- [x] Task 7: Write unit tests with mocked API trait (AC: #6)
  - [x] 7.1 Test `fetch_current()` returns correct HashMap from mock
  - [x] 7.2 Test `fetch_current()` with prefix filtering
  - [x] 7.3 Test `apply()` creates/updates/deletes correctly
  - [x] 7.4 Test credential failure maps to `SyncError::AuthError`
  - [x] 7.5 Test API error maps via mock partial failure
  - [x] 7.6 Throttling retry delegated to AWS SDK RetryConfig — not separately tested
  - [x] 7.7 Test partial failure in `apply()` returns mixed results
  - [x] 7.8 Compile-time check that AwsSyncTarget implements SyncTarget (no AWS types leak)

- [ ] Task 8: Verification (via CI)
  - [ ] 8.1 `cargo build --package zopp-sync --features aws` compiles
  - [ ] 8.2 `cargo test --package zopp-sync --features aws` passes
  - [ ] 8.3 `cargo clippy --package zopp-sync --features aws --all-targets` zero warnings
  - [ ] 8.4 `cargo fmt --all -- --check` passes

## Dev Notes

### Architecture Compliance

**Module location:** `crates/zopp-sync/src/aws/`

**File layout:**
```
crates/zopp-sync/src/
  lib.rs              # Add: #[cfg(feature = "aws")] pub mod aws;
  aws/
    mod.rs            # AwsSyncTarget struct + SyncTarget trait impl
    client.rs         # AWS API client wrapper (list, get, create, update, delete)
```

**Feature gating pattern:**
```rust
// In lib.rs
#[cfg(feature = "aws")]
pub mod aws;

// In Cargo.toml [features]
aws = ["dep:aws-sdk-secretsmanager", "dep:aws-config", "dep:tokio"]
```

### Existing Types to Use (from Story 2.1)

**SyncTarget trait** (`crates/zopp-sync/src/lib.rs`):
```rust
#[async_trait::async_trait]
pub trait SyncTarget: Send + Sync {
    fn display_name(&self) -> &str;
    async fn fetch_current(&self) -> Result<HashMap<String, String>, SyncError>;
    async fn apply(&self, operations: &[DiffOperation]) -> Vec<SyncResult>;
}
```

**DiffOperation** (`crates/zopp-sync/src/types.rs`):
- `Add { key: String, value: String }`
- `Update { key: String, old_value: String, new_value: String }`
- `Remove { key: String }`
- Accessor: `key() -> &str`

**SyncResult** (`crates/zopp-sync/src/types.rs`):
```rust
pub struct SyncResult { pub key: String, pub outcome: SyncOutcome }
pub enum SyncOutcome { Success, Failed { reason: String } }
```

**SyncError** (`crates/zopp-sync/src/error.rs`):
- `AuthError { platform, message, fix }` — for credential failures
- `ApiError { platform, operation, message, fix }` — for API call failures
- `ConnectionError { platform, message, fix }` — for network failures
- `SourceError { message, fix }` — for zopp-side errors

### AWS SDK Usage

**Dependencies to add to `crates/zopp-sync/Cargo.toml`:**
```toml
[dependencies]
aws-sdk-secretsmanager = { workspace = true, optional = true }
aws-config = { workspace = true, optional = true }
tokio = { workspace = true, optional = true }

[features]
aws = ["dep:aws-sdk-secretsmanager", "dep:aws-config", "dep:tokio"]
```

**Add to root `Cargo.toml` workspace dependencies:**
```toml
aws-sdk-secretsmanager = "1.100"
aws-config = "1.8"
```

**Credential resolution** uses `aws-config`'s default provider chain:
```rust
let config = aws_config::defaults(BehaviorVersion::latest())
    .region(Region::new(region.to_string()))
    .load()
    .await;
let client = aws_sdk_secretsmanager::Client::new(&config);
```

This automatically tries: environment variables → `~/.aws/credentials` → EC2/ECS instance metadata.

**Key AWS SM API calls:**
- `list_secrets()` — paginated, use `.into_paginator()` for auto-pagination
- `get_secret_value(secret_id)` — returns `SecretString` or `SecretBinary`
- `create_secret(name, secret_string)` — creates new secret
- `put_secret_value(secret_id, secret_string)` — updates existing secret value
- `delete_secret(secret_id)` — optionally with `force_delete_without_recovery(true)`

### Prefix Handling

When `prefix` is set (e.g., `/prod/myapp/`):
- `fetch_current()`: list all secrets, filter by prefix, strip prefix from key names before returning
- `apply()`: prepend prefix to key names when creating/updating/deleting
- Example: zopp key `DB_HOST` with prefix `/prod/myapp/` → AWS secret name `/prod/myapp/DB_HOST`

Use `list_secrets().filters()` with `FilterNameStringType::Name` and `begin_with` to filter by prefix at the API level when possible.

### Exponential Backoff

For throttling (`ThrottlingException`):
```rust
// Retry with exponential backoff: 100ms, 200ms, 400ms, 800ms, 1.6s, ...
// Cap at ~60 seconds total additional delay
// Max ~5-6 retries
```

The AWS SDK has built-in retry configuration. Use `aws_config::defaults()` with the standard retry config rather than implementing custom retry logic. The SDK's default RetryConfig handles throttling. Only implement custom retry if the SDK's built-in retry is insufficient.

### Error Mapping

Map AWS SDK errors to `SyncError`:
- `SdkError::ServiceError` with `ThrottlingException` → handled by SDK retry, then `ApiError` if exhausted
- `SdkError::ServiceError` with `AccessDeniedException` / `UnrecognizedClientException` → `AuthError`
- `SdkError::ServiceError` with `ResourceNotFoundException` → `ApiError`
- `SdkError::DispatchFailure` / `SdkError::TimeoutError` → `ConnectionError`
- Credential resolution failure → `AuthError` with fix listing all credential sources

### Testing Strategy

Use the AWS SDK's built-in test utilities or mock the HTTP layer:

**Option A — AWS SDK test utilities:**
The AWS SDK supports custom `HttpClient` implementations for testing. You can provide a mock HTTP client that returns pre-configured responses.

**Option B — Trait-based mocking:**
Create a thin `SecretsManagerClient` trait wrapping the SDK calls, implement it with the real SDK client, and use a mock implementation in tests. This is the preferred approach since it keeps tests simple and doesn't require HTTP-level mocking.

```rust
#[async_trait]
trait SecretsManagerApi: Send + Sync {
    async fn list_secrets(&self, prefix: Option<&str>) -> Result<Vec<SecretEntry>, SyncError>;
    async fn get_secret_value(&self, id: &str) -> Result<String, SyncError>;
    async fn create_secret(&self, name: &str, value: &str) -> Result<(), SyncError>;
    async fn put_secret_value(&self, id: &str, value: &str) -> Result<(), SyncError>;
    async fn delete_secret(&self, id: &str) -> Result<(), SyncError>;
}
```

This trait stays internal to the `aws` module (not public). Tests provide a mock implementation.

### Anti-Patterns to Avoid

- Do NOT expose AWS SDK types (Region, SecretListEntry, etc.) outside the `aws` module
- Do NOT store AWS credentials in zopp config — credentials come from environment only
- Do NOT log plaintext secret values — only log key names
- Do NOT implement custom diff logic — use the shared `diff::diff()` from Story 2.1
- Do NOT add sync logic to the server — sync is entirely client-side
- Do NOT add `rust-version.workspace = true` to Cargo.toml (MSRV issue, see Story 2.1 learnings)

### Previous Story Intelligence (Story 2.1)

- `zopp-sync` crate uses `async-trait` with `Send + Sync` bounds on `SyncTarget`
- `SyncError` uses `thiserror` derive with structured Display format
- Feature flags are declared in Cargo.toml but currently empty (no deps) — this story adds the `aws` feature deps
- Omitted `rust-version.workspace = true` from Cargo.toml to avoid MSRV resolver issue
- DiffEngine returns operations sorted alphabetically by key
- Cannot build full workspace locally due to MSRV (rustc 1.88 vs required 1.90) — CI has newer Rust
- Individual package builds work: `cargo check --package zopp-sync`

### Project Structure Notes

- Module at `crates/zopp-sync/src/aws/` — declared in lib.rs with feature gate
- `AwsSyncTarget` is used by Story 2.4 (CLI commands) — must be `pub`
- No changes to CLI or server — this is purely a library addition to zopp-sync
- The `aws` feature flag is already declared in `crates/zopp-sync/Cargo.toml` (but currently empty)

### References

- [Source: _bmad-output/planning-artifacts/architecture.md#Sync Module Structure]
- [Source: _bmad-output/planning-artifacts/architecture.md#SyncTarget Trait]
- [Source: _bmad-output/planning-artifacts/architecture.md#Error Handling]
- [Source: _bmad-output/planning-artifacts/epics.md#Story 2.2]
- [Source: _bmad-output/implementation-artifacts/2-1-*.md — Story 2.1 learnings]

### Pre-Submission Checklist

**Code Quality:**

- [ ] `cargo fmt --all` passes
- [ ] `cargo clippy --package zopp-sync --features aws --all-targets` zero warnings
- [ ] `cargo test --package zopp-sync --features aws` passes
- [ ] `cargo build --package zopp-sync --features aws` compiles

**Security:**

- [ ] No plaintext secret values in any log or error message
- [ ] No AWS credentials stored in zopp config
- [ ] Output functions only display key names, never values

## Dev Agent Record

### Agent Model Used

Claude Opus 4.6

### Debug Log References

### Completion Notes List

- 10 unit tests in aws module (7 async + 3 sync) testing fetch, apply, prefix, auth errors, partial failure
- Used trait-based mocking (SecretsManagerApi) instead of HTTP-level mocking for simplicity
- Exponential backoff delegated to AWS SDK's built-in RetryConfig (not custom implementation)
- `display_name()` returns static `"AWS Secrets Manager"` (not with region) since trait returns `&str`
- All AWS SDK types (Region, Client, etc.) stay internal to `aws` module
- Cannot verify locally due to MSRV (rustc 1.88 vs AWS SDK requires 1.91) — CI handles verification

### Change Log

- Modified `Cargo.toml` — added `aws-config` and `aws-sdk-secretsmanager` workspace deps
- Modified `crates/zopp-sync/Cargo.toml` — added optional AWS deps gated by `aws` feature, added tokio dev-dep
- Modified `crates/zopp-sync/src/lib.rs` — added `#[cfg(feature = "aws")] pub mod aws;`
- Created `crates/zopp-sync/src/aws/mod.rs` — AwsSyncTarget struct, SyncTarget impl, 10 tests
- Created `crates/zopp-sync/src/aws/client.rs` — SecretsManagerApi trait, AwsClient impl, error mapping

### File List

- `Cargo.toml` (modified — workspace deps)
- `Cargo.lock` (modified — new deps resolved)
- `crates/zopp-sync/Cargo.toml` (modified — aws feature deps)
- `crates/zopp-sync/src/lib.rs` (modified — aws module declaration)
- `crates/zopp-sync/src/aws/mod.rs` (new)
- `crates/zopp-sync/src/aws/client.rs` (new)

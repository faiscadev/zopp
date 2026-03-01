# Contribution Guide

> Generated: 2026-03-01 | Scan Level: Exhaustive

## Overview

This guide consolidates zopp's contribution standards from `contributing/` into a single reference.

## Code Style

- **Formatting**: `cargo fmt --all` (rustfmt default settings)
- **Linting**: `cargo clippy --workspace --all-targets --all-features` (warnings as errors in CI)
- **Rust edition**: 2021, MSRV 1.90
- **Error handling**: `thiserror` for library errors, `Box<dyn Error>` for CLI
- **Async**: Tokio runtime, `async-trait` for trait async methods
- **Sensitive data**: Use `Zeroize` + `ZeroizeOnDrop`, never implement `Debug` on key types
- **IDs**: Use strongly-typed ID newtypes from `zopp-storage`

## Testing Requirements

### Unit Tests
- **Goal**: 100% line coverage for crates and apps
- **Real implementations**: Test with real SQLite/PostgreSQL, not mocks
- **Mocking**: Only for reproducing specific error conditions (network failures, race conditions)
- **Coverage**: `./scripts/unit-coverage.sh` generates HTML report

### E2E Tests
- **Requirement**: Every user-facing feature must have an E2E test
- **Backend matrix**: Tests run on 4 combinations (SQLite/PG × Memory/PG events)
- **DEMO alignment**: `DEMO.md` steps must match `demo.rs` E2E test 1:1
- **Location**: `apps/e2e-tests/tests/`

### RBAC Tests
Add RBAC tests for any feature involving permission checks:
- Admin-only operations (verify write/read cannot access)
- Write operations (verify read cannot perform)
- Permission delegation (users can only grant up to their own level)

### Web E2E
- Playwright tests in `apps/zopp-web/tests/`
- Test auth flows, secret management, workspace operations

## PR Process

### Pre-PR Checklist
```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features
cargo test --workspace --all-features
cargo build --bins && cargo run --bin zopp-e2e-test
```

### Commit Conventions
- Descriptive commit messages
- No `Co-Authored-By` trailers
- No AI attribution in PR descriptions

### CI Checks
- **Focus on**: clippy, tests, fmt, E2E tests, web-e2e tests
- **Ignore**: Docker builds (slow, not required for most PRs)
- **Cubic reviews**: AI code reviewer that does incremental + full reviews
  - Fix P1/P2 issues, P3 are minor
  - Request full re-review after fixing: `@cubic-dev-ai Please do a full re-review of the PR.`

## Documentation Standards

**Documentation is product.** Code changes without doc updates are incomplete.

### When to Update Docs
- New CLI commands/flags → `docs/docs/reference/cli/`
- New features → `docs/docs/guides/`
- Config changes → `docs/docs/reference/configuration.md`
- Security changes → `docs/docs/security/`

### Writing Style
- Imperative mood for titles ("Configure TLS" not "Configuring TLS")
- Include working code examples
- Keep CLI examples consistent with actual command output
- Update `docs/sidebars.js` when adding new pages

### Running Docs Locally
```bash
cd docs && npm install && npm run dev
```

## Adding a Storage Backend

Create a new crate implementing the `Store` trait from `zopp-storage`:

```rust
use zopp_storage::Store;

pub struct MyStore { /* ... */ }

#[async_trait::async_trait]
impl Store for MyStore {
    // Implement 100+ methods
}
```

## SQLx Query Changes

When modifying SQL queries, regenerate offline metadata before committing:

```bash
# SQLite
DATABASE_URL=sqlite:///tmp/zopp-prepare.db sqlx migrate run --source crates/zopp-store-sqlite/migrations
DATABASE_URL=sqlite:///tmp/zopp-prepare.db cargo sqlx prepare --package zopp-store-sqlite

# PostgreSQL
DATABASE_URL=postgres://postgres:postgres@localhost/postgres sqlx migrate run --source crates/zopp-store-postgres/migrations
DATABASE_URL=postgres://postgres:postgres@localhost/postgres cargo sqlx prepare --package zopp-store-postgres
```

## Security Guidelines

- **Never log plaintext** keys or secrets in server code
- **Use `Zeroize`** for all sensitive data types
- **Client-side crypto only** — server must never decrypt
- **AAD context** — always include workspace/project/env/key in AEAD context
- **Ed25519 verification** — all gRPC requests must be signature-verified

## Release Process

See [RELEASING.md](../contributing/RELEASING.md) for the full release workflow:
1. Bump versions with `cargo workspaces version`
2. Update Helm chart version
3. Tag and push → CI handles Docker, CLI binaries, Helm chart

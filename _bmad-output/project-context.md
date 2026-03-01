---
project_name: 'zopp'
user_name: 'Lucas'
date: '2026-03-01'
sections_completed: ['technology_stack', 'language_rules', 'framework_rules', 'testing_rules', 'code_quality', 'workflow_rules', 'critical_rules']
status: 'complete'
rule_count: 42
optimized_for_llm: true
---

# Project Context for AI Agents

_This file contains critical rules and patterns that AI agents must follow when implementing code in this project. Focus on unobvious details that agents might otherwise miss._

---

## Technology Stack & Versions

- **Language:** Rust 1.90 stable, edition 2021, resolver 2
- **Async:** Tokio 1.48.0
- **gRPC:** Tonic 0.14, Prost 0.14 (single proto: `crates/zopp-proto/proto/zopp.proto`)
- **HTTP:** Axum 0.8, Tower 0.5, Tower-HTTP 0.6
- **Web UI:** Leptos 0.7 (SSR + WASM hydrate)
- **Database:** SQLx 0.8.6 — dual-backend: SQLite (dev) + PostgreSQL (prod)
- **Crypto:** chacha20poly1305 0.10.1, ed25519-dalek 2.1, x25519-dalek 2.0.1, argon2 0.5.3, zeroize 1.8.2
- **TLS:** rustls 0.23 with ring crypto provider
- **CLI:** Clap 4.5 (derive + env), keyring 3 (platform-native backends)
- **K8s Operator:** kube 2.0.1, k8s-openapi 0.26.1
- **Email:** lettre 0.11 (default SMTP), resend-rs 0.20 (optional feature)
- **Monitoring:** metrics 0.24, tracing 0.1.41
- **Testing:** mockall 0.13, serial_test 3, tempfile 3.14, trybuild 1
- **IDs:** uuid 1.18.1 (v4, v7)

## Critical Implementation Rules

### Language-Specific Rules (Rust)

- **Error handling:** Use `thiserror` for all error types. Each crate defines its own error enum (e.g., `StoreError`, `KdfError`, `EncryptError`). Propagate with `?` operator.
- **Async traits:** Use `async-trait` crate for async trait methods — do not use RPITIT (Rust doesn't stabilize it for all use cases yet in this project).
- **Sensitive data:** All types holding keys, secrets, or plaintext MUST derive `Zeroize` + `ZeroizeOnDrop`. Wrap raw bytes in `Zeroizing<[u8; 32]>` or `Zeroizing<Vec<u8>>`.
- **No Debug on secrets:** Sensitive types must NOT implement `Debug`. Enforced at compile time via `trybuild` tests — if you add a new sensitive type, add a corresponding trybuild test.
- **Strongly-typed IDs:** All entity IDs are newtype wrappers around `Uuid` (e.g., `UserId(Uuid)`, `WorkspaceId(Uuid)`). Never use raw `Uuid` in function signatures — always use the typed wrapper.
- **Feature flags:** Use Cargo feature flags for optional capabilities: `email-smtp` (default), `email-resend`, `wasm`, `hydrate`, `ssr`. Gate dependencies and code behind features.
- **SQLx offline mode:** `SQLX_OFFLINE=true` is set in `.cargo/config.toml`. All queries are compile-time verified against `.sqlx/` metadata. When modifying SQL queries, regenerate metadata per CLAUDE.md instructions.
- **Dual database:** Every SQL migration and store method must work on BOTH SQLite and PostgreSQL. Migrations live in separate directories but must have identical schemas.

### Framework-Specific Rules

#### gRPC (Tonic)
- **Single proto file:** All RPCs defined in `crates/zopp-proto/proto/zopp.proto`. Proto compilation via `tonic-prost-build` in `build.rs`.
- **Auth metadata:** All requests require Ed25519 signature authentication via gRPC metadata — never bypass this in new RPCs.
- **RBAC enforcement:** Server-side permission checks on every RPC. Use the generic permission API (4 methods, not per-resource).
- **gRPC-web:** Browser clients connect via `tonic-web` on port 8080. New RPCs are automatically accessible from the web UI.

#### Storage (SQLx + Trait Abstraction)
- **Trait-based:** `zopp-storage` defines the `Store` trait. `zopp-store-sqlite` and `zopp-store-postgres` implement it independently.
- **New store methods:** Add to the `Store` trait first, then implement in BOTH SQLite and PostgreSQL stores. Never implement in only one backend.
- **Migrations in sync:** SQLite migrations in `crates/zopp-store-sqlite/migrations/`, PostgreSQL in `crates/zopp-store-postgres/migrations/`. Both must have matching schemas.
- **Compile-time SQL:** All queries use SQLx macros (`sqlx::query!`, `sqlx::query_as!`). Regenerate `.sqlx/` metadata after any SQL change.

#### CLI (Clap)
- **Derive-based:** Subcommands use `#[derive(Parser)]` with `#[command(...)]` attributes.
- **Config discovery:** CLI walks upward to find `zopp.toml` (or `.yaml`/`.json`) for workspace/project/environment defaults. All `-w`, `-p`, `-e` flags are optional when config exists.
- **Client-side crypto:** ALL encryption/decryption happens in the CLI. The server is a blind storage layer — never add crypto operations to the server.

#### Web UI (Leptos)
- **Dual-mode:** SSR (`ssr` feature) + WASM hydration (`hydrate` feature). Components must work in both modes.
- **gRPC-web client:** Uses `zopp-proto-web` crate for browser-side gRPC communication.

### Testing Rules

- **Real implementations over mocks:** Test with real SQLite, real PostgreSQL — only use `mockall` to reproduce specific error conditions. Never mock the happy path.
- **4-backend E2E matrix:** E2E tests use `backend_test!` macro generating 4 variants: SQLite+Memory, SQLite+PgEvents, PostgreSQL+Memory, PostgreSQL+PgEvents. Every new E2E test must use this macro.
- **E2E test harness:** `TestHarness` manages server lifecycle, port allocation, binary paths. Use `create_user()` for user simulation with isolated home directories.
- **RBAC testing mandatory:** Any feature touching permissions must have RBAC tests verifying: admin CAN, write/read CANNOT (or appropriate role boundaries). Follow the pattern in `apps/e2e-tests/tests/rbac.rs`.
- **Test naming:** Use descriptive `test_feature_description` naming. E2E test files are per-feature (e.g., `demo.rs`, `rbac.rs`, `invites.rs`).
- **Unit tests inline:** Unit tests go in `#[cfg(test)] mod tests` within the source file, not separate test files.
- **Coverage goal:** 100% unit test coverage for crates. Use E2E tests for code that's impractical to unit test.
- **trybuild tests:** Compile-time safety tests in `zopp-crypto` ensure sensitive types don't implement `Debug`. Add trybuild tests for new sensitive types.
- **DEMO.md alignment:** E2E test steps must match DEMO.md steps 1:1. If you change one, update the other.

### Code Quality & Style Rules

- **Formatting:** `cargo fmt --all` with default rustfmt settings (no custom rustfmt.toml). Run before every commit.
- **Linting:** `cargo clippy --workspace --all-targets --all-features` must pass with zero warnings. Clippy treats warnings as errors in CI (`-D warnings`).
- **File naming:** Snake_case for all Rust files and modules. No exceptions.
- **Module organization:** Trait definitions in `lib.rs`, implementations in dedicated files (e.g., `store.rs`). Re-export public API from `lib.rs`.
- **Workspace dependencies:** All shared dependencies are declared in the workspace `Cargo.toml` `[workspace.dependencies]`. Member crates reference them with `workspace = true`. Never pin a version directly in a member crate if it's already in workspace deps.
- **No unnecessary comments:** Don't add doc comments or inline comments to code you didn't change. Only comment where logic is non-obvious.
- **Crate boundaries:** Each crate has a single responsibility. `zopp-crypto` = crypto primitives, `zopp-storage` = trait definitions, `zopp-store-*` = implementations, `zopp-proto` = gRPC definitions. Don't leak responsibilities across crate boundaries.

### Development Workflow Rules

- **Pre-PR checklist:** Always run in order: `cargo fmt --all` → `cargo clippy --workspace --all-targets --all-features` → `cargo test --workspace --all-features` → `cargo build --bins && cargo run --bin zopp-e2e-test`.
- **No Co-Authored-By:** Never add "Co-Authored-By" trailers to commits.
- **No AI attribution:** Never add "Generated with Claude" or similar to PR descriptions.
- **Commit messages:** Use conventional-style prefixes: `feat:`, `fix:`, `refactor:`, `chore:`, `docs:`, `test:`. Keep concise.
- **CI checks that matter:** Focus on clippy, tests, fmt, E2E tests, web-e2e. Ignore docker builds (slow, not required for most PRs).
- **Cubic code reviewer:** After creating a PR, Cubic reviews automatically. Fix issues, push, and when incremental reviews pass with 0 issues, request full re-review with `@cubic-dev-ai Please do a full re-review of the PR.` Never merge while a full re-review is pending.
- **Branch strategy:** Feature branches off `main`. PR-based workflow.
- **Documentation updates:** New CLI commands/flags require doc updates in `docs/docs/reference/cli/`. Changed behavior requires updating relevant docs.

### Critical Don't-Miss Rules

#### Security (Zero-Knowledge)
- **NEVER log or expose plaintext keys/secrets in server code.** The server is a blind storage layer — it must never see decrypted data.
- **Client-side only crypto:** Encryption, decryption, key wrapping, ECDH — all happen in the CLI or web client. Adding any crypto to the server violates the zero-knowledge architecture.
- **KEK wrapping:** Server stores `(ephemeral_pub, kek_wrapped, kek_nonce)`. Client performs X25519 ECDH to derive shared secret, then unwraps KEK. Never simplify or shortcut this flow.
- **AEAD context binding:** Secret encryption uses XChaCha20-Poly1305 with AAD containing workspace/project/env/key name. Changing any context field breaks decryption.

#### Anti-Patterns
- **Don't add store methods to only one backend.** Every `Store` trait method must be implemented in both `zopp-store-sqlite` AND `zopp-store-postgres`.
- **Don't commit broken offline builds.** If you modify SQL, regenerate `.sqlx/` metadata for BOTH backends before committing.
- **Don't bypass auth.** Every new gRPC RPC must validate Ed25519 signature metadata. No unauthenticated endpoints (except health checks).
- **Don't use raw UUIDs.** Always use the strongly-typed wrappers (`UserId`, `WorkspaceId`, etc.). The type system prevents mixing IDs across entities.

#### Edge Cases
- **rustls crypto provider:** Must call `rustls::crypto::ring::default_provider().install_default()` before any TLS operations. Missing this causes runtime panics.
- **Invite flow:** Invites encrypt KEK with a random 32-byte secret. Server stores `SHA256(secret)` for lookup. Invitee uses secret to decrypt KEK, then re-wraps for their own principal. This is a multi-step flow — don't skip steps.
- **UUID v7 for audit logs:** Audit log IDs use UUID v7 (time-ordered) for chronological sorting. All other IDs use UUID v4.
- **Platform-specific keyring:** CLI uses platform-native keyring backends (Apple Keychain, Windows Credential Manager, Linux Secret Service via zbus). Feature-gated per platform in `Cargo.toml`.

---

## Usage Guidelines

**For AI Agents:**

- Read this file before implementing any code
- Follow ALL rules exactly as documented
- When in doubt, prefer the more restrictive option
- Update this file if new patterns emerge

**For Humans:**

- Keep this file lean and focused on agent needs
- Update when technology stack changes
- Review quarterly for outdated rules
- Remove rules that become obvious over time

Last Updated: 2026-03-01

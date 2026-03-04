---
project_name: 'zopp'
user_name: 'Lucas'
date: '2026-03-04'
sections_completed: ['technology_stack', 'language_rules', 'framework_rules', 'testing_rules', 'code_quality', 'workflow_rules', 'critical_rules']
status: 'complete'
rule_count: 58
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
- **Web UI:** Leptos 0.7 (SSR + WASM hydrate), Tailwind CSS + DaisyUI, Trunk (WASM bundler)
- **Database:** SQLx 0.8.6 — dual-backend: SQLite (dev) + PostgreSQL (prod)
- **Crypto:** chacha20poly1305 0.10.1, ed25519-dalek 2.1, x25519-dalek 2.0.1, argon2 0.5.3, zeroize 1.8.2
- **Crypto WASM:** zopp-crypto-wasm (wasm-bindgen + Web Crypto API bridge)
- **TLS:** rustls 0.23 with ring crypto provider
- **CLI:** Clap 4.5 (derive + env), keyring 3 (platform-native backends)
- **K8s Operator:** kube 2.0.1, k8s-openapi 0.26.1
- **Email:** lettre 0.11 (default SMTP), resend-rs 0.20 (optional feature)
- **Monitoring:** metrics 0.24, metrics-exporter-prometheus 0.16, tracing 0.1.41
- **Testing:** mockall 0.13, serial_test 3, tempfile 3.14, trybuild 1
- **Web E2E Testing:** Playwright
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
- **Workspace dependencies:** All shared dependencies declared in workspace `Cargo.toml` `[workspace.dependencies]`. Member crates reference with `workspace = true`. Never pin a version directly in a member crate if it's already in workspace deps.
- **Crate boundaries:** Each crate has a single responsibility. `zopp-crypto` = crypto primitives, `zopp-storage` = store trait, `zopp-store-*` = implementations, `zopp-events` = event bus trait, `zopp-events-*` = implementations, `zopp-audit` = audit trait, `zopp-secrets` = secret encryption context, `zopp-config` = CLI config management, `zopp-proto` = gRPC definitions. Don't leak responsibilities across crate boundaries.

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

#### Event Bus (zopp-events)
- **Trait-based:** `EventBus` trait with `publish()` and `subscribe()` (returns async stream). Two implementations: `MemoryEventBus` (tokio broadcast, single-server) and `PostgresEventBus` (LISTEN/NOTIFY, multi-server).
- **Auto-detection:** Server selects event backend automatically — postgres DATABASE_URL → postgres events, otherwise memory. Overridable with `--events-backend` flag or separate `ZOPP_EVENTS_DATABASE_URL`.
- **New event types:** When adding events, define in `zopp-events` crate, implement publishing in both backends. `SecretChangeEvent` is the current pattern (event_type, key, version, timestamp).

#### Audit Logging (zopp-audit)
- **Trait-based:** `AuditLog` trait with `record()`, `query()`, `get()`, `count()`. ~45 audit actions covering secrets, workspaces, permissions, groups.
- **AuditResult enum:** Success, PermissionDenied, NotFound, InvalidRequest, Error. Always record the correct result — never skip audit logging for failed operations.
- **UUID v7 for audit IDs:** Audit log entries use UUID v7 (time-ordered) for chronological sorting. All other entity IDs use UUID v4.

#### Secrets Service (zopp-secrets)
- **SecretContext:** Bundles principal keypair, workspace keys, and environment into a single context for encrypt/decrypt operations. Use this high-level API rather than calling crypto primitives directly.
- **DEK caching:** Use `unwrap_dek()` + `decrypt_secret_with_dek()` for batch operations to avoid redundant DEK unwrapping.

#### Web UI (Leptos)
- **Dual-mode:** SSR (`ssr` feature) + WASM hydration (`hydrate` feature). Components must work in both modes.
- **gRPC-web client:** Uses `zopp-proto-web` crate for browser-side gRPC communication.
- **WASM crypto bridge:** Build with `wasm-pack build --target web --out-dir apps/zopp-web/pkg crates/zopp-crypto-wasm` before running web dev server.
- **Dev server:** `cd apps/zopp-web && trunk serve` for hot-reload development.
- **State management:** AuthProvider and WorkspaceProvider patterns for global state.

### Testing Rules

- **Real implementations over mocks:** Test with real SQLite, real PostgreSQL — only use `mockall` to reproduce specific error conditions. Never mock the happy path.
- **4-backend E2E matrix:** E2E tests use `backend_test!` macro generating 4 variants: SQLite+Memory, SQLite+PgEvents, PostgreSQL+Memory, PostgreSQL+PgEvents. Every new E2E test must use this macro.
- **E2E test harness:** `TestHarness` manages server lifecycle, port allocation, binary paths. Use `create_user()` for user simulation with isolated home directories. Never hardcode ports in tests.
- **E2E test files:** One file per feature area: `audit.rs`, `counts.rs`, `demo.rs`, `email_verification.rs`, `environments.rs`, `groups.rs`, `invites.rs`, `k8s.rs`, `keychain.rs`, `principals.rs`, `projects.rs`, `rbac.rs`, `secrets.rs`, `user_permissions.rs`. Add new test files for new feature areas.
- **RBAC testing mandatory:** Any feature touching permissions must have RBAC tests verifying: admin CAN, write/read CANNOT (or appropriate role boundaries). Follow the pattern in `apps/e2e-tests/tests/rbac.rs`.
- **Test naming:** Use descriptive `test_feature_description` naming.
- **Unit tests inline:** Unit tests go in `#[cfg(test)] mod tests` within the source file, not separate test files.
- **Coverage goal:** 100% unit test coverage for crates. Use E2E tests for code that's impractical to unit test.
- **trybuild tests:** Compile-time safety tests in `zopp-crypto` ensure sensitive types don't implement `Debug`. Add trybuild tests for new sensitive types.
- **DEMO.md alignment:** E2E test steps must match DEMO.md steps 1:1. If you change one, update the other.
- **MailHog for email tests:** CI uses MailHog (ports 1025/8025) for email verification testing. E2E tests query MailHog HTTP API to verify sent emails.
- **Keychain tests:** Require gnome-keyring + dbus on Linux CI. Platform-specific keyring tests are feature-gated.
- **K8s tests:** Require `kind` cluster. Only run in CI with K8s setup step.
- **Web E2E tests:** Playwright tests in `apps/zopp-web/`. Run separately via `web-e2e.yaml` CI workflow.
- **Skip Postgres:** Set `SKIP_POSTGRES_TESTS=1` to skip PostgreSQL-dependent test variants locally.

### Code Quality & Style Rules

- **Formatting:** `cargo fmt --all` with default rustfmt settings (no custom rustfmt.toml). Run before every commit.
- **Linting:** `cargo clippy --workspace --all-targets --all-features` must pass with zero warnings. Clippy treats warnings as errors in CI (`-D warnings`).
- **File naming:** Snake_case for all Rust files and modules. No exceptions.
- **Module organization:** Trait definitions in `lib.rs`, implementations in dedicated files (e.g., `store.rs`). Re-export public API from `lib.rs`.
- **No unnecessary comments:** Don't add doc comments or inline comments to code you didn't change. Only comment where logic is non-obvious.

### Development Workflow Rules

- **Pre-PR checklist:** Always run in order: `cargo fmt --all` → `cargo clippy --workspace --all-targets --all-features` → `cargo test --workspace --all-features` → `cargo build --bins && cargo run --bin zopp-e2e-test`.
- **No Co-Authored-By:** Never add "Co-Authored-By" trailers to commits.
- **No AI attribution:** Never add "Generated with Claude" or similar to PR descriptions.
- **Commit messages:** Use conventional-style prefixes: `feat:`, `fix:`, `refactor:`, `chore:`, `docs:`, `test:`. Keep concise.
- **CI checks that matter:** Focus on clippy, tests, fmt, E2E tests, web-e2e. Ignore docker builds (slow, not required for most PRs).
- **Cubic code reviewer:** After creating a PR, Cubic reviews automatically. Fix issues, push, and when incremental reviews pass with 0 issues, request full re-review with `@cubic-dev-ai Please do a full re-review of the PR.` Never merge while a full re-review is pending.
- **Branch strategy:** Feature branches off `main`. PR-based workflow.
- **Documentation updates:** New CLI commands/flags require doc updates in `docs/docs/reference/cli/`. Changed behavior requires updating relevant docs.
- **Database prep for SQL changes:** When modifying SQL queries, regenerate `.sqlx/` metadata for BOTH backends. SQLite: `DATABASE_URL=sqlite:///tmp/zopp-prepare.db cargo sqlx prepare --package zopp-store-sqlite`. PostgreSQL: spin up a temp postgres container, run migrations, then `cargo sqlx prepare --package zopp-store-postgres`.
- **xtask helper:** `cargo xtask` provides database setup and sqlx metadata generation helpers. Use it instead of manual steps when available.
- **Docker dev workflow:** `docker compose -f docker/docker-compose.dev.yaml up` for server + Envoy proxy. Web UI requires separate wasm-pack build + trunk serve.
- **Server bootstrap:** First user requires a server-generated invite token: `cargo run --bin zopp-server invite create --expires-hours 48`, then `cargo run --bin zopp -- join <token> email@example.com`.

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
- **Don't add event types to only one backend.** Every `EventBus` event must be published/subscribed in both `MemoryEventBus` AND `PostgresEventBus`.
- **Don't skip audit logging.** Every permission-checked operation must record an audit event with the correct `AuditResult` — including denied and failed operations.
- **Don't call crypto primitives directly in CLI commands.** Use `SecretContext` from `zopp-secrets` for encrypt/decrypt. Direct crypto calls bypass proper context binding.

#### Edge Cases
- **rustls crypto provider:** Must call `rustls::crypto::ring::default_provider().install_default()` before any TLS operations. Missing this causes runtime panics.
- **Invite flow:** Invites encrypt KEK with a random 32-byte secret. Server stores `SHA256(secret)` for lookup. Invitee uses secret to decrypt KEK, then re-wraps for their own principal. This is a multi-step flow — don't skip steps.
- **UUID v7 for audit logs:** Audit log IDs use UUID v7 (time-ordered) for chronological sorting. All other IDs use UUID v4.
- **Platform-specific keyring:** CLI uses platform-native keyring backends (Apple Keychain, Windows Credential Manager, Linux Secret Service via zbus). Feature-gated per platform in `Cargo.toml`.
- **PostgreSQL event bus channel naming:** `PostgresEventBus` uses automatic channel naming from workspace/project/environment IDs. Channel names must be valid PostgreSQL identifiers.
- **WASM crypto differences:** `zopp-crypto-wasm` wraps the same algorithms but uses Web Crypto API for key derivation. Ensure any crypto changes are mirrored in both `zopp-crypto` and `zopp-crypto-wasm`.
- **Envoy proxy for gRPC-web:** Browser clients connect through Envoy (or tonic-web) which translates gRPC-web to gRPC. New RPCs are automatically accessible but must handle CORS via tower-http.

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

Last Updated: 2026-03-04

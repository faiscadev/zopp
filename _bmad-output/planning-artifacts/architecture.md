---
stepsCompleted: [1, 2, 3, 4, 5, 6, 7, 8]
lastStep: 8
status: 'complete'
completedAt: '2026-03-07'
inputDocuments:
  - product-brief-zopp-2026-03-04.md
  - prd.md
  - ux-design-specification.md
  - research/market-zero-knowledge-secrets-manager-research-2026-03-04.md
  - project-context.md
  - architecture.md (auto-generated reference)
  - integration-architecture.md (auto-generated reference)
  - docs/docs/index.md
  - docs/docs/security/architecture.md
workflowType: 'architecture'
project_name: 'zopp'
user_name: 'Lucas'
date: '2026-03-07'
---

# Architecture Decision Document

_This document builds collaboratively through step-by-step discovery. Sections are appended as we work through each architectural decision together._

## Project Context Analysis

### Requirements Overview

**Functional Requirements:**

33 functional requirements across 5 categories:

| Category | Count | Architectural Impact |
|----------|-------|---------------------|
| Installation & Distribution (FR1-5) | 5 | Shell script + package manager configs; no Rust architecture changes |
| Cloud Secret Manager Sync (FR6-12) | 7 | New `SyncTarget` trait + AWS/GCP implementations; diff engine; incremental sync |
| PaaS Integration Sync (FR13-19) | 7 | Additional `SyncTarget` implementations for Fly/Vercel/Render/Railway |
| Sync Operations & Monitoring (FR20-24) | 5 | Audit log integration for sync events; sync status tracking; rate limit handling |
| Server Deployment (FR25-30) | 6 | Configuration templates only; no server code changes |
| Zero-Knowledge Preservation (FR31-33) | 3 | Architectural constraint — sync agent as service principal with scoped RBAC |

The dominant architectural theme: **a generalized sync framework** that extends the existing K8s operator pattern to cloud and PaaS targets, with a shared CLI output layer for consistent user experience.

**Non-Functional Requirements:**

17 NFRs across 4 categories that constrain architectural decisions:

- **Performance:** Sync <30s for 100 secrets, diff <5s, install <30s. Drives need for incremental sync (changed secrets only) and batch API operations.
- **Security:** No plaintext on disk/logs during sync. Platform credentials never persisted by zopp. Checksum verification on install. TLS for all external communication. Least-privilege sync principals.
- **Integration:** Each sync target isolated — failure in one doesn't affect others. Platform-native auth only. Graceful API version change handling. Automated integration tests per target.
- **Reliability:** Independent target failures. Idempotent sync operations. Per-secret failure reporting (not blanket success/failure). Deployment templates produce servers that survive container restarts.

**UX-Driven Architectural Requirements:**

The UX specification defines a CLI output component system that is architecturally significant:

- 8 reusable output components requiring a shared formatting module
- ANSI color system with `NO_COLOR`/`--no-color` support
- `--json` output for every command (parallel output pipeline)
- Exit code contract (0/1/2/3/4) enforced across all commands
- Terminal width adaptation (80 col minimum, pipe detection)
- Universal flag patterns (`-w`, `-p`, `-e`, `--dry-run`, `--verbose`, `--quiet`)

### Scale & Complexity

- **Primary domain:** CLI developer tooling with external API integrations
- **Complexity level:** Medium — extending proven patterns, not inventing new architecture
- **Estimated new architectural components:** ~12 (sync trait, 6 sync target implementations, diff engine, CLI output library, install script, 3 deployment templates)
- **Existing components touched:** CLI command tree (new sync subcommands), audit logging (sync events)
- **Server changes:** None — zero-knowledge architecture preserved

### Technical Constraints & Dependencies

1. **Existing crate boundaries are fixed.** New sync modules must respect the workspace structure: each sync target is a separate crate or module within the CLI.
2. **SQLx offline mode.** No SQL changes expected, but if sync status tracking requires storage, both SQLite and PostgreSQL backends must be updated with matching schemas.
3. **The K8s sync pattern is the reference implementation.** New sync targets should follow the same architectural model: fetch encrypted → decrypt with principal keys → push plaintext to target.
4. **Platform API instability.** PaaS APIs (Vercel, Render, Fly, Railway) change frequently. Each integration needs version pinning, error mapping, and graceful degradation.
5. **Rate limiting.** Cloud and PaaS APIs have rate limits. Sync must implement exponential backoff with retry — shared across all targets.
6. **Phased delivery.** Phase 1 (curl + AWS + Fly) must be independently valuable. Architecture must support incremental addition of sync targets without restructuring.

### Cross-Cutting Concerns Identified

1. **CLI Output Formatting** — Shared output component library used by all sync commands, diff commands, install script output formatting, and status reporting.
2. **Platform Authentication** — Each sync target has different auth (AWS profiles, GCP ADC, API tokens via env vars). Need a consistent auth resolution pattern that respects platform conventions.
3. **Sync Audit Logging** — Every sync attempt (success/failure) must be recorded in the audit log with timestamp, target, principal, and per-secret results.
4. **Error Handling Standardization** — Structured error format across all sync targets: target, secret, problem, fix instruction. Shared error types with platform-specific variants.
5. **Rate Limit & Retry** — Shared exponential backoff/retry logic reusable across all external API integrations.
6. **Diff Engine** — Compare zopp secrets against target platform state. Shared logic, target-specific fetching. Used by both `zopp diff` and `zopp sync` (which computes diff then applies).
7. **`zopp.toml` Config Resolution** — Existing pattern extended to sync target configuration. Workspace/project/environment defaults already work; sync target details are always explicit CLI flags.

## Starter Template Evaluation

### Primary Technology Domain

**Rust CLI/Server with external API integrations** — brownfield extension of an established codebase. No starter template applicable; all new code extends the existing workspace structure.

### Existing Architectural Foundation

The following decisions are **already made** and stable:

| Decision | Choice | Status |
|----------|--------|--------|
| Language | Rust 1.90 stable, edition 2021 | Stable |
| gRPC | Tonic 0.14 + Prost 0.14 | Stable |
| HTTP Server | Axum 0.8 | Stable |
| CLI Framework | Clap 4.5 (derive) | Stable |
| Database | SQLx 0.8.6 (SQLite + PostgreSQL) | Stable |
| Crypto | XChaCha20-Poly1305, Ed25519, X25519, Argon2id | Stable |
| Web UI | Leptos 0.7 + WASM | Stable |
| K8s Operator | kube-rs 2.0.1 | Stable |
| Error Handling | thiserror per crate | Stable |
| Async | Tokio 1.48.0 + async-trait | Stable |
| Testing | mockall, serial_test, Playwright | Stable |

### New Dependencies Required

**Cloud Provider SDKs:**

| Crate | Version | Purpose | Notes |
|-------|---------|---------|-------|
| `aws-sdk-secretsmanager` | 1.100.0 | AWS Secrets Manager sync | Official AWS SDK; requires `aws-config` companion |
| `aws-config` | 1.8.13 | AWS credential resolution | Auto-resolves env vars, profiles, instance metadata |
| `google-cloud-secretmanager-v1` | 1.0.0 | GCP Secret Manager sync | Official Google Cloud client; just hit 1.0 (Feb 2026) |

**PaaS Integrations (raw HTTP — no official Rust crates exist):**

| Platform | API Type | Auth Method | Notes |
|----------|----------|-------------|-------|
| Fly.io | REST (Machines API) | API token (`FLY_API_TOKEN`) | `fly-sdk` exists but unofficial/incomplete; use reqwest |
| Vercel | REST | API token (`VERCEL_TOKEN`) | No Rust client crate; use reqwest |
| Render | REST | API key (`RENDER_API_KEY`) | `render-api` exists but low adoption; use reqwest |
| Railway | GraphQL | API token (`RAILWAY_TOKEN`) | No Rust client crate; use reqwest + GraphQL |

**CLI Output & Terminal:**

| Crate | Version | Purpose |
|-------|---------|---------|
| `console` | 0.16.2 | Terminal styling (colors, bold, dim) + TTY detection |
| `indicatif` | 0.18.4 | Progress bars/spinners for sync operations |
| `terminal_size` | 0.4.3 | Terminal width detection for adaptive output |

**Already in zopp (no changes needed):**

| Crate | Current Version | Used For |
|-------|----------------|----------|
| `reqwest` | 0.12 | HTTP client for PaaS API calls (evaluate upgrade to 0.13) |
| `serde_json` | 1.0.145 | JSON serialization for API payloads |
| `sha2` | 0.10 | Checksum verification |

### Architectural Decisions Implied by Dependencies

1. **PaaS integrations use raw HTTP, not SDK crates.** All four PaaS platforms lack mature Rust API clients. Each sync target module owns its own API client code — HTTP requests, JSON parsing, error mapping. This gives full control over error handling and retry logic.

2. **AWS and GCP use official SDK crates.** These are mature, well-maintained, and handle credential resolution automatically. Don't re-implement what the SDKs provide.

3. **Railway requires GraphQL.** Unlike the other PaaS platforms (REST), Railway uses a GraphQL API. This may require a GraphQL client crate or hand-rolled queries via reqwest. This is a Phase 3 concern.

4. **CLI output uses console-rs ecosystem.** `console` + `indicatif` is the standard Rust toolkit for terminal output. These handle TTY detection, `NO_COLOR` support, and cross-platform compatibility — aligning with the UX specification requirements.

5. **reqwest 0.12 vs 0.13.** zopp currently uses reqwest 0.12. New sync crates can use either version. If isolated in their own crates, version conflict is avoided.

## Core Architectural Decisions

### Decision Priority Analysis

**Critical Decisions (Block Implementation):**

1. Sync framework structure (single crate, feature flags)
2. Sync execution model (CLI-triggered, no new binary)
3. Audit approach for sync (server stays blind, existing audit sufficient)

**Important Decisions (Shape Architecture):**

4. CLI output architecture (module within CLI)
5. Sync status tracking (live query, no local state)
6. Install script scope (CLI only, raw GitHub URL)
7. Deployment template location (`deploy/` directory)

**Deferred Decisions (Implementation-Time):**

8. Rate limit & retry approach (shared intent, implementation flexible)
9. reqwest version (0.12 vs 0.13 — decide per-crate when building)

### Sync Framework Architecture

- **Decision:** Single `zopp-sync` crate with per-target feature flags
- **Rationale:** Balances isolation (feature-gated dependencies) with simplicity (one crate, shared types). Avoids workspace bloat of 6+ per-target crates.
- **Structure:** `SyncTarget` trait in crate root; modules `aws`, `gcp`, `fly`, `vercel`, `render`, `railway` behind feature flags
- **Shared components:** Diff engine, result types, error types live in crate root (always compiled)

### Sync Execution Model

- **Decision:** CLI-triggered sync in Phase 1. No new binary. The CLI is the sync agent.
- **Rationale:** The CLI already has authenticated principal with keys. Steps 1-2 (fetch & decrypt from zopp) are existing code paths. Sync only adds: fetch target state, diff, push, report.
- **Flow:** `zopp sync <target>` reuses `SecretContext` from `zopp-secrets` for decryption, then calls `SyncTarget::fetch_current()` and `SyncTarget::apply()` on the target implementation.
- **Future:** Continuous sync agent (separate binary, like K8s operator) reuses the same `SyncTarget` trait and diff engine.

### Sync Audit Approach

- **Decision:** Server stays blind. No new audit RPCs for sync events.
- **Rationale:** The server already records `SecretList`/`SecretRead` audit events when the CLI fetches secrets during sync. Adding a separate "sync completed" RPC would be client-optional (can be skipped), violating audit integrity. The zero-knowledge architecture means the server shouldn't know where decrypted secrets go.
- **Compliance story:** Server audit shows who accessed what and when. Target platform's own logs show when values were updated. Two-sided evidence.
- **Identification:** Sync activity identified by principal ID in audit logs — same pattern as the K8s operator.

### CLI Output Architecture

- **Decision:** Output component module within the CLI (`apps/zopp-cli/src/output/`)
- **Rationale:** No separate binary needs the output components in Phase 1. Can be extracted to a crate later if the continuous sync agent needs it.
- **Components:** OperationHeader, PerItemResult, SummaryLine, DiffSummary, StatusTable, ErrorBlock, InstallProgress, NextSteps
- **Cross-cutting:** Handles `--json`, `--no-color`, `NO_COLOR`, `--verbose`, `--quiet`, TTY detection, terminal width adaptation

### Sync Status Tracking

- **Decision:** Live query — `zopp sync status` queries each target platform in real-time
- **Rationale:** No local state to manage, always accurate. Simpler architecture — no cache files, no staleness problems.
- **Implementation:** Runs the diff engine against each configured target; reports counts and health. Requires platform credentials to be available.

### Install Script

- **Decision:** CLI-only binary (`zopp`), raw GitHub URL for hosting, SHA256 checksum verification
- **Rationale:** Most users only need the CLI. Server is a separate concern for self-hosters. Raw GitHub URL avoids custom domain setup.
- **Location:** `scripts/install.sh` in the repo
- **Behavior:** Detect OS + arch, download binary from GitHub Releases, verify SHA256 checksum, install to PATH, print next steps

### Deployment Templates

- **Decision:** First-class artifacts in `deploy/` directory
- **Structure:** `deploy/fly/fly.toml`, `deploy/docker-compose/docker-compose.yml`, `deploy/railway/railway.json`
- **Each template includes:** PostgreSQL configuration, TLS handling, health checks, documentation for generating first invite token

### Cross-Component Dependencies

```
zopp-cli
  ├── src/output/          (CLI output components)
  ├── src/commands/sync/   (sync subcommands, diff subcommands)
  └── depends on:
       ├── zopp-sync        (SyncTarget trait + implementations)
       │    ├── [core]      (trait, diff engine, result types)
       │    ├── [aws]       (aws-sdk-secretsmanager)
       │    ├── [gcp]       (google-cloud-secretmanager-v1)
       │    ├── [fly]       (reqwest → Fly REST API)
       │    ├── [vercel]    (reqwest → Vercel REST API)
       │    ├── [render]    (reqwest → Render REST API)
       │    └── [railway]   (reqwest → Railway GraphQL API)
       ├── zopp-secrets     (SecretContext for fetch & decrypt)
       └── zopp-proto       (gRPC client for server communication)
```

## Implementation Patterns & Consistency Rules

### Existing Patterns (From Project Context — Already Enforced)

These are established and documented in `project-context.md`. Not repeated here:
- Rust naming (snake_case everything), thiserror per crate, strongly-typed IDs
- Trait-based abstractions, async-trait, Zeroize for sensitive data
- SQLx offline mode, dual-backend migrations, compile-time SQL
- Clap derive CLI, `zopp.toml` config discovery
- Testing (real implementations, 4-backend matrix, RBAC tests)
- Code quality (cargo fmt, clippy zero warnings)

### New Patterns for Distribution & Integrations Wave

#### SyncTarget Trait Pattern

**The trait contract AI agents must follow when adding a new sync target:**

```rust
#[async_trait]
pub trait SyncTarget {
    /// Human-readable name for output (e.g., "AWS Secrets Manager", "Fly")
    fn display_name(&self) -> &str;

    /// Fetch current secrets from the target platform
    /// Returns HashMap<key, value> of what's currently on the target
    async fn fetch_current(&self) -> Result<HashMap<String, String>, SyncError>;

    /// Apply a set of diff operations to the target platform
    /// Returns per-secret results (success or failure with reason)
    async fn apply(&self, operations: &[DiffOperation]) -> Vec<SyncResult>;
}
```

**Rules:**
- Every sync target implements this trait and nothing else at the boundary
- The diff engine is shared — targets never compute their own diffs
- `fetch_current()` returns plaintext key-value pairs (decryption already happened)
- `apply()` returns per-secret results — never a blanket success/failure
- Platform-specific types (AWS ARNs, Fly app IDs) stay inside the module — never leak into shared types
- Errors use `SyncError` enum with platform-specific variants

#### Sync Module Structure Pattern

**Every sync target module follows this file layout:**

```
crates/zopp-sync/src/
  lib.rs              # SyncTarget trait, DiffEngine, shared types
  diff.rs             # Diff engine (shared)
  error.rs            # SyncError enum
  types.rs            # DiffOperation, SyncResult, etc.
  aws/
    mod.rs            # AwsSyncTarget struct + SyncTarget impl
    client.rs         # AWS API client wrapper
  fly/
    mod.rs            # FlySyncTarget struct + SyncTarget impl
    client.rs         # Fly API client wrapper
  ...
```

**Rules:**
- Each target has `mod.rs` (trait impl) and `client.rs` (API client)
- Platform credentials are resolved in the target's constructor, not in trait methods
- Feature flag gates the entire module: `#[cfg(feature = "aws")]`
- Unit tests in each module test the API client with mocked HTTP responses
- Integration tests (if any) are feature-gated and clearly marked as requiring real credentials

#### CLI Output Pattern

**Every command that produces sync/diff output must use the output module components:**

```rust
use crate::output::{OperationHeader, PerItemResult, SummaryLine};

output::header("Syncing", &source_path, &target_display);
for result in results {
    output::per_item(&result);
}
output::summary(&results, &target_display);
```

**Rules:**
- Never use `println!` directly for user-facing sync output — always go through `output::*`
- The output module checks `OutputConfig` (json, no_color, verbose, quiet) once at startup
- `--json` produces a complete JSON object, not line-by-line JSON
- Exit codes follow the UX spec contract: 0 (success), 1 (partial), 2 (total failure), 3 (config error), 4 (connection error)
- Error output uses `output::error_block()` — never raw `eprintln!`

#### CLI Command Pattern for Sync/Diff

**Every new sync/diff subcommand follows this structure:**

```rust
#[derive(Parser)]
pub struct SyncAwsArgs {
    #[command(flatten)]
    pub common: SyncCommonArgs,  // -w, -p, -e, --dry-run, --json, --no-color, etc.

    // Target-specific flags use platform terminology
    #[arg(long)]
    pub region: String,

    #[arg(long)]
    pub prefix: Option<String>,
}
```

**Rules:**
- `SyncCommonArgs` is shared across all sync targets — never redefine common flags
- Target-specific flags use the platform's own terminology (AWS: `--region`, `--prefix`; Fly: `--app`; Vercel: `--project`, `--team`)
- `zopp diff <target>` and `zopp sync <target>` accept identical flags — same struct, different execution path
- Platform credentials come from environment variables following platform conventions — never from CLI flags (avoids secrets in shell history)

#### Error Handling Pattern for Sync

**Sync errors follow a structured format that maps to the UX spec:**

```rust
pub enum SyncError {
    /// Platform credentials not found or invalid
    AuthError { platform: String, message: String, fix: String },
    /// API call failed (rate limit, permission, etc.)
    ApiError { platform: String, operation: String, message: String, fix: String },
    /// Network connectivity failure
    ConnectionError { platform: String, message: String },
    /// zopp-side error (can't fetch/decrypt secrets)
    SourceError { message: String },
}
```

**Rules:**
- Every error variant includes a `fix` field with actionable user instructions
- Platform-specific API errors are mapped to these variants — never expose raw API error types to the user
- The output module formats these into the Error Block component
- `SyncError` implements `std::fmt::Display` with the structured format: `Error: [{platform}] {operation} — {message}\n  Fix: {fix}`

#### Install Script Pattern

**`scripts/install.sh` follows these conventions:**

- POSIX-compatible shell (no bashisms)
- Functions prefixed with `zopp_` to avoid namespace collisions
- All user-facing output goes through a `zopp_log` function (consistent formatting)
- Error messages include the fix instruction
- The script is idempotent — running it twice is safe
- No `sudo` usage — if install location requires root, tell the user to run with sudo themselves
- Binary placed in `$HOME/.zopp/bin` by default, with PATH instructions printed

#### Deployment Template Pattern

**Each template in `deploy/<platform>/` includes:**

1. The configuration file (`fly.toml`, `docker-compose.yml`, etc.)
2. A `README.md` with step-by-step deployment instructions
3. Environment variable documentation (what to set, what's optional)
4. Instructions for generating the first invite token from the deployed server

**Rules:**
- Templates use PostgreSQL, never SQLite (production deployments)
- TLS configuration is explicit — no "it'll figure it out" defaults
- Health check endpoints configured: `/healthz` on port 8080
- Templates are tested — CI validates they parse correctly (YAML lint, TOML lint)

### Anti-Patterns to Avoid

1. **Don't add sync logic to the server.** Sync is entirely client-side. If you're touching `apps/zopp-server/`, you're in the wrong place.
2. **Don't store platform credentials in zopp.** AWS keys, API tokens — these come from environment variables at runtime. Never persist them in zopp's config or database.
3. **Don't create a "universal sync config" in zopp.toml.** Sync target details (region, app name, project) are CLI flags, not config file entries. This prevents accidental sync to wrong targets.
4. **Don't implement your own diff logic in a sync target.** Use the shared diff engine. If a platform has diff-specific needs, extend the shared engine rather than bypassing it.
5. **Don't log plaintext secret values** during sync — not in debug output, not in error messages, not in JSON output. Log keys only, never values.

## Project Structure & Boundaries

### New Additions to Existing Structure

The existing zopp workspace structure remains unchanged. This wave adds:

```
zopp/
├── apps/
│   ├── e2e-tests/
│   │   └── tests/
│   │       └── sync.rs                    ← NEW (sync E2E tests)
│   ├── zopp-cli/
│   │   └── src/
│   │       ├── commands/
│   │       │   ├── sync/
│   │       │   │   ├── mod.rs             ← NEW (sync subcommand router)
│   │       │   │   ├── aws.rs             ← NEW (zopp sync aws)
│   │       │   │   ├── gcp.rs             ← NEW (zopp sync gcp)
│   │       │   │   ├── fly.rs             ← NEW (zopp sync fly)
│   │       │   │   ├── vercel.rs          ← NEW (zopp sync vercel)
│   │       │   │   ├── render.rs          ← NEW (zopp sync render)
│   │       │   │   ├── railway.rs         ← NEW (zopp sync railway)
│   │       │   │   └── status.rs          ← NEW (zopp sync status)
│   │       │   ├── diff/
│   │       │   │   ├── mod.rs             ← NEW (diff subcommand router)
│   │       │   │   ├── aws.rs             ← NEW (zopp diff aws)
│   │       │   │   ├── gcp.rs             ← NEW (zopp diff gcp)
│   │       │   │   ├── fly.rs             ← NEW (zopp diff fly)
│   │       │   │   ├── vercel.rs          ← NEW (zopp diff vercel)
│   │       │   │   ├── render.rs          ← NEW (zopp diff render)
│   │       │   │   └── railway.rs         ← NEW (zopp diff railway)
│   │       │   └── ... (existing commands)
│   │       ├── output/
│   │       │   ├── mod.rs                 ← NEW (output component module)
│   │       │   ├── config.rs              ← NEW (OutputConfig: json, color, verbose)
│   │       │   ├── components.rs          ← NEW (Header, PerItem, Summary, etc.)
│   │       │   └── json.rs               ← NEW (JSON output serialization)
│   │       └── ... (existing CLI source)
│   ├── zopp-server/                       (unchanged — no server changes)
│   └── zopp-web/                          (unchanged)
├── crates/
│   ├── zopp-sync/                         ← NEW CRATE
│   │   ├── Cargo.toml                     (feature flags: aws, gcp, fly, vercel, render, railway)
│   │   └── src/
│   │       ├── lib.rs                     (SyncTarget trait, re-exports)
│   │       ├── diff.rs                    (DiffEngine — shared diff logic)
│   │       ├── error.rs                   (SyncError enum)
│   │       ├── types.rs                   (DiffOperation, SyncResult, SyncSecrets)
│   │       ├── aws/
│   │       │   ├── mod.rs                 (AwsSyncTarget + SyncTarget impl)
│   │       │   └── client.rs             (AWS SDK wrapper)
│   │       ├── gcp/
│   │       │   ├── mod.rs                 (GcpSyncTarget + SyncTarget impl)
│   │       │   └── client.rs             (GCP SDK wrapper)
│   │       ├── fly/
│   │       │   ├── mod.rs                 (FlySyncTarget + SyncTarget impl)
│   │       │   └── client.rs             (Fly REST API client)
│   │       ├── vercel/
│   │       │   ├── mod.rs                 (VercelSyncTarget + SyncTarget impl)
│   │       │   └── client.rs             (Vercel REST API client)
│   │       ├── render/
│   │       │   ├── mod.rs                 (RenderSyncTarget + SyncTarget impl)
│   │       │   └── client.rs             (Render REST API client)
│   │       └── railway/
│   │           ├── mod.rs                 (RailwaySyncTarget + SyncTarget impl)
│   │           └── client.rs             (Railway GraphQL API client)
│   └── ... (existing crates unchanged)
├── deploy/                                ← NEW DIRECTORY
│   ├── fly/
│   │   ├── fly.toml
│   │   └── README.md
│   ├── docker-compose/
│   │   ├── docker-compose.yml
│   │   └── README.md
│   └── railway/
│       ├── railway.json
│       └── README.md
├── scripts/                               ← NEW DIRECTORY
│   └── install.sh                         (curl install script)
└── ... (existing root files unchanged)
```

### Architectural Boundaries

**Boundary 1: zopp-sync crate ↔ CLI**
- CLI depends on `zopp-sync` but never calls platform APIs directly
- CLI creates a `SyncTarget` instance with platform credentials, then calls `fetch_current()` and `apply()`
- Diff engine lives in `zopp-sync` — CLI calls it between fetch and apply
- CLI owns output formatting (`output/` module) — `zopp-sync` returns data, CLI formats it

**Boundary 2: zopp-sync ↔ External platforms**
- Each sync target module encapsulates all platform API interaction
- Platform-specific types never cross the module boundary
- Trait boundary: `HashMap<String, String>` for secrets, `Vec<DiffOperation>` for changes
- HTTP/SDK clients are internal to each module

**Boundary 3: Sync commands ↔ Existing CLI**
- New commands use existing `SecretContext` from `zopp-secrets` for fetch & decrypt
- New commands use existing `zopp.toml` config resolution for workspace/project/environment
- New commands share `SyncCommonArgs` for consistent flags
- Existing `zopp sync k8s` and `zopp diff k8s` remain as-is

**Boundary 4: Deploy templates ↔ Everything else**
- Pure configuration — no code, no binary changes
- Templates reference existing `zopp-server` Docker image
- Each template is self-contained: config file + README

### Requirements to Structure Mapping

| FR Category | Primary Location | Supporting Location |
|-------------|-----------------|-------------------|
| FR1-5: Install & Distribution | `scripts/install.sh` | CI workflows for binary releases |
| FR6-12: Cloud Sync (AWS, GCP) | `crates/zopp-sync/src/aws/`, `gcp/` | `apps/zopp-cli/src/commands/sync/` |
| FR13-19: PaaS Sync | `crates/zopp-sync/src/fly/`, `vercel/`, `render/`, `railway/` | `apps/zopp-cli/src/commands/sync/` + `diff/` |
| FR20-24: Sync Operations | `crates/zopp-sync/src/diff.rs`, `types.rs` | `apps/zopp-cli/src/output/`, `commands/sync/status.rs` |
| FR25-30: Server Deployment | `deploy/fly/`, `deploy/docker-compose/`, `deploy/railway/` | — |
| FR31-33: Zero-Knowledge | `crates/zopp-sync/src/lib.rs` (trait enforces client-side) | Existing `zopp-secrets` crate |

### Data Flow: Sync Operation

```
User runs: zopp sync aws --region us-east-1 --prefix /prod/

apps/zopp-cli/src/commands/sync/aws.rs
  │
  ├── 1. Resolve config (zopp.toml + flags)
  ├── 2. Resolve AWS credentials (env vars / profile)
  ├── 3. Build SecretContext (zopp-secrets)
  │      └── Fetch keys + decrypt secrets via gRPC → zopp-server
  ├── 4. Build AwsSyncTarget (zopp-sync, feature "aws")
  │      └── AWS SDK client with resolved credentials
  ├── 5. Fetch target state
  │      └── AwsSyncTarget::fetch_current() → AWS API
  ├── 6. Compute diff
  │      └── DiffEngine::diff(zopp_secrets, aws_secrets)
  ├── 7. Apply changes (unless --dry-run)
  │      └── AwsSyncTarget::apply(diff_operations) → AWS API
  └── 8. Output results
         └── output::header(), output::per_item(), output::summary()
```

## Architecture Validation Results

### Coherence Validation ✅

**Decision Compatibility:**
All 7 architectural decisions are mutually compatible. The single `zopp-sync` crate with feature flags works with the Rust workspace model. CLI-triggered sync reuses the existing `SecretContext` — no new binary or authentication path. Server-stays-blind audit is consistent with zero-knowledge and matches the K8s operator pattern. All new dependency versions are compatible with the existing Cargo workspace (aws-sdk 1.100.0 with tokio 1.48.0, google-cloud-secretmanager-v1 1.0.0 with tonic 0.14). No contradictory decisions found.

**Pattern Consistency:**
`SyncTarget` trait follows the same Rust trait abstraction pattern as existing `Store` trait. Naming is consistent (`AwsSyncTarget` / `FlySyncTarget` — matches `SqliteStore` / `PostgresStore`). Error handling uses `thiserror` (same as every other crate). CLI commands use clap derive with `#[command(flatten)]` (same as existing commands). Module layout (`mod.rs` + `client.rs` per target) is consistent across all sync targets.

**Structure Alignment:**
`crates/zopp-sync/` fits naturally alongside existing crates. CLI commands under `commands/sync/` and `commands/diff/` follow the existing command tree. Output module under `src/output/` is a clean new addition. `deploy/` and `scripts/` at the project root are standard locations. All 4 architectural boundaries are clear and respect existing crate boundaries.

### Requirements Coverage ✅

**Functional Requirements Coverage:**

| FR | Status | Architecture Support |
|----|--------|---------------------|
| FR1 | ✅ | `scripts/install.sh` — curl install with OS/arch detection |
| FR2 | ✅ | Install script pattern: detect OS + arch, download correct binary |
| FR3 | ⏳ Phase 2 | Homebrew formula — packaging/CI concern, no architectural decision needed |
| FR4 | ⏳ Phase 3 | apt package — packaging/CI concern, no architectural decision needed |
| FR5 | ⏳ Phase 3 | nix package — packaging/CI concern, no architectural decision needed |
| FR6 | ✅ | `zopp-sync/src/aws/` — AwsSyncTarget impl |
| FR7 | ✅ | `zopp-sync/src/gcp/` — GcpSyncTarget impl |
| FR8 | ✅ | CLI flags (--prefix, --region) map environments to cloud paths |
| FR9 | ✅ | `zopp diff aws`, `zopp diff gcp` commands in `commands/diff/` |
| FR10 | ✅ | `--dry-run` in SyncCommonArgs — skips `apply()` step |
| FR11 | ✅ | DiffEngine computes deltas; `apply()` only touches changed secrets |
| FR12 | ✅ | Platform-native auth: aws-config for AWS, ADC for GCP |
| FR13 | ✅ | `zopp-sync/src/fly/` — FlySyncTarget impl |
| FR14 | ✅ | `zopp-sync/src/vercel/` — VercelSyncTarget impl |
| FR15 | ✅ | `zopp-sync/src/render/` — RenderSyncTarget impl |
| FR16 | ✅ | `zopp-sync/src/railway/` — RailwaySyncTarget impl |
| FR17 | ✅ | Platform-specific CLI flags (--app, --project, --team, --service) |
| FR18 | ✅ | `zopp diff <target>` commands defined for all PaaS targets |
| FR19 | ✅ | API tokens via env vars (FLY_API_TOKEN, VERCEL_TOKEN, etc.) |
| FR20 | ✅* | Server records SecretList/SecretRead RPCs (inherent audit) |
| FR21 | ✅ | `zopp sync status` — live query via `fetch_current()` on configured targets |
| FR22 | ✅ | Rate limit handling deferred to implementation; SyncError::ApiError captures throttling |
| FR23 | ✅ | SyncError enum: platform + operation + message + fix instruction per error |
| FR24 | ✅ | Service principal runs sync commands (same auth as K8s operator) |
| FR25 | ✅ | `deploy/fly/fly.toml` + README |
| FR26 | ✅ | `deploy/railway/railway.json` + README |
| FR27 | ✅ | `deploy/docker-compose/docker-compose.yml` + README |
| FR28 | ✅ | All templates use PostgreSQL |
| FR29 | ✅ | TLS explicit in templates (automatic via platform or configured) |
| FR30 | ✅ | Each template README includes first invite token instructions |
| FR31 | ✅ | SyncTarget trait enforces client-side decryption |
| FR32 | ✅ | Service principal with scoped RBAC (existing principal system) |
| FR33 | ✅ | Workspace admin creates scoped principal (existing RBAC) |

*FR20 Note: "Records every sync attempt in the audit log" is covered by two-sided evidence: (1) zopp server audit logs capture secret reads by principal ID, (2) target platform logs capture writes. The server doesn't know a "sync" happened — it sees ordinary secret reads. This is the collaboratively decided "server stays blind" approach, consistent with zero-knowledge.

**Non-Functional Requirements Coverage:**

| NFR | Status | Architecture Support |
|-----|--------|---------------------|
| NFR1 | ✅ | Install script: detect + download + verify — no compilation step |
| NFR2 | ✅ | Incremental sync via DiffEngine; batch operations in target modules |
| NFR3 | ✅ | `zopp diff` = fetch_current() + diff — no apply step |
| NFR4 | ✅ | Rate limit handling deferred; SyncError captures the scenario |
| NFR5 | ✅ | Anti-pattern #5: "Don't log plaintext secret values" |
| NFR6 | ✅ | Credentials from env vars only; anti-pattern #2 |
| NFR7 | ✅ | SHA256 checksum verification in install script pattern |
| NFR8 | ✅ | reqwest + AWS SDK + GCP SDK all default to TLS |
| NFR9 | ✅ | Service principal with least-privilege scope |
| NFR10 | ✅ | Feature-gated modules; isolated implementations per target |
| NFR11 | ✅ | Platform-native auth documented per target |
| NFR12 | ✅ | SyncError includes fix instructions; graceful degradation |
| NFR13 | ✅ | Unit tests with mocked HTTP; integration tests feature-gated |
| NFR14 | ✅ | Independent per-target sync commands; one failure doesn't block others |
| NFR15 | ✅ | Diff-based sync is inherently idempotent |
| NFR16 | ✅ | `Vec<SyncResult>` — per-secret success/failure reporting |
| NFR17 | ✅ | Templates include health checks, PostgreSQL, recovery config |

**Result:** 33/33 FRs covered (3 deferred to later phases as packaging concerns). 17/17 NFRs covered.

### Implementation Readiness ✅

**Decision Completeness:**
All 7 critical/important decisions are documented with rationale and dependency versions. 2 decisions explicitly deferred to implementation time (rate limiting approach, reqwest version). New dependency versions are pinned with specific numbers.

**Structure Completeness:**
Complete directory layout with every new file listed and annotated. 4 architectural boundaries clearly defined with data flow directions. Requirements-to-structure mapping table connects every FR category to its file location.

**Pattern Completeness:**
7 implementation patterns with code examples (SyncTarget trait, module structure, CLI output, CLI command, error handling, install script, deployment template). 5 anti-patterns explicitly listed. All patterns include enforceable rules.

### Gap Analysis Results

**Critical Gaps:** None.

**Important Gaps:**
1. **E2E test strategy for sync commands** — `apps/e2e-tests/tests/sync.rs` is defined but doesn't specify whether E2E tests use mocked platform APIs or real accounts. Given the project's testing philosophy ("real implementations, only mock to reproduce specific error conditions"), this needs clarification at story-writing time. Not blocking for architecture.
2. **`zopp sync configure` in user journeys vs architecture** — Diana's journey references `zopp sync configure aws`. The architecture uses explicit flags per command (`zopp sync aws --region ...`), consistent with anti-pattern #3 ("Don't create a universal sync config"). Journey text is aspirational narrative; the FRs correctly specify per-command flags. No actual gap.

**Nice-to-Have Gaps:**
1. CI configuration changes for feature flags (`cargo test --features aws`) — CI concern, not architectural.
2. Output component detailed function signatures — the pattern (`output::header()`, `output::per_item()`, `output::summary()`) is clear enough for implementation.

### Validation Issues Addressed

No critical or important issues found during validation. All architectural decisions are coherent, all requirements are covered, and the implementation patterns are comprehensive enough for AI agents to implement consistently.

### Architecture Completeness Checklist

**✅ Requirements Analysis**

- [x] Project context thoroughly analyzed (33 FRs, 17 NFRs, 4 user journeys)
- [x] Scale and complexity assessed (medium, ~12 new components)
- [x] Technical constraints identified (6 constraints documented)
- [x] Cross-cutting concerns mapped (7 concerns)

**✅ Architectural Decisions**

- [x] Critical decisions documented with versions (7 decided, 2 deferred)
- [x] Technology stack fully specified (new dependencies with versions)
- [x] Integration patterns defined (SyncTarget trait, cross-component dependencies)
- [x] Performance considerations addressed (incremental sync, diff engine)

**✅ Implementation Patterns**

- [x] Naming conventions established (target-specific modules, CLI args)
- [x] Structure patterns defined (mod.rs + client.rs per target)
- [x] Communication patterns specified (trait boundary: HashMap + DiffOperation)
- [x] Process patterns documented (error handling, CLI output, install script)

**✅ Project Structure**

- [x] Complete directory structure defined
- [x] Component boundaries established (4 boundaries)
- [x] Integration points mapped (data flow diagram)
- [x] Requirements to structure mapping complete

### Architecture Readiness Assessment

**Overall Status:** READY FOR IMPLEMENTATION

**Confidence Level:** High — brownfield extension of proven patterns with clear boundaries

**Key Strengths:**
- Extends the established K8s operator sync model — not inventing new architecture
- SyncTarget trait provides a consistent, testable contract for all 6 targets
- Feature-gated crate prevents dependency bloat for users who only need some targets
- Zero server changes — preserves zero-knowledge guarantees by design
- Clear anti-patterns prevent common implementation mistakes

**Areas for Future Enhancement:**
- Continuous sync agent (separate binary) when demand emerges
- Output module extraction to shared crate if multiple binaries need it
- `zopp sync configure` for persistent target config if explicit flags prove too verbose

### Implementation Handoff

**AI Agent Guidelines:**

- Follow all architectural decisions exactly as documented
- Use implementation patterns consistently across all sync targets
- Respect the 4 architectural boundaries
- Refer to this document for all architectural questions
- Consult `project-context.md` for existing rules (not repeated here)

**First Implementation Priority:**
Phase 1: `scripts/install.sh` → `crates/zopp-sync/` (core + aws + fly) → `deploy/fly/` → CLI commands → E2E tests

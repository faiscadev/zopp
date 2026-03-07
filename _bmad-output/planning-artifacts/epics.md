---
stepsCompleted: ['step-01-validate-prerequisites', 'step-02-design-epics', 'step-03-create-stories', 'step-04-final-validation']
status: complete
completedAt: '2026-03-07'
inputDocuments:
  - prd.md
  - architecture.md
  - ux-design-specification.md
---

# zopp - Epic Breakdown

## Overview

This document provides the complete epic and story breakdown for zopp, decomposing the requirements from the PRD, UX Design, and Architecture into implementable stories.

## Requirements Inventory

### Functional Requirements

FR1: A developer can install the zopp CLI on macOS or Linux with a single curl command
FR2: The install script can detect the user's OS and architecture and download the correct binary
FR3: A developer can install the zopp CLI via Homebrew on macOS or Linux
FR4: A developer can install the zopp CLI via apt on Debian/Ubuntu
FR5: A developer can install the zopp CLI via nix
FR6: A user can sync secrets from a zopp environment to AWS Secrets Manager
FR7: A user can sync secrets from a zopp environment to GCP Secret Manager
FR8: A user can map zopp environments to cloud secret paths/names
FR9: A user can preview sync changes before applying them (`zopp diff aws`, `zopp diff gcp`)
FR10: A user can perform a dry-run sync that shows what would change without modifying the target
FR11: The system can sync only changed secrets (incremental sync) rather than the full set
FR12: A user can authenticate with cloud providers using platform-native credentials (AWS profile/env vars, GCP ADC/service account)
FR13: A user can sync secrets from a zopp environment to Fly
FR14: A user can sync secrets from a zopp environment to Vercel
FR15: A user can sync secrets from a zopp environment to Render
FR16: A user can sync secrets from a zopp environment to Railway
FR17: A user can map zopp environments to PaaS deployment targets (project, service, app)
FR18: A user can preview PaaS sync changes before applying them (`zopp diff <target>`)
FR19: A user can authenticate with PaaS platforms using API tokens
FR20: The system records every sync attempt (success or failure) in the audit log
FR21: A user can view sync status for all configured targets (`zopp sync status`)
FR22: The system handles platform API rate limits with automatic backoff and retry
FR23: The system surfaces clear error messages on sync failure identifying the target, secret, and failure reason
FR24: A sync agent (service principal) can run sync operations on behalf of a team without human interaction
FR25: A user can deploy zopp-server to Fly using a provided `fly.toml` template
FR26: A user can deploy zopp-server to Railway using a provided template
FR27: A user can deploy zopp-server using Docker Compose with a provided template
FR28: Each deployment template includes PostgreSQL configuration
FR29: Each deployment template includes TLS configuration (automatic via platform or explicit)
FR30: A user can generate an invite token from a PaaS-deployed server
FR31: All sync operations decrypt secrets client-side (sync agent/CLI), never on the server
FR32: The sync agent authenticates as a service principal with scoped RBAC permissions
FR33: A workspace admin can create a service principal scoped to read-only on specific environments for sync operations

### NonFunctional Requirements

NFR1: Install script completes in under 30 seconds on a standard broadband connection
NFR2: Sync operations complete within 30 seconds for environments with up to 100 secrets
NFR3: `zopp diff` preview commands return results within 5 seconds
NFR4: Rate limit backoff adds no more than 60 seconds of additional delay per sync cycle under normal conditions
NFR5: No plaintext secrets are written to disk, logs, or temporary files during sync operations
NFR6: Platform API credentials (AWS keys, PaaS tokens) are never logged or persisted by zopp — they are read from environment variables or CLI flags at runtime only
NFR7: The install script verifies binary integrity (checksum verification) before placing the binary in PATH
NFR8: All sync communication with external platforms uses TLS
NFR9: Sync agent service principals follow least-privilege: read-only access scoped to specific environments
NFR10: Each sync integration is isolated — a failure or API change in one platform does not affect others
NFR11: Each sync integration supports platform-native authentication methods (no custom auth schemes)
NFR12: Sync integrations handle API version changes gracefully — clear error messages on breaking changes, not silent data corruption
NFR13: Each sync integration has automated integration tests that run against the platform's API (or a mock of it)
NFR14: A failed sync to one target does not block sync to other targets
NFR15: Sync operations are idempotent — running the same sync twice produces the same result
NFR16: Partial sync failures (some secrets synced, some failed) are reported per-secret, not as a blanket failure
NFR17: Deployment templates produce servers that pass health checks and recover from container restarts without data loss

### Additional Requirements

**From Architecture:**

- Brownfield extension — no starter template; all new code extends the existing workspace structure
- Single `zopp-sync` crate with per-target feature flags (aws, gcp, fly, vercel, render, railway)
- `SyncTarget` trait pattern: `fetch_current()` → `DiffEngine::diff()` → `apply()` — shared across all targets
- Shared `DiffEngine` computes deltas; targets never compute their own diffs
- CLI output component module at `apps/zopp-cli/src/output/` with 8 reusable components (OperationHeader, PerItemResult, SummaryLine, DiffSummary, StatusTable, ErrorBlock, InstallProgress, NextSteps)
- `SyncCommonArgs` shared struct for all sync/diff commands (`-w`, `-p`, `-e`, `--dry-run`, `--json`, `--no-color`)
- Platform credentials from environment variables only — never CLI flags, never persisted
- Structured `SyncError` enum with `AuthError`, `ApiError`, `ConnectionError`, `SourceError` — each with `fix` field
- CLI-triggered sync in Phase 1 (no new binary; CLI is the sync agent)
- Server stays blind — no new audit RPCs for sync events; existing SecretList/SecretRead audit events suffice
- Sync status via live query (`zopp sync status` calls `fetch_current()` on each configured target)
- Install script at `scripts/install.sh` — POSIX shell, SHA256 checksum verification, installs to `$HOME/.zopp/bin`
- Deployment templates in `deploy/` directory with per-platform README
- Each sync module follows `mod.rs` + `client.rs` file layout
- Exit code contract: 0 (success), 1 (partial failure), 2 (total failure), 3 (config error), 4 (connection error)
- Anti-patterns: no sync logic on server, no platform credentials stored in zopp, no universal sync config in zopp.toml, no custom diff logic per target, no plaintext secret values in logs

**From UX Design:**

- CLI output follows "Clean Terminal" design direction — header-first, per-item results, summary line, structured errors
- ANSI color semantic mapping: Green/Bold = success/addition, Red/Bold = error/removal, Yellow = warning/change, Cyan = informational headers, White/Bold = emphasis, Dim = timestamps/secondary
- `NO_COLOR` environment variable and `--no-color` flag support — output meaningful without color via symbols (✓, ✗, ⚠, +, -, ~)
- `--json` produces complete JSON object (not line-by-line) for machine-readable output
- `--verbose` adds API call details and timing; `--quiet` suppresses everything except errors
- Terminal width adaptation with 80-column minimum; tables truncate with `...`
- Progress indicators: spinner (⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏) for in-progress, ✓ for completed, ✗ for failed, ⚠ for warnings
- Next-step guidance printed after every terminal state (install → "run zopp join", sync → status check)
- Diff output uses terraform-style formatting: + add, ~ update, - remove with color coding
- Error format: `Error: [target] [operation] failed — [reason]. Fix: [actionable instruction]. Docs: [link]`
- Status table is screenshot-ready for compliance evidence
- Install script output shows platform detection, version, download progress, checksum verification, and "Get started" section

### FR Coverage Map

FR1: Epic 1 — curl install script
FR2: Epic 1 — OS/arch auto-detection
FR3: Epic 6 — Homebrew formula
FR4: Epic 8 — apt package
FR5: Epic 8 — nix package
FR6: Epic 2 — AWS Secrets Manager sync
FR7: Epic 4 — GCP Secret Manager sync
FR8: Epic 2 — Environment-to-cloud-path mapping
FR9: Epic 2 — Preview sync changes (diff)
FR10: Epic 2 — Dry-run sync
FR11: Epic 2 — Incremental sync
FR12: Epic 2 — Platform-native cloud auth
FR13: Epic 3 — Fly sync
FR14: Epic 5 — Vercel sync
FR15: Epic 5 — Render sync
FR16: Epic 7 — Railway sync
FR17: Epic 3 — Environment-to-PaaS-target mapping
FR18: Epic 3 — Preview PaaS sync (diff)
FR19: Epic 3 — PaaS API token auth
FR20: Epic 2 — Sync audit logging
FR21: Epic 2 — Sync status view
FR22: Epic 2 — Rate limit handling
FR23: Epic 2 — Clear sync error messages
FR24: Epic 2 — Sync agent (service principal)
FR25: Epic 3 — Fly deployment template
FR26: Epic 7 — Railway deployment template
FR27: Epic 9 — Docker Compose deployment template
FR28: Epic 3 — PostgreSQL in deployment templates
FR29: Epic 3 — TLS in deployment templates
FR30: Epic 3 — Invite token from PaaS-deployed server
FR31: Epic 2 — Client-side decryption only
FR32: Epic 2 — Service principal with scoped RBAC
FR33: Epic 2 — Create scoped sync service principal

## Epic List

### Epic 1: One-Command CLI Installation
Users can install zopp CLI on macOS or Linux with a single curl command, with automatic platform detection and checksum verification.
**FRs covered:** FR1, FR2
**Phase:** 1

### Epic 2: Sync Framework & AWS Secrets Manager Integration
Teams can sync secrets from zopp to AWS Secrets Manager with preview (diff), dry-run, incremental sync, monitoring (sync status), and audit trail. This epic builds the core sync framework (SyncTarget trait, DiffEngine, CLI output components, SyncCommonArgs, error handling) that all subsequent sync targets reuse.
**FRs covered:** FR6, FR8, FR9, FR10, FR11, FR12, FR20, FR21, FR22, FR23, FR24, FR31, FR32, FR33
**Phase:** 1

### Epic 3: Fly Integration (Sync & Deployment)
Users can both sync secrets to Fly apps AND deploy zopp-server on Fly with zero infrastructure management. Completes the end-to-end Fly story: deploy server there, sync app secrets there.
**FRs covered:** FR13, FR17, FR18, FR19, FR25, FR28, FR29, FR30
**Phase:** 1
**Builds on:** Epic 2 (reuses sync framework)

### Epic 4: GCP Secret Manager Integration
Teams can sync secrets to GCP Secret Manager, enabling multi-cloud secrets management (AWS + GCP) from a single source of truth.
**FRs covered:** FR7
**Phase:** 2
**Builds on:** Epic 2 (reuses sync framework)

### Epic 5: Vercel & Render Integrations
Frontend and API teams can sync secrets to Vercel and Render, eliminating manual secret copying across PaaS dashboards.
**FRs covered:** FR14, FR15
**Phase:** 2
**Builds on:** Epic 2 (reuses sync framework)

### Epic 6: Homebrew Distribution
macOS and Linux developers can install zopp via Homebrew — the highest-impact package manager for the target audience.
**FRs covered:** FR3
**Phase:** 2

### Epic 7: Railway Integration (Sync & Deployment)
Teams can sync secrets to Railway AND deploy zopp-server on Railway.
**FRs covered:** FR16, FR26
**Phase:** 3
**Builds on:** Epic 2 (reuses sync framework)

### Epic 8: Extended Distribution (apt & nix)
Linux server admins install via apt; sovereignty-first engineers install via nix.
**FRs covered:** FR4, FR5
**Phase:** 3

### Epic 9: Docker Compose Deployment
Self-hosters can deploy zopp-server using Docker Compose for container-based deployments without Kubernetes.
**FRs covered:** FR27
**Phase:** 3

---

## Epic 1: One-Command CLI Installation

Users can install zopp CLI on macOS or Linux with a single curl command, with automatic platform detection and checksum verification.

### Story 1.1: Set up cross-platform binary release CI pipeline

As a developer,
I want zopp binaries published to GitHub Releases for all supported platforms,
So that users can download pre-built binaries without compiling from source.

**Acceptance Criteria:**

**Given** a new version tag is pushed to the repository
**When** the CI pipeline runs
**Then** binaries are built for macOS x86_64, macOS aarch64, Linux x86_64, and Linux aarch64
**And** each binary is packaged as a tar.gz archive
**And** SHA256 checksums are generated for each archive
**And** archives and checksums are published to the GitHub Release

### Story 1.2: Create curl install script

As a developer,
I want to install zopp CLI with a single curl command,
So that I can start using zopp in under 30 seconds without building from source.

**Acceptance Criteria:**

**Given** the user runs `curl -fsSL <install-url> | sh` on a supported platform
**When** the script executes
**Then** it detects the user's OS (macOS or Linux) and architecture (x86_64 or aarch64)
**And** it downloads the correct binary archive from GitHub Releases
**And** it verifies the SHA256 checksum before installing
**And** it installs the binary to `$HOME/.zopp/bin`
**And** it prints PATH setup instructions if `$HOME/.zopp/bin` is not in PATH
**And** it prints a "Get started" section with the next command to run

**Given** the user runs the install script on an unsupported platform
**When** the script detects an unsupported OS or architecture
**Then** it prints a clear error message listing supported platforms
**And** it suggests `cargo install` as a fallback

**Given** the checksum verification fails
**When** the downloaded archive doesn't match the expected SHA256
**Then** the script aborts with a clear error message
**And** suggests retrying or downloading manually

**Given** the script has already been run once
**When** the user runs it again
**Then** it completes successfully (idempotent), replacing the existing binary

---

## Epic 2: Sync Framework & AWS Secrets Manager Integration

Teams can sync secrets from zopp to AWS Secrets Manager with preview (diff), dry-run, incremental sync, monitoring (sync status), and audit trail. This epic builds the core sync framework that all subsequent sync targets reuse.

### Story 2.1: Create zopp-sync crate with SyncTarget trait, DiffEngine, and shared types

As a developer building sync integrations,
I want a shared sync framework with a well-defined trait and diff engine,
So that all sync targets follow a consistent pattern and share common logic.

**Acceptance Criteria:**

**Given** the zopp-sync crate is created in `crates/zopp-sync/`
**When** a sync target is implemented
**Then** it implements the `SyncTarget` trait with `display_name()`, `fetch_current()`, and `apply()` methods
**And** the trait uses `HashMap<String, String>` for secrets and `Vec<DiffOperation>` for changes

**Given** two sets of secrets (source and target)
**When** the `DiffEngine::diff()` is called
**Then** it returns a list of `DiffOperation` entries: `Add`, `Update`, and `Remove`
**And** only changed secrets are included (incremental by design)

**Given** the crate defines shared error types
**When** a sync operation fails
**Then** the error is represented as a `SyncError` with variants `AuthError`, `ApiError`, `ConnectionError`, and `SourceError`
**And** each variant includes a `fix` field with actionable user instructions

**Given** the crate defines result types
**When** `apply()` returns
**Then** each secret has an individual `SyncResult` (success or failure with reason)
**And** partial failures are represented per-secret, never as a blanket failure

**Given** the crate uses feature flags
**When** a sync target feature is not enabled
**Then** its dependencies are not compiled

### Story 2.2: Implement AWS Secrets Manager sync target

As a user,
I want zopp to connect to AWS Secrets Manager,
So that I can sync my secrets from zopp to AWS using my existing AWS credentials.

**Acceptance Criteria:**

**Given** the `aws` feature flag is enabled on zopp-sync
**When** `AwsSyncTarget` is constructed
**Then** it resolves AWS credentials automatically via `aws-config` (environment variables, AWS profile, instance metadata)
**And** it accepts `--region` and `--prefix` parameters for targeting

**Given** valid AWS credentials are available
**When** `fetch_current()` is called
**Then** it lists all secrets in AWS Secrets Manager matching the configured prefix
**And** it returns their current values as a `HashMap<String, String>`

**Given** a list of `DiffOperation` entries
**When** `apply()` is called
**Then** it creates new secrets in AWS SM for `Add` operations
**And** it updates existing secrets for `Update` operations
**And** it deletes secrets for `Remove` operations
**And** it returns per-secret `SyncResult` entries

**Given** AWS credentials are missing or invalid
**When** any operation is attempted
**Then** a `SyncError::AuthError` is returned with fix instructions listing credential sources

**Given** the AWS API returns a rate limit error
**When** the sync target encounters throttling
**Then** it retries with exponential backoff
**And** backoff adds no more than 60 seconds of additional delay under normal conditions

**Given** the sync target module
**When** tests are run
**Then** unit tests verify API client behavior with mocked HTTP responses
**And** platform-specific types (ARNs, regions) do not leak outside the aws module

### Story 2.3: Create CLI output component module

As a user running sync commands,
I want consistent, well-formatted terminal output across all commands,
So that I can quickly scan results, understand errors, and take screenshots for compliance.

**Acceptance Criteria:**

**Given** the output module is created at `apps/zopp-cli/src/output/`
**When** any sync or diff command runs
**Then** output uses the shared components: OperationHeader, PerItemResult, SummaryLine, DiffSummary, StatusTable, ErrorBlock

**Given** the `--json` flag is passed
**When** any command produces output
**Then** a complete JSON object is emitted (not line-by-line JSON)
**And** no ANSI color codes are included in JSON output

**Given** `NO_COLOR` environment variable is set or `--no-color` flag is passed
**When** output is rendered
**Then** no ANSI color codes are emitted
**And** symbols (checkmark, cross, warning, +, -, ~) still convey meaning without color

**Given** the `--verbose` flag is passed
**When** a sync operation runs
**Then** additional detail is shown (API calls, timing)

**Given** the `--quiet` flag is passed
**When** a sync operation runs
**Then** only errors are displayed

**Given** any command completes
**When** the exit code is set
**Then** it follows the contract: 0 (success), 1 (partial failure), 2 (total failure), 3 (config error), 4 (connection error)

**Given** the terminal width is detected
**When** table output is rendered
**Then** columns adapt to available width with 80-column minimum
**And** long values are truncated with `...` rather than wrapping

### Story 2.4: Add zopp sync aws and zopp diff aws CLI commands

As a user,
I want to sync secrets from zopp to AWS Secrets Manager and preview changes before applying,
So that I can keep AWS in sync with zopp as my single source of truth.

**Acceptance Criteria:**

**Given** the user runs `zopp diff aws --region us-east-1 --prefix /prod/`
**When** the command executes
**Then** it fetches secrets from zopp (encrypted), decrypts client-side using the principal's keys
**And** it fetches current secrets from AWS Secrets Manager
**And** it displays a color-coded diff: + for additions, ~ for updates, - for removals
**And** it shows a summary line with change counts
**And** no changes are made to AWS (read-only operation)

**Given** the user runs `zopp sync aws --region us-east-1 --prefix /prod/`
**When** the command executes
**Then** it performs the same fetch-decrypt-diff cycle as `zopp diff`
**And** it applies changes to AWS Secrets Manager
**And** it displays per-secret results with checkmark (synced) or cross (failed)
**And** it shows a summary line: "X/Y secrets synced to AWS Secrets Manager (us-east-1)"

**Given** the user passes `--dry-run` to `zopp sync aws`
**When** the command executes
**Then** it shows what would change without modifying AWS (same output as `zopp diff`)

**Given** a `SyncCommonArgs` struct is defined
**When** any sync or diff command is parsed
**Then** it accepts shared flags: `-w`, `-p`, `-e`, `--dry-run`, `--json`, `--no-color`, `--verbose`, `--quiet`
**And** target-specific flags (`--region`, `--prefix`) are defined per-command

**Given** the sync operation is performed by a service principal
**When** the principal has read-only RBAC access to the target environment
**Then** it can fetch and decrypt secrets for sync
**And** the server audit log records the secret access by the principal's ID

**Given** sync is run twice with no changes in between
**When** the second sync executes
**Then** no changes are applied (idempotent)
**And** the output shows "No changes. Target is in sync."

**Given** the sync completes
**When** results are displayed
**Then** no plaintext secret values appear in the output, logs, or temporary files
**And** only secret key names are shown

### Story 2.5: Add zopp sync status command

As a user,
I want to view the sync health of all my configured targets in one command,
So that I can quickly verify everything is in sync and capture compliance evidence.

**Acceptance Criteria:**

**Given** the user runs `zopp sync status`
**When** platform credentials are available in the environment
**Then** it queries each reachable target platform via `fetch_current()`
**And** it compares against current zopp secrets
**And** it displays a StatusTable showing: target name, sync state (in-sync count, drift count), and overall health

**Given** the user has multiple sync targets configured
**When** one target's credentials are missing
**Then** the status for that target shows a credential error with fix instructions
**And** other targets are still queried and displayed (independent failures)

**Given** the `--json` flag is passed
**When** status is displayed
**Then** a complete JSON object with all target statuses is emitted

**Given** the status output is displayed
**When** the user takes a screenshot
**Then** the table is formatted cleanly with aligned columns suitable for compliance documentation

---

## Epic 3: Fly Integration (Sync & Deployment)

Users can both sync secrets to Fly apps AND deploy zopp-server on Fly with zero infrastructure management.

### Story 3.1: Implement Fly sync target and CLI commands

As a user deploying apps on Fly,
I want to sync secrets from zopp to my Fly app,
So that my Fly deployments always have the latest secrets without manual dashboard updates.

**Acceptance Criteria:**

**Given** the `fly` feature flag is enabled on zopp-sync
**When** `FlySyncTarget` is constructed with an app name
**Then** it reads the API token from `FLY_API_TOKEN` environment variable
**And** it connects to the Fly Machines REST API

**Given** valid Fly credentials are available
**When** `fetch_current()` is called
**Then** it retrieves the current secrets set on the Fly app
**And** returns them as a `HashMap<String, String>`

**Given** a list of `DiffOperation` entries
**When** `apply()` is called
**Then** it sets new/updated secrets and removes deleted secrets via the Fly API
**And** it returns per-secret `SyncResult` entries

**Given** the user runs `zopp diff fly --app myapp`
**When** the command executes
**Then** it shows the diff between zopp secrets and the Fly app's current secrets

**Given** the user runs `zopp sync fly --app myapp`
**When** the command executes
**Then** it syncs secrets to the Fly app with per-secret result output
**And** the header confirms: "Syncing zopp/.../... -> Fly (myapp)"

**Given** `FLY_API_TOKEN` is not set
**When** any Fly sync command is run
**Then** a `SyncError::AuthError` is returned with fix instructions

### Story 3.2: Create Fly deployment template

As a developer,
I want to deploy zopp-server on Fly using a provided template,
So that my team has a shared server without managing infrastructure.

**Acceptance Criteria:**

**Given** the deployment template exists at `deploy/fly/fly.toml`
**When** the user runs `fly launch` with the template
**Then** Fly provisions the app with the correct configuration

**Given** the template configuration
**When** the server starts
**Then** PostgreSQL is configured as the database backend (not SQLite)
**And** TLS is handled automatically by Fly's platform
**And** a health check endpoint is configured at `/healthz` on port 8080

**Given** the server is deployed and running
**When** the user runs `fly ssh console -C "zopp-server invite create"`
**Then** an invite token is generated that can be shared with team members

**Given** the `deploy/fly/README.md` exists
**When** a user reads it
**Then** it contains step-by-step deployment instructions
**And** it documents required and optional environment variables
**And** it explains how to generate the first invite token
**And** it explains how to connect the CLI to the deployed server

---

## Epic 4: GCP Secret Manager Integration

Teams can sync secrets to GCP Secret Manager, enabling multi-cloud secrets management from a single source of truth.

### Story 4.1: Implement GCP sync target and CLI commands

As a user with GCP workloads,
I want to sync secrets from zopp to GCP Secret Manager,
So that my GCP services always have the latest secrets from my single source of truth.

**Acceptance Criteria:**

**Given** the `gcp` feature flag is enabled on zopp-sync
**When** `GcpSyncTarget` is constructed with a GCP project ID
**Then** it resolves credentials via Application Default Credentials (ADC) or service account key
**And** it connects to the GCP Secret Manager API

**Given** valid GCP credentials are available
**When** `fetch_current()` is called
**Then** it lists secrets in the specified GCP project matching the configured prefix
**And** retrieves their latest versions as a `HashMap<String, String>`

**Given** a list of `DiffOperation` entries
**When** `apply()` is called
**Then** it creates new secrets for `Add` operations
**And** it adds new versions for `Update` operations
**And** it disables/deletes secrets for `Remove` operations
**And** it returns per-secret `SyncResult` entries

**Given** the user runs `zopp diff gcp --project my-gcp-project --prefix prod-`
**When** the command executes
**Then** it shows the diff between zopp secrets and GCP Secret Manager

**Given** the user runs `zopp sync gcp --project my-gcp-project --prefix prod-`
**When** the command executes
**Then** it syncs secrets to GCP with per-secret result output using the shared output components

**Given** GCP credentials are missing or invalid
**When** any GCP sync command is run
**Then** a `SyncError::AuthError` is returned listing ADC resolution paths and fix instructions

---

## Epic 5: Vercel & Render Integrations

Frontend and API teams can sync secrets to Vercel and Render, eliminating manual secret copying across PaaS dashboards.

### Story 5.1: Implement Vercel sync target and CLI commands

As a frontend developer deploying on Vercel,
I want to sync secrets from zopp to my Vercel project,
So that my Vercel deployments always have the correct environment variables.

**Acceptance Criteria:**

**Given** the `vercel` feature flag is enabled on zopp-sync
**When** `VercelSyncTarget` is constructed with a project name
**Then** it reads the API token from `VERCEL_TOKEN` environment variable
**And** it connects to the Vercel REST API

**Given** valid Vercel credentials are available
**When** `fetch_current()` is called
**Then** it retrieves the current environment variables for the specified project and environment (production/preview/development)
**And** returns them as a `HashMap<String, String>`

**Given** a list of `DiffOperation` entries
**When** `apply()` is called
**Then** it creates, updates, or removes environment variables via the Vercel API
**And** it returns per-secret `SyncResult` entries

**Given** the user runs `zopp diff vercel --project frontend --target production`
**When** the command executes
**Then** it shows the diff between zopp secrets and Vercel environment variables

**Given** the user runs `zopp sync vercel --project frontend --target production`
**When** the command executes
**Then** it syncs secrets to Vercel with per-secret result output

**Given** `VERCEL_TOKEN` is not set
**When** any Vercel sync command is run
**Then** a `SyncError::AuthError` is returned with fix instructions

### Story 5.2: Implement Render sync target and CLI commands

As a developer deploying APIs on Render,
I want to sync secrets from zopp to my Render service,
So that my Render services always have the correct environment variables.

**Acceptance Criteria:**

**Given** the `render` feature flag is enabled on zopp-sync
**When** `RenderSyncTarget` is constructed with a service ID
**Then** it reads the API key from `RENDER_API_KEY` environment variable
**And** it connects to the Render REST API

**Given** valid Render credentials are available
**When** `fetch_current()` is called
**Then** it retrieves the current environment variables for the specified service
**And** returns them as a `HashMap<String, String>`

**Given** a list of `DiffOperation` entries
**When** `apply()` is called
**Then** it creates, updates, or removes environment variables via the Render API
**And** it returns per-secret `SyncResult` entries

**Given** the user runs `zopp diff render --service srv-abc123`
**When** the command executes
**Then** it shows the diff between zopp secrets and Render environment variables

**Given** the user runs `zopp sync render --service srv-abc123`
**When** the command executes
**Then** it syncs secrets to Render with per-secret result output

**Given** `RENDER_API_KEY` is not set
**When** any Render sync command is run
**Then** a `SyncError::AuthError` is returned with fix instructions

---

## Epic 6: Homebrew Distribution

macOS and Linux developers can install zopp via Homebrew.

### Story 6.1: Create Homebrew formula and tap

As a macOS or Linux developer,
I want to install zopp via `brew install`,
So that I can install and update zopp using my preferred package manager.

**Acceptance Criteria:**

**Given** a Homebrew tap repository exists (e.g., `faiscadev/homebrew-tap`)
**When** the user runs `brew install faiscadev/tap/zopp`
**Then** Homebrew downloads and installs the correct binary for their platform

**Given** a new zopp version is released
**When** the CI pipeline runs
**Then** the Homebrew formula is automatically updated with the new version and checksums

**Given** the formula is installed
**When** the user runs `brew upgrade zopp`
**Then** the latest version is installed

**Given** the formula definition
**When** reviewed
**Then** it specifies binaries for macOS (Intel + Apple Silicon) and Linux (x86_64 + ARM64)
**And** it includes SHA256 checksums for each binary

---

## Epic 7: Railway Integration (Sync & Deployment)

Teams can sync secrets to Railway AND deploy zopp-server on Railway.

### Story 7.1: Implement Railway sync target and CLI commands

As a developer deploying on Railway,
I want to sync secrets from zopp to my Railway service,
So that my Railway deployments always have the correct variables.

**Acceptance Criteria:**

**Given** the `railway` feature flag is enabled on zopp-sync
**When** `RailwaySyncTarget` is constructed with a service and environment
**Then** it reads the API token from `RAILWAY_TOKEN` environment variable
**And** it connects to the Railway GraphQL API

**Given** valid Railway credentials are available
**When** `fetch_current()` is called
**Then** it retrieves the current variables for the specified service and environment
**And** returns them as a `HashMap<String, String>`

**Given** a list of `DiffOperation` entries
**When** `apply()` is called
**Then** it creates, updates, or removes variables via the Railway GraphQL API
**And** it returns per-secret `SyncResult` entries

**Given** the user runs `zopp diff railway --service workers --environment production`
**When** the command executes
**Then** it shows the diff between zopp secrets and Railway variables

**Given** the user runs `zopp sync railway --service workers --environment production`
**When** the command executes
**Then** it syncs secrets to Railway with per-secret result output

**Given** `RAILWAY_TOKEN` is not set
**When** any Railway sync command is run
**Then** a `SyncError::AuthError` is returned with fix instructions

### Story 7.2: Create Railway deployment template

As a developer,
I want to deploy zopp-server on Railway using a provided template,
So that my team has a shared server with minimal setup effort.

**Acceptance Criteria:**

**Given** the deployment template exists at `deploy/railway/railway.json`
**When** the user follows the deployment instructions
**Then** Railway provisions the app with the correct configuration

**Given** the template configuration
**When** the server starts
**Then** PostgreSQL is configured as the database backend
**And** TLS is handled by Railway's platform
**And** a health check endpoint is configured

**Given** the server is deployed and running
**When** the user generates an invite token via the Railway console
**Then** the invite token can be shared with team members to join

**Given** the `deploy/railway/README.md` exists
**When** a user reads it
**Then** it contains step-by-step deployment instructions
**And** it documents required and optional environment variables
**And** it explains how to generate the first invite token

---

## Epic 8: Extended Distribution (apt & nix)

Linux server admins install via apt; sovereignty-first engineers install via nix.

### Story 8.1: Create apt package and repository

As a Linux server administrator,
I want to install zopp via `apt install`,
So that I can manage zopp with my system's package manager and receive updates automatically.

**Acceptance Criteria:**

**Given** an apt repository is configured
**When** the user runs `apt install zopp`
**Then** the correct binary is installed for their architecture (x86_64 or ARM64)

**Given** a new zopp version is released
**When** the CI pipeline runs
**Then** .deb packages are built for x86_64 and ARM64
**And** the apt repository is updated with the new packages

**Given** the apt repository is set up
**When** the user runs `apt update && apt upgrade`
**Then** zopp is upgraded to the latest version

**Given** a user wants to add the repository
**When** they follow the documentation
**Then** instructions cover adding the GPG key and repository source

### Story 8.2: Create nix package

As a sovereignty-first engineer using NixOS,
I want to install zopp via nix,
So that I can manage zopp within my reproducible system configuration.

**Acceptance Criteria:**

**Given** a nix flake or derivation exists for zopp
**When** the user runs `nix profile install` or adds zopp to their configuration
**Then** the correct binary is built or fetched for their platform

**Given** a new zopp version is released
**When** the nix package is updated
**Then** users can update to the latest version through their normal nix workflow

**Given** the nix package definition
**When** reviewed
**Then** it follows nixpkgs packaging conventions
**And** it includes the correct build inputs and dependencies

---

## Epic 9: Docker Compose Deployment

Self-hosters can deploy zopp-server using Docker Compose for container-based deployments without Kubernetes.

### Story 9.1: Create Docker Compose deployment template

As a self-hosting engineer,
I want to deploy zopp-server using Docker Compose,
So that I can run a shared zopp server in containers without needing Kubernetes.

**Acceptance Criteria:**

**Given** the deployment template exists at `deploy/docker-compose/docker-compose.yml`
**When** the user runs `docker compose up -d`
**Then** the zopp-server and PostgreSQL containers start correctly

**Given** the template configuration
**When** the server starts
**Then** PostgreSQL is configured as the database backend with a persistent volume
**And** TLS is configured with explicit certificate paths (no automatic platform TLS)
**And** a health check is configured for the zopp-server container

**Given** a container restarts
**When** the server comes back up
**Then** all data is preserved via the PostgreSQL persistent volume
**And** the server passes health checks and resumes normal operation

**Given** the server is deployed and running
**When** the user runs `docker compose exec zopp-server zopp-server invite create`
**Then** an invite token is generated that can be shared with team members

**Given** the `deploy/docker-compose/README.md` exists
**When** a user reads it
**Then** it contains step-by-step deployment instructions
**And** it documents required and optional environment variables
**And** it explains TLS certificate setup
**And** it explains how to generate the first invite token
**And** it documents volume persistence and backup considerations

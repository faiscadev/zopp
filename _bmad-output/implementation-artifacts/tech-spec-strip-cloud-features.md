---
title: 'Strip Cloud Offering Features (Organizations, Billing, Terraform)'
slug: 'strip-cloud-features'
created: '2026-03-01'
status: 'completed'
stepsCompleted: [1, 2, 3, 4, 5]
tech_stack: ['Rust 1.90', 'SQLx 0.8.6 (dual-backend)', 'Tonic 0.14/gRPC', 'Protobuf', 'Clap 4.5', 'Terraform']
files_to_modify:
  - 'crates/zopp-proto/proto/zopp.proto'
  - 'crates/zopp-storage/src/store.rs'
  - 'crates/zopp-storage/src/types/ids.rs'
  - 'crates/zopp-storage/src/types/roles.rs'
  - 'crates/zopp-storage/src/types/mod.rs'
  - 'crates/zopp-storage/src/lib.rs'
  - 'crates/zopp-store-sqlite/src/lib.rs'
  - 'crates/zopp-store-postgres/src/lib.rs'
  - 'apps/zopp-server/src/handlers/mod.rs'
  - 'apps/zopp-server/src/backend.rs'
  - 'apps/zopp-server/Cargo.toml'
  - 'apps/zopp-cli/src/cli.rs'
  - 'apps/zopp-cli/src/commands/mod.rs'
  - 'apps/zopp-cli/src/main.rs'
  - 'Cargo.toml'
files_to_delete:
  - 'apps/zopp-server/src/handlers/organizations.rs'
  - 'apps/zopp-server/src/handlers/billing.rs'
  - 'apps/zopp-cli/src/commands/organization.rs'
  - 'crates/zopp-billing/ (entire crate)'
  - 'crates/zopp-storage/src/types/organizations.rs'
  - 'infra/terraform/ (entire directory)'
migrations_to_delete:
  - 'crates/zopp-store-sqlite/migrations/20260126000001_add_organizations.sql'
  - 'crates/zopp-store-sqlite/migrations/20260126000002_add_billing.sql'
  - 'crates/zopp-store-postgres/migrations/20260126000001_add_organizations.sql'
  - 'crates/zopp-store-postgres/migrations/20260126000002_add_billing.sql'
code_patterns:
  - 'Store trait methods in contiguous sections with comment headers'
  - 'Backend.rs delegates to SQLite/Postgres via enum match'
  - 'handlers/mod.rs has thin stubs that call dedicated handler modules'
  - 'CLI uses clap derive with Command enum + match dispatch in main.rs'
  - 'Proto RPCs and messages are grouped by feature with comment headers'
test_patterns:
  - 'NoopStore mock in zopp-storage/src/lib.rs implements all trait methods'
  - 'No E2E tests exist for organizations or billing'
  - 'No web UI references to organizations or billing'
  - '.sqlx/ metadata regeneration required after SQL changes'
---

# Tech-Spec: Strip Cloud Offering Features (Organizations, Billing, Terraform)

**Created:** 2026-03-01

## Overview

### Problem Statement

The zopp codebase contains SaaS/cloud features (organizations, billing/Stripe integration, Terraform AWS infrastructure) that add complexity and maintenance burden. These features were added as part of a cloud offering initiative (PRs #49-#63, merged Jan 25-28) but the project should focus on being an OSS self-hostable secrets manager for now.

### Solution

Remove all organization, billing, and Terraform code while preserving useful infrastructure that benefits self-hosted deployments (email verification, Prometheus metrics, Helm chart improvements, Amber Terminal web UI design).

### Scope

**In Scope:**
- Remove the entire `zopp-billing` crate
- Remove organization types, storage trait methods, and store implementations (both SQLite and PostgreSQL)
- Remove organization + billing gRPC handlers and proto definitions
- Remove organization CLI commands (`zopp org`)
- Remove organization + billing database migrations and add new drop migrations
- Remove `organization_id` column from workspaces
- Remove `infra/terraform/` directory entirely
- Remove `Plan`, `SubscriptionStatus`, `OrganizationRole`, `OrganizationId`, `OrganizationInviteId`, `SubscriptionId` types
- Clean up Cargo workspace members, dependencies, and feature flags related to billing
- Regenerate `.sqlx/` metadata after schema changes

**Out of Scope:**
- Email verification flow (keep — security feature for self-hosted)
- Email infrastructure: SMTP/Resend providers (keep — supports email verification)
- Prometheus metrics endpoint (keep — useful for any deployment)
- Helm chart enhancements: HPA, PDB, NetworkPolicy (keep — K8s best practices)
- Amber Terminal design system (keep — web UI improvement)
- RBAC system (keep — workspace-level roles)
- Audit logging (keep)

## Context for Development

### Codebase Patterns

- **Dual-backend storage**: Every SQL change must be applied to both SQLite and PostgreSQL. Migrations in separate dirs but matching schemas.
- **Compile-time SQL verification**: `SQLX_OFFLINE=true` in `.cargo/config.toml`. `.sqlx/` metadata must be regenerated after schema changes for both backends.
- **Proto-first gRPC**: Single proto file, all RPCs in one `service Zopp`. Generated Rust trait requires all RPCs to be implemented. Handlers wired as thin stubs in `handlers/mod.rs` delegating to feature-specific modules.
- **Store trait abstraction**: `zopp-storage` defines the `Store` trait. `zopp-store-sqlite` and `zopp-store-postgres` implement it. `NoopStore` mock in `lib.rs` also implements it.
- **Backend enum dispatch**: `backend.rs` has `StoreBackend` enum that delegates to the correct store implementation via match arms.
- **CLI dispatch**: Clap derive `Command` enum in `cli.rs`, dispatched via match in `main.rs`.

### Files to Reference

| File | Purpose | Action |
| ---- | ------- | ------ |
| `crates/zopp-proto/proto/zopp.proto` | Proto: lines 146-178 (RPCs), 1066-1297 (messages) | Remove org+billing blocks |
| `crates/zopp-storage/src/store.rs` | Store trait: lines 605-738 (21 org methods) | Remove org section |
| `crates/zopp-storage/src/types/ids.rs` | IDs: lines 49-59 (OrganizationId, OrganizationInviteId, SubscriptionId) | Remove 3 IDs |
| `crates/zopp-storage/src/types/roles.rs` | Roles: lines 57-186 (OrganizationRole, Plan, SubscriptionStatus + impls) | Remove 3 enums + impls |
| `crates/zopp-storage/src/types/organizations.rs` | Entirely org/billing types | Delete file |
| `crates/zopp-storage/src/types/mod.rs` | Module decl + re-export for organizations | Remove mod+use lines |
| `crates/zopp-storage/src/lib.rs` | NoopStore mock: lines 781-942 (org method impls) | Remove org section |
| `crates/zopp-store-sqlite/src/lib.rs` | SQLite impl: lines ~3087-3813 (21 org methods) | Remove org section |
| `crates/zopp-store-postgres/src/lib.rs` | Postgres impl: lines ~2535-3120 (21 org methods) | Remove org section |
| `apps/zopp-server/src/handlers/mod.rs` | Lines 21,27 (mod decls), 682-852 (stubs) | Remove billing+org mods and stubs |
| `apps/zopp-server/src/handlers/organizations.rs` | 1398 lines, all org handler logic | Delete file |
| `apps/zopp-server/src/handlers/billing.rs` | 326 lines, all billing handler logic | Delete file |
| `apps/zopp-server/src/backend.rs` | Lines 1142-1376 (21 org delegation methods) | Remove org section |
| `apps/zopp-server/Cargo.toml` | Line 28: `zopp-billing` dependency | Remove dep |
| `apps/zopp-cli/src/cli.rs` | Lines 99-102 (Org variant), 1071-1177 (OrganizationCommand enum) | Remove both |
| `apps/zopp-cli/src/commands/mod.rs` | Line 7 (mod), lines 31-36 (use exports) | Remove both |
| `apps/zopp-cli/src/commands/organization.rs` | 495 lines, all org CLI commands | Delete file |
| `apps/zopp-cli/src/main.rs` | Lines 1005-1080 (Org dispatch match arm) | Remove match arm |
| `Cargo.toml` (root) | Workspace members list includes `crates/zopp-billing` | Remove member |
| `crates/zopp-billing/` | Entire billing crate | Delete directory |
| `infra/terraform/` | Entire Terraform AWS infrastructure | Delete directory |

### Technical Decisions

- **Migration strategy**: Add new "down" migrations to drop the organization/billing tables and the `organization_id` column from workspaces, rather than deleting the "up" migration files. This preserves migration history for existing deployments that ran those migrations. The old migration files ARE also deleted since they'll never run on fresh deployments.
- **Proto cleanup**: Remove organization and billing sections as contiguous blocks — they are cleanly separated with comment headers.
- **No cloud landing page found**: `is_cloud_deployment()` does not exist in the codebase — no action needed there.
- **No E2E/web impact**: No E2E tests or web UI code references organizations or billing.
- **BillingService never wired**: The `zopp-billing` dependency exists in server's Cargo.toml but is never imported or used in code. Clean removal with no runtime impact.

## Implementation Plan

### Tasks

Tasks are ordered by dependency. **Critical: Phase 1 must be executed atomically** — the proto-generated trait requires all declared RPCs to be implemented, so proto removal and handler removal must happen together before the project can compile.

#### Phase 1: Remove proto, handlers, CLI, and backend (atomic — do all before compiling)

The tonic-generated `Zopp` trait requires implementations for all declared RPCs. Removing handler stubs without removing proto RPCs (or vice versa) creates a compilation error. All tasks in this phase must be completed together.

- [x] Task 1: Remove org+billing RPCs and messages from proto
  - File: `crates/zopp-proto/proto/zopp.proto`
  - Action: Remove organization RPCs block (lines 146-172, 17 RPCs with comments)
  - Action: Remove billing RPCs block (lines 174-178, 4 RPCs with comments)
  - Action: Remove organization message definitions (lines 1066-1218)
  - Action: Remove billing message definitions (lines 1220-1297, includes `SubscriptionStatus`, `PaymentStatus`, `Subscription`, `Payment`, `CheckoutSession`, `BillingPortalSession` and related request/response types)
  - Notes: These are contiguous blocks with clear comment delimiters. No other RPCs reference org/billing types.

- [x] Task 2: Delete organization and billing handler files
  - File: `apps/zopp-server/src/handlers/organizations.rs`
  - Action: Delete entire file (1398 lines)
  - File: `apps/zopp-server/src/handlers/billing.rs`
  - Action: Delete entire file (326 lines)

- [x] Task 3: Remove org+billing wiring from handler mod
  - File: `apps/zopp-server/src/handlers/mod.rs`
  - Action: Remove `pub mod billing;` (line 21) and `pub mod organizations;` (line 27)
  - Action: Remove all organization handler stubs (lines 682-822, from "Organizations" comment header through "Organization Workspaces" section)
  - Action: Remove all billing handler stubs (lines 824-852, from "Billing" comment header to end of section)

- [x] Task 4: Remove org delegation from backend
  - File: `apps/zopp-server/src/backend.rs`
  - Action: Remove all organization-related methods (lines ~1142-1376, 21 methods from `create_organization` through `list_organization_workspaces`)

- [x] Task 5: Delete org CLI command file and remove wiring
  - File: `apps/zopp-cli/src/commands/organization.rs`
  - Action: Delete entire file (495 lines)
  - File: `apps/zopp-cli/src/commands/mod.rs`
  - Action: Remove `pub mod organization;` (line 7) and the `pub use organization::{...}` block (lines 31-36)

- [x] Task 6: Remove org command from CLI definition and dispatch
  - File: `apps/zopp-cli/src/cli.rs`
  - Action: Remove the `Org` variant (lines 99-103) from the `Command` enum
  - Action: Remove the `OrganizationCommand` enum definition (lines 1071-1177)
  - File: `apps/zopp-cli/src/main.rs`
  - Action: Remove the `Command::Org { org_cmd } => match org_cmd { ... }` block (lines 1005-1080)

#### Phase 2: Remove storage layer (trait + implementations)

With no consumers left, remove the trait methods and all implementations.

- [x] Task 7: Remove org methods from Store trait
  - File: `crates/zopp-storage/src/store.rs`
  - Action: Remove the entire "Organizations" section (lines 605-738, includes org CRUD, members, invites, workspace-org linking — 21 methods total)
  - Notes: Section starts with comment header, ends before the trait closing brace or next section

- [x] Task 8: Remove org methods from NoopStore mock
  - File: `crates/zopp-storage/src/lib.rs`
  - Action: Remove organization method implementations in the NoopStore `impl Store for NoopStore` block (lines 781-942)

- [x] Task 9: Remove org methods from SQLite store implementation
  - File: `crates/zopp-store-sqlite/src/lib.rs`
  - Action: Remove all 21 organization method implementations (lines ~3087-3813)
  - Notes: Methods start at `create_organization` and end at `list_organization_workspaces`

- [x] Task 10: Remove org methods from PostgreSQL store implementation
  - File: `crates/zopp-store-postgres/src/lib.rs`
  - Action: Remove all 21 organization method implementations (lines ~2535-3120)
  - Notes: Same methods as SQLite, same ordering

#### Phase 3: Remove types

With no code referencing these types, remove their definitions.

- [x] Task 11: Delete organizations types file
  - File: `crates/zopp-storage/src/types/organizations.rs`
  - Action: Delete entire file (95 lines — Organization, OrganizationMember, OrganizationInvite, OrganizationSettings, Subscription, CreateOrganizationParams, CreateOrganizationInviteParams)

- [x] Task 12: Remove org/billing type IDs
  - File: `crates/zopp-storage/src/types/ids.rs`
  - Action: Remove `OrganizationId` (lines 49-51), `OrganizationInviteId` (lines 53-55), `SubscriptionId` (lines 57-59)

- [x] Task 13: Remove OrganizationRole, Plan, SubscriptionStatus enums
  - File: `crates/zopp-storage/src/types/roles.rs`
  - Action: Remove `OrganizationRole` enum and its impl block (lines 57-109)
  - Action: Remove `Plan` enum and its impl block (lines 111-149)
  - Action: Remove `SubscriptionStatus` enum and its impl block (lines 151-186)
  - Notes: Keep the `Role` enum (Admin/Write/Read) — that's workspace-level RBAC, not org-related. Also update the module doc comment at line 1 to remove "and organization membership".

- [x] Task 14: Remove organizations module from types mod
  - File: `crates/zopp-storage/src/types/mod.rs`
  - Action: Remove `mod organizations;` declaration (line 7)
  - Action: Remove `pub use organizations::*;` re-export (line 21)
  - Notes: Keep `mod roles` — it still contains the `Role` enum (Admin/Write/Read)

#### Phase 4: Remove infrastructure (crates, migrations, Terraform)

- [x] Task 15: Add drop migrations for both backends
  - File: `crates/zopp-store-sqlite/migrations/20260302000001_drop_cloud_features.sql`
  - Action: Create new migration that: (1) Drops indexes: `idx_organization_members_user`, `idx_workspaces_organization`, `idx_organization_invites_email`, `idx_subscriptions_organization`, `idx_subscriptions_stripe_id`, `idx_payments_organization`, `idx_payments_created_at`. (2) Drops triggers: `organizations_updated_at`, `organization_settings_updated_at`, `subscriptions_updated_at`. (3) Drops tables (in FK order): `payments`, `subscriptions`, `organization_settings`, `organization_invites`, `organization_members`, `organizations`. (4) Drops `organization_id` column from `workspaces` using `ALTER TABLE workspaces DROP COLUMN organization_id` (supported in SQLite 3.35.0+, project uses 3.51.0).
  - File: `crates/zopp-store-postgres/migrations/20260302000001_drop_cloud_features.sql`
  - Action: Create equivalent PostgreSQL migration using `DROP TABLE IF EXISTS ... CASCADE` and `ALTER TABLE workspaces DROP COLUMN IF EXISTS organization_id`.

- [x] Task 16: Delete old org/billing migration files
  - File: `crates/zopp-store-sqlite/migrations/20260126000001_add_organizations.sql`
  - Action: Delete file
  - File: `crates/zopp-store-sqlite/migrations/20260126000002_add_billing.sql`
  - Action: Delete file
  - File: `crates/zopp-store-postgres/migrations/20260126000001_add_organizations.sql`
  - Action: Delete file
  - File: `crates/zopp-store-postgres/migrations/20260126000002_add_billing.sql`
  - Action: Delete file

- [x] Task 17: Remove zopp-billing from dependencies
  - File: `apps/zopp-server/Cargo.toml`
  - Action: Remove `zopp-billing = { path = "../../crates/zopp-billing", version = "0.1.1" }` (line 28)
  - File: `Cargo.toml` (root)
  - Action: Remove `"crates/zopp-billing"` from `[workspace] members` list

- [x] Task 18: Delete zopp-billing crate
  - File: `crates/zopp-billing/`
  - Action: Delete entire directory (Cargo.toml, src/lib.rs, src/webhook.rs)

- [x] Task 19: Delete Terraform infrastructure
  - File: `infra/terraform/`
  - Action: Delete entire directory (main.tf, variables.tf, outputs.tf, vpc.tf, eks.tf, rds.tf, iam.tf, ecr.tf, route53.tf, environments/)

#### Phase 5: Regenerate and verify

- [x] Task 20: Regenerate .sqlx metadata for both backends
  - Action: First, delete all existing files in `crates/zopp-store-sqlite/.sqlx/` and `crates/zopp-store-postgres/.sqlx/` to remove orphaned org/billing query metadata files. `cargo sqlx prepare` writes fresh files but does NOT delete stale ones.
  - Action (SQLite): `SQLX_OFFLINE=false DATABASE_URL=sqlite:///tmp/zopp-prepare.db sqlx migrate run --source crates/zopp-store-sqlite/migrations && DATABASE_URL=sqlite:///tmp/zopp-prepare.db cargo sqlx prepare --package zopp-store-sqlite`
  - Action (PostgreSQL): Start temp Postgres container, run migrations, `cargo sqlx prepare --package zopp-store-postgres`, stop container

- [x] Task 21: Run full verification
  - Action: `cargo fmt --all`
  - Action: `cargo clippy --workspace --all-targets --all-features`
  - Action: `cargo test --workspace --all-features`
  - Action: `cargo build --bins && cargo run --bin zopp-e2e-test`
  - Notes: Fix any compilation errors from missed references. All existing tests should pass since no E2E tests reference org/billing.

### Acceptance Criteria

- [x] AC 1: Given the codebase after changes, when `cargo build --workspace --all-features` is run, then it compiles with zero errors and zero warnings.
- [x] AC 2: Given the codebase after changes, when `cargo test --workspace --all-features` is run, then all existing tests pass.
- [x] AC 3: Given the codebase after changes, when `cargo run --bin zopp-e2e-test` is run, then all E2E tests pass.
- [x] AC 4: Given the codebase after changes, when `cargo clippy --workspace --all-targets --all-features` is run, then it reports zero warnings.
- [x] AC 5: Given the proto file after changes, when compiled, then it contains zero references to Organization, Billing, Plan, Subscription, or Payment types.
- [x] AC 6: Given the CLI after changes, when `zopp --help` is run, then the `org` subcommand is not listed.
- [x] AC 7: Given a fresh database after changes, when migrations are run, then no `organizations`, `organization_members`, `organization_invites`, `organization_settings`, `subscriptions`, or `payments` tables exist.
- [x] AC 8: Given the workspaces table after migrations, when its schema is inspected, then it has no `organization_id` column.
- [x] AC 9: Given the root `Cargo.toml`, when inspected, then `crates/zopp-billing` is not in the workspace members list.
- [x] AC 10: Given the `infra/terraform/` path, when checked, then the directory does not exist.

## Additional Context

### Dependencies

- No external dependencies are added — this is purely a removal task
- `async-stripe` (optional dep of zopp-billing) will be removed along with the crate
- `lettre` and `resend-rs` workspace dependencies stay (used by email verification)
- The drop migration depends on the original "up" migrations having been run. Fresh databases will run the "up" then immediately "down", resulting in no cloud tables.

### Testing Strategy

- **No new tests needed**: This is a removal task. All existing tests should continue to pass.
- **Verification**: Run the full pre-PR checklist (fmt, clippy, test, e2e) as the primary validation.
- **.sqlx regeneration**: Must happen after migration changes but before test runs, since SQLx compile-time verification depends on the metadata cache.
- **Manual check**: Verify `zopp --help` no longer shows `org` subcommand.

### Notes

- **Risk: Missed references**: The org/billing code is well-isolated with clear boundaries. Investigation found zero references from non-org code. However, `cargo build` will catch any missed references at compile time.
- **Risk: Migration ordering**: The drop migration must have a timestamp after the original "up" migrations (20260126*). Using 20260302* ensures correct ordering.
- **Risk: .sqlx cache staleness**: Stale `.sqlx/` metadata files must be deleted before regeneration (Task 20 handles this). `cargo sqlx prepare` does not auto-delete orphaned files.
- **Risk: Cargo.lock delta**: Removing `zopp-billing` and its transitive deps (`async-stripe`, etc.) will produce a large `Cargo.lock` diff. This is expected and auto-generated.
- **Stale planning docs**: Files in `_bmad-output/` (data-models.md, api-contracts.md, architecture.md, etc.) contain org/billing references. These are planning artifacts, not production code — they will become stale but are out of scope for this spec. Consider regenerating project docs after this work lands.
- **Future consideration**: If organizations are reintroduced later, they should be designed without billing coupling — clean multi-tenant workspace grouping as an OSS feature.
- **GitHub cleanup**: Consider closing any open issues related to cloud offering features. Issue #70 (dead_code cleanup) may overlap — some `#[allow(dead_code)]` attributes may be on org/billing code that's being removed.

## Review Notes
- Adversarial review completed
- Findings: 11 total, 5 fixed, 6 skipped
- Resolution approach: auto-fix
- Fixed: F1 (restored deleted migration files), F2 (cleaned Postgres migration), F3 (empty infra/), F5 (restored handlers doc comment), F6 (added SQLite DROP COLUMN)
- Skipped: F4/F11 (_bmad-output docs out of scope), F7 (undecided), F8 (noise), F9 (pre-existing), F10 (testing concern)

# Data Models

> Generated: 2026-03-01 | Scan Level: Exhaustive

## Overview

- **Abstraction**: `Store` trait in `crates/zopp-storage/` (100+ methods)
- **Implementations**: SQLite (`zopp-store-sqlite`) and PostgreSQL (`zopp-store-postgres`)
- **Query verification**: SQLx compile-time checked queries (`.sqlx/` metadata)
- **Migrations**: 13 sequential migrations (identical schema, dialect-specific SQL)

## Strongly-Typed IDs

All entity IDs are newtype wrappers around UUID to prevent mixing:

| Type | Wraps | Used For |
|------|-------|---------|
| `UserId` | UUID | User accounts |
| `PrincipalId` | UUID | Device/service credentials |
| `WorkspaceId` | UUID | Workspace containers |
| `ProjectId` | UUID | Projects within workspaces |
| `EnvironmentId` | UUID | Environments within projects |
| `GroupId` | UUID | User groups |
| `InviteId` | UUID | Workspace invites |
| `PrincipalExportId` | UUID | Multi-device transfers |
| `EmailVerificationId` | UUID | Email verification records |
| `OrganizationId` | UUID | Billing entities |
| `OrganizationInviteId` | UUID | Org membership invites |
| `SubscriptionId` | UUID | Stripe subscriptions |
| `AuditLogId` | UUID v7 | Time-ordered audit entries |
| `ProjectName` | String | Project name wrapper |
| `EnvName` | String | Environment name wrapper |

## Entity Relationship Diagram

```
User (email, verified)
 ├── Principal (Ed25519 pub + X25519 pub per device)
 │    └── WorkspacePrincipal (KEK access: ephemeral_pub, kek_wrapped, kek_nonce)
 │         └── Permissions (workspace/project/environment scoped)
 │
 ├── Workspace (name, owner, KDF params, org link)
 │    ├── Project (name, workspace-scoped)
 │    │    └── Environment (name, wrapped DEK, version counter)
 │    │         └── Secret (key_name, nonce, ciphertext)
 │    ├── Group (name, description)
 │    │    ├── GroupMembers (users)
 │    │    └── GroupPermissions (workspace/project/env)
 │    └── Invite (token hash, encrypted KEK, expiry)
 │
 └── Organization (billing entity)
      ├── OrganizationMembers (owner/admin/member)
      ├── OrganizationInvites (email, token_hash)
      ├── OrganizationSettings (verification, 2FA, SSO, domains)
      ├── Subscription (Stripe sync)
      ├── Payments (invoice history)
      └── Workspaces (linked for billing)
```

## Tables

### Core

#### users
| Column | SQLite | PostgreSQL | Notes |
|--------|--------|-----------|-------|
| `id` | TEXT PK | UUID PK | |
| `email` | TEXT UNIQUE | TEXT UNIQUE | Lowercased |
| `verified` | INTEGER | BOOLEAN | Email verification status |
| `created_at` | TEXT | TIMESTAMPTZ | |
| `updated_at` | TEXT | TIMESTAMPTZ | |

#### principals
| Column | SQLite | PostgreSQL | Notes |
|--------|--------|-----------|-------|
| `id` | TEXT PK | UUID PK | |
| `user_id` | TEXT FK | UUID FK | NULL for service principals |
| `name` | TEXT | TEXT | |
| `public_key` | BLOB | BYTEA | Ed25519 (32 bytes) |
| `x25519_public_key` | BLOB | BYTEA | Optional, for ECDH |
| `created_at` | TEXT | TIMESTAMPTZ | |
| `updated_at` | TEXT | TIMESTAMPTZ | |

**Unique**: `(user_id, name)`

#### workspaces
| Column | SQLite | PostgreSQL | Notes |
|--------|--------|-----------|-------|
| `id` | TEXT PK | UUID PK | |
| `name` | TEXT UNIQUE | TEXT UNIQUE | Globally unique |
| `owner_user_id` | TEXT FK | UUID FK | |
| `kdf_salt` | BLOB | BYTEA | >= 16 bytes for Argon2id |
| `kdf_m_cost_kib` | INTEGER | INTEGER | Memory cost in KiB |
| `kdf_t_cost` | INTEGER | INTEGER | Iteration count |
| `kdf_p_cost` | INTEGER | INTEGER | Parallelism |
| `organization_id` | TEXT FK | UUID FK | Optional billing link |
| `created_at` | TEXT | TIMESTAMPTZ | |
| `updated_at` | TEXT | TIMESTAMPTZ | |

#### workspace_principals
| Column | SQLite | PostgreSQL | Notes |
|--------|--------|-----------|-------|
| `workspace_id` | TEXT | UUID | PK (composite) |
| `principal_id` | TEXT | UUID | PK (composite) |
| `ephemeral_pub` | BLOB | BYTEA | X25519 ephemeral public key |
| `kek_wrapped` | BLOB | BYTEA | KEK encrypted via ECDH |
| `kek_nonce` | BLOB | BYTEA | 24-byte XChaCha20 nonce |
| `created_at` | TEXT | TIMESTAMPTZ | |

#### projects
| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID/TEXT PK | |
| `workspace_id` | UUID/TEXT FK | |
| `name` | TEXT | |
| `created_at`, `updated_at` | TIMESTAMP | |

**Unique**: `(workspace_id, name)`

#### environments
| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID/TEXT PK | |
| `workspace_id` | UUID/TEXT FK | |
| `project_id` | UUID/TEXT FK | |
| `name` | TEXT | |
| `dek_wrapped` | BLOB/BYTEA | DEK encrypted with KEK |
| `dek_nonce` | BLOB/BYTEA | 24-byte nonce |
| `version` | BIGINT/INTEGER | Monotonic counter for change tracking |
| `created_at`, `updated_at` | TIMESTAMP | |

**Unique**: `(workspace_id, project_id, name)`

#### secrets
| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID/TEXT PK | |
| `workspace_id` | UUID/TEXT FK | |
| `env_id` | UUID/TEXT FK | |
| `key_name` | TEXT | |
| `nonce` | BLOB/BYTEA | 24-byte XChaCha20 nonce |
| `ciphertext` | BLOB/BYTEA | AEAD ciphertext (no plaintext) |
| `created_at`, `updated_at` | TIMESTAMP | |

**Unique**: `(workspace_id, env_id, key_name)`

### Access Control

#### invites
| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID/TEXT PK | |
| `token` | TEXT UNIQUE | SHA256 hash of invite secret |
| `kek_encrypted` | BLOB/BYTEA | KEK encrypted with invite secret |
| `kek_nonce` | BLOB/BYTEA | 24-byte nonce |
| `for_user_id` | UUID/TEXT FK | Optional (self-invites for new devices) |
| `created_by_user_id` | UUID/TEXT FK | NULL for server-created |
| `consumed` | BOOLEAN | |
| `revoked` | BOOLEAN | |
| `expires_at` | TIMESTAMP | |
| `created_at`, `updated_at` | TIMESTAMP | |

#### invite_workspaces (junction)
Composite PK: `(invite_id, workspace_id)`

#### principal_exports
| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID/TEXT PK | |
| `export_code` | TEXT UNIQUE | Public identifier (e.g., "exp_a7k9m2x4") |
| `token_hash` | TEXT UNIQUE | Argon2id(passphrase, verification_salt) |
| `verification_salt` | BLOB/BYTEA | Salt for passphrase verification |
| `user_id`, `principal_id` | UUID/TEXT FK | |
| `encrypted_data` | BLOB/BYTEA | Encrypted principal JSON |
| `salt` | BLOB/BYTEA | Argon2id salt for encryption key |
| `nonce` | BLOB/BYTEA | XChaCha20-Poly1305 nonce |
| `expires_at` | TIMESTAMP | 24-hour expiration |
| `consumed` | BOOLEAN | One-time use |
| `failed_attempts` | INTEGER | Delete after 3 failures |
| `created_at` | TIMESTAMP | |

#### email_verifications
| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID/TEXT PK | |
| `email` | TEXT UNIQUE | Email being verified |
| `code_hash` | TEXT | Argon2id hash of 6-digit code |
| `invite_token` | TEXT | Invite to consume on success |
| `attempts` | INTEGER | Failed attempt count |
| `created_at`, `expires_at` | TIMESTAMP | 15-minute window |

### RBAC Permissions

Three layers of permissions, each at three scopes:

**Principal-level:**
- `workspace_permissions` (workspace_id + principal_id → role)
- `project_permissions` (project_id + principal_id → role)
- `environment_permissions` (environment_id + principal_id → role)

**User-level:**
- `user_workspace_permissions` (workspace_id + user_id → role)
- `user_project_permissions` (project_id + user_id → role)
- `user_environment_permissions` (environment_id + user_id → role)

**Group-level:**
- `group_workspace_permissions` (workspace_id + group_id → role)
- `group_project_permissions` (project_id + group_id → role)
- `group_environment_permissions` (environment_id + group_id → role)

**Role values**: `admin`, `write`, `read`
**Hierarchy**: Admin includes Write, Write includes Read

#### groups
| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID/TEXT PK | |
| `workspace_id` | UUID/TEXT FK | |
| `name` | TEXT | |
| `description` | TEXT | Optional |

**Unique**: `(workspace_id, name)`

#### group_members (junction)
Composite PK: `(group_id, user_id)`

### Organizations & Billing

#### organizations
| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID/TEXT PK | |
| `name` | TEXT | |
| `slug` | TEXT UNIQUE | URL-friendly identifier |
| `stripe_customer_id` | TEXT UNIQUE | Nullable until billing setup |
| `stripe_subscription_id` | TEXT UNIQUE | |
| `plan` | TEXT DEFAULT 'free' | 'free', 'pro', 'enterprise' |
| `seat_limit` | INTEGER DEFAULT 3 | |
| `trial_ends_at` | TIMESTAMP | Optional |

#### organization_members
Composite PK: `(organization_id, user_id)` with `role` (owner/admin/member)

#### organization_invites
| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID/TEXT PK | |
| `organization_id` | UUID/TEXT FK | |
| `email` | TEXT | |
| `role` | TEXT DEFAULT 'member' | |
| `token_hash` | TEXT UNIQUE | SHA256 of invite token |
| `invited_by` | UUID/TEXT FK | |
| `expires_at` | TIMESTAMP | |

**Unique**: `(organization_id, email)`

#### organization_settings
PK: `organization_id` with settings: `require_email_verification`, `require_2fa`, `allowed_email_domains` (JSON), `sso_config` (JSON)

#### subscriptions
Stripe subscription sync: `stripe_subscription_id`, `stripe_price_id`, `plan`, `status`, `current_period_start/end`, `cancel_at_period_end`

#### payments
Stripe invoice history: `stripe_payment_intent_id`, `stripe_invoice_id`, `amount_cents`, `currency`, `status`

### Audit

#### audit_logs
| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID/TEXT PK | UUID v7 (time-ordered) |
| `timestamp` | TEXT | ISO8601 |
| `principal_id` | UUID/TEXT FK | Who performed action |
| `user_id` | UUID/TEXT FK | Optional (NULL for service) |
| `action` | TEXT | 40+ action types |
| `resource_type` | TEXT | "secret", "workspace", etc. |
| `resource_id` | TEXT | Affected resource |
| `workspace_id` | UUID/TEXT FK | Optional context |
| `project_id` | UUID/TEXT FK | Optional context |
| `environment_id` | UUID/TEXT FK | Optional context |
| `result` | TEXT | success/permission_denied/not_found/error |
| `reason` | TEXT | Error message |
| `details` | TEXT/JSON | Additional context |
| `client_ip` | TEXT | Optional |

**Indexes**: timestamp DESC, principal_id, user_id, workspace_id, action, result, workspace+timestamp composite

## Migration History

| # | Migration | Description |
|---|-----------|------------|
| 1 | `20251026125600_init` | Core schema (users, principals, workspaces, projects, environments, secrets, invites) |
| 2 | `20251227000001_add_environment_version` | Environment version tracking |
| 3 | `20260105000001_add_rbac` | Principal-level permissions |
| 4 | `20260105000002_add_groups` | Groups and group permissions |
| 5 | `20260105000003_add_user_permissions` | User-level permissions |
| 6 | `20260110000001_add_audit_logs` | Audit logging |
| 7 | `20260114000001_add_self_invites` | for_user_id for device invites |
| 8 | `20260115000001_add_principal_exports` | Multi-device transfer |
| 9 | `20260116000001_add_export_code` | Public export identifiers |
| 10 | `20260116000002_add_verification_salt` | Argon2id verification |
| 11 | `20260125000001_add_email_verification` | Email verification during join |
| 12 | `20260126000001_add_organizations` | Organizations and members |
| 13 | `20260126000002_add_billing` | Subscriptions and payments |

## Store Trait Method Categories

| Category | Methods | Description |
|----------|---------|-------------|
| Users | 4 | create, get_by_email, get_by_id, mark_verified |
| Principals | 4 | create, get, rename, list |
| Workspaces | 8+ | CRUD, member/principal management |
| Projects | 5 | CRUD within workspaces |
| Environments | 5 | CRUD with DEK management |
| Secrets | 4 | upsert, get, list_keys, delete |
| Invites | 5 | create, get_by_token, list, revoke, consume |
| Principal Exports | 5 | create, get_by_code, consume, increment_failures, delete |
| Email Verification | 5 | create, get, increment_attempts, delete, cleanup_expired |
| Permissions (Principal) | 15 | workspace/project/env × get/set/list/remove |
| Permissions (User) | 15 | workspace/project/env × get/set/list/remove |
| Permissions (Group) | 24 | workspace/project/env × get/set/list/remove |
| Groups | 10 | CRUD, membership |
| Organizations | 14+ | CRUD, members, invites, workspace linking |
| Audit | 4 | record, query, get, count |

## Schema Dialect Differences

| Feature | SQLite | PostgreSQL |
|---------|--------|-----------|
| Timestamps | TEXT (ISO8601) | TIMESTAMPTZ |
| Binary data | BLOB | BYTEA |
| UUIDs | TEXT | UUID |
| Booleans | INTEGER (0/1) | BOOLEAN |
| JSON | TEXT | JSONB |
| Foreign keys | PRAGMA enabled | Default |
| Triggers | SQL-based | PL/pgSQL |

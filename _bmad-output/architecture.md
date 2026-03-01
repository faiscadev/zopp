# Architecture

> Generated: 2026-03-01 | Scan Level: Exhaustive

## Executive Summary

Zopp is an open-source, self-hostable, CLI-first secrets manager with **zero-knowledge encryption**. The server never sees plaintext keys or secrets — all cryptographic operations happen client-side (CLI, Web UI, or K8s Operator). The system uses a layered key hierarchy (KEK → DEK → Secret) with X25519 ECDH for key wrapping and XChaCha20-Poly1305 AEAD for encryption.

## Architecture Principles

1. **Zero-knowledge** — Server is a blind storage layer; never sees plaintext
2. **Client-side encryption** — All crypto in CLI (native Rust) or browser (WASM)
3. **Multi-user workspaces** — KEKs wrapped per-principal via ECDH
4. **Local-first** — Works fully offline with SQLite; no vendor lock-in
5. **Trait-based abstraction** — Storage, events, billing are pluggable backends

## Technology Stack

| Layer | Technology | Version |
|-------|-----------|---------|
| Language | Rust | 1.90 (stable, edition 2021) |
| gRPC | Tonic + Prost | 0.14 |
| HTTP | Axum | 0.8 |
| Async | Tokio | 1.48.0 |
| Database | SQLx (SQLite + PostgreSQL) | 0.8.6 |
| Crypto | XChaCha20-Poly1305, Ed25519, X25519, Argon2id | — |
| TLS | Rustls (ring) | 0.23 |
| Web Frontend | Leptos + WASM | 0.7 |
| K8s Operator | kube-rs | 2.0.1 |
| Marketing | Astro + Tailwind | 4.0 |
| Docs | Docusaurus | 3.7.0 |
| CI/CD | GitHub Actions | 11 workflows |
| IaC | Terraform (AWS) | >= 1.5 |
| Packaging | Helm | Chart 0.1.1 |

## Cryptographic Architecture

### Key Hierarchy

```
User (email identity)
 └── Principal (device/service credential)
      ├── Ed25519 keypair ─── Authentication (request signing)
      └── X25519 keypair ──── Encryption (ECDH key exchange)
           └── Workspace
                └── KEK (32-byte Key Encryption Key)
                     │  Wrapped per-principal: ECDH(ephemeral, principal_x25519)
                     │  Server stores: (ephemeral_pub, kek_wrapped, kek_nonce)
                     │
                     └── Environment
                          └── DEK (32-byte Data Encryption Key)
                               │  Wrapped with KEK via XChaCha20-Poly1305
                               │  Server stores: (dek_wrapped, dek_nonce)
                               │
                               └── Secret
                                    Encrypted with DEK via XChaCha20-Poly1305
                                    AAD: "secret:{workspace}:{project}:{env}:{key}"
                                    Server stores: (nonce, ciphertext)
```

### Cryptographic Primitives

| Primitive | Algorithm | Parameters |
|-----------|-----------|-----------|
| KDF | Argon2id | 64 MiB memory, 3 iterations, 1 parallelism (19 MiB for WASM) |
| AEAD | XChaCha20-Poly1305 | 32-byte key, 24-byte nonce, 16-byte tag |
| Key Exchange | X25519 ECDH | 32-byte keys, ephemeral per-wrap |
| Signatures | Ed25519 | 32-byte keys, 64-byte signatures |
| Hashing | SHA-256 | Request body + invite token hashing |

### Authentication Protocol

Every gRPC request carries Ed25519 signature metadata:

```
1. Compute: request_hash = SHA256(method_name + protobuf_body)
2. Compose: message = method_name + request_hash + timestamp_le_bytes
3. Sign:    signature = Ed25519.sign(message, principal_private_key)
4. Headers: principal-id, timestamp, signature (hex), request-hash (hex)
```

Server verifies signature against stored public key and validates timestamp freshness.

### Memory Safety

- `Zeroize` + `ZeroizeOnDrop` on all sensitive types (`MasterKey`, `Dek`, `SharedSecret`, `Keypair`)
- `Zeroizing<Vec<u8>>` wrapper for decrypted plaintext
- Compile-time `trybuild` test ensures sensitive types don't implement `Debug`

## Server Architecture

### gRPC Service (Tonic)

- **80+ RPC methods** across 15 categories
- **1 streaming RPC**: `WatchSecrets` (server → client, secret change events)
- **HTTP endpoints**: `/healthz`, `/readyz`, `/metrics` (Axum on port 8080)

### RPC Categories

| Category | Methods | Description |
|----------|---------|-------------|
| Auth | 3 | Join, Register, bootstrap |
| Workspaces | 8 | CRUD, member management, KEK distribution |
| Projects | 5 | CRUD within workspaces |
| Environments | 5 | CRUD with wrapped DEKs |
| Secrets | 5 | Encrypted CRUD + streaming watch |
| Invites | 5 | Create, consume, list, revoke |
| Principal Exports | 4 | Multi-device credential transfer |
| Email Verification | 3 | Join flow verification |
| Permissions (Principal) | 12 | Workspace/project/env × CRUD |
| Permissions (User) | 12 | User-level RBAC |
| Permissions (Group) | 12 | Group-level RBAC |
| Groups | 8 | CRUD + membership |
| Audit | 3 | Query, get, count |
| Organizations | 14 | Billing entities + membership |
| Health | 1 | gRPC health check |

### Email System

Feature-flagged email providers:
- **SMTP** (default, `email-smtp` feature) — Lettre with Rustls TLS
- **Resend** (optional, `email-resend` feature) — Resend API

## Storage Architecture

### Trait Abstraction

`zopp-storage` defines the `Store` trait with 100+ methods. Two implementations:

| Backend | Crate | Use Case |
|---------|-------|---------|
| SQLite | `zopp-store-sqlite` | Development, small deployments |
| PostgreSQL | `zopp-store-postgres` | Production, multi-replica |

Both use SQLx with compile-time query verification (`.sqlx/` metadata).

### Database Schema (13 Migrations)

**Core Tables:**
- `users` — Email identity, verification status
- `principals` — Ed25519 + X25519 public keys per device
- `workspaces` — Name, owner, KDF parameters, organization link
- `workspace_principals` — Per-principal KEK wrapping (ephemeral_pub, kek_wrapped, kek_nonce)
- `projects` — Workspace-scoped containers
- `environments` — Project-scoped, holds wrapped DEK + version counter
- `secrets` — Encrypted key-value pairs (nonce + ciphertext only)

**Access Control:**
- `invites` + `invite_workspaces` — Workspace invite tokens with encrypted KEK
- `principal_exports` — Multi-device credential transfer (encrypted with passphrase)
- `email_verifications` — 6-digit code verification (15-minute window)
- `workspace_permissions`, `project_permissions`, `environment_permissions` — Principal-level RBAC
- `user_workspace_permissions`, `user_project_permissions`, `user_environment_permissions` — User-level RBAC
- `groups`, `group_members`, `group_*_permissions` — Group-based RBAC

**Organizations & Billing:**
- `organizations` — Billing entity with Stripe integration
- `organization_members`, `organization_invites`, `organization_settings`
- `subscriptions`, `payments` — Stripe sync

**Audit:**
- `audit_logs` — UUID v7 (time-ordered), 40+ action types, indexed for compliance queries

### Strongly-Typed IDs

All IDs are newtype wrappers around UUID to prevent accidental mixing:
`UserId`, `PrincipalId`, `WorkspaceId`, `ProjectId`, `EnvironmentId`, `GroupId`, `InviteId`, `PrincipalExportId`, `EmailVerificationId`, `OrganizationId`, `OrganizationInviteId`, `SubscriptionId`

### RBAC Model

```
Role Hierarchy: Admin > Write > Read

Permission Resolution (first match wins):
1. Direct principal permission (workspace/project/environment)
2. Direct user permission (workspace/project/environment)
3. Group permission (workspace/project/environment)
4. Inherited from parent scope (env inherits project, project inherits workspace)
```

Roles: `Admin` (full control), `Write` (create/update, includes Read), `Read` (view only)

## Event System

`zopp-events` defines the `EventBus` trait for secret change notifications:

| Implementation | Crate | Multi-Replica | Latency |
|---------------|-------|---------------|---------|
| Memory | `zopp-events-memory` | No | Instant |
| PostgreSQL | `zopp-events-postgres` | Yes | ~10ms |

Events: `SecretChangeEvent` with type (Created/Updated/Deleted), key, version, timestamp.

Used by `WatchSecrets` streaming RPC → consumed by K8s operator for real-time sync.

## CLI Architecture

### Command Structure (Clap)

15 top-level commands: `join`, `workspace`, `principal`, `project`, `environment`, `secret`, `invite`, `sync`, `diff`, `permission`, `group`, `audit`, `org`, `run`, `completions`

### Credential Storage

| Mode | Storage | Platform |
|------|---------|----------|
| Keychain (default) | System keychain | macOS (Keychain), Linux (Secret Service/zbus), Windows (Credential Manager) |
| File (`--use-file-storage`) | `~/.zopp/config.json` | All platforms |

### Project Configuration

`zopp.toml` / `.yaml` / `.json` provides workspace/project/environment defaults. CLI walks directory tree upward to find config, allowing nested project overrides.

### Key Features

- **Secret injection**: `zopp run -- <command>` injects decrypted secrets as env vars
- **K8s sync/diff**: Direct sync to K8s Secrets with managed labels
- **Import/export**: `.env` format roundtrip
- **Principal export/import**: EFF passphrase (6 words, ~77 bits entropy) + XChaCha20 encryption
- **Shell completions**: Bash, Zsh, Fish, PowerShell, Elvish

## Web UI Architecture (Leptos)

### Stack

- **Framework**: Leptos 0.7 (Rust fullstack web framework)
- **Rendering**: Client-side WASM (`wasm32-unknown-unknown` via Trunk)
- **Styling**: Tailwind CSS
- **Crypto**: `zopp-crypto-wasm` (40+ WASM-bindgen exports)
- **Transport**: gRPC-web via Envoy proxy (port 8080)
- **Storage**: IndexedDB for principal credentials

### Routes

| Path | Page | Description |
|------|------|-------------|
| `/` | Landing | Welcome page |
| `/login`, `/import` | Login | Import principal via export code |
| `/register`, `/invite` | Register | Join via invite token |
| `/settings` | Settings | User/principal management |
| `/workspaces/:ws` | Projects | List projects |
| `/workspaces/:ws/invites` | Invites | Manage invites |
| `/workspaces/:ws/permissions` | Permissions | RBAC management |
| `/workspaces/:ws/projects/:proj` | Environments | List environments |
| `/workspaces/:ws/.../environments/:env` | Secrets | View/manage secrets |

### State Management

- `AuthContext` — Principal + credentials (RwSignal)
- `WorkspaceContext` — Current workspace + list (RwSignal)
- Auto-load from IndexedDB on mount, persist to localStorage

### Components

Button, Card, Modal, Alert, Badge, Avatar, Spinner, LinkButton, Layout, Sidebar

## Kubernetes Operator Architecture

### CRD: ZoppSecretSync

```yaml
apiVersion: zopp.dev/v1alpha1
kind: ZoppSecretSync
spec:
  source:
    workspace: acme
    project: backend
    environment: production
  target:
    secretName: app-secrets
    namespace: my-app
  syncIntervalSeconds: 60
  suspend: false
```

### Dual-Sync Strategy

1. **Event streaming** (primary) — persistent `WatchSecrets` gRPC stream, <1s latency
2. **Periodic polling** (safeguard) — full sync every 60s, catches missed events
3. Auto-reconnect with exponential backoff (5s → 60s)

### Reconciliation

1. Watch `ZoppSecretSync` CRD changes
2. Fetch + decrypt secrets using service principal credentials
3. Create/update K8s Secret with plaintext values (base64-encoded)
4. Patch Deployment annotations to trigger rolling restart
5. Update CRD status (lastSyncTime, conditions)

## Billing Architecture

### Model

- `BillingService` trait with Stripe implementation (optional `stripe` feature)
- Plans: Free (3 seats), Pro (per-seat), Enterprise (custom)
- 14-day trial support
- Checkout/portal session management via Stripe

### Organization Hierarchy

```
Organization (billing entity)
 ├── Members (owner/admin/member roles)
 ├── Settings (email verification, 2FA, SSO, allowed domains)
 ├── Subscription (Stripe sync)
 └── Workspaces (linked for billing)
```

## Testing Architecture

### Strategy

| Level | Location | Coverage |
|-------|----------|---------|
| Unit tests | Alongside code in `crates/` and `apps/` | 100% goal for crates |
| E2E tests | `apps/e2e-tests/` | All user-facing features |
| Web E2E | `apps/zopp-web/tests/` | Playwright + Chromium |

### Backend Matrix

E2E tests run against 4 backend combinations via `backend_test!` macro:

| Storage | Events | Use Case |
|---------|--------|---------|
| SQLite | Memory | Lightweight dev |
| SQLite | PostgreSQL | Event distribution |
| PostgreSQL | Memory | Storage testing |
| PostgreSQL | PostgreSQL | Full production |

### Key Test Modules

- `demo.rs` — Canonical user journey (aligned 1:1 with DEMO.md)
- `secrets.rs` — CRUD, special chars, multi-user
- `rbac.rs` — Permission enforcement across all scopes
- `invites.rs` — Invite lifecycle
- `email_verification.rs` — MailHog integration
- `principals.rs` — Export/import, service principals
- `audit.rs` — Audit trail queries
- `groups.rs` — Group RBAC
- Playwright specs — Auth, secrets, workspaces, invites, permissions, settings

## Infrastructure

### Docker

- Multi-stage builds (rust:bookworm → debian:bookworm-slim)
- Non-root containers (UID 1000)
- Multi-arch: linux/amd64 + linux/arm64
- Dev containers with cargo-watch, hot reload

### CI/CD (11 Workflows)

Build → Test → Lint → E2E → Web E2E → Audit → Docker → CLI Release → Helm Release → Helm Validation → Docs

### AWS (Terraform)

VPC (3 AZs) → EKS (managed nodes) → RDS PostgreSQL 16 → ECR (3 repos) → Route53 + ACM → IAM (IRSA + GitHub OIDC)

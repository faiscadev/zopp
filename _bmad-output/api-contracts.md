# API Contracts

> Generated: 2026-03-01 | Scan Level: Exhaustive

## Overview

- **Service**: `ZoppService` (gRPC, Tonic 0.14)
- **Proto**: `crates/zopp-proto/proto/zopp.proto`
- **Implementation**: `apps/zopp-server/src/handlers/`
- **Port**: 50051 (gRPC), 8080 (HTTP health/metrics)
- **Auth**: Ed25519 signature in gRPC metadata (all RPCs except invite lookups)
- **Streaming**: 1 server-streaming RPC (`WatchSecrets`)
- **Total Methods**: 80+

## Authentication Protocol

All authenticated requests require gRPC metadata headers:

| Header | Value | Purpose |
|--------|-------|---------|
| `principal-id` | UUID string | Identify caller |
| `timestamp` | Unix seconds (i64) | Replay prevention |
| `signature` | Hex-encoded Ed25519 (64 bytes) | Request authenticity |
| `request-hash` | Hex-encoded SHA256 (32 bytes) | Body integrity |

**Signature message**: `method_name + SHA256(method + body) + timestamp_le_bytes`

## HTTP Endpoints (Axum, port 8080)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/healthz` | GET | Liveness probe (always 200) |
| `/readyz` | GET | Readiness probe (200 when gRPC bound) |
| `/metrics` | GET | Prometheus metrics |

## RPC Methods by Category

### 1. Authentication (3 methods)

| RPC | Auth | Description |
|-----|------|-------------|
| `Join(JoinRequest) → JoinResponse` | None (invite token) | Register new user + principal, consume invite |
| `Register(RegisterRequest) → RegisterResponse` | None (invite token) | Alternative registration path |
| `JoinWithVerification(JoinWithVerificationRequest) → JoinWithVerificationResponse` | None | Join with email verification code |

**JoinRequest fields**: `token`, `email`, `principal_name`, `public_key`, `x25519_public_key`, workspace wrapping data (ephemeral_pub, kek_wrapped, kek_nonce)

### 2. Workspaces (8 methods)

| RPC | Auth | Description |
|-----|------|-------------|
| `CreateWorkspace(CreateWorkspaceRequest) → CreateWorkspaceResponse` | Yes | Create workspace with KEK wrapping data |
| `ListWorkspaces(ListWorkspacesRequest) → ListWorkspacesResponse` | Yes | List accessible workspaces |
| `GetWorkspace(GetWorkspaceRequest) → GetWorkspaceResponse` | Yes | Get workspace details |
| `GetWorkspaceByName(GetWorkspaceByNameRequest) → GetWorkspaceByNameResponse` | Yes | Lookup by name |
| `GetWorkspaceKeys(GetWorkspaceKeysRequest) → GetWorkspaceKeysResponse` | Yes | Get wrapped KEK for principal |
| `AddWorkspacePrincipal(AddWorkspacePrincipalRequest) → AddWorkspacePrincipalResponse` | Yes (Admin) | Grant principal access with wrapped KEK |
| `RemoveWorkspacePrincipal(RemoveWorkspacePrincipalRequest) → RemoveWorkspacePrincipalResponse` | Yes (Admin) | Revoke principal access |
| `ListWorkspacePrincipals(ListWorkspacePrincipalsRequest) → ListWorkspacePrincipalsResponse` | Yes | List principals with access |

### 3. Projects (5 methods)

| RPC | Auth | Description |
|-----|------|-------------|
| `CreateProject` | Yes (Write+) | Create project in workspace |
| `ListProjects` | Yes (Read+) | List projects in workspace |
| `GetProject` | Yes (Read+) | Get project details |
| `GetProjectByName` | Yes (Read+) | Lookup by name |
| `DeleteProject` | Yes (Admin) | Delete project |

### 4. Environments (5 methods)

| RPC | Auth | Description |
|-----|------|-------------|
| `CreateEnvironment` | Yes (Write+) | Create env with wrapped DEK |
| `ListEnvironments` | Yes (Read+) | List environments in project |
| `GetEnvironment` | Yes (Read+) | Get env details + wrapped DEK |
| `GetEnvironmentByName` | Yes (Read+) | Lookup by name |
| `DeleteEnvironment` | Yes (Admin) | Delete environment |

### 5. Secrets (5 methods)

| RPC | Auth | Description |
|-----|------|-------------|
| `UpsertSecret` | Yes (Write+) | Create or update encrypted secret |
| `GetSecret` | Yes (Read+) | Get encrypted secret (nonce + ciphertext) |
| `ListSecretKeys` | Yes (Read+) | List secret key names (no values) |
| `DeleteSecret` | Yes (Write+) | Delete secret |
| `WatchSecrets` | Yes (Read+) | **Server-streaming**: real-time change events |

**UpsertSecret fields**: `workspace_id`, `environment_id`, `key`, `nonce` (24 bytes), `ciphertext` (encrypted value)

### 6. Invites (5 methods)

| RPC | Auth | Description |
|-----|------|-------------|
| `CreateInvite` | Yes (Admin) | Create workspace invite with encrypted KEK |
| `GetInvite` | None (token lookup) | Lookup invite by SHA256(secret) |
| `ConsumeInvite` | None (during join) | Mark invite as consumed |
| `ListInvites` | Yes (Admin) | List workspace invites |
| `RevokeInvite` | Yes (Admin) | Revoke unused invite |

### 7. Principal Exports (4 methods)

| RPC | Auth | Description |
|-----|------|-------------|
| `CreatePrincipalExport` | Yes | Store encrypted principal (24h expiry) |
| `GetPrincipalExportByCode` | None (code lookup) | Fetch encrypted principal by export code |
| `ConsumePrincipalExport` | None | Mark export as consumed (one-time) |
| `IncrementExportFailedAttempts` | None | Track failed passphrase attempts (delete at 3) |

### 8. Email Verification (3 methods)

| RPC | Auth | Description |
|-----|------|-------------|
| `CreateEmailVerification` | None | Send verification code (6-digit, 15-min window) |
| `VerifyEmail` | None | Validate code, complete join |
| `ResendVerificationCode` | None | Resend code (rate limited) |

### 9. Permissions — Principal Level (12 methods)

| Scope | Operations |
|-------|-----------|
| Workspace | `SetWorkspacePermission`, `GetWorkspacePermission`, `ListWorkspacePermissions`, `RemoveWorkspacePermission` |
| Project | `SetProjectPermission`, `GetProjectPermission`, `ListProjectPermissions`, `RemoveProjectPermission` |
| Environment | `SetEnvironmentPermission`, `GetEnvironmentPermission`, `ListEnvironmentPermissions`, `RemoveEnvironmentPermission` |

All require Admin role. Roles: `admin`, `write`, `read`.

### 10. Permissions — User Level (12 methods)

Same pattern as principal permissions but scoped to user email:
`SetUserWorkspacePermission`, `GetUserWorkspacePermission`, `ListUserWorkspacePermissions`, `RemoveUserWorkspacePermission` (and project/environment variants)

### 11. Permissions — Group Level (12 methods)

Same pattern scoped to group:
`SetGroupWorkspacePermission`, etc.

Plus: `GetEffectivePermissions` — resolves combined permissions from all sources.

### 12. Groups (8 methods)

| RPC | Auth | Description |
|-----|------|-------------|
| `CreateGroup` | Yes (Admin) | Create group in workspace |
| `GetGroup` / `GetGroupByName` | Yes (Read+) | Get group details |
| `ListGroups` | Yes (Read+) | List workspace groups |
| `UpdateGroup` | Yes (Admin) | Rename/update description |
| `DeleteGroup` | Yes (Admin) | Delete group |
| `AddGroupMember` | Yes (Admin) | Add user to group |
| `RemoveGroupMember` | Yes (Admin) | Remove user from group |
| `ListGroupMembers` | Yes (Read+) | List group members |

### 13. Audit (3 methods)

| RPC | Auth | Description |
|-----|------|-------------|
| `ListAuditLogs` | Yes (Admin) | Query audit entries (filters: action, result, time range) |
| `GetAuditLog` | Yes (Admin) | Get specific audit entry by ID |
| `CountAuditLogs` | Yes (Admin) | Count matching entries |

### 14. Organizations (14 methods)

| RPC | Auth | Description |
|-----|------|-------------|
| `CreateOrganization` | Yes | Create org with slug |
| `GetOrganization` / `GetOrganizationBySlug` | Yes | Get org details |
| `ListUserOrganizations` | Yes | List user's orgs |
| `UpdateOrganization` | Yes (Owner/Admin) | Update org name/slug |
| `DeleteOrganization` | Yes (Owner) | Delete org |
| `AddOrganizationMember` | Yes (Admin+) | Add member by email |
| `ListOrganizationMembers` | Yes | List org members |
| `UpdateOrganizationMemberRole` | Yes (Admin+) | Change member role |
| `RemoveOrganizationMember` | Yes (Admin+) | Remove member |
| `CreateOrganizationInvite` | Yes (Admin+) | Invite by email |
| `ListOrganizationInvites` | Yes | List pending invites |
| `AcceptOrganizationInvite` | None (token) | Accept org invite |
| `SetWorkspaceOrganization` | Yes (Owner) | Link workspace to org |
| `ListOrganizationWorkspaces` | Yes | List org workspaces |

### 15. Principals (4 methods)

| RPC | Auth | Description |
|-----|------|-------------|
| `GetPrincipal` | Yes | Get principal public keys |
| `ListPrincipals` | Yes | List user's principals |
| `RenamePrincipal` | Yes | Rename principal |
| `CreateServicePrincipal` | Yes (Admin) | Create service principal with workspace access |

# Integration Architecture

> Generated: 2026-03-01 | Scan Level: Exhaustive

## Overview

Zopp is a multi-part system where **all cryptographic operations happen client-side**. The server is a blind storage layer that never sees plaintext keys or secrets. Communication flows through gRPC (native clients) and gRPC-web (browser client via Envoy proxy).

## System Architecture

```
                                    ┌──────────────────────────────┐
                                    │         Kubernetes           │
                                    │                              │
┌──────────────┐   gRPC (50051)     │  ┌────────────────────────┐  │
│   zopp CLI   │ ──────────────────────→│     zopp-server        │  │
│  (Rust bin)  │                    │  │  (Tonic gRPC + Axum)   │  │
└──────┬───────┘                    │  │                        │  │
       │                            │  │  ┌──────┐  ┌────────┐ │  │
       │ kubectl API                │  │  │ Auth │  │Handlers│ │  │
       │ (sync/diff)                │  │  │Ed25519│  │ 80+RPC│ │  │
       │                            │  │  └──────┘  └───┬────┘ │  │
       ↓                            │  │                │      │  │
┌──────────────┐                    │  │         ┌──────↓────┐ │  │
│  Kubernetes  │←── K8s API ────────── │         │   SQLx    │ │  │
│   Secrets    │                    │  │         │  Storage  │ │  │
└──────────────┘                    │  │         └─────┬─────┘ │  │
       ↑                            │  └───────────────│───────┘  │
       │                            │                  │          │
       │ Create/Update              │          ┌───────↓────────┐ │
       │                            │          │  SQLite (dev)  │ │
┌──────┴───────┐   gRPC (50051)     │          │  PostgreSQL    │ │
│zopp-operator │ ──────────────────────→       │  (production)  │ │
│  (kube-rs)   │                    │          └───────┬────────┘ │
│              │←── Watch CRDs ─────│                  │          │
└──────────────┘                    │          ┌───────↓────────┐ │
                                    │          │  Event Bus     │ │
┌──────────────┐   gRPC-web (8080)  │          │  - Memory      │ │
│   zopp-web   │ ──→ Envoy ────────────→       │  - PG LISTEN/  │ │
│ (Leptos WASM)│     proxy          │          │    NOTIFY      │ │
└──────────────┘                    │          └────────────────┘ │
                                    └──────────────────────────────┘
```

## Integration Points

### 1. CLI → Server (gRPC)

| Aspect | Detail |
|--------|--------|
| **Protocol** | gRPC over HTTP/2 (Tonic) |
| **Port** | 50051 |
| **Auth** | Ed25519 signature in gRPC metadata |
| **TLS** | Optional (auto-upgrade for `https://` URLs) |
| **Auth Headers** | `principal-id`, `timestamp`, `signature`, `request-hash` |

**Request signing flow:**
1. CLI encodes protobuf request body
2. Computes `request_hash = SHA256(method + body)`
3. Signs `message = method + request_hash + timestamp_le_bytes` with Ed25519
4. Attaches metadata headers to gRPC request
5. Server verifies signature against principal's stored public key

**Crypto flow (client-side only):**
1. CLI unwraps workspace KEK via ECDH (X25519)
2. CLI unwraps environment DEK using KEK
3. CLI encrypts/decrypts secrets with DEK (XChaCha20-Poly1305)
4. Server only stores/retrieves encrypted blobs

### 2. Web UI → Server (gRPC-web via Envoy)

| Aspect | Detail |
|--------|--------|
| **Protocol** | gRPC-web over HTTP/1.1 (Fetch API) |
| **Proxy** | Envoy (port 8080) translates to gRPC (port 50051) |
| **Auth** | Same Ed25519 signature scheme via WASM |
| **Crypto** | All crypto via `zopp-crypto-wasm` (40+ WASM functions) |
| **Storage** | Credentials stored in IndexedDB |

**Browser crypto stack:**
- `zopp-crypto-wasm` compiled to WebAssembly
- Exposed via `wasm-bindgen` to JavaScript
- Leptos components call WASM functions for all crypto
- Argon2id uses reduced memory (19 MiB vs 64 MiB) for browser compatibility

### 3. Operator → Server (gRPC)

| Aspect | Detail |
|--------|--------|
| **Protocol** | gRPC over HTTP/2 (same as CLI) |
| **Auth** | Service principal credentials (Ed25519) |
| **Credentials** | Loaded from file/K8s secret |
| **Dual-sync** | Streaming (real-time) + polling (60s safeguard) |

**Sync mechanism:**
1. **Event streaming** — persistent `WatchSecrets` gRPC stream for instant updates (<1s latency)
2. **Periodic polling** — full sync every 60 seconds as safeguard
3. Automatic reconnection with exponential backoff (5s → 60s)

### 4. Operator → Kubernetes API

| Aspect | Detail |
|--------|--------|
| **Protocol** | Kubernetes API (kube-rs) |
| **Resources** | `ZoppSecretSync` CRD, `Secret`, `Deployment` |
| **RBAC** | ServiceAccount with scoped permissions |
| **Scope** | Namespace-scoped or cluster-wide |

**CRD flow:**
1. User creates `ZoppSecretSync` resource specifying source (workspace/project/env) and target (K8s secret)
2. Operator reconciles: fetches, decrypts, and syncs secrets
3. Operator patches Deployment annotations to trigger pod restarts on change

### 5. CLI → Kubernetes API (sync/diff)

| Aspect | Detail |
|--------|--------|
| **Protocol** | Kubernetes API (kube-rs) |
| **Commands** | `zopp sync k8s`, `zopp diff k8s` |
| **Auth** | kubeconfig or in-cluster |
| **Labels** | `app.kubernetes.io/managed-by: zopp` |

### 6. Server → Database (SQLx)

| Aspect | Detail |
|--------|--------|
| **Protocol** | SQLite (file) or PostgreSQL (TCP) |
| **ORM** | SQLx with compile-time query verification |
| **Abstraction** | `Store` trait in `zopp-storage` |
| **Migrations** | 13 migrations (identical schema, dialect-specific SQL) |

### 7. Server → Event Bus

| Aspect | Detail |
|--------|--------|
| **Protocol** | In-memory (tokio broadcast) or PostgreSQL LISTEN/NOTIFY |
| **Abstraction** | `EventBus` trait in `zopp-events` |
| **Events** | `SecretChangeEvent` (Created/Updated/Deleted + key + version) |
| **Purpose** | Powers `WatchSecrets` streaming RPC for operator real-time sync |

## Shared Crate Dependencies

```
zopp-server ──→ zopp-proto ←── zopp-cli
    │               │              │
    │               ↓              │
    │          zopp-storage        │
    │           ↑       ↑         │
    │      zopp-store   zopp-store │
    │      -sqlite      -postgres  │
    │               │              │
    ├──→ zopp-audit │              │
    ├──→ zopp-billing              │
    ├──→ zopp-events               │
    │    ├── zopp-events-memory    │
    │    └── zopp-events-postgres  │
    │               │              │
    └───────────────┼──────────────┘
                    ↓
              zopp-crypto ←── zopp-secrets ←── zopp-cli
                    │                          zopp-operator
                    ↓
            zopp-crypto-wasm ←── zopp-web
                    │
                    ↓
            zopp-proto-web ←── zopp-web
```

## Data Flow: Secret Lifecycle

### Write Secret (CLI)

```
1. CLI: Generate random DEK (if new environment)
2. CLI: Encrypt DEK with workspace KEK → (dek_wrapped, dek_nonce)
3. CLI: Encrypt secret value with DEK → (nonce, ciphertext)
         AAD = "secret:{workspace}:{project}:{env}:{key}"
4. CLI → Server: UpsertSecret(encrypted nonce + ciphertext)
5. Server: Store blob in database (never decrypted)
6. Server: Publish SecretChangeEvent to event bus
7. Event bus: Notify subscribers (operator watch streams)
```

### Read Secret (Web UI)

```
1. Web: Load principal from IndexedDB
2. Web → Envoy → Server: GetWorkspaceKeys (authenticated via Ed25519)
3. Web (WASM): Unwrap KEK via ECDH(principal_x25519, ephemeral_pub)
4. Web → Envoy → Server: GetEnvironment (get wrapped DEK)
5. Web (WASM): Unwrap DEK using KEK
6. Web → Envoy → Server: GetSecret (get encrypted blob)
7. Web (WASM): Decrypt secret with DEK + context AAD
8. Web: Display plaintext in UI
```

### Sync to Kubernetes (Operator)

```
1. Operator: Reconcile ZoppSecretSync CRD
2. Operator → Server: GetWorkspaceKeys + GetEnvironment + ListSecrets
3. Operator: Decrypt all secrets (same crypto as CLI)
4. Operator → K8s API: Create/Update Secret with decrypted values
5. Operator → K8s API: Patch Deployment annotation (trigger restart)
6. Operator: Maintain WatchSecrets stream for real-time updates
7. On change event: Re-fetch, re-decrypt, re-sync affected secret
```

## Authentication Flow: Invite & Join

```
                  Admin                    New User
                    │                         │
                    │ invite create            │
                    ↓                         │
              Generate 32-byte secret         │
              KEK encrypted with secret       │
              Server stores SHA256(secret)    │
                    │                         │
                    │── inv_<hex> ──────────→ │
                    │                         │ join <token> <email>
                    │                         ↓
                    │                   Generate Ed25519 + X25519 keypair
                    │                   Decrypt KEK using invite secret
                    │                   Re-wrap KEK for own principal (ECDH)
                    │                         │
                    │                         │── Register(pub_keys, wrapped_kek) ──→ Server
                    │                         │
                    │                   Store credentials in keychain/IndexedDB
```

## Port Map

| Service | Port | Protocol | Purpose |
|---------|------|----------|---------|
| zopp-server | 50051 | gRPC/HTTP2 | Main API |
| zopp-server | 8080 | HTTP | Health + metrics |
| Envoy proxy | 8080 | HTTP | gRPC-web translation |
| zopp-operator | 8080 | HTTP | Health checks |
| zopp-web (dev) | 3000 | HTTP | Trunk dev server |
| MailHog (test) | 1025 | SMTP | Test email |
| MailHog (test) | 8025 | HTTP | Email API |
| PostgreSQL | 5432 | TCP | Database |

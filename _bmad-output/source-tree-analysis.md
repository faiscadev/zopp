# Source Tree Analysis

> Generated: 2026-03-01 | Scan Level: Exhaustive

## Repository Structure

**Type:** Monorepo (Cargo workspace + JS apps)
**Primary Language:** Rust (edition 2021, MSRV 1.90)
**License:** AGPL-3.0

```
zopp/
├── apps/                           # Deployable binaries & applications
│   ├── e2e-tests/                  # End-to-end integration test suite
│   │   └── tests/                  # Test modules (demo, secrets, RBAC, invites, audit...)
│   │       └── common/             # Test harness, MailHog client, helpers
│   ├── zopp-cli/                   # CLI binary ("zopp")
│   │   └── src/
│   │       ├── commands/           # Command implementations (join, secret, workspace, etc.)
│   │       └── config/             # Config resolution (user, keychain, project/zopp.toml)
│   ├── zopp-server/                # gRPC server binary
│   │   └── src/
│   │       ├── handlers/           # gRPC RPC implementations (80+ methods)
│   │       ├── email/              # Email provider abstraction (SMTP/Resend)
│   │       └── tests/              # Server-level integration tests
│   │           └── handlers/       # Handler-specific tests
│   ├── zopp-operator/              # Kubernetes operator binary
│   │   └── src/                    # CRD, controller, sync, watch, credentials, reload
│   ├── zopp-web/                   # Web UI (Leptos SPA + WASM)
│   │   ├── src/
│   │   │   ├── components/         # Reusable UI components (Button, Modal, Card, etc.)
│   │   │   ├── pages/              # Route pages (secrets, projects, environments, etc.)
│   │   │   ├── services/           # Crypto (WASM), gRPC-web, IndexedDB storage, config
│   │   │   └── state/              # Leptos signals (auth, workspace contexts)
│   │   ├── style/                  # Tailwind CSS
│   │   └── tests/                  # Playwright E2E tests
│   │       └── fixtures/           # Test setup (IndexedDB injection, server bootstrap)
│   └── zopp-marketing/             # Marketing site (Astro + Tailwind)
│       └── src/
│           ├── components/         # Astro components
│           ├── layouts/            # Page layouts
│           ├── pages/              # Static pages
│           └── styles/             # Tailwind styles
│
├── crates/                         # Shared library crates
│   ├── zopp-crypto/                # Core cryptographic primitives
│   │   ├── src/                    # Argon2id, XChaCha20-Poly1305, X25519 ECDH, SHA256
│   │   └── tests/compile_fail/     # Trybuild: ensures no Debug on sensitive types
│   ├── zopp-crypto-wasm/           # WASM bindings for browser crypto (40+ functions)
│   │   └── src/                    # wasm-bindgen exports for all crypto operations
│   ├── zopp-proto/                 # gRPC service definitions
│   │   ├── proto/zopp.proto        # ★ Protobuf schema (all RPCs + messages)
│   │   └── src/                    # Generated Rust types
│   ├── zopp-proto-web/             # gRPC-web client (browser Fetch-based)
│   │   └── src/                    # Protobuf + tonic-web-wasm-client
│   ├── zopp-storage/               # Storage trait abstraction (backend-agnostic)
│   │   └── src/
│   │       └── types/              # Strongly-typed IDs (UserId, WorkspaceId, etc.)
│   ├── zopp-store-sqlite/          # SQLite storage implementation
│   │   ├── migrations/             # 13 SQL migrations (init → billing)
│   │   └── src/                    # SQLx compile-time verified queries
│   ├── zopp-store-postgres/        # PostgreSQL storage implementation
│   │   ├── migrations/             # 13 SQL migrations (mirrors SQLite)
│   │   └── src/                    # SQLx compile-time verified queries
│   ├── zopp-audit/                 # Audit logging abstraction
│   │   └── src/                    # AuditEvent, AuditAction (40+ types), AuditLog trait
│   ├── zopp-billing/               # Billing/subscription management
│   │   └── src/                    # BillingService trait, Stripe integration
│   ├── zopp-config/                # CLI configuration management
│   │   └── src/                    # PrincipalConfig, credential loading
│   ├── zopp-events/                # Event bus abstraction
│   │   └── src/                    # EventBus trait, SecretChangeEvent
│   ├── zopp-events-memory/         # In-memory event bus (tokio broadcast)
│   │   └── src/                    # Single-server, dev use
│   ├── zopp-events-postgres/       # PostgreSQL event bus (LISTEN/NOTIFY)
│   │   └── src/                    # Multi-replica, production use
│   └── zopp-secrets/               # Secret encryption/decryption context
│       └── src/                    # SecretContext (KEK→DEK→Secret pipeline)
│
├── charts/                         # Helm chart for Kubernetes deployment
│   └── zopp/
│       ├── crds/                   # ZoppSecretSync CRD YAML
│       ├── templates/              # Helm templates (server, operator, RBAC, etc.)
│       └── values-examples/        # Example configurations (sqlite, postgres, tls)
│
├── contributing/                   # Developer guidelines
│   ├── DEVELOPMENT.md              # Setup and local development
│   ├── TESTING.md                  # Testing philosophy and standards
│   ├── DOCUMENTING.md              # Documentation workflow
│   └── RELEASING.md                # Release process
│
├── docker/                         # Docker development configs
│   ├── docker-compose.dev.yaml     # Full dev stack (server + envoy + web + cli)
│   ├── docker-compose.test.yaml    # MailHog for email testing
│   ├── envoy-grpc-web.yaml         # Envoy gRPC-web proxy config
│   ├── server-dev.Dockerfile       # Dev server with cargo-watch
│   ├── cli-dev.Dockerfile          # Dev CLI container
│   └── web-dev.Dockerfile          # Dev web with Node.js + trunk + wasm-pack
│
├── docs/                           # Documentation site (Docusaurus 3.7.0)
│   └── docs/
│       ├── installation/           # CLI, Docker, Kubernetes install guides
│       ├── guides/                 # Core concepts, team collaboration, CI/CD, K8s operator
│       ├── reference/
│       │   └── cli/                # Per-command reference (14 commands documented)
│       ├── security/               # Architecture, cryptography docs
│       └── self-hosting/           # Server, database, TLS, Docker Compose guides
│
├── examples/                       # Example configurations
│   └── docker-compose/             # Docker Compose examples
│
├── infra/                          # Infrastructure as Code
│   └── terraform/                  # AWS (EKS, RDS, ECR, Route53, IAM)
│       └── environments/           # Environment-specific tfvars
│
├── scripts/                        # Utility scripts
│   ├── run-web-e2e.sh              # Web E2E test runner
│   └── unit-coverage.sh            # Coverage report generator
│
├── xtask/                          # Cargo xtask build utilities
│   └── src/
│
├── .github/workflows/              # CI/CD (11 workflows)
├── .interface-design/              # UI design system reference
│
├── Cargo.toml                      # ★ Workspace root (21 members)
├── server.Dockerfile               # Production server image
├── cli.Dockerfile                  # Production CLI image
├── operator.Dockerfile             # Production operator image
├── CLAUDE.md                       # AI assistant instructions
├── DEMO.md                         # Demo walkthrough (aligned with E2E tests)
├── README.md                       # Project overview
└── LICENSE                         # AGPL-3.0
```

## Critical Folders

| Folder | Purpose | Why Critical |
|--------|---------|-------------|
| `crates/zopp-crypto/src/` | All cryptographic primitives | Core zero-knowledge guarantees |
| `crates/zopp-storage/src/` | Storage trait abstraction | Backend-agnostic contract |
| `crates/zopp-proto/proto/` | gRPC API definition | Single source of truth for all RPCs |
| `apps/zopp-server/src/handlers/` | RPC implementations | Server business logic |
| `apps/zopp-cli/src/commands/` | CLI command handlers | Primary user interface |
| `crates/zopp-store-*/migrations/` | Database schemas | Data model source of truth |
| `apps/e2e-tests/tests/` | E2E test suite | Validates zero-knowledge guarantees |
| `.github/workflows/` | CI/CD pipelines | Build, test, release automation |

## Entry Points

| Binary | Entry Point | Purpose |
|--------|-------------|---------|
| `zopp` | `apps/zopp-cli/src/main.rs` | CLI client |
| `zopp-server` | `apps/zopp-server/src/main.rs` | gRPC server (port 50051) + HTTP health (port 8080) |
| `zopp-operator` | `apps/zopp-operator/src/main.rs` | K8s operator + health (port 8080) |
| `zopp-web` | `apps/zopp-web/src/lib.rs` | Leptos WASM SPA (hydrate) |
| `zopp-e2e-test` | `apps/e2e-tests/src/main.rs` | E2E test runner |

## Integration Points

```
┌─────────────┐   gRPC (50051)   ┌──────────────┐   SQLx    ┌────────────────┐
│  zopp (CLI)  │ ──────────────→ │ zopp-server   │ ───────→ │ SQLite/PostgreSQL│
└─────────────┘                  │  (tonic)      │          └────────────────┘
                                 │               │
┌─────────────┐   gRPC-web       │               │   LISTEN/NOTIFY
│  zopp-web   │ ──→ Envoy ────→ │               │ ←──────→ PG Event Bus
│  (Leptos)   │     (8080)       └──────────────┘
└─────────────┘                         ↑
                                        │ gRPC (50051)
┌──────────────┐   K8s API      ┌──────┴───────┐
│ zopp-operator │ ──────────→   │  Kubernetes   │
│  (kube-rs)   │ ←── Watch ──  │  (Secrets)    │
└──────────────┘                └──────────────┘
```

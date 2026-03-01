# Project Overview

> Generated: 2026-03-01 | Scan Level: Exhaustive

## What is Zopp?

Zopp is an **open-source, self-hostable, CLI-first secrets manager** with zero-knowledge encryption. It enables teams to securely store, share, and inject secrets (API keys, database passwords, tokens) without the server ever seeing plaintext values.

## Key Principles

- **Zero-knowledge** — Server never sees plaintext keys or secrets
- **Client-side encryption** — All crypto operations happen in the CLI, Web UI, or K8s Operator
- **Multi-user workspaces** — Teams share workspace KEKs (wrapped per-principal via ECDH)
- **Local-first** — Works fully offline with SQLite; no vendor lock-in
- **CLI-first** — Primary interface is the command line; Web UI for convenience

## Repository Facts

| Property | Value |
|----------|-------|
| **Repository** | [github.com/faiscadev/zopp](https://github.com/faiscadev/zopp) |
| **License** | AGPL-3.0 |
| **Version** | 0.1.1 |
| **Language** | Rust (edition 2021, MSRV 1.90) |
| **Architecture** | Monorepo (Cargo workspace, 21 members) |
| **Database** | SQLite (dev) / PostgreSQL 16 (prod) |
| **API** | gRPC (Tonic 0.14) + gRPC-web (via Envoy) |
| **CI/CD** | GitHub Actions (11 workflows) |
| **Container Registry** | ghcr.io/faiscadev |
| **Helm Chart** | oci://ghcr.io/faiscadev/charts/zopp |

## Tech Stack Summary

| Layer | Technology |
|-------|-----------|
| Core | Rust, Tokio, Tonic (gRPC), Axum (HTTP), SQLx |
| Crypto | XChaCha20-Poly1305, Ed25519, X25519, Argon2id |
| Web | Leptos 0.7 (WASM), Tailwind CSS |
| K8s | kube-rs operator, Helm chart |
| Infra | Docker (multi-arch), Terraform (AWS), GitHub Actions |
| Docs | Docusaurus 3.7.0 |

## Components

| Component | Type | Description |
|-----------|------|-------------|
| `zopp` (CLI) | Binary | Primary user interface — manage secrets, workspaces, permissions |
| `zopp-server` | Binary | gRPC server — blind storage layer, auth, RBAC |
| `zopp-operator` | Binary | K8s operator — syncs secrets to Kubernetes Secrets |
| `zopp-web` | WASM SPA | Web UI — Leptos frontend with client-side WASM crypto |
| `zopp-marketing` | Static site | Marketing/landing page (Astro + Tailwind) |
| 10 shared crates | Libraries | Crypto, storage, proto, events, audit, billing, config, secrets |
| Helm chart | Package | Kubernetes deployment configuration |
| Terraform | IaC | AWS infrastructure (EKS, RDS, ECR, Route53) |

## Architecture Type

**Layered service architecture with zero-knowledge encryption:**

```
Clients (CLI, Web, Operator)     ← All crypto here
    │
    ↓ gRPC / gRPC-web
Server (blind storage)           ← Never sees plaintext
    │
    ↓ SQLx
Database (SQLite / PostgreSQL)   ← Stores only ciphertext
```

## Documentation Map

- [Architecture](./architecture.md) — Full technical architecture
- [Source Tree Analysis](./source-tree-analysis.md) — Annotated directory structure
- [Integration Architecture](./integration-architecture.md) — How components communicate
- [Development Guide](./development-guide.md) — Building, testing, running locally
- [Deployment Guide](./deployment-guide.md) — Docker, Helm, Terraform, CI/CD
- [API Contracts](./api-contracts.md) — gRPC service reference
- [Data Models](./data-models.md) — Database schema and storage traits
- [Contribution Guide](./contribution-guide.md) — Code style, PR process, testing standards

### Existing Documentation (Docusaurus Site)

- [User Documentation](./docs/index.md) — Quickstart, installation, guides
- [CLI Reference](./docs/reference/cli/index.md) — Per-command documentation
- [Security](./docs/security/index.md) — Crypto architecture, security model
- [Self-Hosting](./docs/self-hosting/index.md) — Server, database, TLS setup

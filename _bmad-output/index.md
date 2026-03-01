# Zopp — Project Documentation Index

> Generated: 2026-03-01 | Exhaustive Scan | 10 documents generated

## Project Overview

- **Type:** Monorepo (Cargo workspace, 21 members + JS apps)
- **Primary Language:** Rust (edition 2021, MSRV 1.90)
- **Architecture:** Zero-knowledge secrets manager with client-side encryption
- **License:** AGPL-3.0
- **Version:** 0.1.1

## Quick Reference

### Components

| Component | Type | Tech |
|-----------|------|------|
| `zopp` (CLI) | Binary | Rust, Clap, keychain integration |
| `zopp-server` | Binary | Rust, Tonic (gRPC), Axum, SQLx |
| `zopp-operator` | Binary | Rust, kube-rs, CRD controller |
| `zopp-web` | WASM SPA | Rust, Leptos 0.7, Tailwind |
| `zopp-marketing` | Static site | Astro 4, Tailwind |
| 10 shared crates | Libraries | Crypto, storage, proto, events, audit, billing |
| Helm chart | Package | Kubernetes deployment |
| Terraform | IaC | AWS (EKS, RDS, ECR) |

### Key Entry Points

| Binary | Entry Point |
|--------|-------------|
| CLI | `apps/zopp-cli/src/main.rs` |
| Server | `apps/zopp-server/src/main.rs` |
| Operator | `apps/zopp-operator/src/main.rs` |
| Web UI | `apps/zopp-web/src/lib.rs` |
| Proto | `crates/zopp-proto/proto/zopp.proto` |

## Generated Documentation

- [Project Overview](./project-overview.md) — Executive summary, components, tech stack
- [Architecture](./architecture.md) — Crypto architecture, server, storage, events, RBAC, testing
- [Source Tree Analysis](./source-tree-analysis.md) — Annotated directory structure, critical folders
- [Integration Architecture](./integration-architecture.md) — How components communicate, data flows
- [API Contracts](./api-contracts.md) — gRPC service reference (80+ RPCs, 15 categories)
- [Data Models](./data-models.md) — Database schema, 20+ tables, Store trait, migration history
- [Development Guide](./development-guide.md) — Prerequisites, building, testing, running locally
- [Deployment Guide](./deployment-guide.md) — Docker, Helm, Terraform/AWS, CI/CD pipeline
- [Contribution Guide](./contribution-guide.md) — Code style, PR process, testing standards

## Existing Documentation (Docusaurus Site)

### User Documentation (`docs/docs/`)

- [Home](./docs/index.md) — Documentation landing page
- [Quickstart](./docs/quickstart.md) — Getting started guide

### Installation

- [Overview](./docs/installation/index.md)
- [CLI Installation](./docs/installation/cli.md)
- [Docker](./docs/installation/docker.md)
- [Kubernetes](./docs/installation/kubernetes.md)

### Guides

- [Core Concepts](./docs/guides/core-concepts.md) — Key hierarchy, principals, workspaces
- [Joining a Team](./docs/guides/joining-a-team.md)
- [Team Collaboration](./docs/guides/team-collaboration.md)
- [Import & Export](./docs/guides/import-export.md)
- [CI/CD Integration](./docs/guides/ci-cd.md)
- [Kubernetes Operator](./docs/guides/kubernetes-operator.md)

### CLI Reference

- [Overview](./docs/reference/cli/index.md)
- [join](./docs/reference/cli/join.md), [workspace](./docs/reference/cli/workspace.md), [project](./docs/reference/cli/project.md), [environment](./docs/reference/cli/environment.md)
- [secret](./docs/reference/cli/secret.md), [invite](./docs/reference/cli/invite.md), [principal](./docs/reference/cli/principal.md)
- [permission](./docs/reference/cli/permission.md), [group](./docs/reference/cli/group.md), [audit](./docs/reference/cli/audit.md)
- [diff](./docs/reference/cli/diff.md), [sync](./docs/reference/cli/sync.md), [run](./docs/reference/cli/run.md)
- [Configuration](./docs/reference/configuration.md), [Environment Variables](./docs/reference/environment-variables.md)

### Security

- [Overview](./docs/security/index.md)
- [Architecture](./docs/security/architecture.md)
- [Cryptography](./docs/security/cryptography.md)

### Self-Hosting

- [Overview](./docs/self-hosting/index.md)
- [Server Setup](./docs/self-hosting/server.md)
- [Database](./docs/self-hosting/database.md)
- [TLS](./docs/self-hosting/tls.md)
- [Docker Compose](./docs/self-hosting/docker-compose.md)

### Other Existing Docs

- [README.md](../README.md) — Project overview
- [CLAUDE.md](../CLAUDE.md) — AI assistant instructions
- [DEMO.md](../DEMO.md) — Demo walkthrough (aligned with E2E tests)
- [Contributing: Development](../contributing/DEVELOPMENT.md)
- [Contributing: Testing](../contributing/TESTING.md)
- [Contributing: Documentation](../contributing/DOCUMENTING.md)
- [Contributing: Releasing](../contributing/RELEASING.md)
- [Helm Chart README](../charts/zopp/README.md)
- [Terraform README](../infra/terraform/README.md)
- [Operator README](../apps/zopp-operator/README.md)

## Getting Started

### For Development
1. Install [prerequisites](./development-guide.md#prerequisites) (Rust 1.90+, Docker)
2. `cargo build --workspace`
3. `cargo run --bin zopp-server serve` (starts server on port 50051)
4. `cargo run --bin zopp -- <command>` (use CLI)

### For AI-Assisted Development
Start with [Architecture](./architecture.md) for technical context, then reference specific docs:
- **Adding features**: [API Contracts](./api-contracts.md) + [Data Models](./data-models.md)
- **Understanding crypto**: [Architecture § Cryptographic Architecture](./architecture.md#cryptographic-architecture)
- **Integration work**: [Integration Architecture](./integration-architecture.md)
- **Writing tests**: [Contribution Guide § Testing](./contribution-guide.md#testing-requirements)

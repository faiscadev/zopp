# Development Guide

> Generated: 2026-03-01 | Scan Level: Exhaustive

## Prerequisites

| Tool | Version | Required For |
|------|---------|-------------|
| Rust (stable) | 1.90+ | All Rust crates and binaries |
| Docker | Latest | Integration tests, dev environment |
| PostgreSQL 16 | Optional | Production backend development |
| Node.js | 20+ | Web UI, marketing site, docs |
| wasm-pack | Latest | WASM crypto module |
| trunk | Latest | Leptos web UI dev server |
| protoc | Latest | gRPC proto compilation |
| kubectl + kind | Latest | K8s operator development |
| Terraform | >= 1.5 | Infrastructure development |
| Helm | Latest | Chart development |

## Quick Start

```bash
# Clone and build
git clone https://github.com/faiscadev/zopp.git
cd zopp
cargo build --workspace

# Start server (SQLite, default port 50051)
cargo run --bin zopp-server serve

# Use CLI (in another terminal)
cargo run --bin zopp -- <command>
```

## Building

```bash
# Debug build (all workspace members)
cargo build --workspace

# Release build
cargo build --workspace --release

# Build specific binary
cargo build --bin zopp-server
cargo build --bin zopp          # CLI
cargo build --bin zopp-operator

# Build Docker images
docker build -f server.Dockerfile -t zopp-server:latest .
docker build -f cli.Dockerfile -t zopp-cli:latest .
docker build -f operator.Dockerfile -t zopp-operator:latest .
```

## Running Locally

### Server with SQLite (default)

```bash
cargo run --bin zopp-server serve
# Or with explicit path:
cargo run --bin zopp-server serve --db mydata.db
```

### Server with PostgreSQL

```bash
docker run --name zopp-pg -e POSTGRES_PASSWORD=postgres -p 5432:5432 -d postgres:16
DATABASE_URL=postgres://postgres:postgres@localhost/postgres cargo run --bin zopp-server serve
```

### Server with TLS

```bash
cargo run --bin zopp-server serve \
  --tls-cert /path/to/server.crt \
  --tls-key /path/to/server.key
# mTLS:
  --tls-client-ca /path/to/ca.crt
```

### Web UI (Leptos)

Requires Envoy proxy for gRPC-web translation.

**Option 1: Docker Compose (easiest)**
```bash
docker compose -f docker/docker-compose.dev.yaml up zopp-server envoy
wasm-pack build --target web --out-dir apps/zopp-web/pkg crates/zopp-crypto-wasm
cd apps/zopp-web && npm install && trunk serve
```

**Option 2: Everything local**
```bash
# Terminal 1: Server
cargo run --bin zopp-server serve
# Terminal 2: Envoy proxy
docker run -v $(pwd)/docker/envoy-grpc-web-local.yaml:/etc/envoy/envoy.yaml \
  --add-host=host.docker.internal:host-gateway -p 8080:8080 envoyproxy/envoy:v1.28-latest
# Terminal 3: WASM build (one-time)
wasm-pack build --target web --out-dir apps/zopp-web/pkg crates/zopp-crypto-wasm
# Terminal 4: Web UI
cd apps/zopp-web && npm install && trunk serve
```

Web UI at http://localhost:3000

### Bootstrapping a User

```bash
# Create server invite (admin operation)
cargo run --bin zopp-server invite create --expires-hours 48
# Join as first user
cargo run --bin zopp -- join <inv_token> your@email.com
# Create workspace
cargo run --bin zopp -- workspace create my-workspace
```

## Testing

### All Tests

```bash
cargo test --workspace --all-features
```

### Unit Tests Only

```bash
cargo test --workspace --exclude e2e-tests
```

### E2E Tests

```bash
cargo build --bins
cargo test --package e2e-tests
```

E2E tests run against 4 backend combinations automatically:
- SQLite + Memory events
- SQLite + PostgreSQL events
- PostgreSQL + Memory events
- PostgreSQL + PostgreSQL events

### Web E2E Tests (Playwright)

```bash
./scripts/run-web-e2e.sh
```

### Coverage

```bash
./scripts/unit-coverage.sh
# Output: coverage/html/index.html
```

### PostgreSQL Tests

```bash
docker run --name zopp-postgres -e POSTGRES_PASSWORD=postgres -p 5432:5432 -d postgres:16
DATABASE_URL=postgres://postgres:postgres@localhost/postgres cargo test --package zopp-store-postgres
```

## Linting & Formatting

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features
```

## Pre-PR Checklist

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features
cargo test --workspace --all-features
cargo build --bins && cargo run --bin zopp-e2e-test
```

## SQLx Offline Mode

When modifying SQL queries, regenerate compile-time metadata:

### SQLite
```bash
export SQLX_OFFLINE=false
DATABASE_URL=sqlite:///tmp/zopp-prepare.db sqlx migrate run --source crates/zopp-store-sqlite/migrations
DATABASE_URL=sqlite:///tmp/zopp-prepare.db cargo sqlx prepare --package zopp-store-sqlite
```

### PostgreSQL
```bash
export SQLX_OFFLINE=false
docker run --name zopp-postgres -e POSTGRES_PASSWORD=postgres -p 5432:5432 -d postgres:16
DATABASE_URL=postgres://postgres:postgres@localhost/postgres sqlx migrate run --source crates/zopp-store-postgres/migrations
DATABASE_URL=postgres://postgres:postgres@localhost/postgres cargo sqlx prepare --package zopp-store-postgres
docker stop zopp-postgres && docker rm zopp-postgres
```

## Testing Philosophy

- **Use real implementations** — real SQLite, real PostgreSQL, real crypto
- **Only mock to reproduce specific error conditions** — network failures, race conditions
- **Every user-facing feature** must have an E2E test
- **100% unit test coverage goal** for crates (some code tested via E2E instead)
- **RBAC tests** for any feature involving permission checks

## Documentation Development

```bash
cd docs
npm install    # First time
npm run dev    # Hot reload dev server
npm run build  # Production build
```

## Release Process

1. Bump versions: `cargo workspaces version --no-git-commit -y patch`
2. Update Helm chart version in `charts/zopp/Chart.yaml`
3. Commit, tag, and push: `git tag v0.x.x && git push origin main --tags`
4. Publish to crates.io: `cargo workspaces publish --no-git-commit --from-git`
5. CI builds and publishes Docker images, CLI binaries, and Helm chart automatically

## Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `DATABASE_URL` | Server database connection | SQLite (in-memory) |
| `ZOPP_SERVER` | CLI server address | `http://127.0.0.1:50051` |
| `ZOPP_TLS_CERT` | Server TLS certificate path | None |
| `ZOPP_TLS_KEY` | Server TLS key path | None |
| `ZOPP_TLS_CLIENT_CA` | mTLS client CA path | None |
| `ZOPP_TLS_CA_CERT` | CLI custom CA cert | None |
| `ZOPP_USE_FILE_STORAGE` | CLI: store creds in file (not keychain) | false |
| `ZOPP_CREDENTIALS` | Operator credentials file path | None |
| `ZOPP_NAMESPACE` | Operator watch namespace | All |
| `ZOPP_HEALTH_ADDR` | Operator health server | `0.0.0.0:8080` |
| `SQLX_OFFLINE` | Enable/disable offline SQL verification | true |

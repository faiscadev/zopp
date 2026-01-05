# Development Guide

## Prerequisites

- Rust 1.90+ (stable)
- Docker (optional, for integration tests)
- PostgreSQL (optional, for Postgres backend development)

## Building and Testing

```bash
# Build all crates
cargo build --workspace

# Run tests
cargo test --workspace

# Format and lint
cargo fmt --all
cargo clippy --workspace --all-targets --all-features

# Build Docker images
docker build -f server.Dockerfile -t zopp-server .
docker build -f operator.Dockerfile -t zopp-operator .
docker build -f cli.Dockerfile -t zopp-cli .
```

## Running Locally

### Server (SQLite)
```bash
cargo run --bin zopp-server serve
```

### Server (PostgreSQL)
```bash
# Start PostgreSQL
docker run --name zopp-pg -e POSTGRES_PASSWORD=postgres -p 5432:5432 -d postgres:16

# Run server
DATABASE_URL=postgres://postgres:postgres@localhost/postgres cargo run --bin zopp-server serve
```

### CLI
```bash
# After server is running
cargo run --bin zopp -- workspace create acme
cargo run --bin zopp -- secret set FOO bar
```

## Release Process

To create a new release (e.g., v0.1.1):

1. **Bump versions** (use `patch`, `minor`, or `major`):
   ```bash
   cargo workspaces version --no-git-commit --no-git-tag patch
   ```

2. **Update Helm chart version**:
   ```bash
   # Edit charts/zopp/Chart.yaml
   # Update both 'version' and 'appVersion' to match (e.g., 0.1.1)
   ```

3. **Commit and tag**:
   ```bash
   git add .
   git commit -m "Release v0.1.1"
   git tag v0.1.1
   git push origin main --tags
   ```

4. **Publish to crates.io**:
   ```bash
   cargo workspaces publish --no-git-commit --from-git
   ```
   Note: You'll need to be logged in to crates.io (`cargo login`)

5. **Wait for CI** to build and publish:
   - CLI binaries (Linux/macOS/Windows, amd64/arm64) → GitHub Releases
   - Docker images (linux/amd64, linux/arm64) → ghcr.io
   - Helm chart → GitHub Pages

**Version bump types:**
- `patch`: 0.1.0 → 0.1.1 (bug fixes)
- `minor`: 0.1.0 → 0.2.0 (new features, backwards compatible)
- `major`: 0.1.0 → 1.0.0 (breaking changes)
- `custom 2.5.3`: Set specific version

## Storage Backends

Each storage backend lives in its own crate and implements the `Store` trait from `zopp-storage`. See individual crate READMEs for backend-specific details:

- `crates/zopp-store-sqlite/` - SQLite implementation

### Adding a Storage Backend

Create a new crate that implements the `Store` trait. The implementation can use any approach - SQL database, key-value store, file system, etc.

```rust
use zopp_storage::Store;

pub struct MyStore { /* ... */ }

#[async_trait::async_trait]
impl Store for MyStore {
    // Implement required methods
}
```

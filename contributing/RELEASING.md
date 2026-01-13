# Release Process

To create a new release (e.g., v0.1.1):

## 1. Bump versions

Use `patch`, `minor`, or `major`:

```bash
cargo workspaces version --no-git-commit -y patch
```

**Version bump types:**
- `patch`: 0.1.0 → 0.1.1 (bug fixes)
- `minor`: 0.1.0 → 0.2.0 (new features, backwards compatible)
- `major`: 0.1.0 → 1.0.0 (breaking changes)
- `custom 2.5.3`: Set specific version

## 2. Update Helm chart version

Edit `charts/zopp/Chart.yaml` and update both `version` and `appVersion` to match (e.g., 0.1.1).

## 3. Commit and tag

```bash
git add .
git commit -m "Release v0.1.1"
git tag v0.1.1
git push origin main --tags
```

## 4. Publish to crates.io

```bash
cargo workspaces publish --no-git-commit --from-git
```

Note: You'll need to be logged in to crates.io (`cargo login`)

## 5. Wait for CI

CI will build and publish:
- CLI binaries (Linux/macOS/Windows, amd64/arm64) → GitHub Releases
- Docker images (linux/amd64, linux/arm64) → ghcr.io
- Helm chart → GitHub Pages

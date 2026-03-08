# Story 1.1: Set up cross-platform binary release CI pipeline

Status: done

## Story

As a developer,
I want zopp binaries published to GitHub Releases for all supported platforms with SHA256 checksums,
so that users can download pre-built binaries without compiling from source and verify their integrity.

## Acceptance Criteria

1. **Given** a new version tag is pushed to the repository, **when** the CI pipeline runs, **then** binaries are built for macOS x86_64, macOS aarch64, Linux x86_64, and Linux aarch64, each packaged as a tar.gz archive.

2. **Given** the build completes, **when** archives are created, **then** SHA256 checksums are generated for each archive and published alongside them to the GitHub Release.

3. **Given** a PR is opened, **when** the CI pipeline runs, **then** it performs a dry-run build (no release created) to verify compilation succeeds on all targets.

4. **Given** a tag matching `v[0-9]+.[0-9]+.[0-9]+` is pushed, **when** the release job runs, **then** a GitHub Release is created with auto-generated notes, all tar.gz archives, and a checksums file.

5. **Given** the release artifacts are published, **when** a user downloads an archive, **then** they can verify its integrity against the published SHA256 checksum.

## Tasks / Subtasks

- [x] Task 1: Add SHA256 checksum generation to `cli-release.yaml` (AC: #2)
  - [x] After packaging each binary as tar.gz, compute `sha256sum` (Linux) or `shasum -a 256` (macOS) for the archive
  - [x] Include the checksum in the uploaded artifact (or generate in the release job)
- [x] Task 2: Add checksums file to GitHub Release (AC: #2, #4)
  - [x] In the `create-release` job, after downloading all artifacts, generate a combined `checksums.txt` with all archive checksums
  - [x] Upload `checksums.txt` alongside the tar.gz archives in `gh release create`
- [x] Task 3: Verify existing dry-run behavior on PRs (AC: #3)
  - [x] Confirm existing workflow already builds on PRs without creating releases
- [x] Task 4: Test the release pipeline (AC: #1, #4, #5)
  - [x] Verify checksum format is standard: `<hash>  <filename>` (two spaces, matching `sha256sum` output format)

## Dev Notes

### Critical Context: Existing Workflow

**The CLI release workflow already exists at `.github/workflows/cli-release.yaml` (126 lines).** This is NOT a greenfield story — you are enhancing an existing, working pipeline.

**What already works:**
- Cross-platform build matrix: macOS x86_64, macOS aarch64, Linux x86_64, Linux aarch64, Windows x86_64
- tar.gz packaging for each target
- Artifact upload between build and release jobs
- GitHub Release creation with `gh release create` and `--generate-notes`
- Dry-run on PRs (builds without releasing)
- Semver tag validation (`v[0-9]+.[0-9]+.[0-9]+`)
- Cross-compilation for Linux aarch64 (gcc-aarch64-linux-gnu)
- protoc installation, rust-cache

**What's missing (your scope):**
- SHA256 checksum generation for each tar.gz archive
- A combined `checksums.txt` file uploaded to the GitHub Release

### Implementation Approach

**Option A (Recommended): Generate checksums in the `create-release` job** after downloading all artifacts. This avoids platform-specific checksum commands (`sha256sum` on Linux vs `shasum -a 256` on macOS) since the release job runs on `ubuntu-latest`.

Add a step between "Move artifacts to root" and "Create release":

```yaml
- name: Generate checksums
  shell: bash
  run: |
    sha256sum zopp-*.tar.gz > checksums.txt
    cat checksums.txt
```

Then update the `gh release create` command to also upload `checksums.txt`:

```yaml
gh release create ${{ github.ref_name }} \
  --title "zopp ${{ steps.version.outputs.version }}" \
  --generate-notes \
  zopp-*.tar.gz \
  checksums.txt
```

### Architecture Constraints

- Binary naming: `zopp-<target>.tar.gz` (e.g., `zopp-x86_64-unknown-linux-gnu.tar.gz`)
- Checksum format: Standard `sha256sum` output (`<hash>  <filename>`)
- The install script at `install.sh` will use these checksums in Story 1.2 — ensure the format is parseable
- Windows target (`x86_64-pc-windows-msvc`) is included in the existing matrix but NOT mentioned in the epic's acceptance criteria (macOS + Linux only). Keep it as-is — don't remove it.

### Files to Modify

- `.github/workflows/cli-release.yaml` — Add checksum generation and upload

### What NOT to Do

- Do NOT rewrite the existing workflow — only add the checksum steps
- Do NOT remove the Windows target from the build matrix
- Do NOT change the existing artifact naming convention
- Do NOT add binary signing (out of scope for this story)
- Do NOT modify `install.sh` (that's Story 1.2)

### Testing

- Push a test tag to verify the full pipeline (or rely on the PR dry-run mode for build verification)
- Verify `checksums.txt` format is standard `sha256sum` output
- The existing PR trigger already validates builds work

### References

- [Source: .github/workflows/cli-release.yaml] — Existing release workflow
- [Source: _bmad-output/architecture.md] — Install script decision: SHA256 checksum verification
- [Source: install.sh] — Current install script (will consume checksums in Story 1.2)
- [Source: _bmad-output/planning-artifacts/epics.md#Epic 1] — Epic requirements

## Dev Agent Record

### Agent Model Used

Claude Opus 4.6

### Debug Log References

### Completion Notes List

- Added "Generate checksums" step to `create-release` job in cli-release.yaml, using `sha256sum` on ubuntu-latest (avoids cross-platform command differences)
- Added `checksums.txt` to the `gh release create` upload list
- Chose to generate checksums in the release job (Option A from dev notes) rather than per-build-matrix job — simpler, single platform, all archives available
- Verified dry-run behavior: `create-release` job has `if: startsWith(github.ref, 'refs/tags/')` guard — PRs only run `build-binaries`
- Verified checksum format: `sha256sum` produces `<hash>  <filename>` (standard two-space separator)

### Change Log

- 2026-03-07: Added SHA256 checksum generation and upload to CLI release workflow

### File List

- `.github/workflows/cli-release.yaml` (modified)

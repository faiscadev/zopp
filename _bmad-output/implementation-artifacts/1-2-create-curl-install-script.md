# Story 1.2: Create curl install script

Status: ready-for-dev

## Story

As a developer,
I want to install zopp CLI with a single curl command,
so that I can start using zopp in under 30 seconds without building from source.

## Acceptance Criteria

1. **Given** the user runs `curl -fsSL <install-url> | sh` on a supported platform, **when** the script executes, **then** it detects the user's OS (macOS or Linux) and architecture (x86_64 or aarch64), downloads the correct binary archive from GitHub Releases, verifies the SHA256 checksum before installing, installs the binary to `$HOME/.zopp/bin`, prints PATH setup instructions if `$HOME/.zopp/bin` is not in PATH, and prints a "Get started" section with the next command to run.

2. **Given** the user runs the install script on an unsupported platform, **when** the script detects an unsupported OS or architecture, **then** it prints a clear error message listing supported platforms and suggests `cargo install` as a fallback.

3. **Given** the checksum verification fails, **when** the downloaded archive doesn't match the expected SHA256, **then** the script aborts with a clear error message and suggests retrying or downloading manually.

4. **Given** the script has already been run once, **when** the user runs it again, **then** it completes successfully (idempotent), replacing the existing binary.

5. **Given** the install script output, **when** the user observes terminal output, **then** it follows the UX template: shows platform detection, version, download progress, checksum verification, install location, success message, and next steps.

## Tasks / Subtasks

- [ ] Task 1: Rewrite install.sh with architecture-compliant structure (AC: #1, #2, #4)
  - [ ] Move install script to `scripts/install.sh` (architecture spec location) and update root `install.sh` to delegate or replace
  - [ ] Implement POSIX-compatible shell with `zopp_` prefixed functions
  - [ ] Implement OS/arch detection (macOS x86_64, macOS aarch64, Linux x86_64, Linux aarch64)
  - [ ] Map to Rust target triples and human-readable names
  - [ ] Change default install location to `$HOME/.zopp/bin`
  - [ ] Ensure idempotency (replace existing binary without error)
  - [ ] No `sudo` usage — print guidance if permission denied

- [ ] Task 2: Add SHA256 checksum verification (AC: #1, #3)
  - [ ] Download `checksums.txt` from the same GitHub Release
  - [ ] Parse the `<hash>  <filename>` format to extract checksum for current target
  - [ ] Verify using `sha256sum` (Linux) or `shasum -a 256` (macOS)
  - [ ] Abort with clear error message on checksum mismatch

- [ ] Task 3: Implement UX-compliant output formatting (AC: #5)
  - [ ] Implement `zopp_log` function for consistent output formatting
  - [ ] Show structured output: header, platform detection, version, progress, verification, success, next steps
  - [ ] Use symbols (✓, ✗) for step completion status
  - [ ] Support `NO_COLOR` env var and `--no-color` flag
  - [ ] Detect TTY and suppress colors/symbols when piped

- [ ] Task 4: Implement error handling (AC: #2, #3)
  - [ ] Unsupported platform: list supported platforms, suggest `cargo install`
  - [ ] Network errors: clear message with retry suggestion
  - [ ] Checksum mismatch: abort with security warning
  - [ ] Permission denied: suggest running with sudo or using a different install dir

- [ ] Task 5: Add install script tests (AC: #1-5)
  - [ ] Add shellcheck validation in CI or as a pre-commit check
  - [ ] Add basic test that verifies script syntax and function definitions

## Dev Notes

### Critical Context: Existing Install Script

**The install script already exists at `install.sh` (93 lines).** This is a rewrite to meet architecture and UX requirements, not a greenfield script.

**Current install.sh gaps vs requirements:**
- No SHA256 checksum verification (critical security gap — NFR7)
- No structured output formatting (plain `echo` statements)
- Install location is `/usr/local/bin` or `$HOME/.local/bin` — should be `$HOME/.zopp/bin`
- No `zopp_log` function pattern (architecture requirement)
- No `NO_COLOR` support
- No human-readable platform names in output
- Error messages are generic, not structured with fix instructions

### Architecture Requirements

- **Location:** `scripts/install.sh` (keep root `install.sh` as a symlink or one-liner redirector for backward compatibility with existing docs/links)
- **Shell:** POSIX-compatible (`#!/bin/sh`), no bashisms
- **Functions:** All prefixed with `zopp_` (e.g., `zopp_detect_platform`, `zopp_download`, `zopp_verify_checksum`)
- **Output:** All user-facing output through `zopp_log` function
- **Install path:** `$HOME/.zopp/bin` by default
- **Idempotent:** Running twice is safe, replaces existing binary
- **No sudo:** Never invoke sudo; if permission denied, guide user

### UX Output Template

Follow this exact template from the UX spec:
```
  zopp installer v1.0

  Detected: macOS aarch64 (Apple Silicon)
  Latest:   zopp v1.2.3

  Downloading... ✓
  Verifying checksum... ✓ (SHA256 matched)
  Installing to ~/.zopp/bin/zopp... ✓

  zopp v1.2.3 installed successfully!

  Next: Run `zopp join <invite-token> you@email.com` to get started.
  Docs: https://zopp.dev/quickstart
```

### Checksum Verification Implementation

The `checksums.txt` file (from Story 1.1) is published to each GitHub Release with format:
```
<sha256-hash>  zopp-x86_64-unknown-linux-gnu.tar.gz
<sha256-hash>  zopp-aarch64-unknown-linux-gnu.tar.gz
<sha256-hash>  zopp-x86_64-apple-darwin.tar.gz
<sha256-hash>  zopp-aarch64-apple-darwin.tar.gz
<sha256-hash>  zopp-x86_64-pc-windows-msvc.tar.gz
```

**Verification approach:**
1. Download `checksums.txt` from the same release URL
2. Extract the expected hash for the current target: `grep "zopp-$TARGET.tar.gz" checksums.txt | awk '{print $1}'`
3. Compute actual hash of downloaded archive
4. Compare and abort if mismatch

**Cross-platform hash commands:**
- Linux: `sha256sum <file> | awk '{print $1}'`
- macOS: `shasum -a 256 <file> | awk '{print $1}'`

### Platform Detection Display Mapping

| Target Triple | Human-Readable Display |
|---|---|
| x86_64-unknown-linux-gnu | Linux x86_64 |
| aarch64-unknown-linux-gnu | Linux aarch64 (ARM64) |
| x86_64-apple-darwin | macOS x86_64 (Intel) |
| aarch64-apple-darwin | macOS aarch64 (Apple Silicon) |

### GitHub API / Download URLs

- Latest release API: `https://api.github.com/repos/faiscadev/zopp/releases/latest`
- Binary download: `https://github.com/faiscadev/zopp/releases/download/$VERSION/zopp-$TARGET.tar.gz`
- Checksums download: `https://github.com/faiscadev/zopp/releases/download/$VERSION/checksums.txt`

### Previous Story Intelligence (Story 1.1)

- Checksums format is standard `sha256sum` output: `<hash>  <filename>` (two spaces)
- Binary naming: `zopp-<target-triple>.tar.gz`
- Checksums file is named `checksums.txt`
- The release workflow publishes both archives and checksums to the same GitHub Release

### What NOT to Do

- Do NOT use bashisms — must be POSIX shell (`#!/bin/sh`)
- Do NOT invoke `sudo` automatically
- Do NOT use spinners (too complex for POSIX shell, not critical for install script)
- Do NOT remove the root `install.sh` — keep it functional for existing links
- Do NOT add Windows support to the install script (Windows users use other install methods)

### References

- [Source: _bmad-output/planning-artifacts/architecture.md] — Install script decision, function naming, behavior requirements
- [Source: _bmad-output/planning-artifacts/ux-design-specification.md] — Install output template (lines 323-338), design direction
- [Source: install.sh] — Current install script (to be rewritten)
- [Source: _bmad-output/implementation-artifacts/1-1-set-up-cross-platform-binary-release-ci-pipeline.md] — Checksum format and binary naming

## Dev Agent Record

### Agent Model Used

### Debug Log References

### Completion Notes List

### File List

# Epic 1 Review Notes

## PR #74: Set up cross-platform binary release CI pipeline

### Gaps in Dev Process
- Sprint status was incorrectly marked as "done" while PRs were still open and unmerged — status tracking should only move to "done" after PR merge

### Incorrect Decisions During Development
- None identified — implementation was straightforward (adding checksum generation to existing workflow)

### Deferred Work
- None

### Patterns for Future Stories
- Verify sprint status accuracy before marking stories complete — "done" should mean merged, not just PR opened

## PR #75: Create curl install script

### Gaps in Dev Process
- Two-file install script design (root `install.sh` delegating to `scripts/install.sh`) was unnecessary complexity — user review correctly identified this should be a single file
- Missing checksum entry in `checksums.txt` was handled with a warn-and-skip instead of a hard abort — Cubic caught this as a P1 security issue across two reviews
- Dev agent did not catch the "skip verification" anti-pattern despite the story explicitly requiring strict checksum verification

### Incorrect Decisions During Development
- Architecture spec called for `scripts/install.sh` as the canonical location with root `install.sh` as wrapper — this added complexity without benefit for a single-file install script

### Deferred Work
- None

### Patterns for Future Stories
- For shell scripts, prefer single self-contained files over wrapper/delegate patterns unless there's a clear reason
- All security-critical verification steps should abort on failure, never skip — treat "skip verification" as a red flag during development
- Cubic's P1 findings on security paths are consistently valuable — prioritize addressing them

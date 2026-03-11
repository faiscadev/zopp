# Epic 2 Review Notes

## PR #81: Create zopp-sync crate with SyncTarget trait, DiffEngine, and shared types

### Gaps in Dev Process
- None identified — PR merged without review findings

### Incorrect Decisions During Development
- None identified

### Deferred Work
- None

### Patterns for Future Stories
- Clean merge on first review suggests good story spec and implementation alignment

## PR #82: Create CLI output component module

### Gaps in Dev Process
- `--verbose` and `--quiet` were not marked as mutually exclusive in clap — Cubic caught this as a P2

### Incorrect Decisions During Development
- None identified

### Deferred Work
- None

### Patterns for Future Stories
- Always add `conflicts_with` for mutually exclusive CLI flags
- Rebase conflict resolution required careful reasoning about tracking file state vs code state — tracking files (story artifacts, execution state) often have both sides partially correct

## PR #83: Implement AWS Secrets Manager sync target

### Gaps in Dev Process
- `fetch_current` silently swallowed per-key errors — owner caught this in review. Dev agent should have designed for error visibility from the start
- `"connection"` substring check too broad for error classification — Cubic P2. Dev should use specific error patterns, not generic substrings
- Story 2.1 artifact doc not updated when 2.2 added `aws/` module — Cubic P3

### Incorrect Decisions During Development
- AC#2 was interpreted as "skip errors silently" when it should have been "return partial results WITH errors for caller to decide"

### Deferred Work
- None

### Patterns for Future Stories
- When fetching collections with per-item errors, always return both successes and errors — never silently discard
- Error classification by string matching should use specific patterns, not broad substrings
- Update referenced artifacts when adding modules that contradict prior documentation

## PR #84: Add zopp sync aws and zopp diff aws CLI commands

### Gaps in Dev Process
- `diff aws` reused `SyncCommonArgs` (including `--dry-run`/`--force`) — Cubic P2. Read-only commands should not accept write-only flags
- Per-key fetch errors from `FetchResult` not reflected in exit code — Cubic P1. CLI returned SUCCESS even when some secrets couldn't be fetched
- `fetch_current()` return type changed in PR #83 review (HashMap → FetchResult) but PR #84 wasn't updated to match — caused compilation failure after rebase

### Incorrect Decisions During Development
- Shared `SyncCommonArgs` between sync and diff commands without considering that diff is read-only and doesn't use `--dry-run`/`--force`

### Deferred Work
- None

### Patterns for Future Stories
- Read-only commands should have their own args struct — don't share with write commands
- When a trait signature changes in a review fix, check all consumers in the PR chain for compatibility
- Always propagate partial-failure state to exit codes — callers (CI, scripts) rely on exit codes for correctness

## PR #80: Add zopp sync status command

### Gaps in Dev Process
- `fetch_current()` return type change from PR #83 review required a fix in sync_status.rs after rebase — same issue as PR #84
- Cubic P2 about partial-failure exit code was a false positive — `from_results(total, errors)` already handles it correctly, but with only 1 target currently, 1/1 failure = total failure by design
- `rustfmt` formatting issue on long format string — should always run `cargo fmt` before pushing

### Incorrect Decisions During Development
- None identified

### Deferred Work
- None

### Patterns for Future Stories
- Always run `cargo fmt` locally before pushing, now that rustc is updated to 1.94
- When a trait return type changes in an earlier PR review, every downstream PR in the chain will need the same fix — consider batch-fixing in one pass

---
stepsCompleted: ["step-01-document-discovery", "step-02-prd-analysis", "step-03-epic-coverage-validation", "step-04-ux-alignment", "step-05-epic-quality-review", "step-06-final-assessment"]
documentsUsed:
  prd: "_bmad-output/planning-artifacts/prd.md"
  architecture: "_bmad-output/planning-artifacts/architecture.md"
  epics: "_bmad-output/planning-artifacts/epics.md"
  ux: "_bmad-output/planning-artifacts/ux-design-specification.md"
  productBrief: "_bmad-output/planning-artifacts/product-brief-zopp-2026-03-04.md"
---

# Implementation Readiness Assessment Report

**Date:** 2026-03-07
**Project:** zopp

## PRD Analysis

### Functional Requirements

FR1: A developer can install the zopp CLI on macOS or Linux with a single curl command
FR2: The install script can detect the user's OS and architecture and download the correct binary
FR3: A developer can install the zopp CLI via Homebrew on macOS or Linux
FR4: A developer can install the zopp CLI via apt on Debian/Ubuntu
FR5: A developer can install the zopp CLI via nix
FR6: A user can sync secrets from a zopp environment to AWS Secrets Manager
FR7: A user can sync secrets from a zopp environment to GCP Secret Manager
FR8: A user can map zopp environments to cloud secret paths/names
FR9: A user can preview sync changes before applying them (`zopp diff aws`, `zopp diff gcp`)
FR10: A user can perform a dry-run sync that shows what would change without modifying the target
FR11: The system can sync only changed secrets (incremental sync) rather than the full set
FR12: A user can authenticate with cloud providers using platform-native credentials (AWS profile/env vars, GCP ADC/service account)
FR13: A user can sync secrets from a zopp environment to Fly
FR14: A user can sync secrets from a zopp environment to Vercel
FR15: A user can sync secrets from a zopp environment to Render
FR16: A user can sync secrets from a zopp environment to Railway
FR17: A user can map zopp environments to PaaS deployment targets (project, service, app)
FR18: A user can preview PaaS sync changes before applying them (`zopp diff <target>`)
FR19: A user can authenticate with PaaS platforms using API tokens
FR20: The system records every sync attempt (success or failure) in the audit log
FR21: A user can view sync status for all configured targets (`zopp sync status`)
FR22: The system handles platform API rate limits with automatic backoff and retry
FR23: The system surfaces clear error messages on sync failure identifying the target, secret, and failure reason
FR24: A sync agent (service principal) can run sync operations on behalf of a team without human interaction
FR25: A user can deploy zopp-server to Fly using a provided `fly.toml` template
FR26: A user can deploy zopp-server to Railway using a provided template
FR27: A user can deploy zopp-server using Docker Compose with a provided template
FR28: Each deployment template includes PostgreSQL configuration
FR29: Each deployment template includes TLS configuration (automatic via platform or explicit)
FR30: A user can generate an invite token from a PaaS-deployed server
FR31: All sync operations decrypt secrets client-side (sync agent/CLI), never on the server
FR32: The sync agent authenticates as a service principal with scoped RBAC permissions
FR33: A workspace admin can create a service principal scoped to read-only on specific environments for sync operations

**Total FRs: 33**

### Non-Functional Requirements

NFR1: (Performance) Install script completes in under 30 seconds on a standard broadband connection
NFR2: (Performance) Sync operations complete within 30 seconds for environments with up to 100 secrets
NFR3: (Performance) `zopp diff` preview commands return results within 5 seconds
NFR4: (Performance) Rate limit backoff adds no more than 60 seconds of additional delay per sync cycle under normal conditions
NFR5: (Security) No plaintext secrets are written to disk, logs, or temporary files during sync operations
NFR6: (Security) Platform API credentials (AWS keys, PaaS tokens) are never logged or persisted by zopp — read from environment variables or CLI flags at runtime only
NFR7: (Security) The install script verifies binary integrity (checksum verification) before placing the binary in PATH
NFR8: (Security) All sync communication with external platforms uses TLS
NFR9: (Security) Sync agent service principals follow least-privilege: read-only access scoped to specific environments
NFR10: (Integration) Each sync integration is isolated — a failure or API change in one platform does not affect others
NFR11: (Integration) Each sync integration supports platform-native authentication methods (no custom auth schemes)
NFR12: (Integration) Sync integrations handle API version changes gracefully — clear error messages on breaking changes, not silent data corruption
NFR13: (Integration) Each sync integration has automated integration tests that run against the platform's API (or a mock of it)
NFR14: (Reliability) A failed sync to one target does not block sync to other targets
NFR15: (Reliability) Sync operations are idempotent — running the same sync twice produces the same result
NFR16: (Reliability) Partial sync failures (some secrets synced, some failed) are reported per-secret, not as a blanket failure
NFR17: (Reliability) Deployment templates produce servers that pass health checks and recover from container restarts without data loss

**Total NFRs: 17**

### Additional Requirements

**Zero-Knowledge Preservation (Architectural Constraint):**
- Server remains blind — all sync operations happen outside the server; decryption occurs in the sync agent, never on the server
- Sync agent pattern extends the existing K8s operator model (service account principal with its own keys)
- No new trust assumptions — sync agent is trusted exactly as much as any other principal with workspace access

**Implementation Constraints:**
- No new server RPCs needed — sync uses existing `ListSecrets`/`GetSecret` + client-side decryption
- Each sync target is a separate Rust module (isolated, independently testable)
- Platform credentials passed via environment variables or CLI flags — not stored in zopp (avoids bootstrapping problem)
- Priority order for distribution: curl install → brew → apt → nix
- Priority order for deployment templates: Fly → Railway → Docker Compose

**Phasing Constraints:**
- Phase 1 (MVP): curl install, AWS Secrets Manager sync, Fly deployment template, Fly sync integration
- Phase 2: GCP Secret Manager, Vercel, Render integrations, brew formula
- Phase 3: Railway sync, apt package, nix package, Railway deployment template, Docker Compose template

### PRD Completeness Assessment

The PRD is **well-structured and complete** for its scope. Requirements are clearly numbered (FR1–FR33, NFR1–NFR17), phasing is explicit and rationale-driven, and user journeys map directly to capabilities. The zero-knowledge preservation constraint is prominently articulated. One notable characteristic: this is a brownfield PRD — the core product is already built; this PRD covers the distribution and integrations wave only. This means epics/stories must stay tightly scoped to the delta described here and not re-implement existing core features.

## Epic Coverage Validation

### Coverage Matrix

| FR | PRD Requirement (Summary) | Epic Coverage | Story | Status |
|----|--------------------------|---------------|-------|--------|
| FR1 | curl install on macOS/Linux | Epic 1 | Story 1.2 | ✓ Covered |
| FR2 | Install script OS/arch detection | Epic 1 | Story 1.2 | ✓ Covered |
| FR3 | Homebrew install | Epic 6 | Story 6.1 | ✓ Covered |
| FR4 | apt install | Epic 8 | Story 8.1 | ✓ Covered |
| FR5 | nix install | Epic 8 | Story 8.2 | ✓ Covered |
| FR6 | Sync to AWS Secrets Manager | Epic 2 | Stories 2.2, 2.4 | ✓ Covered |
| FR7 | Sync to GCP Secret Manager | Epic 4 | Story 4.1 | ✓ Covered |
| FR8 | Map environments to cloud paths | Epic 2 | Story 2.2, 2.4 (--prefix flag) | ✓ Covered |
| FR9 | Preview cloud sync changes (diff) | Epic 2 | Story 2.4 (`zopp diff aws`); Epic 4 Story 4.1 (`zopp diff gcp`) | ✓ Covered |
| FR10 | Dry-run sync | Epic 2 | Story 2.4 (--dry-run) | ✓ Covered |
| FR11 | Incremental sync | Epic 2 | Stories 2.1 (DiffEngine), 2.2 | ✓ Covered |
| FR12 | Platform-native cloud auth | Epic 2 | Story 2.2 (AWS); Epic 4 Story 4.1 (GCP) | ✓ Covered |
| FR13 | Sync to Fly | Epic 3 | Story 3.1 | ✓ Covered |
| FR14 | Sync to Vercel | Epic 5 | Story 5.1 | ✓ Covered |
| FR15 | Sync to Render | Epic 5 | Story 5.2 | ✓ Covered |
| FR16 | Sync to Railway | Epic 7 | Story 7.1 | ✓ Covered |
| FR17 | Map environments to PaaS targets | Epic 3 | Stories 3.1, 5.1, 5.2, 7.1 (target flags) | ✓ Covered |
| FR18 | Preview PaaS sync changes (diff) | Epic 3 | Stories 3.1, 5.1, 5.2, 7.1 | ✓ Covered |
| FR19 | PaaS API token auth | Epic 3 | Stories 3.1, 5.1, 5.2, 7.1 | ✓ Covered |
| FR20 | Sync audit logging | Epic 2 | Story 2.4 (uses existing server audit) | ⚠ Partial — see notes |
| FR21 | Sync status view | Epic 2 | Story 2.5 | ✓ Covered |
| FR22 | Rate limit backoff | Epic 2 | Story 2.2 | ✓ Covered |
| FR23 | Clear sync error messages | Epic 2 | Stories 2.1 (SyncError types), 2.3 (ErrorBlock) | ✓ Covered |
| FR24 | Sync agent (headless, non-interactive) | Epic 2 | Story 2.4 (partial — Phase 1 is CLI-triggered) | ⚠ Partial — see notes |
| FR25 | Fly deployment template | Epic 3 | Story 3.2 | ✓ Covered |
| FR26 | Railway deployment template | Epic 7 | Story 7.2 | ✓ Covered |
| FR27 | Docker Compose deployment template | Epic 9 | Story 9.1 | ✓ Covered |
| FR28 | PostgreSQL in all deployment templates | Epics 3, 7, 9 | Stories 3.2, 7.2, 9.1 | ✓ Covered |
| FR29 | TLS in all deployment templates | Epics 3, 7, 9 | Stories 3.2, 7.2, 9.1 | ✓ Covered |
| FR30 | Invite token from PaaS-deployed server | Epics 3, 7, 9 | Stories 3.2, 7.2, 9.1 | ✓ Covered |
| FR31 | Client-side decryption only | Epic 2 | Story 2.4 (explicit AC) | ✓ Covered |
| FR32 | Sync agent authenticates as service principal | Epic 2 | Story 2.4 (explicit AC) | ✓ Covered |
| FR33 | Admin creates scoped sync service principal | Epic 2 | **No dedicated story found** | ❌ GAP |

### Missing / Partial Requirements

#### ❌ GAP — FR33: Create Scoped Sync Service Principal

**Full requirement:** A workspace admin can create a service principal scoped to read-only on specific environments for sync operations.

**Finding:** The epics coverage map claims FR33 is covered in Epic 2, and Story 2.4 assumes such a principal already exists ("Given the sync operation is performed by a service principal / When the principal has read-only RBAC access..."). However, there is no story that covers the **creation workflow** for this service principal. The existing `zopp join` flow is for human users. There is no story for `zopp service-principal create` or equivalent CLI command.

**Impact:** High. Without this story, users have no documented path to create the service principal required to run the sync. The sync framework is complete but the prerequisite setup step is missing.

**Recommendation:** Add a story to Epic 2 (e.g., Story 2.0 or 2.6): "As a workspace admin, I want to create a service principal with read-only access to a specific environment, so that I can configure automated sync without granting workspace-wide privileges."

**Note on existing core product:** If `zopp` already has a working service principal creation command in the current core product (pre-this-PRD), this gap may not require a new story — but it should be called out explicitly in the epic description and verified before implementation begins.

---

#### ⚠ PARTIAL — FR20: Sync Audit Logging

**Full requirement:** The system records every sync attempt (success or failure) in the audit log.

**Finding:** Story 2.4 covers this only implicitly: "the server audit log records the secret access by the principal's ID." The architecture doc explicitly states: "No new audit RPCs for sync events; existing SecretList/SecretRead audit events suffice." This means sync audit events piggyback on existing secret read events — each `GetSecret` call is logged, but there is no dedicated sync attempt audit event with timestamp, target, and result.

**Impact:** Medium. The PRD says "Sync failures recorded in audit log — every sync attempt (success or failure) is an auditable event with timestamp, target, and result." The architecture decision to use existing audit events may not fully satisfy this requirement, particularly for compliance scenarios where auditors want to see "secrets were synced to AWS at 14:32:07" rather than just "secrets were read."

**Recommendation:** Confirm with stakeholder whether existing SecretRead audit events are sufficient for compliance purposes. If not, a lightweight client-side sync log (stored locally or as a zopp-tracked event) may be needed.

---

#### ⚠ PARTIAL — FR24: Headless Sync Agent

**Full requirement:** A sync agent (service principal) can run sync operations on behalf of a team without human interaction.

**Finding:** The architecture doc explicitly scopes Phase 1 as "CLI-triggered sync" with "no new binary; CLI is the sync agent." This is architecturally sound (cron/CI can call `zopp sync aws` non-interactively), but there's no story addressing how to configure or run the CLI non-interactively (credential sourcing for CI, token management, etc.).

**Impact:** Low for Phase 1 (most teams will figure out cron/CI themselves), but worth documenting.

**Recommendation:** Consider adding acceptance criteria to Story 2.4 or a separate story covering "running zopp sync in CI/CD non-interactively" — including how the service principal's credentials are provided in a headless environment.

---

#### Minor: Coverage Map Inaccuracy for FR28, FR29, FR30

The FR Coverage Map in epics.md lists FR28, FR29, FR30 as covered only in "Epic 3," but these apply to all three deployment templates (Epics 3, 7, and 9). The actual story content correctly covers all three. This is a documentation inconsistency in the epics' coverage map section only — not a true coverage gap.

### Coverage Statistics

- **Total PRD FRs:** 33
- **Fully covered in epics:** 30
- **Partially covered:** 2 (FR20, FR24)
- **Not covered / Gaps:** 1 (FR33)
- **FR coverage percentage:** 91% full, 97% partial
- **NFR coverage in stories:** NFRs are cross-cutting; most are addressed in architecture constraints and story ACs. NFR3 (diff <5s performance target) and NFR12 (graceful API version changes) have no explicit acceptance criteria in any story.

## UX Alignment Assessment

### UX Document Status

**Found** — `ux-design-specification.md` (1,361 lines, 2026-03-04). Status: complete. Input documents include `prd.md`, confirming the UX was developed from the PRD. The UX document covers the full wave: curl install, all seven sync targets, all three deployment templates.

### UX ↔ PRD Alignment

**Overall: Strong alignment.** The UX was built directly from the PRD. All user personas map 1:1 to PRD journeys. All sync targets, diff/sync command patterns, flag conventions, and audit trail requirements align with the PRD's functional requirements.

**Specific alignments confirmed:**
- All 7 sync targets (k8s, aws, gcp, fly, vercel, render, railway) present in both documents
- Diff-then-sync pattern (`zopp diff <target>` → `zopp sync <target>`) matches PRD FR9, FR10, FR18
- `--dry-run` flag matches PRD FR10
- Platform-native auth conventions match PRD FR12, FR19
- Per-secret failure reporting matches PRD FR23, NFR16
- Exit code contract (0/1/2/3/4) aligns with PRD's reliability and scripting requirements
- `--json`, `--no-color`, `--verbose`, `--quiet` flags all consistent with architecture's `SyncCommonArgs`

**Misalignment 1 (Medium): `zopp sync status` phasing conflict**

UX Component Strategy explicitly states the Status Table component is **Phase 2**: *"Phase 1... Operation Header, Per-Item Result Line, Summary Line, Diff Summary, Error Block, Install Progress, Next Steps Block. Phase 2 (GCP + Vercel + Render + brew): Status Table component added (enables `zopp sync status` once multiple targets exist)."*

However, Epic 2 (Phase 1) includes **Story 2.5: "Add zopp sync status command."** The architecture additional requirements also list all 8 components together without a Phase 2 qualifier for StatusTable.

**Impact:** If the UX intent is correct (status is only useful with multiple targets, so Phase 2), then Story 2.5 should be moved to Epic 4 or 5. If the Epic intent is correct (status in Phase 1, even with just AWS), the UX phasing note should be corrected.

**Recommendation:** Clarify intent with stakeholder. The status command with a single target (just AWS in Phase 1) is still useful as a health check, and implementing the component early is low cost. Moving it to Phase 2 defers value unnecessarily. Recommend keeping Story 2.5 in Phase 1 and updating the UX phasing note.

---

**Misalignment 2 (Low): `--force` sync flag in UX, absent from PRD and architecture**

UX Flag Consistency Patterns define:
> `--force` — Force sync even if target not managed by zopp

This flag does not appear in any PRD FR, NFR, or in the architecture's `SyncCommonArgs` definition. It's a UX addition not backed by a requirement or architecture decision.

**Impact:** Low. Developers implementing sync commands may or may not implement this flag — the inconsistency could lead to omission.

**Recommendation:** Either add `--force` to `SyncCommonArgs` in the architecture and to Story 2.3's acceptance criteria, or remove it from the UX spec if it's not required.

---

**UX reinforces FR20 gap (audit logging):**
Journey 2 (Diana), Step 7 explicitly states: *"The audit log records the sync event automatically."* This is presented to users as a feature. This reinforces the concern raised under FR20 — the architecture decision to rely on existing `SecretRead` events (rather than dedicated sync audit events) may not match the UX promise made to users. If a user expects to see "synced to AWS Secrets Manager at 14:32" in the audit log, but the log only shows individual secret reads, there's a UX expectation gap.

---

### UX ↔ Architecture Alignment

**Overall: Excellent alignment.** The architecture's additional requirements in the epics document have fully incorporated the UX specification's CLI output requirements.

**Confirmed aligned:**
- 8 CLI output components listed in architecture match UX Component Strategy
- ANSI color semantics match UX color system (Green=success, Red=error, Yellow=warning, Cyan=info)
- `NO_COLOR` / `--no-color` support confirmed in both
- `--json` complete JSON object format confirmed in both
- 80-column minimum terminal width confirmed in both
- Spinner progress indicator confirmed in both
- Error format (`Error: [target] [operation] failed — [reason]. Fix: [actionable instruction]. Docs: [link]`) confirmed in both
- Terraform-style diff format (+/~/- with color) confirmed in both

**Minor gap: TTY detection and ASCII fallback**

UX specifies: *"When stdout is not a TTY (piped to another command or redirected to a file), output strips ANSI codes, drops progress indicators, and uses plain ASCII symbols (`[ok]` instead of `✓`)."*

The architecture additional requirements cover `--no-color` and `NO_COLOR` but do **not** explicitly mention TTY detection for the pipe/redirect case. This behavior is important for scriptability (e.g., `zopp diff aws | less`, `zopp sync status > report.txt`).

**Recommendation:** Add TTY detection to Story 2.3's acceptance criteria: "Given stdout is not a TTY (piped/redirected), output strips ANSI codes and uses ASCII fallback symbols."

---

### Warnings

1. **`zopp sync status` phase placement:** Resolve conflict between UX (Phase 2) and Epic 2 Story 2.5 (Phase 1). Recommend Phase 1 for better user value.

2. **`--force` flag:** Untracked in architecture and PRD; ensure it's either added to architecture's `SyncCommonArgs` or removed from UX spec.

3. **Audit log UX expectation:** UX creates an explicit user expectation that sync events appear in the audit log. Confirm the architecture's approach (reusing SecretRead events) satisfies this expectation before implementation begins.

4. **TTY detection:** Architecture story should explicitly include TTY detection for ASCII fallback — a scriptability requirement that affects every sync command's output implementation.

## Epic Quality Review

### Epic Structure Validation

#### Epic User-Value and Independence Assessment

| Epic | Title | User-Centric? | User Outcome Clear? | Independent? | Notes |
|------|-------|:---:|:---:|:---:|-------|
| Epic 1 | One-Command CLI Installation | ✓ | ✓ | ✓ | Fully standalone |
| Epic 2 | Sync Framework & AWS Secrets Manager | ⚠ | ✓ | ✓ | "Sync Framework" is technical; user-value comes from AWS integration |
| Epic 3 | Fly Integration (Sync & Deployment) | ✓ | ✓ | Needs Epic 2 | Backward dep only |
| Epic 4 | GCP Secret Manager Integration | ✓ | ✓ | Needs Epic 2 | Backward dep only |
| Epic 5 | Vercel & Render Integrations | ✓ | ✓ | Needs Epic 2 | Backward dep only |
| Epic 6 | Homebrew Distribution | ✓ | ✓ | Needs Epic 1 | Backward dep only (undocumented) |
| Epic 7 | Railway Integration (Sync & Deployment) | ✓ | ✓ | Needs Epics 1, 2 | Backward deps only |
| Epic 8 | Extended Distribution (apt & nix) | ✓ | ✓ | Needs Epic 1 | Backward dep only (undocumented) |
| Epic 9 | Docker Compose Deployment | ✓ | ✓ | ✓ | Standalone template |

**No forward dependencies found between epics.** Epics 3–7 correctly declare "Builds on: Epic 2" — all backward. No epic requires a later epic to function.

---

### 🟠 Major Issue 1: Epic 2 Title Conflates Technical Foundation with User Feature

**Epic 2 is named "Sync Framework & AWS Secrets Manager Integration"** — the "Sync Framework" half is a technical milestone, not a user feature. The epic goal correctly anchors on user value ("Teams can sync secrets to AWS Secrets Manager"), but the title and story organization expose the framework-building nature.

The epic contains 5 stories:
- Story 2.1: Create zopp-sync crate, SyncTarget trait, DiffEngine — **developer story (no user value alone)**
- Story 2.2: Implement AWS Secrets Manager sync target — **library implementation (no CLI yet)**
- Story 2.3: Create CLI output component module — **developer story (no user value alone)**
- Story 2.4: Add zopp sync aws and zopp diff aws CLI commands — **first story delivering user value**
- Story 2.5: Add zopp sync status command — **user value**

Stories 2.1, 2.2, and 2.3 produce no usable user-facing feature on their own. Only Story 2.4 delivers the first user capability. A user can do nothing with zopp after Stories 2.1–2.3 that they couldn't before.

**However:** This structure is a deliberate and pragmatic choice for a brownfield Rust project. Building a new crate with shared types before implementing consumers is correct engineering. The stories are sized appropriately for individual implementation sessions. The alternative (one mega-story) would be harder to track and review.

**Assessment:** Not a blocking defect, but the epic title should be updated to reflect user value more clearly. Consider: **"AWS Secrets Manager Sync"** with Story 2.1/2.3 treated explicitly as "enabling stories" in the epic description.

**Recommendation:** Update Epic 2 description to explicitly identify Stories 2.1 and 2.3 as internal enabler stories. No structural change needed — just transparency.

---

### Story Quality Assessment

#### Story-by-Story Validation

**Story 1.1: Set up cross-platform binary release CI pipeline**
- Format: "As a developer" — contributor story, not end-user story ⚠
- Value: Enables Story 1.2 (install script requires binaries in GitHub Releases). Infrastructure story.
- ACs: Well-structured GWT ✓. Missing error scenario (what if build fails for one platform?). Minor gap.
- **Assessment:** Acceptable enabler story. Flagging as 🟡 minor concern (developer story framing).

**Story 1.2: Create curl install script**
- User story ✓. Multiple error scenarios covered (unsupported platform, checksum mismatch, idempotent re-run) ✓
- Depends on Story 1.1 output (binaries in GitHub Releases) — correct within-epic ordering ✓
- **Assessment:** High quality. No violations.

**Story 2.1: Create zopp-sync crate with SyncTarget trait, DiffEngine, and shared types**
- "As a developer building sync integrations" — developer/contributor story, not user story ⚠
- All ACs are technical implementation details (crate structure, trait methods, feature flags). No user-observable outcome.
- **Assessment:** Necessary enabler story for a Rust project. Acceptable within the constraints of the tech stack. 🟡 minor concern — document as enabling story explicitly.

**Story 2.2: Implement AWS Secrets Manager sync target**
- "As a user, I want zopp to connect to AWS Secrets Manager" — user framing but delivers a Rust library, not a CLI command. User cannot verify this story is done without Story 2.4.
- ACs are thorough: credential resolution, operations, error handling, rate limit backoff, unit tests ✓
- Note on "unit tests verify API client behavior with mocked HTTP responses" — this references unit testing, not the full NFR13 requirement for integration tests against the actual AWS API.
- **Assessment:** 🟡 Minor concern — story 2.2 alone is not user-verifiable. Paired with 2.4 it completes a user feature.

**Story 2.3: Create CLI output component module**
- "As a user running sync commands" — user framing but this is internal infrastructure ⚠
- ACs cover: output components, `--json`, `--no-color`, `--verbose`, `--quiet`, exit codes, terminal width ✓
- **Missing from ACs: TTY detection and ASCII fallback** for piped/redirected output (identified in UX alignment) ❌
- **Assessment:** 🟠 Major gap — missing TTY detection AC. Should add: "Given stdout is not a TTY (piped or redirected) / When any command produces output / Then ANSI codes are stripped and Unicode symbols downgrade to ASCII equivalents ([ok], [FAIL], [WARN])."

**Story 2.4: Add zopp sync aws and zopp diff aws CLI commands**
- User-centric ✓. This is the capstone story of Epic 2 that delivers real user value.
- ACs are thorough: diff output, sync output, dry-run, SyncCommonArgs, service principal, idempotency, no-plaintext constraint ✓
- Well-structured GWT format with multiple scenarios ✓
- **Assessment:** High quality. No critical violations.

**Story 2.5: Add zopp sync status command**
- User-centric ✓. Multiple scenarios covered (healthy targets, credential errors, JSON output, compliance screenshot) ✓
- **Phase placement conflict** with UX spec (Phase 2 per UX, Phase 1 per Epic 2) — already documented ⚠
- **Assessment:** High quality story. Phase placement needs resolution.

**Story 3.1: Implement Fly sync target and CLI commands**
- User-centric ✓. Note this story combines both target implementation AND CLI commands (unlike Epic 2's split) — more cohesive approach for follow-on targets. The pattern from 2.2+2.4 is appropriately consolidated here.
- ACs cover: token auth, fetch_current(), apply(), diff, sync, error handling ✓
- **Assessment:** High quality. Good pattern consolidation.

**Story 3.2: Create Fly deployment template**
- User-centric ✓. ACs cover template, PostgreSQL, TLS, health check, invite token, README ✓
- **Assessment:** Complete and well-specified.

**Story 4.1: GCP sync target and CLI commands**
- Same consolidated pattern as 3.1 ✓
- ACs cover ADC credential resolution, operations, error handling with ADC resolution path documentation ✓
- **Assessment:** High quality.

**Story 5.1: Vercel sync target and CLI commands**
- User-centric ✓. Notably includes `--target production/preview/development` parameter — matches Vercel's environment model ✓
- **Assessment:** High quality.

**Story 5.2: Render sync target and CLI commands**
- User-centric ✓. Uses Render's `--service` flag convention ✓
- **Assessment:** High quality.

**Story 6.1: Create Homebrew formula and tap**
- User-centric ✓. ACs cover installation, CI auto-update, upgrade, cross-platform binary support, checksums ✓
- **Undocumented cross-epic dependency:** Epic 6 requires Epic 1 (Story 1.1 binary releases). Not mentioned in Epic 6 description.
- **Assessment:** 🟡 Minor concern — add "Depends on: Epic 1" to Epic 6 description.

**Story 7.1: Railway sync target and CLI commands**
- User-centric ✓. Correctly identifies Railway uses **GraphQL API** (not REST like other targets) — shows good platform research.
- **Assessment:** High quality. Awareness of platform-specific API differences is good.

**Story 7.2: Create Railway deployment template**
- User-centric ✓. Same pattern as Story 3.2 ✓
- **Assessment:** High quality.

**Story 8.1: Create apt package and repository**
- User-centric ✓. ACs cover installation, CI builds, upgrade path, GPG key setup ✓
- **Undocumented cross-epic dependency:** Epic 8 requires Epic 1 (binary releases). Not mentioned in Epic 8 description.
- **Assessment:** 🟡 Minor concern — add "Depends on: Epic 1" to Epic 8 description.

**Story 8.2: Create nix package**
- User-centric ✓. References `nixpkgs` conventions correctly ✓
- **Assessment:** High quality.

**Story 9.1: Create Docker Compose deployment template**
- User-centric ✓. Notably handles TLS differently from Fly/Railway (explicit certificate paths, not automatic platform TLS) — appropriate for self-hosted scenario ✓
- ACs cover: template, Postgres with persistent volume, TLS, health check, restart recovery, invite generation, README with TLS setup, volume backup ✓ — the most complete deployment template story
- **Assessment:** High quality. Best specified deployment template story.

---

### Dependency Analysis

#### Within-Epic Dependencies

All within-epic story ordering is correct:

| Epic | Dependency Order |
|------|----------------|
| Epic 1 | 1.1 → 1.2 (binaries needed before install script) |
| Epic 2 | 2.1 → 2.2/2.3 → 2.4 → 2.5 (framework → target → CLI → status) |
| Epic 3 | 3.1 and 3.2 are independent within epic (sync and deploy are separate) |
| Epics 4-9 | Single or paired independent stories |

**No forward dependencies found.** No story references a future story's outputs.

#### Cross-Epic Dependencies

| Dependency | Documented? | Issue? |
|-----------|:-----------:|--------|
| Epics 3, 4, 5, 7 depend on Epic 2 | ✓ Explicit | None |
| Epic 6 depends on Epic 1 | ❌ Not documented | 🟡 Minor |
| Epic 8 depends on Epic 1 | ❌ Not documented | 🟡 Minor |
| Epic 9 depends on neither Epic 1 nor 2 | N/A | None — standalone |

---

### Best Practices Compliance Checklist

| Epic | Delivers User Value | Independent | Stories Sized OK | No Forward Deps | Clear ACs | FR Traceability |
|------|:--:|:--:|:--:|:--:|:--:|:--:|
| Epic 1 | ✓ | ✓ | ⚠ 1.1 is dev story | ✓ | ✓ | ✓ |
| Epic 2 | ⚠ mixed | ✓ | ⚠ 2.1, 2.3 are dev stories | ✓ | ⚠ 2.3 missing TTY AC | ✓ |
| Epic 3 | ✓ | needs Ep2 | ✓ | ✓ | ✓ | ✓ |
| Epic 4 | ✓ | needs Ep2 | ✓ | ✓ | ✓ | ✓ |
| Epic 5 | ✓ | needs Ep2 | ✓ | ✓ | ✓ | ✓ |
| Epic 6 | ✓ | needs Ep1 (undoc) | ✓ | ✓ | ✓ | ✓ |
| Epic 7 | ✓ | needs Ep2 | ✓ | ✓ | ✓ | ✓ |
| Epic 8 | ✓ | needs Ep1 (undoc) | ✓ | ✓ | ✓ | ✓ |
| Epic 9 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |

### Summary of Quality Findings

#### 🔴 Critical Violations
None. No epics are pure technical milestones with zero user value. No forward dependencies. No circular dependencies.

#### 🟠 Major Issues
1. **Story 2.3 missing TTY detection AC** — A key UX requirement (ASCII fallback for piped output) has no acceptance criteria in any story.
2. **FR33 has no implementing story** — Already documented in FR Coverage section.

#### 🟡 Minor Concerns
1. Stories 1.1, 2.1, 2.3 are developer/enabler stories — acceptable for Rust crate projects but should be labeled as "enabling stories" in the epic description.
2. Epic 2 title partially reflects technical foundation — consider renaming to "AWS Secrets Manager Sync" to emphasize user value.
3. `zopp sync status` phase conflict (Epic 2 vs UX Phase 2) — needs stakeholder resolution.
4. Epics 6 and 8 missing documented cross-epic dependency on Epic 1.
5. `--force` flag in UX not tracked in architecture or stories.

---

## Summary and Recommendations

### Overall Readiness Status

## ✅ READY — all must-fix and should-fix issues resolved (2026-03-07)

The zopp distribution and integrations wave has **strong, well-aligned planning artifacts.** The PRD is complete with 33 clearly numbered FRs and 17 NFRs. The architecture is detailed and technically sound. The UX specification is comprehensive and design-forward. The epics cover 9 epics and 17 stories across 3 phases. No critical blocking issues were found.

Implementation can begin on Phase 1 stories (Epic 1, Epic 2, Epic 3) with targeted fixes applied in parallel.

---

### Critical Issues Requiring Immediate Action

#### 1. ❌ Missing Story for FR33 — Service Principal Creation Workflow

**What:** No story covers how a workspace admin creates a service principal scoped to read-only on specific environments (required prerequisite for all sync operations).

**Impact:** Developers implementing Epic 2 will implement sync using service principals, but users will have no documented path to create them. Story 2.4's AC assumes the principal exists.

**Action:** Before implementation begins on Story 2.4, resolve one of:
- (a) Confirm the existing core product already has a working `zopp principal create` (or equivalent) command, document it in the Epic 2 description, and add an AC to Story 2.4 referencing it.
- (b) Add a new Story 2.0 or 2.6: "As a workspace admin, I want to create a service principal scoped to read-only access on a specific environment for automated sync operations."

---

#### 2. 🟠 Story 2.3 Missing TTY Detection Acceptance Criteria

**What:** The UX specification explicitly requires that when stdout is piped or redirected (non-TTY), Unicode symbols downgrade to ASCII equivalents and ANSI codes are stripped. This behavior is not captured in Story 2.3's acceptance criteria.

**Impact:** Without explicit ACs, developers may not implement TTY detection. This breaks `zopp diff aws | less`, `zopp sync status > report.txt`, and all other pipe/redirect use cases.

**Action:** Add to Story 2.3: *"Given stdout is not a TTY (piped or redirected to a file) / When any command produces output / Then no ANSI escape codes are emitted / And Unicode symbols downgrade to ASCII equivalents (✓→[ok], ✗→[FAIL], ⚠→[WARN]) / And progress spinners are suppressed."*

---

#### 3. 🟠 Audit Log Expectation Gap for FR20

**What:** The PRD (FR20), UX ("The audit log records the sync event automatically"), and user journeys all create an explicit expectation that sync events appear in the audit log with timestamp, target, and result. The architecture resolves this by reusing existing `SecretRead` events, not creating new sync-specific audit events.

**Impact:** This architectural decision may not satisfy the compliance narrative users expect (auditors want "synced to AWS at 14:32" not "secret DATABASE_URL read at 14:32"). This is a potential compliance story quality issue.

**Action:** Before Epic 2 implementation, confirm with stakeholder: are `SecretRead` audit events sufficient for the compliance use case in Journey 2 and Journey 3? If not, plan a lightweight sync event log (even client-side) before implementation.

---

### Recommended Next Steps

1. **Resolve FR33 gap** (1-2 hours) — Check existing core product for service principal creation capability. Add a story or update Epic 2 description with explicit prerequisites before any Epic 2 development begins.

2. **Add TTY detection AC to Story 2.3** (15 minutes) — Edit Story 2.3 to add the TTY detection acceptance criterion. Ensure the implementing developer adds `terminal_size` crate and TTY-check logic.

3. **Confirm audit log sufficiency for FR20** (30-minute stakeholder discussion) — Decide whether existing SecretRead events satisfy the "sync audit trail" UX promise. Document the decision.

4. **Resolve `zopp sync status` phase placement** (15 minutes) — Decide: Phase 1 (keep in Epic 2, Status Table built in Phase 1) or Phase 2 (move Story 2.5 to Epic 4 and update UX spec). Recommended: keep in Phase 1 — useful with a single target and low incremental cost.

5. **Document cross-epic dependencies** (15 minutes) — Add "Depends on: Epic 1" to Epic 6 and Epic 8 descriptions. Add "Depends on: Epic 1" to Epic 7 description (needs binary releases for deployment).

6. **Decide on `--force` flag** (15 minutes) — Either add `--force` to architecture's `SyncCommonArgs` and to Story 2.3/2.4 ACs, or remove it from the UX spec.

7. **Begin Phase 1 implementation** — Once items 1-3 above are resolved, implementation is unblocked. Recommended story execution order: `1.1 → 1.2 → 2.1 → 2.3 → 2.2 → 2.4 → 2.5 → 3.1 → 3.2`

---

### Final Note

This assessment identified **9 issues** across **4 categories** (FR coverage gap, audit design, UX/epic inconsistencies, documentation gaps):

| Severity | Count | Issues |
|----------|:-----:|--------|
| ❌ Must fix before implementation | 1 | FR33 missing story |
| 🟠 Should fix before or during Phase 1 | 2 | Story 2.3 TTY AC; FR20 audit design clarification |
| 🟡 Minor — fix when convenient | 6 | Status phase conflict; `--force` flag; undoc dependencies; epic title; enabler story labels |

**The planning artifacts are of high quality overall.** The PRD-to-architecture-to-UX-to-epic chain is consistent and well-reasoned. The phased delivery strategy is pragmatic for a solo developer. The zero-knowledge constraint is correctly threaded through all layers. The 9 issues found are largely documentation gaps and small clarifications — not fundamental design problems.

---

**Assessment completed:** 2026-03-07
**Issues resolved:** 2026-03-07 (all must-fix and should-fix items addressed in `epics.md`)
**Report file:** `_bmad-output/planning-artifacts/implementation-readiness-report-2026-03-07.md`
**Assessor:** Implementation Readiness Workflow (BMAD BMM)

---

### Resolution Log

| Issue | Resolution | Location |
|-------|-----------|----------|
| FR33 — missing story | Confirmed existing core product capability: `zopp principal create --service` + `zopp permission set --role read` already implemented. Added prerequisites note to Epic 2 description. | `epics.md` Epic 2 prerequisites |
| FR33 — FR Coverage Map | Updated to reference existing core product capability | `epics.md` FR Coverage Map |
| Story 2.3 — missing TTY detection AC | Added GWT acceptance criterion for TTY detection + ASCII fallback | `epics.md` Story 2.3 |
| Story 2.4 — `--force` flag missing from SyncCommonArgs | Added `--force` to SyncCommonArgs AC with description of its purpose | `epics.md` Story 2.4 |
| FR20 — audit log expectation gap | Added explicit note to Epic 2 clarifying the two-sided evidence model (SecretRead events + platform logs). Architecture decision confirmed intentional. | `epics.md` Epic 2 audit note |
| `zopp sync status` phase conflict | Added note to Epic 2 confirming Phase 1 placement is correct. StatusTable built in Phase 1. | `epics.md` Epic 2 status note |
| Epic 6 — undocumented Epic 1 dependency | Added `Depends on: Epic 1` | `epics.md` Epic 6 |
| Epic 8 — undocumented Epic 1 dependency | Added `Depends on: Epic 1` | `epics.md` Epic 8 |

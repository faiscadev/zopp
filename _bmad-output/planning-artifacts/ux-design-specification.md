---
stepsCompleted: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
status: complete
inputDocuments:
  - product-brief-zopp-2026-03-04.md
  - prd.md
  - project-context.md
  - docs/docs/index.md
  - docs/docs/quickstart.md
  - docs/docs/guides/index.md
  - docs/docs/guides/core-concepts.md
  - docs/docs/reference/cli/index.md
  - docs/docs/reference/cli/sync.md
  - docs/docs/reference/cli/run.md
  - docs/docs/reference/configuration.md
  - docs/docs/security/architecture.md
  - docs/docs/installation/index.md
  - docs/docs/self-hosting/index.md
date: '2026-03-04'
author: 'Lucas'
---

# UX Design Specification zopp

**Author:** Lucas
**Date:** 2026-03-04

---

## Executive Summary

### Project Vision

zopp is a CLI-first, zero-knowledge, self-hostable secrets manager whose core product is built and functional. This UX design covers the next wave of features: distribution (curl install script, brew/apt/nix), cloud and PaaS integrations (AWS, GCP, Vercel, Render, Fly, Railway sync), and server deployment templates (Fly, Railway, Docker Compose). The goal is to take zopp from a working tool to one that's easy to install, integrates with real infrastructure, and deploys anywhere — without compromising the zero-knowledge architecture or CLI-first simplicity.

The primary interface remains the CLI. All new sync commands extend the established `zopp sync k8s` pattern. `zopp.toml` project defaults eliminate repetitive flags. The web dashboard exists but is secondary for this wave.

### Target Users

**Sam — The Simplicity Seeker** (Primary for installation & deployment)
Full-stack developer at a 15-person startup. Maintains Vault reluctantly. Wants to install zopp in one command, store a secret in 5 minutes, and never think about secrets infrastructure again. Values speed, low friction, and "it just works" reliability. Will deploy zopp-server on Fly rather than manage a VPS.

**Diana — The Pragmatic CTO** (Primary for cloud sync)
CTO of a 60-person Series A startup. AWS-heavy stack, SOC 2 audit starting. Needs zopp as the single source of truth with automatic sync to AWS and GCP. Evaluates on TCO, setup speed, and integration breadth. Cares about zero-knowledge as a compliance checkbox, not a philosophical position.

**Raj — The Compliance-Driven DevOps Lead** (Primary for PaaS sync)
DevOps lead at a 120-person B2B SaaS company. Deploys across Vercel, Render, and Railway. Needs centralized secret management across PaaS platforms with audit trails for SOC 2. Values consistency, auditability, and the ability to screenshot evidence for compliance reviewers.

**Marco — The Sovereignty-First Engineer** (Secondary — existing core serves him)
Senior DevOps engineer who self-hosts everything. Reads source code, checks licenses. Already well-served by zopp's core. Distribution improvements (brew, nix) and deployment templates benefit him at the margins.

### Key Design Challenges

1. **Consistency across sync targets** — Seven sync targets with different auth methods (kubeconfig, AWS profiles, API tokens) and platform concepts (namespaces, projects, apps, services). The CLI must feel uniform: same flag patterns, same output format, same error structure — despite platform differences underneath.

2. **Error clarity in multi-system operations** — Sync involves zopp and an external platform. Errors must distinguish source (zopp auth failure vs. AWS rate limit vs. invalid Vercel token), identify the specific secret and target, and provide actionable fix instructions. No generic "sync failed" messages.

3. **First-run trust and confidence** — The curl install script is the first experience. Users piping shell from the internet need visible confidence signals: checksum verification, clear progress output, platform detection confirmation, and explicit "what to do next" guidance. The install sets the tone for the entire product relationship.

4. **Progressive complexity** — Sam wants `zopp sync fly` to work with minimal flags. Raj needs `--dry-run`, environment-to-target mapping, sync status monitoring, and audit evidence. The same commands must serve both users without overwhelming beginners or under-serving power users.

### Design Opportunities

1. **The preview-before-act pattern** — `zopp diff <target>` and `--dry-run` create a trust-building UX signature: every outward action can be previewed first. This mirrors `terraform plan` — a pattern the target audience already knows and trusts. Consistency here builds confidence across all sync targets.

2. **`zopp sync status` as single-pane health view** — One command showing the health of all configured sync targets is the "compliance screenshot" Raj needs and the "is everything working" check Sam wants. High UX leverage from a single command.

3. **Install script as brand experience** — Clear, well-formatted output with progress indicators, platform detection, checksum verification, and a guided "next steps" prompt at completion. This is zopp's handshake with every new user.

## Core User Experience

### Defining Experience

zopp's next wave has two core interactions that define its UX:

**The Gateway: Installation**
The curl install script is the single most critical interaction. It's one-time per user but gates all subsequent adoption. Every user journey starts here. The experience must build trust immediately: detect the platform, show what's happening, verify the binary, and guide the user to their first command.

**The Core Loop: Sync**
`zopp sync <target>` is the recurring action that delivers this wave's value. The core loop is: change a secret in zopp → sync outward → verify it landed. This loop must feel reliable and predictable across all seven sync targets. A user who learns one sync command has learned them all.

**The Complement: Deploy**
Server deployment via Fly/Railway/Docker Compose templates is a one-time setup action. It unblocks team adoption by eliminating infrastructure management. The experience should feel as simple as deploying any other web app.

### Platform Strategy

**Primary platform: Terminal (CLI)**
All interactions are keyboard-driven CLI commands producing structured text output. The terminal is the workspace for the target audience — they live here. No GUI is required or planned for sync in this wave.

**Operating systems:** macOS (Intel + Apple Silicon) and Linux (x86_64 + ARM64) are the primary targets. The install script, package managers, and deployment templates all serve these platforms.

**Network model:** Local zopp operations (secret set/get/run) work with the zopp server. Sync operations additionally require connectivity to external platforms (AWS, GCP, PaaS providers). Sync failures due to network issues must be clearly distinguished from auth or permission errors.

**Configuration model:** `zopp.toml` provides project-level defaults (workspace, project, environment). Platform credentials use existing environment conventions (AWS_PROFILE, VERCEL_TOKEN, FLY_API_TOKEN). Sync target mapping is explicit CLI configuration, not automatic discovery.

### Effortless Interactions

1. **Platform auth pickup** — If the user has AWS credentials configured, `zopp sync aws` uses them automatically. Same for GCP ADC, Fly API tokens, Vercel tokens. zopp respects the platform conventions users already have in place.

2. **Flag-free daily use** — With `zopp.toml` defaults set, the daily sync command is just `zopp sync fly` — no workspace, project, or environment flags needed. The common case requires zero ceremony.

3. **Diff-then-sync workflow** — `zopp diff aws` shows exactly what would change. `zopp sync aws` applies it. Same command structure, same flags, predictable pairing. This becomes muscle memory, like `git diff` then `git commit`.

4. **Install-to-first-secret pipeline** — The install script completes and prints "Next: run `zopp join <token> you@email.com` to get started." Each step tells the user what to do next. No dead ends, no "now what?" moments.

### Critical Success Moments

| Moment | User | Experience | UX Signal |
|--------|------|------------|-----------|
| Install completes | Sam | `zopp --version` prints the version | Clear success message with next-step guidance |
| First secret synced | Diana | `zopp sync aws` confirms secrets pushed to AWS | Per-secret confirmation with target path shown |
| All targets healthy | Raj | `zopp sync status` shows green across all platforms | Screenshot-ready status table for compliance |
| Team onboarded | Sam | First teammate joins via invite from Fly-deployed server | Invite flow works end-to-end from PaaS |
| Preview matches apply | All | `zopp diff fly` output matches what `zopp sync fly` actually does | Trust built through predictability |

### Experience Principles

1. **Predictable before powerful** — Every sync command follows the same structure: `zopp sync <target> [flags]`. Same flag names, same output format, same error structure across all targets. A user who learns one sync target already knows them all. Consistency over cleverness.

2. **Preview before act** — Every outward operation has a preview mode. `zopp diff <target>` shows what would change. `--dry-run` simulates execution. Users should never wonder "what will this do?" — the answer is always one flag away. This mirrors `terraform plan`, a pattern the audience trusts.

3. **Fail loud, fix clear** — Errors name the specific target, the specific secret, and the specific failure reason. Every error includes what went wrong and what to do about it. No silent failures, no raw stack traces, no "sync failed" without context. Errors are structured: `[target] [secret] [problem] [fix]`.

4. **Zero-config where possible, explicit where necessary** — Platform credentials use existing environment conventions. `zopp.toml` eliminates repeated flags. But sync target mapping (which zopp environment maps to which platform target) is always explicit user configuration — no magic guessing that could push secrets to the wrong place.

5. **Trust through transparency** — The install script shows what it does. Sync commands show what they changed. Audit logs record every outward push with timestamp, target, and principal. The user can always verify what happened and when.

## Desired Emotional Response

### Primary Emotional Goals

**Quiet confidence** is zopp's primary emotional target. Users should feel *certain* that their secrets are handled correctly — not excited, not delighted, but *assured*. This is infrastructure tooling: the best emotional outcome is that the user stops thinking about it. zopp should feel like a lock on a door — you check it once, you trust it, you move on.

**Secondary emotional goals:**
- **Competence** — users should feel they already know how to use each new command because it follows patterns they've learned
- **Relief** — from the operational burden of alternatives (Vault complexity, SaaS costs, .env insecurity)
- **Professional empowerment** — compliance-driven users should feel equipped to prove their secrets management to any auditor

### Emotional Journey Mapping

| Stage | Target Feeling | Design Implication |
|-------|---------------|-------------------|
| **Discovery** | Curiosity → "this might be simpler" | README and docs lead with simplicity proof: one install command, one secret command, one run command |
| **Installation** | Relief → "that was fast and clean" | Install script completes in seconds with clear progress, no ambiguous output |
| **First secret** | Competence → "I already know this" | CLI follows conventions the audience knows (git-like subcommands, POSIX flags) |
| **First sync** | Satisfaction → "it did exactly what I expected" | Per-secret confirmation output showing source and destination |
| **Error encounter** | Informed control → "I know what to do" | Structured errors: target, secret, problem, fix. No raw stack traces |
| **Daily use** | Invisibility → "I don't think about secrets" | `zopp.toml` defaults + `zopp sync <target>` with no flags. Zero ceremony |
| **Compliance review** | Professional empowerment → "I can prove this" | `zopp sync status` and audit logs provide screenshot-ready evidence |

### Micro-Emotions

**Confidence over confusion** — The dominant emotional axis. Every command output, every error message, every progress indicator should reinforce that the user understands what's happening. Confusion is the primary enemy of trust in a security tool.

**Trust over skepticism** — Built through verifiability, not claims. `zopp diff` before `zopp sync`. Checksums on install. Audit logs for every outward push. Open source code that users can read. Trust is earned through transparency at every interaction.

**Accomplishment over frustration** — Each step in a flow should feel like forward progress. The install prints a success message with next steps. The sync confirms what was pushed and where. The status shows all-green. No dead ends, no ambiguous states.

**Emotions to actively prevent:**
- **Anxiety about wrong-target sync** — pushing secrets to the wrong platform is the nightmare scenario. `--dry-run` and `zopp diff` exist to make this fear unnecessary.
- **Doubt about sync state** — "did it work?" should never be an open question. Every sync ends with explicit per-secret confirmation or explicit per-secret failure.
- **Overwhelm from complexity** — seven sync targets with different auth methods must feel like one consistent pattern, not seven things to learn.

### Design Implications

| Emotional Goal | UX Design Choice |
|---------------|-----------------|
| Quiet confidence | Consistent output format across all commands; no surprises |
| Competence | Follow CLI conventions the audience already knows (git, terraform, kubectl) |
| Relief | Minimal required flags; `zopp.toml` defaults handle the common case |
| Informed control | Structured error format: `[target] [secret] [problem] → [fix]` |
| Trust | Preview mode for every outward action; audit trail for every sync event |
| Invisibility (daily use) | Zero-flag daily commands; no maintenance prompts or update nags |
| Professional empowerment | `zopp sync status` outputs a clean, screenshot-ready status table |

### Emotional Design Principles

1. **Certainty is the product** — In a security tool, the user's emotional state IS the product. If they feel uncertain about what zopp did, the UX has failed regardless of whether the operation succeeded technically.

2. **Silence means success** — For daily operations, the ideal emotional state is not thinking about zopp at all. The tool should be invisible when everything works. Noise should be reserved for things that need attention.

3. **Errors are conversations, not dead ends** — When something goes wrong, the user should feel guided, not abandoned. Every error message is a conversation: "here's what happened, here's why, here's what to do." The emotional goal of error states is informed control, not frustration.

4. **Verify, don't trust (and make it easy)** — zopp's brand promise is "verify, don't trust" for zero-knowledge encryption. This same principle applies to UX: give users the tools to verify every action (`diff`, `--dry-run`, `status`, audit logs) so they never have to take zopp's word for it.

## UX Pattern Analysis & Inspiration

### Inspiring Products Analysis

**git — The foundational CLI mental model**
The `diff` → `commit` → `push` workflow is the pattern zopp mirrors for sync operations. `git status` as a single-pane view of "where am I and what's changed" directly inspires `zopp sync status`. The subcommand grammar (`verb noun [flags]`) is the convention zopp follows. Key lesson: predictable command grammar creates transferable knowledge. Key warning: git's cryptic error messages are the anti-model for zopp.

**terraform — The preview-before-act gold standard**
`terraform plan` → `terraform apply` is the exact UX pattern zopp adopts for `zopp diff` → `zopp sync`. Multi-provider support (AWS, GCP, Azure) with a consistent interface solves the same challenge zopp faces with seven sync targets. Color-coded diff output (green additions, red deletions, yellow changes) is proven to make changes scannable at a glance. Key lesson: plan/preview output builds trust for outward-facing operations. Key warning: avoid introducing stateful complexity (terraform state files) — keep sync stateless from the CLI.

**rustup — The curl-install gold standard**
The `curl | sh` install experience for Rust is the benchmark zopp must match. Platform detection, clear progress indicators, PATH setup guidance, and a success message with explicit next steps. The target audience already trusts this pattern — zopp should feel equally polished. Key lesson: the install script is the first brand impression and must be flawless.

**fly (flyctl) — The PaaS CLI reference**
`fly launch` → `fly deploy` is opinionated, fast, and minimal. Excellent defaults mean most commands need zero flags. Interactive prompts fill in missing context without breaking scriptability. Key lesson: PaaS-style simplicity is achievable for server deployment templates. Key warning: command behavior must not change silently between versions.

### Transferable UX Patterns

**Command Patterns:**
- **Diff-then-apply** (git, terraform) → `zopp diff <target>` then `zopp sync <target>`. Same flags, predictable pairing. The user always knows how to preview before acting.
- **Status as single-pane view** (git status) → `zopp sync status` shows all configured sync targets, their last sync time, success/failure state, and overall health in one command.
- **Consistent multi-provider grammar** (terraform) → All seven sync targets use identical flag patterns. Learning `zopp sync aws` teaches `zopp sync vercel`.
- **`--dry-run` as safety net** (kubectl) → Every sync command supports `--dry-run` for risk-free exploration of what would change.

**Output Patterns:**
- **Color-coded diffs** (terraform plan, git diff) → Green for secrets to add, red for secrets to remove, yellow for secrets to update. Scannable at a glance.
- **Next-step guidance** (rustup) → Every command completion prints what to do next. Install → "run `zopp join`". First workspace → "run `zopp project create`". No dead ends.
- **Header confirmation** (terraform) → Every sync output starts with a header confirming the source (zopp environment) and destination (target platform + path). No ambiguity about what's being synced where.

**Install Patterns:**
- **Platform detection with confirmation** (rustup) → "Detected: macOS aarch64 (Apple Silicon). Downloading zopp v1.2.3..." Show what was detected so the user can verify.
- **Checksum verification** (rustup) → Verify binary integrity before placing in PATH. Print verification result.
- **PATH guidance** (rustup) → If the binary isn't in PATH, explain how to add it for the user's shell.

### Anti-Patterns to Avoid

1. **Cryptic error messages (git)** — "fatal: refusing to merge unrelated histories" teaches the user nothing. Every zopp error must explain what happened, why, and what to do about it. Error format: `Error: [target] [operation] failed — [reason]. Fix: [actionable instruction]`.

2. **Local state complexity (terraform)** — No local state file for sync tracking. The zopp server is the source of truth. Sync operations are stateless from the CLI: read from zopp, push to target, report results. No drift files, no lock files, no state corruption scenarios.

3. **Context confusion (kubectl)** — kubectl users regularly run commands against the wrong cluster because the active context is invisible. zopp must always confirm the sync target in output headers: "Syncing: zopp/mycompany/backend/production → AWS Secrets Manager (us-east-1)". Make the destination impossible to miss.

4. **Silent partial success** — Some tools report "sync complete" when 9 out of 10 secrets synced. zopp must report per-secret results. Partial failures are surfaced individually, not buried in a summary. The exit code must reflect partial failure.

### Design Inspiration Strategy

**Adopt directly:**
- Terraform's plan/apply UX model for `zopp diff` / `zopp sync`
- Rustup's install script experience (platform detection, progress, next-step guidance)
- Git's subcommand grammar and status-as-overview pattern
- Color-coded diff output for scannable sync previews

**Adapt for zopp:**
- Terraform's multi-provider consistency — apply to zopp's seven sync targets but without HCL configuration files. zopp uses CLI flags and `zopp.toml`, not a separate config language.
- Fly's opinionated defaults — apply to deployment templates but with explicit PostgreSQL and TLS configuration rather than magic auto-detection.

**Avoid entirely:**
- Git's cryptic error messages — every zopp error is a conversation with an actionable fix
- Terraform's local state files — sync is stateless from the CLI
- kubectl's invisible context — always confirm the target in output
- Any tool's silent partial success — per-secret reporting, honest exit codes

## Design System Foundation

### Design System Choice

**CLI Output Design Language** — zopp's primary design system is a specification for terminal output: colors, structure, formatting, and interaction patterns applied consistently across all CLI commands. This is the visual language users interact with daily.

**Web Dashboard: Tailwind CSS + DaisyUI** — The existing web UI design system is already established and production-ready. This wave does not introduce new web UI features. Future dashboard extensions (sync status, configuration UI) will inherit the existing DaisyUI component library and Leptos component patterns.

### Rationale for Selection

1. **CLI is the primary interface** — All new features in this wave (install script, sync commands, deployment templates) are CLI interactions. The "design system" must address terminal output, not web components.
2. **Terminal output has no component library** — Unlike web UIs, there's no "Tailwind for terminals." The design system must be a specification document that developers follow when implementing command output.
3. **Consistency is the core UX principle** — The #1 experience principle is "predictable before powerful." A CLI output specification ensures every sync target, every diff, every error message follows the same visual rules.
4. **Web dashboard is stable** — Tailwind CSS + DaisyUI is already chosen, implemented, and working. No changes needed for this wave.

### Implementation Approach

**CLI Output Specification:**

**Color Palette (ANSI terminal colors):**

| Color | Semantic Meaning | Usage |
|-------|-----------------|-------|
| Green (bold) | Success / Addition | Sync confirmation, new secrets, install complete |
| Red (bold) | Error / Removal | Sync failure, deleted secrets, critical errors |
| Yellow | Warning / Change | Modified secrets, non-critical warnings, dry-run notices |
| Cyan | Informational | Headers, target names, metadata |
| White (bold) | Emphasis | Section headers, key names |
| Dim/Gray | Secondary | Timestamps, IDs, supplementary info |

**Output Structure Templates:**

**Sync output:**
```
Syncing: zopp/<workspace>/<project>/<environment> → <Target> (<region/context>)

  ✓ DATABASE_URL          synced
  ✓ API_KEY               synced
  ✗ STRIPE_SECRET         failed — 403 Forbidden
                           Fix: Check API token permissions for write access

Synced: 2/3 secrets | Failed: 1/3 | Target: AWS Secrets Manager (us-east-1)
```

**Diff output:**
```
Diff: zopp/<workspace>/<project>/<environment> → <Target> (<region/context>)

  + NEW_SECRET            (add)
  ~ DATABASE_URL          (update)
  - OLD_SECRET            (remove)

Changes: 1 add, 1 update, 1 remove
```

**Status output:**
```
Sync Status

  Target                    Last Sync           Status
  ─────────────────────────────────────────────────────
  AWS Secrets Manager       2 min ago           ✓ healthy
  Fly (myapp)               15 min ago          ✓ healthy
  Vercel (frontend)         1 hr ago            ⚠ 1 failed

Overall: 2 healthy, 1 warning, 0 errors
```

**Error output:**
```
Error: [aws] sync failed — InvalidAccessKeyId
  The AWS access key ID does not exist.
  Fix: Check AWS_ACCESS_KEY_ID is set correctly, or run `aws configure`.
```

**Install script output:**
```
  zopp installer v1.0

  Detected: macOS aarch64 (Apple Silicon)
  Latest:   zopp v1.2.3

  Downloading... ✓
  Verifying checksum... ✓ (SHA256 matched)
  Installing to /usr/local/bin/zopp... ✓

  zopp v1.2.3 installed successfully!

  Next: Run `zopp join <invite-token> you@email.com` to get started.
  Docs: https://zopp.dev/quickstart
```

**Progress indicators:**
- Spinner (⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏) for in-progress operations
- `✓` (green) for completed steps
- `✗` (red) for failed steps
- `⚠` (yellow) for warnings

### Customization Strategy

**No-color mode:** All output must work without colors when `--no-color` flag is passed or `NO_COLOR` environment variable is set. Structure and symbols (✓, ✗, +, -, ~) convey meaning without relying on color alone.

**Machine-readable output:** All commands support `--json` flag for structured JSON output. This enables scripting, piping to `jq`, and integration with other tools. The human-readable format is the default; JSON is opt-in.

**Terminal width:** Output adapts to terminal width. Tables truncate long values with `...` rather than wrapping. Minimum supported width: 80 columns.

**Verbosity levels:** Default output is concise. `--verbose` adds detail (individual API calls, timing). `--quiet` suppresses everything except errors. These three levels apply uniformly across all commands.

## Defining Interaction

### The Defining Experience

**"I changed a secret in one place and it was everywhere in seconds."**

This is the sentence users will use to describe zopp to peers. The defining experience is the diff-then-sync cycle: preview what will change, apply the changes, see confirmation. One source of truth (zopp), outward push to any platform, verified result.

The power of this experience is its simplicity relative to the alternative. Today, changing a shared secret across AWS, Vercel, and Fly means logging into three dashboards, finding the right project in each, updating the value manually, and hoping you didn't miss one. With zopp: `zopp secret set KEY value` → `zopp sync aws` → `zopp sync fly` → `zopp sync vercel`. Done.

### User Mental Model

**Mental models users bring:**

| Source | Mental Model | How zopp Maps |
|--------|-------------|---------------|
| .env files | "Secrets are key-value pairs in a file" | Same mental model, no file. Values exist in zopp, not on disk |
| git | "Diff shows what changed, push sends it" | `zopp diff aws` → `zopp sync aws` maps directly |
| terraform | "Plan shows impact, apply executes" | Preview-before-act is the same trusted pattern |
| Vault | "Secrets infrastructure is complex" | zopp's defining experience is the absence of this complexity |

**Mental model zopp creates:** "My secrets live in zopp. Everything else just reads from it." This is the single-source-of-truth mental model. Users should think of external platforms (AWS, Vercel, Fly) as downstream consumers, not as places where secrets are managed.

### Success Criteria

1. **Pattern transfer** — A user who has synced to AWS can sync to Vercel without reading docs. The command structure, flags, and output format are identical.
2. **Instant comprehension** — `zopp diff` output is immediately understandable through color, symbols, and counts. No legend needed.
3. **Unambiguous confirmation** — `zopp sync` confirms exactly what happened per-secret. No "sync complete" without details.
4. **Sub-30-second cycle** — The full diff → sync cycle completes in under 30 seconds for environments with up to 100 secrets.
5. **Self-service errors** — A user who encounters a sync error knows what to do from the error message alone, without searching docs or Stack Overflow.

### Pattern Analysis

**100% established patterns, novel combination.** The diff-then-apply pattern (terraform), subcommand grammar (git), per-item status reporting (cargo build), color-coded diffs (git diff) — all deeply familiar to the target audience. No user education is needed for the interaction patterns.

The innovation is not in the interaction design but in what it enables: zero-knowledge encrypted secrets synced to multiple heterogeneous platforms with one consistent CLI experience. The UX challenge is consistency across platforms, not novelty of interaction.

### Experience Mechanics

**The diff-then-sync cycle (detailed):**

**1. Initiation — Preview**
```
$ zopp diff aws
```
User initiates by requesting a preview. This is the safe entry point — nothing changes.

**2. Processing — Compare**
CLI fetches secrets from zopp (encrypted), decrypts client-side, fetches current state from target platform, computes diff. Progress spinner shown during network operations.

**3. Feedback — Diff Output**
```
Diff: zopp/acme/backend/production → AWS Secrets Manager (us-east-1)

  + NEW_API_KEY          (add)
  ~ DATABASE_URL         (update)
  - DEPRECATED_TOKEN     (remove)

Changes: 1 add, 1 update, 1 remove
```
Color-coded, symbol-prefixed, with header confirming source → destination. Summary line provides at-a-glance count.

**4. Decision — User Reviews**
User reads the diff. If it matches expectations, they proceed. If not, they adjust secrets in zopp first. The diff is a checkpoint, not a commitment.

**5. Execution — Sync**
```
$ zopp sync aws
```
User applies the changes. CLI performs the same fetch-decrypt-compare cycle, then pushes changes to the target platform.

**6. Confirmation — Per-Secret Results**
```
Syncing: zopp/acme/backend/production → AWS Secrets Manager (us-east-1)

  ✓ NEW_API_KEY          added
  ✓ DATABASE_URL         updated
  ✓ DEPRECATED_TOKEN     removed

Synced: 3/3 secrets | Target: AWS Secrets Manager (us-east-1)
```
Every secret gets an individual result. Summary confirms total. Exit code reflects success (0), partial failure (1), or total failure (2).

**7. Completion — Self-Contained**
The operation is complete. No follow-up action required. The audit log records the sync event automatically. If errors occurred, each failed secret includes its own fix instruction.

## Visual Design Foundation

### Design Direction: Amber Terminal

**Established visual identity from `.interface-design/system.md`.** Industrial precision — cold neutrals with amber signal color. Like server equipment LEDs against steel. A serious cryptographic tool that happens to be beautiful.

This direction governs both the web dashboard and, philosophically, the CLI output. The same principles apply: amber communicates action and attention. Gray builds structure. Restraint is the aesthetic.

### Color System

**Web Dashboard (established):**

Dual-theme system respecting `prefers-color-scheme`. CSS custom properties with domain-specific token naming:
- `--vault-*` — surface colors (base, surface-100/200/300, inset)
- `--cipher-*` — text hierarchy (text, secondary, muted, faint)
- `--terminal-*` — borders (subtle, default, strong, focus)
- `--amber` — signal color, used sparingly for actions, focus states, and key data

| Semantic | Light | Dark |
|----------|-------|------|
| Amber accent | `#d97706` | `#f59e0b` |
| Success | `#059669` | `#34d399` |
| Warning | `#d97706` | `#fbbf24` |
| Error | `#dc2626` | `#f87171` |
| Info | `#2563eb` | `#60a5fa` |

**CLI Output (mapped from Amber Terminal):**

The CLI color palette mirrors the web semantic colors using ANSI equivalents:

| ANSI Color | Maps To | CLI Usage |
|------------|---------|-----------|
| Yellow/Bold | Amber accent | Key emphasis, secret names, warnings |
| Green/Bold | Success | ✓ marks, sync confirmations, additions |
| Red/Bold | Error | ✗ marks, sync failures, removals |
| Cyan | Info | Headers, target names, metadata |
| White/Bold | Cipher-text | Section headers, emphasis |
| Dim | Cipher-muted | Timestamps, IDs, secondary info |

The amber-as-signal philosophy translates: in the terminal, yellow/bold is the attention color used for key names and warnings — not for decoration.

### Typography System

**Web Dashboard:**
- Sans: `Inter`, `-apple-system`, `BlinkMacSystemFont`, sans-serif
- Mono: `JetBrains Mono`, `Fira Code`, `SF Mono`, monospace
- All secret values, keys, IDs, timestamps: monospace
- Data alignment: `font-variant-numeric: tabular-nums`
- Scale: 24px (page title) → 18px (section) → 16px (card) → 14px (body) → 13px (label/data) → 12px (caption)

**CLI Output:**
- Terminal renders in the user's configured monospace font — no font control from zopp
- Visual hierarchy through: bold weight, color, indentation, and whitespace
- All output is monospace by nature — use alignment and column spacing for structure

### Spacing & Layout Foundation

**Web Dashboard:**
- Base unit: 4px
- Cards: 16px padding, 6px border-radius
- Page content: 32px horizontal margins
- Depth: borders only, no shadows ("This is a terminal-inspired interface")
- Border radius max: 8px for containers (technical feel = sharper corners)

**CLI Output:**
- 2-space indentation for nested items
- Consistent column alignment across all table-style output
- Single blank line between sections
- No decorative borders or box-drawing characters — whitespace and indentation create structure
- Minimum supported width: 80 columns

### Accessibility Considerations

**Web Dashboard:**
- Both light and dark themes are equal citizens
- Amber focus ring (2px box-shadow) for keyboard navigation
- Semantic colors have muted variants for backgrounds (sufficient contrast)
- Interactive elements have hover, focus, active, and disabled states

**CLI Output:**
- `NO_COLOR` environment variable support — all output meaningful without color
- Symbols (✓, ✗, ⚠, +, -, ~) carry meaning independently of color
- `--no-color` flag as explicit override
- `--json` flag for machine-readable output (screen readers, scripting)
- No reliance on emoji — ASCII/Unicode symbols only

### Unified Design Principles

1. **Amber is signal, not decoration** — In both web and CLI, amber/yellow draws attention to what matters: actions, warnings, key data. It's never used for backgrounds or structural elements.
2. **Borders over shadows** — The web dashboard uses border separation exclusively. The CLI uses whitespace and indentation. Both avoid visual weight that doesn't communicate.
3. **Monospace for data** — Secret values, keys, IDs, and timestamps are always monospace in both interfaces. This is a data-centric tool; the typography reflects it.
4. **Restraint is the aesthetic** — No bounce animations, no decorative emoji, no gratuitous color. Every visual element earns its place by communicating something. "This is a serious tool."

## Design Direction Decision

### Design Directions Explored

The visual direction for zopp is established across two interfaces:

1. **Web Dashboard: Amber Terminal** — Defined in `.interface-design/system.md`. Cold slate neutrals with amber signal color. Borders-only depth. Inter + JetBrains Mono typography. Full light/dark theme support. Already implemented in the Leptos web UI with Tailwind CSS custom theme.

2. **CLI Output: Clean Terminal** — Minimal, aligned, symbol-driven output. Whitespace creates hierarchy, symbols (✓, ✗, ⚠, +, -, ~) carry meaning independently of color, and every output confirms source → destination in its header.

No alternative directions were explored because: (a) the web design system is already established and in production, and (b) the CLI output style follows directly from the experience principles (predictable, preview-before-act, fail loud) and the Amber Terminal aesthetic philosophy (restraint, precision, signal-not-decoration).

### Chosen Direction

**Clean Terminal** for all CLI output in this wave. Characteristics:

- **Header-first** — every sync/diff output starts with a header line confirming the operation and its source → destination
- **Per-item results** — individual ✓/✗ for each secret, never a blanket "success"
- **Summary line** — counts and target confirmation at the end of every operation
- **Structured errors** — problem statement, explanation, fix instruction, docs link
- **No decoration** — no box-drawing characters, no emoji, no ASCII art. Whitespace and indentation only.

### CLI Output Reference Mockups

**Install script:**
```
  zopp installer v1.0

  Platform:  macOS aarch64 (Apple Silicon)
  Version:   v1.2.3
  Binary:    zopp, zopp-server

  Downloading zopp...          ✓
  Downloading zopp-server...   ✓
  Verifying checksums...       ✓ SHA256 matched
  Installing to /usr/local/bin ✓

  ✓ zopp v1.2.3 installed successfully

  Get started:
    zopp-server serve              Start a local server
    zopp join <token> you@email    Join the server
    zopp --help                    See all commands

  Docs: https://zopp.dev/quickstart
```

**Sync (success):**
```
Syncing zopp/acme/backend/production → AWS Secrets Manager (us-east-1)

  ✓ DATABASE_URL        synced
  ✓ API_KEY             synced
  ✓ STRIPE_SECRET       synced

✓ 3/3 secrets synced to AWS Secrets Manager (us-east-1)
```

**Sync (partial failure):**
```
Syncing zopp/acme/backend/production → AWS Secrets Manager (us-east-1)

  ✓ DATABASE_URL        synced
  ✓ API_KEY             synced
  ✗ STRIPE_SECRET       AccessDeniedException
                         Fix: IAM role needs secretsmanager:PutSecretValue permission

⚠ 2/3 secrets synced, 1 failed | Target: AWS Secrets Manager (us-east-1)
```

**Diff:**
```
Diff: zopp/acme/backend/production → AWS Secrets Manager (us-east-1)

  + NEW_API_KEY         add
  ~ DATABASE_URL        update
  - OLD_TOKEN           remove

3 changes: 1 add, 1 update, 1 remove
```

**Status:**
```
Sync Status

  Target                     Last Sync          Result
  ──────────────────────────────────────────────────────
  AWS Secrets Manager        2m ago             ✓ 12/12
  Fly (myapp-prod)           18m ago            ✓ 8/8
  Vercel (frontend)          1h ago             ⚠ 5/6

2 healthy, 1 warning
```

**Error (credentials missing):**
```
Error: AWS credentials not found

  zopp looked for AWS credentials in:
    1. AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY environment variables
    2. AWS_PROFILE environment variable
    3. ~/.aws/credentials default profile

  Fix: Set AWS credentials using any of the methods above.
  Docs: https://zopp.dev/guides/sync/aws
```

**No changes:**
```
Diff: zopp/acme/backend/production → Fly (myapp-prod)

  No changes. Target is in sync.
```

### Design Rationale

1. **Consistency with Amber Terminal philosophy** — The CLI output applies the same principles as the web dashboard: restraint, precision, and signal-not-decoration. Amber/yellow is used for emphasis and warnings. Green for success. Red for failure.
2. **Audience familiarity** — The output style follows conventions from git, terraform, and cargo that the target audience uses daily. No learning curve for reading output.
3. **Scriptability** — Clean, predictable output structure with `--json` alternative enables automation. Exit codes (0 = success, 1 = partial failure, 2 = total failure) follow POSIX conventions.
4. **Accessibility** — Symbols carry meaning without color. `NO_COLOR` and `--no-color` disable ANSI codes. Structure is preserved in plain text.

## User Journey Flows

### Journey 1: Install & First Use (Sam)

**Goal:** From zero to first encrypted secret in under 5 minutes.

```mermaid
flowchart TD
    A[Sam runs curl install script] --> B{Platform detected?}
    B -->|Yes| C[Download correct binary]
    B -->|No| D[Error: Unsupported platform]
    D --> E[Show supported platforms + cargo install fallback]
    C --> F{Checksum valid?}
    F -->|Yes| G[Install to PATH]
    F -->|No| H[Error: Checksum mismatch, retry or manual download]
    G --> I[Print success + next steps]
    I --> J[Sam runs: zopp join token email]
    J --> K{Server reachable?}
    K -->|Yes| L[Principal created, keys generated]
    K -->|No| M[Error: Connection refused + fix instructions]
    L --> N[Sam runs: zopp workspace create mycompany]
    N --> O[Workspace + KEK created]
    O --> P[Sam runs: zopp project create backend]
    P --> Q[Sam runs: zopp environment create dev]
    Q --> R[Environment + DEK created]
    R --> S[Sam runs: zopp secret set DB_URL value]
    S --> T[Secret encrypted client-side, stored]
    T --> U[Sam runs: zopp run -- npm start]
    U --> V[✓ App starts with secrets injected]
```

**Step-by-step CLI flow:**
```
# Step 1: Install (30 seconds)
$ curl -fsSL https://get.zopp.dev | sh
  ✓ zopp v1.2.3 installed successfully
  Get started: zopp join <token> you@email

# Step 2: Join server (10 seconds)
$ zopp join inv_abc123 sam@startup.com
  ✓ Registered as sam@startup.com
  ✓ Principal 'sams-macbook' created

# Step 3: Create workspace (10 seconds)
$ zopp workspace create startup
  ✓ Workspace 'startup' created

# Step 4: Create project + environment (20 seconds)
$ zopp project create backend -w startup
  ✓ Project 'backend' created
$ zopp environment create development -w startup -p backend
  ✓ Environment 'development' created

# Step 5: Configure defaults (10 seconds)
$ cat > zopp.toml << 'EOF'
[defaults]
workspace = "startup"
project = "backend"
environment = "development"
EOF

# Step 6: First secret (10 seconds)
$ zopp secret set DATABASE_URL "postgresql://user:pass@localhost/db"
  ✓ Secret 'DATABASE_URL' set

# Step 7: The "aha" moment (5 seconds)
$ zopp run -- npm start
  # App boots with DATABASE_URL injected. No .env file.
```

**Total elapsed: ~2 minutes.** Well under the 5-minute target.

**Error recovery points:**
- Install fails → show cargo install fallback + GitHub releases link
- Server unreachable → show how to check server URL, common causes (port, TLS)
- Join fails (invalid token) → explain token format, suggest getting new token from admin

---

### Journey 2: Cloud Sync Setup (Diana)

**Goal:** zopp becomes the single source of truth with automatic sync to AWS.

**Prerequisite:** zopp is already in use, secrets are managed in zopp.

```mermaid
flowchart TD
    A[Diana's team has secrets in zopp] --> B[DevOps runs: zopp diff aws]
    B --> C{AWS credentials found?}
    C -->|No| D[Error: AWS credentials not found + fix]
    C -->|Yes| E{First sync to this target?}
    E -->|Yes| F[Show all secrets as additions]
    E -->|No| G[Show diff: adds, updates, removes]
    F --> H[DevOps reviews diff output]
    G --> H
    H --> I{Changes look correct?}
    I -->|No| J[Adjust secrets in zopp first]
    J --> B
    I -->|Yes| K[DevOps runs: zopp sync aws]
    K --> L[Per-secret results displayed]
    L --> M{All synced?}
    M -->|Yes| N[✓ Summary: X/X secrets synced]
    M -->|No| O[⚠ Summary: X/Y synced, Z failed + per-secret fix]
    O --> P[Fix issues, re-run sync]
    N --> Q[DevOps runs: zopp sync status]
    Q --> R[Status shows AWS healthy]
```

**Step-by-step CLI flow:**
```
# Step 1: Preview what would sync (safe, read-only)
$ zopp diff aws --region us-east-1 --prefix /prod/backend/
Diff: zopp/acme/backend/production → AWS Secrets Manager (us-east-1)

  + DATABASE_URL        add
  + API_KEY             add
  + STRIPE_SECRET       add
  + REDIS_URL           add

4 changes: 4 add, 0 update, 0 remove

# Step 2: Apply the sync
$ zopp sync aws --region us-east-1 --prefix /prod/backend/
Syncing zopp/acme/backend/production → AWS Secrets Manager (us-east-1)

  ✓ DATABASE_URL        synced
  ✓ API_KEY             synced
  ✓ STRIPE_SECRET       synced
  ✓ REDIS_URL           synced

✓ 4/4 secrets synced to AWS Secrets Manager (us-east-1)

# Step 3: Verify health
$ zopp sync status
Sync Status

  Target                     Last Sync          Result
  ──────────────────────────────────────────────────────
  AWS Secrets Manager        just now           ✓ 4/4

1 healthy

# Later: Update a secret, re-sync
$ zopp secret set DATABASE_URL "postgresql://new-host/db"
  ✓ Secret 'DATABASE_URL' updated

$ zopp diff aws --region us-east-1 --prefix /prod/backend/
Diff: zopp/acme/backend/production → AWS Secrets Manager (us-east-1)

  ~ DATABASE_URL        update

1 change: 0 add, 1 update, 0 remove

$ zopp sync aws --region us-east-1 --prefix /prod/backend/
  ✓ DATABASE_URL        synced
✓ 1/1 secrets synced to AWS Secrets Manager (us-east-1)
```

**Error recovery points:**
- AWS credentials missing → list all credential sources checked, link to AWS docs
- IAM permission denied → name the specific missing permission
- Rate limited → automatic backoff with progress indicator, no user action needed
- Partial failure → per-secret error with fix, successful secrets are not rolled back

---

### Journey 3: PaaS Multi-Platform Sync (Raj)

**Goal:** Centralize secrets across Vercel, Render, and Railway with audit trail.

```mermaid
flowchart TD
    A[Raj has secrets in zopp for 3 platforms] --> B[Set platform tokens as env vars]
    B --> C[zopp diff vercel --project frontend]
    C --> D[Review Vercel diff]
    D --> E[zopp diff render --service api]
    E --> F[Review Render diff]
    F --> G[zopp diff railway --service workers]
    G --> H[Review Railway diff]
    H --> I{All diffs look correct?}
    I -->|Yes| J[zopp sync vercel --project frontend]
    J --> K[zopp sync render --service api]
    K --> L[zopp sync railway --service workers]
    L --> M[zopp sync status]
    M --> N[Screenshot status for compliance]
    I -->|No| O[Adjust secrets, re-diff]
    O --> C
```

**Step-by-step CLI flow:**
```
# Prerequisites: Platform tokens in environment
$ export VERCEL_TOKEN=tok_xxx
$ export RENDER_API_KEY=rnd_xxx
$ export RAILWAY_TOKEN=xxx

# Step 1: Preview all three targets
$ zopp diff vercel --project frontend -e production
Diff: zopp/acme/frontend/production → Vercel (frontend)
  ~ STRIPE_KEY          update
1 change: 0 add, 1 update, 0 remove

$ zopp diff render --service api -e production
Diff: zopp/acme/api/production → Render (api)
  ~ STRIPE_KEY          update
1 change: 0 add, 1 update, 0 remove

$ zopp diff railway --service workers -e production
Diff: zopp/acme/workers/production → Railway (workers)
  ~ STRIPE_KEY          update
1 change: 0 add, 1 update, 0 remove

# Step 2: Sync all three
$ zopp sync vercel --project frontend -e production
  ✓ STRIPE_KEY          synced
✓ 1/1 secrets synced to Vercel (frontend)

$ zopp sync render --service api -e production
  ✓ STRIPE_KEY          synced
✓ 1/1 secrets synced to Render (api)

$ zopp sync railway --service workers -e production
  ✓ STRIPE_KEY          synced
✓ 1/1 secrets synced to Railway (workers)

# Step 3: Compliance evidence
$ zopp sync status
Sync Status

  Target                     Last Sync          Result
  ──────────────────────────────────────────────────────
  Vercel (frontend)          just now           ✓ 12/12
  Render (api)               just now           ✓ 8/8
  Railway (workers)          just now           ✓ 5/5

3 healthy
```

---

### Journey 4: PaaS Server Deploy (Sam)

**Goal:** Deploy zopp-server on Fly so the team has a shared server without managing infrastructure.

```mermaid
flowchart TD
    A[Sam wants shared server] --> B[Download fly.toml template]
    B --> C[fly launch with template]
    C --> D[Fly provisions app + Postgres]
    D --> E[Automatic TLS via Fly]
    E --> F[Server is live at app.fly.dev]
    F --> G[Generate invite: fly ssh console]
    G --> H[Share invite with team on Slack]
    H --> I[Teammates run: zopp join token email]
    I --> J[Team is onboarded]
    J --> K[Sam never SSHs into server again]
```

**Step-by-step CLI flow:**
```
# Step 1: Get the template
$ curl -fsSL https://raw.githubusercontent.com/faiscadev/zopp/main/deploy/fly/fly.toml -o fly.toml

# Step 2: Launch on Fly
$ fly launch --copy-config
  # Fly detects fly.toml, provisions app + Postgres addon
  # Automatic TLS on <appname>.fly.dev

# Step 3: Generate first invite
$ fly ssh console -C "zopp-server invite create --expires-hours 48"
  inv_7f8a9b2c...

# Step 4: Share invite, team joins
$ zopp --server https://zopp-startup.fly.dev join inv_7f8a9b2c sam@startup.com
  ✓ Registered as sam@startup.com
  ✓ Principal 'sams-macbook' created

# Step 5: Done. Server runs on Fly. Zero maintenance.
```

---

### Journey Patterns

**Pattern 1: Preview-then-execute**
Every outward operation follows the same two-step pattern:
1. `zopp diff <target> [flags]` — safe, read-only preview
2. `zopp sync <target> [flags]` — apply changes

Same flags, same output format, predictable pairing across all targets.

**Pattern 2: Structured error recovery**
Every error follows the same format:
1. What happened (error name)
2. Why (explanation)
3. How to fix (actionable instruction)
4. Where to learn more (docs link)

Users never see a raw error without a fix path.

**Pattern 3: Status as checkpoint**
After any sync operation, `zopp sync status` provides a single-pane view of all targets. This serves dual purpose: operational health check and compliance evidence.

### Flow Optimization Principles

1. **Shortest path to value** — Install journey is 7 steps, ~2 minutes. Each step has exactly one command. No configuration wizards, no interactive prompts blocking the flow.
2. **Safe defaults** — `zopp diff` is always safe to run (read-only). The user builds confidence with previews before committing to sync. No destructive default behaviors.
3. **Independent target operations** — Each sync target is independent. Failing to sync to AWS doesn't block syncing to Vercel. Users can fix issues per-target without re-running everything.
4. **No hidden state** — Every command shows its full context in the output header. The user always knows which zopp environment maps to which external target.

## Component Strategy

### Design System Components

**Web Dashboard (established — no new components this wave):**

The Amber Terminal design system provides all web UI components needed: buttons (primary/amber, secondary/ghost, destructive), cards with border-only depth, inputs (standard + monospace for secrets), secrets display with reveal interaction, tables, badges, modals, and sidebar navigation.

No new web components are needed for this wave. If sync status surfaces in the dashboard later, it uses the existing table and badge components.

### CLI Output Components

The CLI has its own "component library" — reusable output patterns that every command implementation must follow:

**Component 1: Operation Header**
```
<Verb>: zopp/<workspace>/<project>/<environment> → <Target> (<context>)
```
Purpose: Confirms source and destination before any output. Prevents context confusion.
Variants: `Syncing:`, `Diff:`, `Deleting:` (verb changes, structure identical).

**Component 2: Per-Item Result Line**
```
  ✓ SECRET_NAME         <action>
  ✗ SECRET_NAME         <error>
                         Fix: <instruction>
```
Purpose: Shows the result for each individual secret.
States: Success (✓ green), failure (✗ red), addition (+ green), update (~ yellow), removal (- red).
Rules: Secret name left-aligned, padded to consistent column width. Fix instruction indented on next line.

**Component 3: Summary Line**
```
✓ 3/3 secrets synced to <Target> (<context>)
⚠ 2/3 secrets synced, 1 failed | Target: <Target> (<context>)
```
Purpose: At-a-glance result of the entire operation.
States: All success (✓ green), partial failure (⚠ yellow), total failure (✗ red).

**Component 4: Diff Summary**
```
3 changes: 1 add, 1 update, 1 remove
```
or
```
No changes. Target is in sync.
```
Purpose: Summarizes the diff at a glance.

**Component 5: Status Table**
```
  Target                     Last Sync          Result
  ──────────────────────────────────────────────────────
  <Target Name>              <time ago>         ✓ <count>
```
Purpose: Single-pane view of all configured sync targets.

**Component 6: Error Block**
```
Error: <context> — <problem>

  <explanation>

  Fix: <actionable instruction>
  Docs: <url>
```
Purpose: Structured error that guides the user to resolution. No raw stack traces.

**Component 7: Install Progress**
```
  <step description>...    ✓
  <step description>...    ✓ <detail>
```
Purpose: Step-by-step progress during install script execution.

**Component 8: Next Steps Block**
```
  Get started:
    <command>                  <description>
    <command>                  <description>
```
Purpose: Guides the user to their next action after a completed operation.

### Component Implementation Strategy

**For CLI components:**
- Each component is a Rust formatting function in a shared output module
- All components respect `--no-color` / `NO_COLOR` — symbols carry meaning without color
- All components have a `--json` alternative that outputs structured JSON
- Column widths auto-adjust based on content, with a minimum of 80 columns
- Components are unit-tested: given inputs, assert exact output strings

**For web dashboard:**
- No new components this wave
- Future sync status page reuses existing table + badge components
- Component specifications live in `.interface-design/system.md`

### Implementation Roadmap

**Phase 1 (curl install + AWS sync + Fly):**
All 7 CLI output components built — they're the foundation every sync target uses:
Operation Header, Per-Item Result Line, Summary Line, Diff Summary, Error Block, Install Progress, Next Steps Block.

**Phase 2 (GCP + Vercel + Render + brew):**
Status Table component added (enables `zopp sync status` once multiple targets exist). All Phase 1 components reused as-is for new sync targets.

**Phase 3 (Railway + apt + nix + Docker Compose):**
No new components — all patterns established in Phase 1-2. Only new sync target implementations using existing components.

## UX Consistency Patterns

### Command Output Patterns

**Pattern: Confirmation on mutation**
Every command that changes state (set, sync, create, delete) outputs an explicit confirmation line. Read-only commands (get, list, diff, status) output data without preamble.

```
# Mutation → confirmation
$ zopp secret set API_KEY "value"
  ✓ Secret 'API_KEY' set

# Read → data only
$ zopp secret get API_KEY
postgresql://user:pass@localhost/db
```

**Pattern: Plural-aware output**
List commands adapt output to result count:
```
# Zero results
$ zopp secret list
No secrets found in acme/backend/development.

# One or more results
$ zopp secret list
DATABASE_URL
API_KEY
STRIPE_SECRET
```

**Pattern: Destructive operation warning**
Commands that remove data require `--force` or show a confirmation prompt:
```
$ zopp environment delete production
  This will delete environment 'production' and all 12 secrets in it.
  This action cannot be undone.

  To confirm, run: zopp environment delete production --force
```

### Feedback Patterns

**Success feedback:**
Single-line with ✓ symbol. Green when color is available. Includes the entity name.
```
  ✓ Workspace 'acme' created
  ✓ Secret 'API_KEY' set
  ✓ 3/3 secrets synced to AWS Secrets Manager (us-east-1)
```

**Warning feedback:**
⚠ symbol, yellow. Used for partial success or non-critical issues.
```
  ⚠ 2/3 secrets synced, 1 failed | Target: AWS Secrets Manager (us-east-1)
  ⚠ zopp.toml not found — using command-line flags
```

**Error feedback:**
Uses the Error Block component. Always structured: context, problem, fix, docs.
```
Error: [aws] sync failed — InvalidAccessKeyId
  The AWS access key ID does not exist.
  Fix: Check AWS_ACCESS_KEY_ID is set correctly, or run `aws configure`.
  Docs: https://zopp.dev/guides/sync/aws
```

**Info feedback:**
Dim/gray text for supplementary information that doesn't require action.
```
  Using workspace 'acme' from zopp.toml
  Using AWS profile 'default'
```

### Flag Consistency Patterns

**Pattern: Universal flags across all commands**
```
-w, --workspace <NAME>     Workspace (overrides zopp.toml)
-p, --project <NAME>       Project (overrides zopp.toml)
-e, --environment <NAME>   Environment (overrides zopp.toml)
    --json                 Output as JSON
    --no-color             Disable colored output
    --verbose              Verbose output
    --quiet                Suppress non-error output
-h, --help                 Show help
```

**Pattern: Sync-specific flags (consistent across all targets)**
```
    --dry-run              Show what would change without applying
    --force                Force sync even if target not managed by zopp
```

**Pattern: Target-specific flags (named for the platform's convention)**
```
# AWS uses AWS terminology
--region <REGION>          AWS region
--prefix <PATH>            Secret name prefix in AWS

# Fly uses Fly terminology
--app <APP>                Fly app name

# Vercel uses Vercel terminology
--project <PROJECT>        Vercel project name
--team <TEAM>              Vercel team (optional)

# Render uses Render terminology
--service <SERVICE>        Render service name
```

### Navigation Patterns

**Pattern: Help as discovery**
`--help` on any command shows subcommands with one-line descriptions. Users discover features by exploring the command tree.
```
$ zopp sync --help
Sync secrets to external systems

Usage: zopp sync <COMMAND>

Commands:
  k8s       Sync to Kubernetes Secret
  aws       Sync to AWS Secrets Manager
  fly       Sync to Fly secrets
  status    Show sync health for all targets
  help      Print help for a subcommand
```

**Pattern: Config file as implicit context**
zopp.toml provides implicit context. When used, a dim info line confirms which defaults are active:
```
$ zopp secret list
  Using workspace 'acme', project 'backend', environment 'development' from zopp.toml
DATABASE_URL
API_KEY
```

**Pattern: Explicit over implicit for targets**
Unlike workspace/project/environment (which can default from zopp.toml), sync target details are always explicit CLI flags. No auto-discovery of AWS regions or Fly apps — too risky for a security tool.

### Exit Code Patterns

Consistent exit codes across all commands for scriptability:

| Exit Code | Meaning | Usage |
|-----------|---------|-------|
| 0 | Success | All operations completed successfully |
| 1 | Partial failure | Some operations succeeded, some failed |
| 2 | Total failure | No operations succeeded |
| 3 | Configuration error | Missing credentials, invalid config, bad flags |
| 4 | Connection error | Server unreachable, network failure |

### JSON Output Pattern

Every command supports `--json` for machine-readable output. The JSON structure mirrors the human-readable output:

```json
{
  "command": "sync",
  "target": "aws",
  "source": "zopp/acme/backend/production",
  "destination": "AWS Secrets Manager (us-east-1)",
  "results": [
    {"key": "DATABASE_URL", "status": "synced"},
    {"key": "API_KEY", "status": "synced"},
    {"key": "STRIPE_SECRET", "status": "failed", "error": "AccessDeniedException", "fix": "IAM role needs secretsmanager:PutSecretValue permission"}
  ],
  "summary": {"total": 3, "synced": 2, "failed": 1}
}
```

## Responsive Design & Accessibility

### Responsive Strategy

**CLI: Terminal Width Adaptation**

The CLI is the primary interface. "Responsive" means adapting to terminal width, not screen size:

- **80 columns (minimum)** — All output must be readable at 80 columns. Column-aligned output (Status Table, Per-Item Result Lines) wraps gracefully. Error Block text reflows. This is the reference width for all mockups and tests.
- **120+ columns (wide terminal)** — Status Table and diff output may use additional padding for readability. No additional data surfaces — wider terminals get breathing room, not more content.
- **Pipe/redirect detection** — When stdout is not a TTY (piped to another command or redirected to a file), output strips ANSI codes, drops progress indicators, and uses plain ASCII symbols (`[ok]` instead of `✓`). This ensures `zopp diff aws | less` and `zopp sync status > report.txt` work correctly.

**Web Dashboard: Amber Terminal Responsive Approach**

The web dashboard is a complement interface — it provides visual parity, not mobile workflows. Strategy: **desktop-first, graceful degradation.**

- **Desktop (1024px+)** — Full layout: sidebar navigation + main content area. This is the primary web experience. Tables, secrets lists, and audit logs use the full width.
- **Tablet (768px–1023px)** — Sidebar collapses to icon-only rail or hamburger toggle. Content area takes full width. Tables remain usable but may horizontally scroll for wide audit log entries.
- **Mobile (320px–767px)** — Sidebar becomes hamburger overlay. Tables transform to card-based layouts for secrets and audit entries. Functional but not optimized — the CLI is the mobile-bandwidth interface.

Rationale: DevOps engineers managing secrets are at their workstations. The dashboard exists for visual overview and team onboarding, not mobile secret management. Investing heavily in mobile-optimized layouts would be premature.

### Breakpoint Strategy

**Web Dashboard Breakpoints (Tailwind defaults):**

| Breakpoint | Width | Layout Behavior |
|------------|-------|----------------|
| `sm` | 640px | Card layouts for tables, stacked forms |
| `md` | 768px | Sidebar rail, two-column forms |
| `lg` | 1024px | Full sidebar, tabular layouts |
| `xl` | 1280px | Max content width, extra padding |

Approach: Desktop-first with `max-width` overrides for smaller sizes, matching the Amber Terminal design system's existing implementation.

**CLI "Breakpoints" (terminal width thresholds):**

| Width | Behavior |
|-------|----------|
| < 60 cols | Minimal: truncate long secret names, drop table alignment |
| 60–79 cols | Compact: shorter column padding, abbreviated target names |
| 80+ cols | Standard: full output as designed |
| 120+ cols | Comfortable: extra padding, no additional information |

Detection: `terminal_size` crate on startup. Default to 80 if detection fails (pipe, unknown terminal).

### Accessibility Strategy

**Target: WCAG 2.1 AA for the web dashboard.** This is the industry standard and sufficient for zopp's audience.

**CLI Accessibility (primary interface):**

1. **`NO_COLOR` / `--no-color` standard** — Full compliance with [no-color.org](https://no-color.org). When `NO_COLOR` is set or `--no-color` is passed, all ANSI escape codes are suppressed. Already defined in the Component Strategy — enforced at the output formatting layer, not per-command.

2. **Symbol-based semantics** — Meaning is never conveyed by color alone. The symbols carry the state:
   - `✓` = success (green is enhancement, not requirement)
   - `✗` = failure (red is enhancement)
   - `⚠` = warning (yellow is enhancement)
   - `+` / `~` / `-` = add / update / remove in diffs
   - These symbols are distinct even in monochrome terminals and screen readers

3. **`--json` as universal accessibility escape hatch** — Every command supports `--json`. Screen readers, custom scripts, and assistive tooling can parse structured JSON instead of formatted terminal output. This is more accessible than trying to make ANSI-formatted CLI output screen-reader-friendly.

4. **Plain ASCII fallback** — When output is piped (non-TTY), Unicode symbols downgrade to ASCII: `✓` → `[ok]`, `✗` → `[FAIL]`, `⚠` → `[WARN]`, `+` / `~` / `-` remain as-is. This ensures compatibility with terminals that don't support Unicode and with log aggregation tools.

5. **Descriptive error messages** — Error Block component uses full sentences, not codes. A screen reader reading "Error: aws sync failed — InvalidAccessKeyId. The AWS access key ID does not exist. Fix: Check AWS_ACCESS_KEY_ID is set correctly" conveys full meaning without visual context.

**Web Dashboard Accessibility (complement interface):**

1. **Color contrast** — The Amber Terminal design system specifies `--cipher-primary` (foreground) against `--vault-base` (background). Both light and dark themes must meet 4.5:1 contrast ratio for normal text, 3:1 for large text. The amber accent (`#E6A817` / `#D4990A`) against dark backgrounds needs verification — amber on dark slate may need brightness adjustment for AA compliance.

2. **Keyboard navigation** — All interactive elements (buttons, inputs, sidebar links, table rows) must be keyboard-accessible via Tab/Shift+Tab. Focus indicators use the `--amber` ring style from the design system. Modal dialogs trap focus. Escape closes overlays.

3. **Semantic HTML** — Leptos components render semantic elements: `<nav>` for sidebar, `<main>` for content, `<table>` for tabular data (not divs), `<button>` for actions (not styled anchors), `<form>` for inputs. ARIA labels on icon-only buttons (sidebar collapsed state).

4. **Screen reader support** — Secret values behind reveal toggles use `aria-expanded`. Status badges use `aria-label` (e.g., `aria-label="healthy"` on a green badge). Live regions (`aria-live="polite"`) for async operation results (sync status updates).

5. **Motion sensitivity** — No animations by default. If animation is added later, respect `prefers-reduced-motion` media query. Progress indicators use text updates, not spinners.

### Testing Strategy

**CLI Accessibility Testing:**

- **Automated:** Unit tests for output formatting functions verify that `NO_COLOR=1` produces zero ANSI escape codes. Test plain ASCII fallback when `!stdout.is_terminal()`.
- **Manual:** Verify CLI output is readable in macOS VoiceOver Terminal mode. Key checkpoint: can a screen reader user understand `zopp sync status` output from `--json` mode?
- **Pipe compatibility:** E2E tests pipe CLI output through `cat` and verify clean, parseable output without ANSI artifacts.

**Web Dashboard Accessibility Testing:**

- **Automated:** Playwright accessibility checks (`@axe-core/playwright`) on key pages: login, secrets list, workspace settings, audit log. Target: zero critical violations.
- **Contrast verification:** Validate amber accent colors against both light and dark theme backgrounds using automated contrast checkers in CI.
- **Keyboard testing:** Playwright tests verify Tab order through sidebar → main content → actions. Verify modal focus trapping.
- **Manual:** Periodic VoiceOver (macOS) and NVDA (Windows) testing of primary flows: login, view secrets, navigate workspaces.

**Responsive Testing:**

- **CLI:** E2E tests set `COLUMNS=80` and `COLUMNS=60` to verify output adapts to narrow terminals. Test pipe mode by redirecting to file.
- **Web:** Playwright viewport presets at 1280px, 768px, and 375px. Verify sidebar collapse, table-to-card transformation, and no horizontal overflow.

### Implementation Guidelines

**CLI Development:**

- Use `terminal_size` crate for width detection. Cache at command start — don't re-query mid-output.
- Wrap all output through a shared formatter that checks `NO_COLOR`, `--no-color`, and TTY state before emitting ANSI codes.
- Test every output component at width 80 and width 60. If it breaks at 60, add truncation logic.
- `--json` output must include all information present in human-readable output. Never omit fields from JSON that appear in formatted output.

**Web Development:**

- Use Tailwind's responsive prefixes (`lg:`, `md:`, `sm:`) for layout changes. No custom media queries unless Tailwind defaults are insufficient.
- All `<button>` and `<a>` elements must have visible focus styles using `focus-visible:ring-2 focus-visible:ring-amber`.
- Icon-only interactive elements require `aria-label`. Example: collapsed sidebar icons, reveal/hide secret toggle.
- Test with browser DevTools accessibility inspector before merging any new page or component.
- Secret values: use `aria-live="assertive"` on reveal so screen readers announce the value when revealed.

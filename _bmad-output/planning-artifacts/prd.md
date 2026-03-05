---
stepsCompleted: ['step-01-init', 'step-02-discovery', 'step-02b-vision', 'step-02c-executive-summary', 'step-03-success', 'step-04-journeys', 'step-05-domain', 'step-06-innovation', 'step-07-project-type', 'step-08-scoping', 'step-09-functional', 'step-10-nonfunctional', 'step-11-polish', 'step-12-complete']
status: complete
completedAt: '2026-03-04'
classification:
  projectType: 'developer-tool-cli-hybrid'
  domain: 'security-developer-infrastructure'
  complexity: 'medium-high'
  projectContext: 'brownfield'
inputDocuments:
  - product-brief-zopp-2026-03-04.md
  - research/market-zero-knowledge-secrets-manager-research-2026-03-04.md
  - brainstorming-session-2026-03-04-001.md
  - project-context.md
  - docs/docs/index.md
  - docs/docs/guides/index.md
  - docs/docs/security/index.md
  - docs/docs/installation/index.md
  - docs/docs/reference/cli/index.md
  - docs/docs/reference/index.md
  - docs/docs/self-hosting/index.md
workflowType: 'prd'
documentCounts:
  briefs: 1
  research: 1
  brainstorming: 1
  projectDocs: 7
date: '2026-03-04'
author: 'Lucas'
---

# Product Requirements Document - zopp

**Author:** Lucas
**Date:** 2026-03-04

## Executive Summary

zopp is an open-source, self-hostable, CLI-first secrets manager with zero-knowledge encryption. The server is architecturally blind — all encryption happens client-side using XChaCha20-Poly1305, X25519 ECDH, and Argon2id. The server stores only encrypted blobs and wrapped keys; it cannot decrypt anything, even if fully compromised.

zopp's core product is built and functional: secrets lifecycle management, hierarchical key encryption, multi-user workspaces with RBAC, audit logging, a web dashboard, and a Kubernetes operator. This PRD scopes the **next wave of features** — distribution, integrations, and deployment options — that take zopp from a working tool to one that's easy to install, integrates with real infrastructure, and deploys anywhere.

The primary entry point is `zopp run -- <command>`, which injects secrets directly into process environments, eliminating .env files entirely. The target users are sovereignty-first engineers who self-host everything, engineers fatigued by Vault's operational complexity, pragmatic CTOs optimizing for total cost of ownership, and DevOps leads handed compliance mandates who need the simplest possible audit narrative.

Success is measured purely by adoption — starting with dogfooding across all faisca projects, then organic open-source adoption. No monetization is planned or scoped.

### What Makes This Special

The intersection nobody else occupies: **auditable zero-knowledge + single-binary simplicity + genuine open-source license + free forever**. Any single differentiator can be copied — Akeyless claims zero-knowledge (proprietary, unauditable), Infisical is open-source (growing complexity, license shifts), Doppler is simple (SaaS, vendor trust required). The combination is the moat.

The core strategic insight: zero-knowledge is not just a security feature — it's a **compliance shortcut**. Instead of proving access controls are perfect for SOC 2 auditors, you prove the server is architecturally blind. That reframes the entire value proposition for compliance-driven buyers.

zopp ships as a single binary with SQLite as the default backend. No PostgreSQL, no Redis, no infrastructure provisioning required. Teams graduate to PostgreSQL when they need production scale, not because the tool demands it.

## Project Classification

- **Project Type:** Developer tool / CLI hybrid (CLI-first with gRPC server, Leptos web UI, and Kubernetes operator)
- **Domain:** Security / Developer Infrastructure
- **Complexity:** Medium-High (zero-knowledge cryptography, multi-backend storage, RBAC, audit logging — not regulated but security-critical)
- **Project Context:** Brownfield — core product is built and functional; this PRD covers the next phase of distribution, integrations, and deployment

## Success Criteria

### User Success

- **One-command install on macOS/Linux** — any developer can install zopp CLI without building from source (`curl -fsSL ... | sh`)
- **Time-to-first-secret under 5 minutes** — install CLI, connect to server, store and retrieve first encrypted secret
- **`zopp run` in daily workflow** — secrets injected into process environments without thinking about it; .env files eliminated
- **zopp as single source of truth** — secrets managed in zopp flow automatically to AWS Secrets Manager, GCP Secret Manager, Vercel, Render, Fly, and Railway. Teams manage secrets in one place.
- **Self-host without Kubernetes** — Docker Compose or PaaS one-click deploy gets a zopp server running in minutes

### Business Success

Since zopp is not a business, business success = adoption success:

- **Dogfooding complete** — 100% of faisca projects use zopp in production with `zopp.toml` committed
- **Zero .env files** — no .env files exist anywhere in faisca workflows
- **Zero secrets-related incidents** — no leaked credentials or access issues
- **Near-zero maintenance** — zopp infrastructure runs itself; less than 1 hour/month of unplanned maintenance
- **Organic discovery signal** — GitHub stars, issues filed by external users, and organic mentions (tracked but not optimized for)

### Technical Success

- **Cross-platform install scripts** — macOS (Intel + Apple Silicon), Linux (x86_64 + ARM64) covered by automated builds and install script
- **Package manager distribution** — brew, apt, nix packages published and maintained
- **Cloud sync reliability** — secrets sync to external platforms within seconds of change, with conflict detection and failure alerts
- **PaaS integration stability** — integrations work reliably without manual intervention after initial setup
- **Zero regressions** — existing core functionality (secrets lifecycle, RBAC, audit, K8s operator, web UI) remains stable through all additions

### Measurable Outcomes

| Outcome | Target | Measurement |
|---------|--------|-------------|
| faisca projects on zopp | 100% | Count of repos with `zopp.toml` |
| .env files in faisca | 0 | Grep across all repos |
| Install-to-first-secret | < 5 min | Manual testing of install flow |
| Cloud sync latency | < 30s after change | Integration test timing |
| Secrets incidents | 0 | Incident tracking |
| Unplanned maintenance | < 1 hr/month | Time tracking |

## User Journeys

### Journey 1: Sam Discovers and Installs zopp

**Persona:** Sam — full-stack developer, 15-person startup, maintains Vault reluctantly, wants something that "just works"

**Opening Scene:** Sam is browsing Reddit and sees a comment: "We replaced Vault with zopp — single binary, zero-knowledge, took 10 minutes." He clicks through to the GitHub repo. The README shows `curl -fsSL https://get.zopp.dev | sh`. He's intrigued but skeptical — he's been burned by tools that promise simplicity.

**Rising Action:** Sam opens his terminal and runs the install command. The script detects macOS ARM64, downloads the correct binary, and places it in his PATH. He runs `zopp --version` — it works. He follows the quickstart: starts the server with `zopp-server serve`, creates a workspace, sets his first secret. Total elapsed time: 4 minutes.

**Climax:** Sam runs `zopp run -- npm start` on his side project. The app boots with database credentials injected. No .env file. No Vault unsealing ritual. No YAML. He stares at the terminal for a second, processing how little friction there was.

**Resolution:** Over the next week, Sam migrates his team's staging secrets from Vault to zopp. He commits `zopp.toml` to each repo. The team's Vault cluster sits idle. Sam spends zero hours that month on secrets infrastructure maintenance. He posts on the team's Slack: "We're off Vault. You're welcome."

**Capabilities Revealed:** curl install script, cross-platform binary detection, quickstart flow, `zopp run` as primary interface, `zopp.toml` project defaults

---

### Journey 2: Diana Sets Up Cloud Sync for Her Team

**Persona:** Diana — CTO of 60-person Series A startup, AWS-heavy stack, SOC 2 audit starting, per-seat SaaS costs growing

**Opening Scene:** Diana's team has been using zopp for three months. It's their source of truth for secrets across five projects. But their production Kubernetes pods still pull from AWS Secrets Manager, and someone has to manually copy updated secrets over whenever credentials rotate. Last week a stale database password caused a 20-minute outage.

**Rising Action:** Diana sees that zopp now supports automatic sync to AWS Secrets Manager. She assigns her DevOps lead to set it up. He runs `zopp sync configure aws --region us-east-1` and authenticates with the team's AWS credentials. He maps zopp environments to AWS secret paths: `production` syncs to `/prod/`, `staging` syncs to `/staging/`.

**Climax:** A developer updates the database password in zopp. Within seconds, the new value appears in AWS Secrets Manager. The next pod restart picks it up automatically. No manual copy. No stale credentials. No outage risk. Diana checks the audit log — every sync event is recorded with timestamps and destinations.

**Resolution:** Diana expands sync to GCP Secret Manager for their secondary cloud workloads. zopp is now the single control plane for secrets across both clouds. At the SOC 2 audit, she shows the auditor: "All secrets are managed in a zero-knowledge system and synced outward. The server never sees plaintext." The auditor moves on. Diana calculates they've saved $1,800/month in SaaS per-seat fees and eliminated an entire class of credential staleness bugs.

**Capabilities Revealed:** Cloud sync configuration, AWS Secrets Manager integration, GCP Secret Manager integration, automatic outward sync on change, environment-to-path mapping, sync audit logging, multi-cloud support

---

### Journey 3: Raj Connects PaaS Integrations for Deployment

**Persona:** Raj — DevOps lead at 120-person B2B SaaS, compliance mandate, deploys across Vercel (frontend), Render (API), and Railway (background workers)

**Opening Scene:** Raj's team manages secrets across three PaaS platforms. Each has its own secrets UI. When a shared API key rotates, someone has to update it in three dashboards manually. Raj has already been written up for a missed update that broke the background worker for two hours. His compliance report flags "inconsistent secret management across deployment platforms" as a risk.

**Rising Action:** Raj configures zopp's PaaS integrations. For each platform, he authenticates via API token and maps zopp environments to deployment targets: `production/frontend` syncs to Vercel, `production/api` syncs to Render, `production/workers` syncs to Railway. He runs a test sync — all three platforms update simultaneously.

**Climax:** The shared Stripe API key needs rotation. Raj runs `zopp secret set STRIPE_KEY <new-value>`. Within seconds, all three platforms have the new key. He checks the audit log: three sync events, three confirmations, zero manual steps. He screenshots the audit trail for the compliance report.

**Resolution:** Raj's next compliance review is the shortest one yet. "Secrets are centrally managed with zero-knowledge encryption. Changes propagate automatically to all deployment targets. Full audit trail attached." The compliance reviewer checks the box and moves on. Raj's team never manually copies a secret between dashboards again.

**Capabilities Revealed:** PaaS integration configuration (Vercel, Render, Railway), API token authentication per platform, environment-to-deployment mapping, simultaneous multi-platform sync, sync confirmation events, audit trail for compliance

---

### Journey 4: Sam Deploys zopp Server on Fly

**Persona:** Sam — full-stack developer, 15-person startup, doesn't want to manage infrastructure

**Opening Scene:** Sam has been running zopp-server locally for a month. His team loves it. But the server runs on his laptop — when he closes the lid, nobody can access secrets. The team needs a shared server, but Sam doesn't want to manage a VPS, configure TLS, or touch Kubernetes. He wants something as easy as deploying a web app.

**Rising Action:** Sam finds the Fly deployment guide in the zopp docs. He runs `fly launch` with the provided `fly.toml` template. The template includes a PostgreSQL addon and automatic TLS — no certificate management. He sets `DATABASE_URL` as a Fly secret (ironic, he thinks) and deploys. The server is live in under 5 minutes with a public HTTPS endpoint.

**Climax:** Sam generates the first invite token: `fly ssh console -C "zopp-server invite create"`. He shares the invite link with his team on Slack. Within an hour, five teammates have joined, each with their own principals. Secrets are flowing. TLS is handled. The server is running on infrastructure Sam doesn't have to think about.

**Resolution:** The server runs for months on Fly's free tier. Sam never SSHs into it again. When the team grows to 15 people, he scales the Fly machine with one command. His total infrastructure maintenance for secrets management: zero. He moves on to building features.

**Capabilities Revealed:** Fly.toml deployment template, PaaS one-click deploy, automatic TLS via platform, PostgreSQL addon support, invite flow from PaaS-hosted server, zero-infrastructure deployment path

---

### Journey Requirements Summary

| Journey | Key Capabilities Required |
|---------|--------------------------|
| **Sam — Install & First Use** | curl install script, cross-platform binary detection, streamlined quickstart |
| **Diana — Cloud Sync** | AWS SM sync, GCP SM sync, automatic outward flow on change, environment mapping, sync audit events |
| **Raj — PaaS Integrations** | Vercel/Render/Fly/Railway integrations, API token auth, multi-platform simultaneous sync, sync confirmations |
| **Sam — PaaS Server Deploy** | Fly/Railway deployment templates, PaaS-specific docs, automatic TLS via platform, PostgreSQL addon config, zero-infra deployment path |

**Cross-cutting capabilities revealed:**
- Audit logging for all sync events (cloud and PaaS)
- Configuration CLI for managing integration targets (`zopp sync configure`)
- Failure alerting when sync targets are unreachable
- Environment-to-target mapping as a first-class concept

## Domain-Specific Requirements

### Zero-Knowledge Preservation

- **Server remains blind** — all sync operations happen outside the server. Decryption occurs in the sync agent (service principal), never on the server.
- **Sync agent pattern** — extends the existing K8s operator model. A service account principal with its own keys runs the sync, decrypting secrets client-side before pushing to external platforms.
- **No new trust assumptions** — the sync agent is trusted exactly as much as any other principal with workspace access. RBAC controls what it can read.

### Failure Handling

- **Sync failures recorded in audit log** — every sync attempt (success or failure) is an auditable event with timestamp, target, and result.
- **Queryable sync status** — `zopp sync status` shows last sync time, success/failure, and target health per integration.
- **No silent failures** — failed syncs must be surfaced. At minimum: CLI-queryable. Stretch: webhook notifications.

### Security Considerations

- **API token rotation** — integration credentials (passed via environment variables or CLI flags) are rotatable without downtime. The sync agent reads them fresh on each invocation.
- **Least-privilege sync principal** — sync agent's RBAC should be scoped to read-only on specific environments, not workspace-wide admin.
- **Audit trail for compliance** — all outward sync events provide evidence for SOC 2 and similar audits: what was synced, where, when, by which principal.

## Developer Tool / CLI Specific Requirements

### Project-Type Overview

zopp is a hybrid developer tool: CLI-first secrets manager with gRPC server, web dashboard, K8s operator, and (in this wave) outward sync to cloud and PaaS platforms. The CLI is the primary interface for all operations. New features in this wave extend the existing `zopp sync` command pattern and add distribution mechanisms (install scripts, package managers, deployment templates).

### Installation & Distribution

**Priority order (sequential, not parallel):**

1. **curl install script** (first priority) — Shell script that detects OS (macOS/Linux), architecture (x86_64/ARM64), downloads the correct binary from GitHub Releases, places it in PATH. Must work on fresh machines with no prerequisites beyond `curl` and a POSIX shell.
2. **brew** — Homebrew formula for macOS and Linux. Highest-impact package manager for the target audience.
3. **apt** — Debian/Ubuntu package repository for Linux server environments.
4. **nix** — Nix package for the sovereignty-first audience who uses NixOS.

**Binary matrix:**

| OS | Architecture | Format |
|----|-------------|--------|
| macOS | x86_64 (Intel) | tar.gz |
| macOS | aarch64 (Apple Silicon) | tar.gz |
| Linux | x86_64 | tar.gz |
| Linux | aarch64 | tar.gz |

### Sync Command Architecture

**Extends the existing `zopp sync k8s` pattern.** New sync targets follow identical conventions:

```
zopp sync <target> [flags]
```

**Existing pattern (K8s):**
- `zopp sync k8s --namespace <ns> --secret <name> -w/-p/-e`
- `zopp diff k8s [same flags]` — preview changes before syncing
- Service principal authentication via Ed25519 signatures
- Client-side decryption: fetch encrypted → decrypt with principal keys → write plaintext to target
- Local config: `zopp.toml` defaults + CLI flag overrides
- Labels/annotations for tracking: `zopp.dev/synced-at`, `zopp.dev/synced-by`

**New sync targets follow the same model:**

| Command | Target | Auth Method |
|---------|--------|-------------|
| `zopp sync k8s` | Kubernetes Secret | kubeconfig |
| `zopp sync aws` | AWS Secrets Manager | AWS credentials (env vars / profile) |
| `zopp sync gcp` | GCP Secret Manager | Service account key / ADC |
| `zopp sync vercel` | Vercel environment variables | API token |
| `zopp sync render` | Render environment variables | API token |
| `zopp sync fly` | Fly secrets | API token |
| `zopp sync railway` | Railway variables | API token |

**Each sync command:**
- Reads secrets from zopp (encrypted), decrypts client-side
- Authenticates with target platform using platform-native credentials
- Pushes plaintext to target
- Supports `--dry-run` to preview changes
- Corresponding `zopp diff <target>` command to show delta before syncing

**Platform credentials:** Passed via environment variables or CLI flags, same pattern as `--kubeconfig` for K8s. Not stored in zopp (avoids bootstrapping problem while keeping things simple).

### Continuous Sync (Operator Pattern Extension)

For teams that want automatic sync (not just CLI-triggered):

- **Sync agent** runs as a service principal (same pattern as K8s operator)
- Periodically polls zopp for changes and pushes to configured targets
- Initially: CLI-triggered sync (`zopp sync aws`). Continuous agent is a follow-up.
- The K8s operator already implements this pattern — cloud/PaaS agents would be architecturally identical.

### Deployment Templates

**Start with Fly, expand later:**

1. **Fly.io** (first) — `fly.toml` template, PostgreSQL addon, automatic TLS. Best CLI-first ergonomics for the target audience.
2. **Railway** (second) — similar model, different audience slice
3. **Docker Compose** (third) — for self-hosters who want containers without K8s

Each template includes:
- Server configuration with PostgreSQL
- TLS handling (automatic via platform or explicit certs)
- Health check configuration
- Documentation for generating first invite token from the deployed instance

### Implementation Considerations

- **No new server RPCs needed** — sync uses existing `ListSecrets`/`GetSecret` + client-side decryption, same as K8s
- **Each sync target is a separate Rust module** — keeps integration code isolated and independently testable
- **Platform API stability** — PaaS APIs change frequently. Each integration should have version pinning and graceful degradation on API changes.
- **Rate limiting** — cloud/PaaS APIs have rate limits. Sync commands should handle throttling gracefully (backoff + retry).
- **Error messages** — sync failures must clearly indicate: which target, which secret, what went wrong, how to fix it. No generic "sync failed" errors.

## Project Scoping & Phased Development

### MVP Strategy & Philosophy

**MVP Approach:** Pattern-proving MVP. Phase 1 proves the end-to-end pattern works (one install method, one cloud sync, one PaaS sync, one PaaS deploy). Subsequent phases expand to additional targets using the proven pattern.

**Resource Requirements:** Solo developer. Each sync target is an independent module — work is parallelizable if contributors emerge, but sequentially deliverable by one person.

### Phase 1 — Prove the Pattern

**Core deliverables that prove the wave works end-to-end:**

| Deliverable | Rationale |
|-------------|-----------|
| curl install script | Unblocks everything — can't adopt what you can't install |
| AWS Secrets Manager sync | Highest-demand cloud provider; proves the cloud sync pattern |
| Fly deployment template | Proves zero-infra server deployment; enables new users |
| Fly sync integration | Completes the Fly story — deploy server there AND sync app secrets there |

**User journeys supported:** Sam installs via curl (Journey 1), Diana syncs to AWS (Journey 2), Sam deploys server on Fly (Journey 4)

**Success gate:** A new user can install zopp via curl, deploy the server on Fly, sync secrets to AWS and to their Fly app — all without building from source, managing infrastructure, or touching Kubernetes.

### Phase 2 — Expand to High-Impact Targets

**Broadens coverage to the most-demanded platforms:**

| Deliverable | Rationale |
|-------------|-----------|
| GCP Secret Manager sync | Completes multi-cloud story |
| Vercel integration | Highest-demand PaaS for frontend teams |
| Render integration | Popular API/backend deployment target |
| brew formula | Highest-impact package manager for macOS developers |

**User journeys supported:** Raj connects PaaS integrations (Journey 3)

**Success gate:** A team can use zopp as their single source of truth across AWS, GCP, Vercel, and Render. macOS developers install via brew.

### Phase 3 — Complete the Distribution

**Fills out the long tail of targets and distribution:**

| Deliverable | Rationale |
|-------------|-----------|
| Railway sync integration | Completes PaaS coverage |
| apt package | Linux server environments |
| nix package | Sovereignty-first audience |
| Railway deployment template | Additional PaaS deploy option |
| Docker Compose template | Self-hosters who want containers without K8s |

**Success gate:** zopp is installable via curl, brew, apt, or nix. Secrets sync to AWS, GCP, Vercel, Render, Fly, and Railway. Server deploys on Fly, Railway, Docker Compose, or K8s.

### Growth Features (Post-Wave)

- **Technical blog** — Deep posts on zero-knowledge architecture, crypto decisions, engineering stories (work item tracked as roadmap deliverable)
- **Onboarding polish** — First-run wizard, streamlined invite UX, guided setup
- **CLI-Dashboard full parity** — Web UI covers everything the CLI can do
- **Secret rotation & expiry tracking** — Expiry warnings, automated rotation for supported services

### Vision (Future)

- **Terraform Provider** — GitOps for secrets infrastructure; define workspaces, RBAC, environments in code
- **SSO integration** — Bridge from developer tool to enterprise-ready
- **REST API** — Built only when a specific integration demands it
- **Sustainability model** — Explored only when community demand emerges; no bait-and-switch

### Risk Mitigation Strategy

**Technical Risks:**
- Platform API instability — each integration is an isolated module with pinned API versions and integration tests. Breaking changes affect one target, not all.
- Sync at scale — incremental sync (changed secrets only), batch API operations, rate limit handling with exponential backoff.
- Zero-knowledge preservation — sync agent decrypts client-side only. Architecture review before each new sync target to verify no plaintext touches the server.

**Market Risks:**
- Low risk — this wave makes an existing working product more accessible, not a new product bet. If nobody notices, the product is still better for existing users (faisca dogfooding).

**Resource Risks:**
- Solo developer — phasing ensures each phase is independently valuable. Partial delivery is fine. Each sync target is independent work that doesn't block others.
- Community contributions — sync modules are well-scoped, isolated units ideal for first-time contributors. Could attract PRs once the pattern is established in Phase 1.

## Functional Requirements

### Installation & Distribution

- **FR1:** A developer can install the zopp CLI on macOS or Linux with a single curl command
- **FR2:** The install script can detect the user's OS and architecture and download the correct binary
- **FR3:** A developer can install the zopp CLI via Homebrew on macOS or Linux
- **FR4:** A developer can install the zopp CLI via apt on Debian/Ubuntu
- **FR5:** A developer can install the zopp CLI via nix

### Cloud Secret Manager Sync

- **FR6:** A user can sync secrets from a zopp environment to AWS Secrets Manager
- **FR7:** A user can sync secrets from a zopp environment to GCP Secret Manager
- **FR8:** A user can map zopp environments to cloud secret paths/names
- **FR9:** A user can preview sync changes before applying them (`zopp diff aws`, `zopp diff gcp`)
- **FR10:** A user can perform a dry-run sync that shows what would change without modifying the target
- **FR11:** The system can sync only changed secrets (incremental sync) rather than the full set
- **FR12:** A user can authenticate with cloud providers using platform-native credentials (AWS profile/env vars, GCP ADC/service account)

### PaaS Integration Sync

- **FR13:** A user can sync secrets from a zopp environment to Fly
- **FR14:** A user can sync secrets from a zopp environment to Vercel
- **FR15:** A user can sync secrets from a zopp environment to Render
- **FR16:** A user can sync secrets from a zopp environment to Railway
- **FR17:** A user can map zopp environments to PaaS deployment targets (project, service, app)
- **FR18:** A user can preview PaaS sync changes before applying them (`zopp diff <target>`)
- **FR19:** A user can authenticate with PaaS platforms using API tokens

### Sync Operations & Monitoring

- **FR20:** The system records every sync attempt (success or failure) in the audit log
- **FR21:** A user can view sync status for all configured targets (`zopp sync status`)
- **FR22:** The system handles platform API rate limits with automatic backoff and retry
- **FR23:** The system surfaces clear error messages on sync failure identifying the target, secret, and failure reason
- **FR24:** A sync agent (service principal) can run sync operations on behalf of a team without human interaction

### Server Deployment

- **FR25:** A user can deploy zopp-server to Fly using a provided `fly.toml` template
- **FR26:** A user can deploy zopp-server to Railway using a provided template
- **FR27:** A user can deploy zopp-server using Docker Compose with a provided template
- **FR28:** Each deployment template includes PostgreSQL configuration
- **FR29:** Each deployment template includes TLS configuration (automatic via platform or explicit)
- **FR30:** A user can generate an invite token from a PaaS-deployed server

### Zero-Knowledge Preservation

- **FR31:** All sync operations decrypt secrets client-side (sync agent/CLI), never on the server
- **FR32:** The sync agent authenticates as a service principal with scoped RBAC permissions
- **FR33:** A workspace admin can create a service principal scoped to read-only on specific environments for sync operations

## Non-Functional Requirements

### Performance

- **NFR1:** Install script completes in under 30 seconds on a standard broadband connection
- **NFR2:** Sync operations complete within 30 seconds for environments with up to 100 secrets
- **NFR3:** `zopp diff` preview commands return results within 5 seconds
- **NFR4:** Rate limit backoff adds no more than 60 seconds of additional delay per sync cycle under normal conditions

### Security

- **NFR5:** No plaintext secrets are written to disk, logs, or temporary files during sync operations
- **NFR6:** Platform API credentials (AWS keys, PaaS tokens) are never logged or persisted by zopp — they are read from environment variables or CLI flags at runtime only
- **NFR7:** The install script verifies binary integrity (checksum verification) before placing the binary in PATH
- **NFR8:** All sync communication with external platforms uses TLS
- **NFR9:** Sync agent service principals follow least-privilege: read-only access scoped to specific environments

### Integration

- **NFR10:** Each sync integration is isolated — a failure or API change in one platform does not affect others
- **NFR11:** Each sync integration supports platform-native authentication methods (no custom auth schemes)
- **NFR12:** Sync integrations handle API version changes gracefully — clear error messages on breaking changes, not silent data corruption
- **NFR13:** Each sync integration has automated integration tests that run against the platform's API (or a mock of it)

### Reliability

- **NFR14:** A failed sync to one target does not block sync to other targets
- **NFR15:** Sync operations are idempotent — running the same sync twice produces the same result
- **NFR16:** Partial sync failures (some secrets synced, some failed) are reported per-secret, not as a blanket failure
- **NFR17:** Deployment templates produce servers that pass health checks and recover from container restarts without data loss


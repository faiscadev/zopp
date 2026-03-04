---
stepsCompleted: [1, 2, 3, 4, 5, 6]
status: complete
inputDocuments:
  - brainstorming-session-2026-03-04-001.md
  - market-zero-knowledge-secrets-manager-research-2026-03-04.md
  - project-context.md
  - docs/docs/index.md
  - docs/docs/quickstart.md
  - docs/docs/security/architecture.md
date: 2026-03-04
author: Lucas
---

# Product Brief: zopp

## Executive Summary

zopp is an open-source, self-hostable, CLI-first secrets manager with zero-knowledge encryption. It exists because teams today are forced to choose between operational complexity (HashiCorp Vault), vendor trust (SaaS platforms), cloud lock-in (AWS/GCP/Azure native tools), or plain insecurity (.env files). zopp eliminates that trade-off by combining auditable zero-knowledge encryption with single-binary simplicity and a genuine open-source license.

The secrets management market is valued at $4.2B (2025) and growing at 13.8% CAGR. The competitive landscape is fragmenting — enterprise incumbents are consolidating (IBM acquired HashiCorp for $6.4B), SaaS players charge per-seat, and open-source challengers like Infisical are drifting toward enterprise complexity. zopp targets the underserved intersection of teams that want self-hosted control without self-hosted complexity, and zero-knowledge guarantees they can verify — not just trust.

---

## Core Vision

### Problem Statement

Development teams handle secrets — API keys, database credentials, service tokens — every day, but the available tools force painful trade-offs. HashiCorp Vault is powerful but requires dedicated infrastructure teams to operate. SaaS platforms are convenient but require trusting a third party with your most sensitive data. Cloud-native tools lock you into a single provider. And the most common approach — .env files shared through Slack and email — offers zero encryption, zero audit trails, and a 22% chance of becoming a breach vector (per 2025 Verizon DBIR).

The core problem: **there is no secrets manager that is simultaneously simple to operate, zero-knowledge by architecture, genuinely open-source, and free.**

### Problem Impact

- **96% of organizations** struggle with secrets sprawl across repositories, config files, and collaboration tools
- **23.8 million secrets** leaked on public GitHub in 2024 alone — a 25% year-over-year increase
- **71% of leaked secrets** remain active two years later, providing prolonged attacker access
- **37% of organizations** store secrets in environment variables or hardcoded in application code
- Teams using Vault report steep learning curves, operational burden, and scaling costs that are "so inhibitive"
- SaaS secrets managers charge $15–25/user/month — prohibitive for cost-conscious teams and startups

### Why Existing Solutions Fall Short

| Solution | What It Gets Right | Where It Falls Short |
|----------|-------------------|---------------------|
| **HashiCorp Vault** | Deep feature set, de facto standard | Operational complexity, BSL license, steep learning curve |
| **Infisical** | Open-source community, broad features | Growing complexity, PostgreSQL+Redis required, license shifting |
| **Akeyless** | Zero-knowledge marketing, lightweight | Proprietary (DFC), not self-hostable, unauditable claims |
| **Cloud SM (AWS/GCP/Azure)** | Tight cloud integration | Vendor lock-in, single-cloud only, per-secret pricing |
| **.env files** | Zero setup, universally understood | No encryption, no audit, no team sync, accidental commits |

No existing tool occupies the intersection of zero-knowledge + self-hosted + simple + open-source + free.

### Proposed Solution

zopp is a secrets manager built on one principle: **the server should be provably blind.** All encryption happens client-side using XChaCha20-Poly1305, X25519 ECDH, and Argon2id. The server stores only encrypted blobs and wrapped keys — it cannot decrypt anything, even if compromised.

zopp ships as a single binary with SQLite as the default backend — no PostgreSQL, no Redis, no infrastructure provisioning. Start the server, create a workspace, store your first encrypted secret. Teams graduate to PostgreSQL when they need production scale, not because the tool demands it.

The CLI is the primary interface: `zopp secret set`, `zopp secret get`, `zopp run -- npm start`. The `zopp run` command injects secrets directly into process environments, eliminating .env files entirely — not managing them better, but making them unnecessary. A web dashboard provides visual parity for teams that need it.

zopp is born from firsthand experience — built by an engineer who joined a startup using a SaaS secrets manager and realized teams shouldn't have to trust a third party with their most sensitive data when a better architecture is possible.

### Key Differentiators

1. **Auditable zero-knowledge** — Client-side encryption with open-source code. Verify the server is blind by reading the source, not by trusting marketing claims.
2. **Single-binary simplicity** — One binary, SQLite default, zero-config start. Running a secrets manager shouldn't require a platform team.
3. **Genuine open-source license** — No BSL, no SSPL, no license bait-and-switch. The license is a feature, not fine print.
4. **`zopp run` as the .env killer** — Secrets injected directly into process environments. No files on disk, no accidental commits, no sync between teammates.
5. **Free, no per-seat pricing** — Core functionality is free forever. Teams of any size can adopt without procurement friction.
6. **The combination is the moat** — Any single differentiator can be copied. The intersection of all six is zopp's unique position.

---

## Target Users

### Primary Users

**1. Marco — The Sovereignty-First Engineer**

Marco is a senior DevOps engineer at a 30-person startup. He self-hosts Gitea, runs Tailscale, and chooses tools based on principles before features. He was using Vault reluctantly until the BSL license change — now he's actively searching for a genuinely open-source alternative. He finds tools through GitHub, Hacker News, and lobste.rs, not vendor marketing.

- **Motivation:** Data sovereignty, auditable code, permissive licensing, no vendor lock-in
- **Current workaround:** Vault (reluctantly) or SOPS + KMS — functional but either over-complex or limited
- **Pain:** Doesn't trust SaaS providers with secrets; frustrated that "open source" tools keep changing licenses
- **Success moment:** Reads zopp's source code, verifies the server is blind, deploys it on his own infrastructure in 10 minutes
- **zopp pitch:** "Verify, don't trust. Read the code — the server can't see your secrets."

**2. Diana — The Pragmatic CTO**

Diana is CTO of a 60-person Series A startup. She doesn't care about crypto internals — she cares about setup speed, ops burden, cost, and whether it integrates with their AWS and Vercel stack. Zero-knowledge is a compliance checkbox for the SOC 2 audit they're starting, not a philosophical position. She evaluates based on total cost of ownership and how fast her team can adopt.

- **Motivation:** Low TCO, fast setup, integration breadth, compliance readiness
- **Current workaround:** SaaS secrets manager (per-seat pricing, growing with headcount), or .env files managed through a shared 1Password vault
- **Pain:** SaaS costs scaling with headcount; wants self-hosted control without self-hosted complexity
- **Success moment:** Sets up zopp server in one Docker command, has her team onboarded in an afternoon, checks the SOC 2 box
- **zopp pitch:** "One binary, zero config, zero per-seat cost. Your team is onboarded by lunch."

**3. Raj — The Compliance-Driven DevOps Lead**

Raj is a DevOps lead at a 120-person B2B SaaS company. He's been handed a compliance mandate — SOC 2 Type II — and needs to prove secrets are managed properly. Security questionnaire reviewers are asking for evidence of secrets management controls, and missing this gets them cut from enterprise deals. He doesn't pick the tool; he picks the tool that makes the audit narrative simplest.

- **Motivation:** Audit trails, access controls, provable zero-knowledge for auditors
- **Current workaround:** AWS Secrets Manager + manual access reviews — functional but hard to demonstrate to auditors
- **Pain:** Proving access controls are perfect is hard; needs a simpler compliance story
- **Success moment:** Tells the auditor "the server is architecturally blind — it cannot see secrets even if compromised" and the auditor moves on
- **zopp pitch:** "Zero-knowledge as compliance shortcut. Don't prove access controls are perfect — prove the server is blind."

**4. Sam — The Simplicity Seeker**

Sam is a full-stack developer at a 15-person startup. They deployed Vault six months ago and it takes more time to maintain than the app it protects. Sam wants something that "just works" — install, configure, done. They don't want to think about Raft consensus, unsealing, or HA clusters. They want to store secrets and get back to building features.

- **Motivation:** Developer experience, fast setup, low ops burden, time back for actual work
- **Current workaround:** Vault (painful) or .env files (insecure but easy)
- **Pain:** Vault's learning curve, operational burden, documentation gaps; nearly 50% of engineering leaders report DevOps burnout
- **Success moment:** Replaces Vault with zopp in an afternoon, runs `zopp run -- npm start`, never thinks about secrets infrastructure again
- **zopp pitch:** "One binary replaces your Vault cluster. Get back to building."

### Secondary Users

**Security Team Lead** — Reviews zopp's architecture for compliance sign-off. Needs security documentation, crypto architecture details, and audit log capabilities. Doesn't use zopp daily but must approve its adoption.

**Startup Founder / VP Eng** — Needs to pass SOC 2 or respond to vendor security questionnaires. Cares that "secrets management" is a checked box. Relies on their engineering team's recommendation.

### User Journey

**Discovery → Adoption → Expansion**

| Stage | Marco (Sovereignty) | Diana (Pragmatic) | Raj (Compliance) | Sam (Simplicity) |
|-------|--------------------|--------------------|-------------------|-------------------|
| **Discovery** | GitHub, HN, OSS communities | Peer recommendation, "Vault alternative" search | Compliance research, comparison articles | "Simple secrets manager" search, Reddit |
| **First impression** | Reads source code, checks license | Reads quickstart, checks integrations list | Reads security architecture docs, audit capabilities | Reads README, tries locally in 15 min |
| **Onboarding** | Builds from source, deploys on own infra | `docker run`, team onboarded same day | Evaluates audit logs, RBAC, writes compliance narrative | `curl \| sh`, first secret in 5 min |
| **"Aha!" moment** | Verifies server is blind by reading crypto code | Sees $0/month vs per-seat SaaS bill | "The server can't see secrets" simplifies entire audit | `zopp run -- npm start` replaces Vault + .env |
| **Long-term value** | Advocates in OSS communities, contributes | Expands to all teams, integrates with CI/CD | Uses audit logs for ongoing compliance evidence | Forgets secrets infra exists — it just works |
| **Expansion trigger** | Recommends to peers, writes blog posts | Adds projects/environments as company grows | Adds teams as compliance scope expands | Team adopts after seeing how easy it is |

---

## Success Metrics

### User Success Metrics

zopp is built for its creator first. The primary measure of success is whether Lucas adopts zopp as his production secrets manager across faisca projects and never looks back.

**Core User Success:**
- **Time-to-first-secret under 5 minutes** — Install the CLI, start the server, store and retrieve the first encrypted secret in under 5 minutes
- **Zero .env files in faisca repositories** — `zopp run` fully replaces .env files across all projects
- **"It just works" reliability** — Secrets are always available when needed; the tool never gets in the way of shipping features
- **Near-zero maintenance** — Secrets infrastructure runs itself; no babysitting required

**Behavioral Indicators:**
- `zopp run` is part of daily development workflow without thinking about it
- `zopp.toml` is committed to every faisca project repository
- No .env files exist anywhere in the workflow
- Secrets infrastructure requires near-zero maintenance

### Business Objectives

zopp is not a business — it's an open-source tool built to solve a real problem for its creator. Business objectives are intentionally deferred in favor of product quality and authentic adoption.

**Phase 1: Dogfooding (Current)**
- zopp becomes the production secrets manager for all faisca projects
- The tool is stable, reliable, and pleasant to use daily

**Phase 2: Open-Source Adoption (Future)**
- Other developers and teams discover and adopt zopp organically
- Community forms around shared values (zero-knowledge, open source, simplicity)
- Contributors emerge from users who care about the project

**Phase 3: Sustainability (When the community asks for it)**
- Monetization explored only when there's genuine demand
- Revenue model respects open-source principles — no bait-and-switch

---

## MVP Scope

### Core Features (Shipped)

zopp's core product is already built and production-ready. The following capabilities exist today:

**Secrets Management:**
- Full secrets lifecycle: `zopp secret set`, `get`, `list`, `import`, `export`
- `zopp run` for environment injection — the .env killer
- Zero-knowledge encryption (XChaCha20-Poly1305, X25519 ECDH, Argon2id)
- Hierarchical key management (User → Principal → KEK → DEK → Secret)
- Context-bound AEAD encryption with workspace/project/env/key AAD

**Infrastructure:**
- Single-binary server with SQLite default, PostgreSQL for production
- gRPC transport with mTLS support
- Ed25519 signature authentication on all requests
- Kubernetes operator for secret syncing
- Web UI (Leptos SSR + WASM)

**Collaboration:**
- Multi-user workspaces with invite flow
- Fine-grained RBAC (admin, write, read)
- Groups for permission management
- Audit logging with ~45 action types
- Event bus (memory + PostgreSQL backends)

**Developer Experience:**
- `zopp.toml` for project defaults — no repeated flags
- .env import/export for migration
- Email verification
- Multi-principal support (multiple devices)

### Out of Scope for MVP

The following are explicitly deferred — they are future growth features, not core requirements:

- **Config management** — zopp is a secrets manager, not a config manager
- **Secret rotation & expiry** — valuable but not blocking core usage
- **SSO integration** — enterprise feature, not needed for current audience
- **REST API** — build only when a specific integration demands it
- **Managed/hosted offering** — self-hosted simplicity is the positioning

### MVP Success Criteria

The MVP is feature-complete: zopp has everything needed to manage secrets for Kubernetes workloads in production. The next milestone is dogfooding at faisca.

**Validation criteria:**
- Creator adopts zopp for production infrastructure at faisca
- Zero-knowledge architecture works as designed — server is provably blind
- Single-binary + SQLite setup works for development, PostgreSQL + K8s operator works for production
- The tool doesn't get in the way — it just works

### Future Vision

**Near-term: Distribution & Integrations**

Following the prioritized roadmap from product brainstorming:

1. **curl install script** — One-line install, removes the biggest friction point for new users
2. **Cloud secret manager sync** — AWS Secrets Manager, GCP Secret Manager; zopp as zero-knowledge control plane that syncs outward
3. **PaaS integrations** — Vercel, Render, Fly, Railway; meet users where they deploy
4. **More server deployment options** — Docker Compose templates, PaaS one-click deploys beyond K8s
5. **Technical blog** — Deep posts on zero-knowledge architecture, crypto decisions; the Tailscale marketing playbook
6. **Remaining distribution** — brew, apt, nix
7. **Onboarding polish** — First-run wizard, streamlined invite UX

**Logic:** Make it installable → make it integrate with real infra → make it deployable anywhere → tell the story → polish the entry experience.

**Long-term: Community & Ecosystem**

- CLI-Dashboard full parity (both first-class citizens)
- Terraform Provider for GitOps secrets infrastructure
- Secret rotation & expiry tracking
- SSO integration as bridge to enterprise readiness
- Sustainability model when community demand emerges

**Anti-Scope (Permanent):**
- No config management — zopp is a secrets manager, period
- No competitor namedropping in messaging
- No premature monetization
- No speculative feature building — use cases pull features into existence

### Key Performance Indicators

**Dogfooding KPIs (Now):**

| KPI | Target | Measurement |
|-----|--------|-------------|
| faisca projects using zopp | 100% | Count of projects with `zopp.toml` |
| .env files in faisca repos | 0 | Grep for `.env` files across repos |
| Secrets-related incidents | 0 | Any leaked credential or access issue |
| Unplanned maintenance | Near zero | Hours spent fixing zopp infrastructure per month |

**Community KPIs (Future — track but don't optimize for):**

| KPI | Signal | Why It Matters |
|-----|--------|---------------|
| GitHub stars | Community interest | Social proof for new evaluators |
| Issues and discussions | Active usage | People care enough to report and discuss |
| External contributors | Community health | Others find zopp worth improving |
| Organic mentions | Word-of-mouth | Engineers recommending zopp unprompted |

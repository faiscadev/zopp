# Story 3.2: Create Fly deployment template

Status: review

## Story

As a developer,
I want to deploy zopp-server on Fly using a provided template,
so that my team has a shared server without managing infrastructure.

## Acceptance Criteria

1. **Given** the deployment template exists at `deploy/fly/fly.toml`, **When** the user runs `fly launch` with the template, **Then** Fly provisions the app with the correct configuration.

2. **Given** the template configuration, **When** the server starts, **Then** PostgreSQL is configured as the database backend (not SQLite) **And** TLS is handled automatically by Fly's platform **And** a health check endpoint is configured at `/healthz` on port 8080.

3. **Given** the server is deployed and running, **When** the user runs `fly ssh console -C "zopp-server invite create"`, **Then** an invite token is generated that can be shared with team members.

4. **Given** the `deploy/fly/README.md` exists, **When** a user reads it, **Then** it contains step-by-step deployment instructions **And** it documents required and optional environment variables **And** it explains how to generate the first invite token **And** it explains how to connect the CLI to the deployed server.

## Tasks / Subtasks

- [x] Task 1: Create Fly deployment template (AC: 1, 2)
  - [x] 1.1 Create `deploy/fly/fly.toml` with app configuration
  - [x] 1.2 Configure PostgreSQL as attached database (Fly Postgres)
  - [x] 1.3 Configure health check using `/healthz` on port 8080
  - [x] 1.4 Configure gRPC service on internal port 50051
  - [x] 1.5 Set appropriate VM size and auto-stop settings

- [x] Task 2: Create deployment README (AC: 3, 4)
  - [x] 2.1 Create `deploy/fly/README.md` with step-by-step instructions
  - [x] 2.2 Document `fly launch` and `fly deploy` workflow
  - [x] 2.3 Document Fly Postgres setup (`fly postgres create` + `fly postgres attach`)
  - [x] 2.4 Document environment variables (DATABASE_URL, email config, etc.)
  - [x] 2.5 Document invite token generation via `fly ssh console`
  - [x] 2.6 Document connecting CLI to deployed server
  - [x] 2.7 Document TLS (automatic via Fly's edge, gRPC uses h2c internally)

- [x] Task 3: Validation
  - [x] 3.1 Verify fly.toml passes `fly launch --config deploy/fly/fly.toml` syntax check (dry review)
  - [x] 3.2 Ensure README instructions are consistent with fly.toml settings

## Dev Notes

### Fly Platform Details

**Fly Machines Configuration:**
- Fly uses `fly.toml` for app configuration
- Apps are deployed as Machines (micro VMs)
- Fly handles TLS termination at the edge — the app runs plain gRPC (h2c) internally
- Fly Postgres is a managed Postgres service attached to apps

**Key fly.toml Sections:**
```toml
app = "zopp-server"  # User will change this during fly launch

[build]
  dockerfile = "server.Dockerfile"

[env]
  # Non-secret environment variables
  ZOPP_EMAIL_VERIFICATION_REQUIRED = "false"

[http_service]
  internal_port = 50051
  force_https = true
  auto_stop_machines = "stop"
  auto_start_machines = true
  min_machines_running = 0
  processes = ["app"]

[[services]]
  protocol = "tcp"
  internal_port = 50051

  [[services.ports]]
    port = 443
    handlers = ["tls", "http"]

  [[services.ports]]
    port = 80
    handlers = ["http"]

[checks]
  [checks.health]
    port = 8080
    type = "http"
    interval = "10s"
    timeout = "2s"
    path = "/healthz"
    method = "GET"

[[vm]]
  size = "shared-cpu-1x"
  memory = "256mb"
```

**Database Configuration:**
- Users create a Fly Postgres cluster: `fly postgres create --name zopp-db`
- Attach to app: `fly postgres attach zopp-db --app zopp-server`
- This automatically sets `DATABASE_URL` as a secret on the app
- zopp-server detects the postgres:// URL and uses PostgreSQL backend

**Health Checks:**
- zopp-server serves HTTP health on port 8080 by default (`--health-addr 0.0.0.0:8080`)
- Liveness: `GET /healthz` → 200 "ok"
- Readiness: `GET /readyz` → 200 when gRPC ready, 503 otherwise
- Fly uses checks to determine if a Machine is healthy

**TLS:**
- Fly automatically terminates TLS at the edge
- Internal traffic within Fly's network is h2c (HTTP/2 cleartext)
- No need for `--tls-cert` / `--tls-key` flags on the server
- CLI connects to `https://<app>.fly.dev:443` — Fly routes to internal port 50051

**Invite Token Generation:**
- Users run: `fly ssh console -C "/usr/local/bin/zopp-server invite create"`
- The zopp-server binary is at `/usr/local/bin/zopp-server` in the Docker image
- This outputs an invite token that can be shared
- Note: The `invite create` subcommand on the server binary creates a bootstrap invite

**CLI Connection:**
- After deployment, the server is available at `https://<appname>.fly.dev`
- Users configure their CLI: `zopp join <invite-token> <email> --server https://<appname>.fly.dev`

### Environment Variables Reference

**Required (set automatically by Fly Postgres attach):**
- `DATABASE_URL` — PostgreSQL connection string

**Optional:**
- `ZOPP_EMAIL_VERIFICATION_REQUIRED` — "true"/"false" (default "true")
- `ZOPP_EMAIL_PROVIDER` — "resend" or "smtp"
- `ZOPP_EMAIL_FROM` — Sender email address
- `RESEND_API_KEY` — If using Resend email provider
- SMTP variables if using SMTP

### Architecture Notes

- This story is purely configuration/documentation — no Rust code changes
- The existing `server.Dockerfile` is used as-is (Fly builds from Dockerfile)
- The `deploy/` directory is new; this is the first deployment template
- Follow similar patterns to the Helm chart in `charts/zopp/` for reference on configuration values

### Project Structure Notes

- New directory: `deploy/fly/`
- Files: `deploy/fly/fly.toml`, `deploy/fly/README.md`
- No changes to existing source code
- No Cargo.toml changes

### References

- [Source: server.Dockerfile] — Docker build for zopp-server
- [Source: apps/zopp-server/src/main.rs] — Server startup, health check endpoints, CLI args
- [Source: charts/zopp/values.yaml] — Helm chart defaults (reference for env vars)
- [Source: CLAUDE.md] — Server commands, TLS configuration, DATABASE_URL usage

### Pre-Submission Checklist

Before submitting a PR, verify each item relevant to your story's scope.

**Documentation:**

- [ ] fly.toml uses correct ports (50051 gRPC, 8080 health)
- [ ] README instructions are accurate and complete
- [ ] No secrets or credentials appear in template files
- [ ] Environment variable documentation matches server implementation

## Dev Agent Record

### Agent Model Used

Claude Opus 4.6

### Debug Log References

### Completion Notes List

- Created fly.toml with gRPC on port 50051, health checks on port 8080
- PostgreSQL via Fly Postgres attach (sets DATABASE_URL automatically)
- TLS handled by Fly edge — no server-side TLS config needed
- README covers full deployment workflow: launch, postgres, deploy, invite, connect CLI
- Email verification disabled by default in template (enable after configuring email provider)

### File List

- deploy/fly/fly.toml (new) — Fly deployment configuration
- deploy/fly/README.md (new) — Step-by-step deployment instructions

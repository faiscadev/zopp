# Deployment Guide

> Generated: 2026-03-01 | Scan Level: Exhaustive

## Deployment Options

| Method | Best For | Complexity |
|--------|----------|-----------|
| Docker Compose | Small teams, quick setup | Low |
| Helm on Kubernetes | Production, scaling | Medium |
| Terraform + EKS | AWS production | High |

## Docker Images

All images published to `ghcr.io/faiscadev/`:

| Image | Port | Purpose |
|-------|------|---------|
| `zopp-server` | 50051 (gRPC), 8080 (HTTP) | Main server |
| `zopp-operator` | 8080 (health) | K8s operator |
| `zopp-cli` | — | CLI client |

Images are multi-arch: `linux/amd64` + `linux/arm64`.

### Docker Compose (Simple Deployment)

See `examples/docker-compose/` for ready-to-use examples.

```bash
# SQLite (simplest)
docker run -p 50051:50051 -v zopp-data:/data zopp-server:latest

# PostgreSQL
docker run -e DATABASE_URL=postgres://user:pass@host/db -p 50051:50051 zopp-server:latest

# With TLS
docker run -v /certs:/certs -p 50051:50051 zopp-server:latest \
  serve --tls-cert /certs/server.crt --tls-key /certs/server.key
```

## Kubernetes (Helm)

### Install

```bash
# Add the chart
helm install zopp oci://ghcr.io/faiscadev/charts/zopp

# Or from source
helm install zopp ./charts/zopp
```

### Configuration

Key `values.yaml` settings:

**Server:**
- `server.enabled`: true (default)
- `server.image.repository`: `ghcr.io/faiscadev/zopp-server`
- `server.replicaCount`: 1 (default)
- `server.service.grpcPort`: 50051
- `server.service.httpPort`: 8080

**Database:**
- `database.type`: `sqlite` (default) or `postgresql`
- `database.sqlite.path`: `/data/zopp.db`
- `database.sqlite.persistence.size`: `1Gi`
- `database.postgresql.url`: Connection string (or use secret)
- `database.postgresql.existingSecret`: K8s secret name

**Events Bus:**
- `eventsBus.backend`: `auto` (default), `memory`, or `postgres`
- Auto: Uses PostgreSQL events if DB is postgres, else memory

**Operator:**
- `operator.enabled`: false (default)
- `operator.credentials.existingSecret`: K8s secret with operator creds
- `operator.watchNamespace`: empty = cluster-wide

**TLS:**
- `tls.enabled`: false (default)
- `tls.certSecretName`: K8s TLS secret

**Monitoring:**
- `prometheus.enabled`: false (default)
- `prometheus.serviceMonitor.enabled`: false

**Autoscaling:**
- `autoscaling.enabled`: false (default)
- `autoscaling.minReplicas`: 1
- `autoscaling.maxReplicas`: 10

### Example Configurations

```bash
# SQLite (development)
helm install zopp ./charts/zopp

# PostgreSQL (production)
helm install zopp ./charts/zopp \
  --set database.type=postgresql \
  --set database.postgresql.url=postgres://user:pass@host/db

# Full production (server + operator + TLS + monitoring)
helm install zopp ./charts/zopp \
  --set database.type=postgresql \
  --set database.postgresql.existingSecret=zopp-db-creds \
  --set operator.enabled=true \
  --set operator.credentials.existingSecret=zopp-operator-creds \
  --set tls.enabled=true \
  --set tls.certSecretName=zopp-tls \
  --set prometheus.enabled=true
```

## AWS Infrastructure (Terraform)

Located in `infra/terraform/`.

### Resources Provisioned

| Resource | Service | Details |
|----------|---------|---------|
| VPC | Networking | 3 AZs, public/private/database subnets |
| EKS | Kubernetes | v1.29, managed node groups (t3.medium) |
| RDS | Database | PostgreSQL 16, encrypted, auto-scaling |
| ECR | Registry | 3 repos (server, operator, web) |
| Route53 | DNS | Optional, with ACM certificate |
| IAM | Access | IRSA roles, GitHub Actions OIDC |
| Secrets Manager | Credentials | RDS credentials |

### Deploy

```bash
cd infra/terraform

# Configure
cp environments/staging.tfvars terraform.tfvars
# Edit terraform.tfvars with your settings

terraform init
terraform plan
terraform apply
```

### Key Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `aws_region` | `us-east-1` | AWS region |
| `environment` | — | `staging` or `production` |
| `eks_cluster_version` | `1.29` | Kubernetes version |
| `eks_node_instance_types` | `[t3.medium]` | Node instance types |
| `db_instance_class` | `db.t3.medium` | RDS instance class |
| `domain_name` | — | Optional domain |
| `eks_public_access_cidrs` | — | Must be explicitly set |

## CI/CD Pipeline

11 GitHub Actions workflows:

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| `build.yaml` | All pushes | Cross-platform build (Linux/macOS/Windows) |
| `test.yaml` | All pushes | Unit tests + coverage |
| `lint.yaml` | All pushes | rustfmt + clippy |
| `e2e.yaml` | main + PRs | E2E tests (4 backend combos) |
| `web-e2e.yaml` | All pushes | Playwright web tests |
| `audit.yaml` | Weekly + push | Dependency vulnerability scan |
| `docker.yaml` | main + tags | Multi-arch Docker images → ghcr.io |
| `cli-release.yaml` | Tags (v*) | CLI binaries → GitHub Releases |
| `helm-release.yaml` | Tags (v*) | Helm chart → OCI registry |
| `helm.yaml` | charts/** changes | Helm lint + template validation |
| `docs.yaml` | docs/** changes | Docusaurus → GitHub Pages |

### Release Flow

1. Tag push (`v*.*.*`) triggers:
   - `cli-release.yaml` → 5 platform binaries to GitHub Releases
   - `docker.yaml` → Multi-arch images with semver tags to ghcr.io
   - `helm-release.yaml` → Waits for CLI, packages chart to OCI registry
2. Coverage reports deployed to GitHub Pages alongside docs

## Health Endpoints

**Server:**
- `GET /healthz` — Liveness probe (always 200)
- `GET /readyz` — Readiness probe (200 when gRPC bound)
- `GET /metrics` — Prometheus metrics

**Operator:**
- `GET /health` — Liveness probe (always 200)
- `GET /ready` — Readiness probe (verifies gRPC connection)

## Security Considerations

- All containers run as non-root user (UID 1000)
- EBS volumes encrypted (Terraform)
- RDS deletion protection enabled in production
- GitHub Actions OIDC scoped to main branch + release tags
- Secrets Manager for database credentials
- TLS configurable for all components
- Network policies available via Helm

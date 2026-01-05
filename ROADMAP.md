# Roadmap

## Features

Core functionality needed for production use:

- [ ] **RBAC**
  - Roles: admin, write, read-only
  - Permissions at workspace/project/environment level (not per-secret)
  - Principals (not users) have permissions
  - Privilege escalation prevention: can only create principals with subset of your permissions
  - Example: read-only principal on prod can't create write principals for prod

- [ ] **Audit logging**
  - Track who (principal) accessed/modified which secrets when
  - Immutable audit trail
  - Queryable for compliance

- [ ] **Secret versioning/rollback**
  - Keep history of secret changes
  - Ability to rollback to previous version
  - Track who changed what when

- [ ] **Migration tooling**
  - Import from .env files
  - Import from 1Password
  - Import from AWS Secrets Manager
  - Import from HashiCorp Vault

## Documentation

Guides needed for teams to adopt:

- [ ] **Production deployment guide**
  - K8s + PostgreSQL setup
  - RDS configuration
  - TLS/mTLS configuration
  - Resource requirements

- [ ] **Migration guide**
  - How to migrate from 1Password, AWS SM, etc.
  - Step-by-step onboarding for existing teams
  - Common gotchas

- [ ] **Security architecture/threat model**
  - Zero-knowledge architecture explanation
  - What the server can/cannot see
  - Attack vectors and mitigations
  - Key management best practices

## Observability

Operational visibility for production:

- [ ] **Structured logging (JSON)**
  - Replace println! with structured logs
  - Include request IDs, principal IDs, timestamps
  - Ready for aggregation (Datadog, Splunk, etc.)

- [ ] **Metrics (Prometheus)**
  - RPC latency histograms
  - Error rates by RPC method
  - Active connections
  - Database query performance
  - Cache hit rates

## Developer Experience

Making zopp easy to use:

- [ ] **Better error messages**
  - Clear actionable errors (not just "failed to decrypt")
  - Suggestions for common mistakes
  - Better CLI help text

- [ ] **Integration examples**
  - GitHub Actions workflow
  - GitLab CI example
  - Docker Compose setup
  - Local development patterns

## Trust

Building confidence for security/leadership approval:

- [ ] **Security documentation**
  - Threat model document
  - Security best practices
  - Incident response procedures
  - Responsible disclosure policy

- [ ] **Dependency audit**
  - Review all third-party crates
  - Document critical dependencies
  - Supply chain security posture

## Contributing

See [DEVELOPMENT.md](./DEVELOPMENT.md) for how to contribute to these roadmap items.

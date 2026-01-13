# Testing Standards

## Philosophy

1. **E2E tests** verify features work across all backend combinations
2. **Unit tests** aim for 100% coverage with real implementations

## E2E Tests

Location: `apps/e2e-tests/`

### Requirements

- Every user-facing feature must have an E2E test
- Tests run against all backend combinations:
  | Storage    | Events     |
  |------------|------------|
  | SQLite     | Memory     |
  | SQLite     | PostgreSQL |
  | PostgreSQL | Memory     |
  | PostgreSQL | PostgreSQL |
- Tests use real binaries (`zopp`, `zopp-server`, `zopp-operator`)

### Running

```bash
cargo build --bins
cargo test --package e2e-tests
```

## Unit Tests

Location: alongside code in `crates/` and `apps/`

### Requirements

- Aim for 100% line coverage for both crates and apps
- Both `crates/` (libraries) and `apps/` (binaries) must have unit tests
- Apps have testable functions (crypto, config parsing, request signing, etc.)
- Use real implementations when testing trait implementations
- Only mock to reproduce specific error conditions

### Running

```bash
# Run all unit tests (excludes e2e-tests)
cargo test --workspace --exclude e2e-tests

# Generate coverage report
./scripts/unit-coverage.sh
```

## Mocking Policy

**When testing a trait implementation** (e.g., `zopp-store-sqlite` implementing `Store`):
- Use real dependencies (real SQLite, real PostgreSQL)
- No mocks

**When testing code that consumes an abstraction** (e.g., code that takes `impl Store`):
- Mock implementations are acceptable
- Useful for testing error handling, edge cases

**Example:**
```rust
// Testing zopp-store-sqlite → use real SQLite
let store = SqliteStore::open_in_memory().await?;

// Testing business logic that uses Store → mock is OK
struct MockStore { ... }
impl Store for MockStore { ... }
```

Mocking is also acceptable for:
- Simulating network failures
- Reproducing race conditions
- Forcing specific error paths

## When E2E is More Practical

Some code is easier to test via E2E than unit tests:

- **CLI commands**: Thin wrappers around gRPC calls. The actual logic (crypto, config) lives in crates.
- **Server handlers**: Require authenticated requests. Handler logic is tested via E2E.
- **Operator**: Requires Kubernetes APIs. K8s integration is tested via E2E with kind clusters.

## PostgreSQL Testing

For `zopp-store-postgres` coverage:
```bash
# Start PostgreSQL
docker run --name zopp-postgres -e POSTGRES_PASSWORD=postgres -p 5432:5432 -d postgres:16

# Run tests with PostgreSQL
DATABASE_URL=postgres://postgres:postgres@localhost/postgres cargo test --package zopp-store-postgres
```

CI uses PostgreSQL services for E2E tests across all backend combinations.

## RBAC Testing

Location: `apps/e2e-tests/tests/rbac.rs`

### When to Add RBAC Tests

Add RBAC tests when implementing features that involve:

- **Permission checks**: Any server handler that checks Admin/Write/Read roles
- **New CLI commands**: Commands that require specific permission levels
- **Permission inheritance**: Features where workspace/project/environment permissions cascade

### What to Test

1. **Admin-only operations**: Verify admin can access, write/read cannot
2. **Write operations**: Verify write+ can perform, read cannot
3. **Read operations**: Verify read+ can perform, no permission cannot
4. **Permission delegation**: Verify users can only grant permissions up to their own level

### Example RBAC Test Pattern

```rust
#[tokio::test]
async fn test_feature_requires_admin() -> Result<(), Box<dyn std::error::Error>> {
    let port = find_available_port()?;
    let env = TestEnv::setup("feature_rbac", port).await?;

    let alice = env.create_user("alice"); // Will be admin (owner)
    let bob = env.create_user("bob");     // Will be write
    let charlie = env.create_user("charlie"); // Will be read

    // Setup: Alice creates workspace
    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;

    // Test 1: Admin CAN use feature
    let output = env.feature_command(&alice, "acme");
    assert_success(&output, "Admin can use feature");

    // Test 2: Write role CANNOT use feature
    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;
    env.set_user_permission(&alice, "acme", &bob.email, "write")?;

    let output = env.feature_command(&bob, "acme");
    assert_denied(&output, "Write role cannot use feature");

    // Test 3: Read role CANNOT use feature
    let ws_invite2 = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&charlie, &ws_invite2)?;
    env.set_user_permission(&alice, "acme", &charlie.email, "read")?;

    let output = env.feature_command(&charlie, "acme");
    assert_denied(&output, "Read role cannot use feature");

    Ok(())
}
```

### RBAC Test Helpers

The `TestEnv` struct in `rbac.rs` provides many helper methods:
- `set_user_permission()`, `set_principal_permission()` - Set workspace permissions
- `set_user_project_permission()` - Set project permissions
- `set_principal_env_permission_check()` - Set environment permissions
- `assert_success()`, `assert_denied()` - Check command results

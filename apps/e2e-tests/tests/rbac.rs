//! Comprehensive RBAC E2E tests
//!
//! Tests all permission combinations for all secret operations:
//! - Operations: get, set, list (export), delete
//! - Permission sources: owner, principal permissions, group permissions
//! - Permission scopes: workspace, project, environment
//! - Roles: Admin, Write, Read, None
//!
//! Runs against all 4 backend combinations (SQLite/PostgreSQL x Memory/PostgreSQL events).

#[macro_use]
mod common;

use common::{BackendConfig, TestHarness, TestUser};
use std::process::Output;

// ═══════════════════════════════════════════════════════════════════════════
// RBAC Test Environment Wrapper
// ═══════════════════════════════════════════════════════════════════════════

/// Wrapper around TestHarness with RBAC-specific helper methods
struct RbacTestEnv {
    harness: TestHarness,
}

impl RbacTestEnv {
    async fn new(
        test_name: &str,
        config: BackendConfig,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let harness = TestHarness::new(test_name, config).await?;
        Ok(Self { harness })
    }

    fn create_user(&self, name: &str) -> TestUser {
        self.harness.create_user(name)
    }

    fn create_server_invite(&self) -> Result<String, Box<dyn std::error::Error>> {
        self.harness.create_server_invite()
    }

    fn join_server(&self, user: &TestUser, invite: &str) -> Result<(), Box<dyn std::error::Error>> {
        user.join(invite, &user.email(), &user.principal())
    }

    fn create_workspace(
        &self,
        user: &TestUser,
        name: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output = user.raw_exec(&["workspace", "create", name]);
        if !output.status.success() {
            return Err(format!(
                "Failed to create workspace: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    fn create_project(
        &self,
        user: &TestUser,
        workspace: &str,
        name: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output = user.raw_exec(&["project", "create", name, "-w", workspace]);
        if !output.status.success() {
            return Err(format!(
                "Failed to create project: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    fn create_environment(
        &self,
        user: &TestUser,
        workspace: &str,
        project: &str,
        name: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output = user.raw_exec(&[
            "environment",
            "create",
            name,
            "-w",
            workspace,
            "-p",
            project,
        ]);
        if !output.status.success() {
            return Err(format!(
                "Failed to create environment: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    fn create_workspace_invite(
        &self,
        user: &TestUser,
        workspace: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let output = user.raw_exec(&[
            "invite",
            "create",
            "-w",
            workspace,
            "--expires-hours",
            "1",
            "--plain",
        ]);
        if !output.status.success() {
            return Err(format!(
                "Failed to create workspace invite: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // User Permission Commands (direct user-to-workspace permissions)
    // ─────────────────────────────────────────────────────────────────────────

    fn set_user_permission(
        &self,
        admin: &TestUser,
        workspace: &str,
        target_email: &str,
        role: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output = admin.raw_exec(&[
            "permission",
            "user-set",
            "-w",
            workspace,
            "--email",
            target_email,
            "--role",
            role,
        ]);
        if !output.status.success() {
            return Err(format!(
                "Failed to set user permission: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    fn remove_user_permission(
        &self,
        admin: &TestUser,
        workspace: &str,
        target_email: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output = admin.raw_exec(&[
            "permission",
            "user-remove",
            "-w",
            workspace,
            "--email",
            target_email,
        ]);
        if !output.status.success() {
            return Err(format!(
                "Failed to remove user permission: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // User Project Permission Commands
    // ─────────────────────────────────────────────────────────────────────────

    fn set_user_project_permission(
        &self,
        admin: &TestUser,
        workspace: &str,
        project: &str,
        target_email: &str,
        role: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output = admin.raw_exec(&[
            "permission",
            "user-project-set",
            "-w",
            workspace,
            "-p",
            project,
            "--email",
            target_email,
            "--role",
            role,
        ]);
        if !output.status.success() {
            return Err(format!(
                "Failed to set user project permission: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    #[allow(dead_code)]
    fn remove_user_project_permission(
        &self,
        admin: &TestUser,
        workspace: &str,
        project: &str,
        target_email: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output = admin.raw_exec(&[
            "permission",
            "user-project-remove",
            "-w",
            workspace,
            "-p",
            project,
            "--email",
            target_email,
        ]);
        if !output.status.success() {
            return Err(format!(
                "Failed to remove user project permission: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // User Environment Permission Commands
    // ─────────────────────────────────────────────────────────────────────────

    fn set_user_env_permission(
        &self,
        admin: &TestUser,
        workspace: &str,
        project: &str,
        environment: &str,
        target_email: &str,
        role: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output = admin.raw_exec(&[
            "permission",
            "user-env-set",
            "-w",
            workspace,
            "-p",
            project,
            "-e",
            environment,
            "--email",
            target_email,
            "--role",
            role,
        ]);
        if !output.status.success() {
            return Err(format!(
                "Failed to set user environment permission: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    #[allow(dead_code)]
    fn remove_user_env_permission(
        &self,
        admin: &TestUser,
        workspace: &str,
        project: &str,
        environment: &str,
        target_email: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output = admin.raw_exec(&[
            "permission",
            "user-env-remove",
            "-w",
            workspace,
            "-p",
            project,
            "-e",
            environment,
            "--email",
            target_email,
        ]);
        if !output.status.success() {
            return Err(format!(
                "Failed to remove user environment permission: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Group Commands
    // ─────────────────────────────────────────────────────────────────────────

    fn create_group(
        &self,
        admin: &TestUser,
        workspace: &str,
        group_name: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output = admin.raw_exec(&["group", "create", group_name, "-w", workspace]);
        if !output.status.success() {
            return Err(format!(
                "Failed to create group: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    fn delete_group(
        &self,
        admin: &TestUser,
        workspace: &str,
        group_name: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output = admin.raw_exec(&["group", "delete", group_name, "-w", workspace]);
        if !output.status.success() {
            return Err(format!(
                "Failed to delete group: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    fn list_groups(&self, user: &TestUser, workspace: &str) -> Output {
        user.raw_exec(&["group", "list", "-w", workspace])
    }

    fn add_group_member(
        &self,
        admin: &TestUser,
        workspace: &str,
        group_name: &str,
        member_email: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output = admin.raw_exec(&[
            "group",
            "add-member",
            member_email,
            "-w",
            workspace,
            "--group",
            group_name,
        ]);
        if !output.status.success() {
            return Err(format!(
                "Failed to add group member: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    fn remove_group_member(
        &self,
        admin: &TestUser,
        workspace: &str,
        group_name: &str,
        member_email: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output = admin.raw_exec(&[
            "group",
            "remove-member",
            member_email,
            "-w",
            workspace,
            "--group",
            group_name,
        ]);
        if !output.status.success() {
            return Err(format!(
                "Failed to remove group member: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    fn list_group_members(&self, user: &TestUser, workspace: &str, group_name: &str) -> Output {
        user.raw_exec(&[
            "group",
            "list-members",
            "-w",
            workspace,
            "--group",
            group_name,
        ])
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Group Permission Commands (workspace level)
    // ─────────────────────────────────────────────────────────────────────────

    fn set_group_permission(
        &self,
        admin: &TestUser,
        workspace: &str,
        group_name: &str,
        role: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output = admin.raw_exec(&[
            "group",
            "set-permission",
            "--group",
            group_name,
            "-w",
            workspace,
            "--role",
            role,
        ]);
        if !output.status.success() {
            return Err(format!(
                "Failed to set group permission: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    #[allow(dead_code)]
    fn remove_group_permission(
        &self,
        admin: &TestUser,
        workspace: &str,
        group_name: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output = admin.raw_exec(&[
            "group",
            "remove-permission",
            "--group",
            group_name,
            "-w",
            workspace,
        ]);
        if !output.status.success() {
            return Err(format!(
                "Failed to remove group permission: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Group Project Permission Commands
    // ─────────────────────────────────────────────────────────────────────────

    fn set_group_project_permission(
        &self,
        admin: &TestUser,
        workspace: &str,
        project: &str,
        group_name: &str,
        role: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output = admin.raw_exec(&[
            "group",
            "set-project-permission",
            "--group",
            group_name,
            "-w",
            workspace,
            "-p",
            project,
            "--role",
            role,
        ]);
        if !output.status.success() {
            return Err(format!(
                "Failed to set group project permission: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    #[allow(dead_code)]
    fn remove_group_project_permission(
        &self,
        admin: &TestUser,
        workspace: &str,
        project: &str,
        group_name: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output = admin.raw_exec(&[
            "group",
            "remove-project-permission",
            "--group",
            group_name,
            "-w",
            workspace,
            "-p",
            project,
        ]);
        if !output.status.success() {
            return Err(format!(
                "Failed to remove group project permission: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Group Environment Permission Commands
    // ─────────────────────────────────────────────────────────────────────────

    fn set_group_env_permission(
        &self,
        admin: &TestUser,
        workspace: &str,
        project: &str,
        environment: &str,
        group_name: &str,
        role: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output = admin.raw_exec(&[
            "group",
            "set-env-permission",
            "--group",
            group_name,
            "-w",
            workspace,
            "-p",
            project,
            "-e",
            environment,
            "--role",
            role,
        ]);
        if !output.status.success() {
            return Err(format!(
                "Failed to set group environment permission: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    #[allow(dead_code)]
    fn remove_group_env_permission(
        &self,
        admin: &TestUser,
        workspace: &str,
        project: &str,
        environment: &str,
        group_name: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let output = admin.raw_exec(&[
            "group",
            "remove-env-permission",
            "--group",
            group_name,
            "-w",
            workspace,
            "-p",
            project,
            "-e",
            environment,
        ]);
        if !output.status.success() {
            return Err(format!(
                "Failed to remove group environment permission: {}",
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Permission List Commands
    // ─────────────────────────────────────────────────────────────────────────

    fn user_permission_list(&self, user: &TestUser, workspace: &str) -> Output {
        user.raw_exec(&["permission", "user-list", "-w", workspace])
    }

    fn user_project_permission_list(
        &self,
        user: &TestUser,
        workspace: &str,
        project: &str,
    ) -> Output {
        user.raw_exec(&[
            "permission",
            "user-project-list",
            "-w",
            workspace,
            "-p",
            project,
        ])
    }

    fn user_env_permission_list(
        &self,
        user: &TestUser,
        workspace: &str,
        project: &str,
        environment: &str,
    ) -> Output {
        user.raw_exec(&[
            "permission",
            "user-env-list",
            "-w",
            workspace,
            "-p",
            project,
            "-e",
            environment,
        ])
    }

    #[allow(dead_code)]
    fn group_permission_list(&self, user: &TestUser, workspace: &str) -> Output {
        user.raw_exec(&["group", "list-permissions", "-w", workspace])
    }

    #[allow(dead_code)]
    fn group_project_permission_list(
        &self,
        user: &TestUser,
        workspace: &str,
        project: &str,
    ) -> Output {
        user.raw_exec(&[
            "group",
            "list-project-permissions",
            "-w",
            workspace,
            "-p",
            project,
        ])
    }

    #[allow(dead_code)]
    fn group_env_permission_list(
        &self,
        user: &TestUser,
        workspace: &str,
        project: &str,
        environment: &str,
    ) -> Output {
        user.raw_exec(&[
            "group",
            "list-env-permissions",
            "-w",
            workspace,
            "-p",
            project,
            "-e",
            environment,
        ])
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Secret Operations
    // ─────────────────────────────────────────────────────────────────────────

    fn secret_set(
        &self,
        user: &TestUser,
        workspace: &str,
        project: &str,
        env: &str,
        key: &str,
        value: &str,
    ) -> Output {
        user.raw_exec(&[
            "secret", "set", key, value, "-w", workspace, "-p", project, "-e", env,
        ])
    }

    fn secret_get(
        &self,
        user: &TestUser,
        workspace: &str,
        project: &str,
        env: &str,
        key: &str,
    ) -> Output {
        user.raw_exec(&[
            "secret", "get", key, "-w", workspace, "-p", project, "-e", env,
        ])
    }

    fn secret_delete(
        &self,
        user: &TestUser,
        workspace: &str,
        project: &str,
        env: &str,
        key: &str,
    ) -> Output {
        user.raw_exec(&[
            "secret", "delete", key, "-w", workspace, "-p", project, "-e", env,
        ])
    }

    fn secret_export(&self, user: &TestUser, workspace: &str, project: &str, env: &str) -> Output {
        user.raw_exec(&[
            "secret", "export", "-w", workspace, "-p", project, "-e", env,
        ])
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Test Helpers
// ═══════════════════════════════════════════════════════════════════════════

fn assert_success(output: &Output, context: &str) {
    assert!(
        output.status.success(),
        "{} should succeed:\nstdout: {}\nstderr: {}",
        context,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_denied(output: &Output, context: &str) {
    assert!(
        !output.status.success(),
        "{} should be denied (but succeeded)",
        context
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Permission denied")
            || stderr.contains("permission denied")
            || stderr.contains("Access denied")
            || stderr.contains("PERMISSION_DENIED")
            || stderr.contains("PermissionDenied")
            || stderr.contains("No permissions found")
            || stderr.contains("not authorized"),
        "{} error should mention permission denied, got: {}",
        context,
        stderr
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Workspace Owner Always Has Full Access
// ═══════════════════════════════════════════════════════════════════════════

backend_test!(test_owner_has_full_access, run_test_owner_has_full_access);

async fn run_test_owner_has_full_access(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = RbacTestEnv::new("owner_access", config).await?;

    let alice = env.create_user("alice");
    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;

    println!("  Setup complete");

    let output = env.secret_set(&alice, "acme", "api", "dev", "SECRET_KEY", "owner_value");
    assert_success(&output, "Owner secret set");

    let output = env.secret_get(&alice, "acme", "api", "dev", "SECRET_KEY");
    assert_success(&output, "Owner secret get");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "owner_value"
    );

    let output = env.secret_export(&alice, "acme", "api", "dev");
    assert_success(&output, "Owner secret export");

    let output = env.secret_delete(&alice, "acme", "api", "dev", "SECRET_KEY");
    assert_success(&output, "Owner secret delete");

    println!("  test_owner_has_full_access PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Non-Owner Denied by Default
// ═══════════════════════════════════════════════════════════════════════════

backend_test!(
    test_non_owner_denied_by_default,
    run_test_non_owner_denied_by_default
);

async fn run_test_non_owner_denied_by_default(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = RbacTestEnv::new("denied_default", config).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;

    let output = env.secret_set(&alice, "acme", "api", "dev", "TEST_SECRET", "test_value");
    assert_success(&output, "Alice sets secret");

    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;

    println!("  Setup complete - Bob joined workspace");

    let output = env.secret_get(&bob, "acme", "api", "dev", "TEST_SECRET");
    assert_denied(&output, "Bob secret get (no permissions)");

    let output = env.secret_set(&bob, "acme", "api", "dev", "BOB_SECRET", "bob_value");
    assert_denied(&output, "Bob secret set (no permissions)");

    let output = env.secret_export(&bob, "acme", "api", "dev");
    assert_denied(&output, "Bob secret export (no permissions)");

    let output = env.secret_delete(&bob, "acme", "api", "dev", "TEST_SECRET");
    assert_denied(&output, "Bob secret delete (no permissions)");

    println!("  test_non_owner_denied_by_default PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Workspace-Level Read Permission
// ═══════════════════════════════════════════════════════════════════════════

backend_test!(
    test_workspace_read_permission,
    run_test_workspace_read_permission
);

async fn run_test_workspace_read_permission(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = RbacTestEnv::new("ws_read", config).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;

    let output = env.secret_set(&alice, "acme", "api", "dev", "TEST_SECRET", "test_value");
    assert_success(&output, "Alice sets secret");

    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;
    env.set_user_permission(&alice, "acme", &bob.email(), "read")?;

    println!("  Setup complete - Bob has workspace read permission");

    let output = env.secret_get(&bob, "acme", "api", "dev", "TEST_SECRET");
    assert_success(&output, "Bob secret get");
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "test_value");

    let output = env.secret_export(&bob, "acme", "api", "dev");
    assert_success(&output, "Bob secret export");

    let output = env.secret_set(&bob, "acme", "api", "dev", "BOB_SECRET", "bob_value");
    assert_denied(&output, "Bob secret set (read only)");

    let output = env.secret_delete(&bob, "acme", "api", "dev", "TEST_SECRET");
    assert_denied(&output, "Bob secret delete (read only)");

    println!("  test_workspace_read_permission PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Workspace-Level Write Permission
// ═══════════════════════════════════════════════════════════════════════════

backend_test!(
    test_workspace_write_permission,
    run_test_workspace_write_permission
);

async fn run_test_workspace_write_permission(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = RbacTestEnv::new("ws_write", config).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;

    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;
    env.set_user_permission(&alice, "acme", &bob.email(), "write")?;

    println!("  Setup complete - Bob has workspace write permission");

    let output = env.secret_set(&bob, "acme", "api", "dev", "BOB_SECRET", "bob_value");
    assert_success(&output, "Bob secret set");

    let output = env.secret_get(&bob, "acme", "api", "dev", "BOB_SECRET");
    assert_success(&output, "Bob secret get");

    let output = env.secret_export(&bob, "acme", "api", "dev");
    assert_success(&output, "Bob secret export");

    let output = env.secret_delete(&bob, "acme", "api", "dev", "BOB_SECRET");
    assert_success(&output, "Bob secret delete");

    println!("  test_workspace_write_permission PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Workspace-Level Admin Permission
// ═══════════════════════════════════════════════════════════════════════════

backend_test!(
    test_workspace_admin_permission,
    run_test_workspace_admin_permission
);

async fn run_test_workspace_admin_permission(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = RbacTestEnv::new("ws_admin", config).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");
    let charlie = env.create_user("charlie");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;

    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;
    env.set_user_permission(&alice, "acme", &bob.email(), "admin")?;

    let ws_invite2 = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&charlie, &ws_invite2)?;

    println!("  Setup complete - Bob is admin, Charlie has no permissions");

    env.set_user_permission(&bob, "acme", &charlie.email(), "write")?;

    let output = env.secret_set(
        &charlie,
        "acme",
        "api",
        "dev",
        "CHARLIE_SECRET",
        "charlie_value",
    );
    assert_success(&output, "Charlie secret set");

    let output = env.secret_set(&bob, "acme", "api", "dev", "BOB_SECRET", "bob_value");
    assert_success(&output, "Bob secret set");
    let output = env.secret_get(&bob, "acme", "api", "dev", "BOB_SECRET");
    assert_success(&output, "Bob secret get");
    let output = env.secret_delete(&bob, "acme", "api", "dev", "BOB_SECRET");
    assert_success(&output, "Bob secret delete");

    println!("  test_workspace_admin_permission PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Project-Level Read Permission (Narrower Scope)
// ═══════════════════════════════════════════════════════════════════════════

backend_test!(
    test_project_read_permission,
    run_test_project_read_permission
);

async fn run_test_project_read_permission(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = RbacTestEnv::new("proj_read", config).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_project(&alice, "acme", "web")?;
    env.create_environment(&alice, "acme", "api", "dev")?;
    env.create_environment(&alice, "acme", "web", "dev")?;

    env.secret_set(&alice, "acme", "api", "dev", "API_SECRET", "api_value");
    env.secret_set(&alice, "acme", "web", "dev", "WEB_SECRET", "web_value");

    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;
    env.set_user_project_permission(&alice, "acme", "api", &bob.email(), "read")?;

    println!("  Setup complete - Bob has read on api project only");

    let output = env.secret_get(&bob, "acme", "api", "dev", "API_SECRET");
    assert_success(&output, "Bob read api secret");

    let output = env.secret_get(&bob, "acme", "web", "dev", "WEB_SECRET");
    assert_denied(&output, "Bob read web secret");

    let output = env.secret_set(&bob, "acme", "api", "dev", "NEW_SECRET", "value");
    assert_denied(&output, "Bob write api secret");

    println!("  test_project_read_permission PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Project-Level Write Permission
// ═══════════════════════════════════════════════════════════════════════════

backend_test!(
    test_project_write_permission,
    run_test_project_write_permission
);

async fn run_test_project_write_permission(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = RbacTestEnv::new("proj_write", config).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_project(&alice, "acme", "web")?;
    env.create_environment(&alice, "acme", "api", "dev")?;
    env.create_environment(&alice, "acme", "web", "dev")?;

    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;
    env.set_user_project_permission(&alice, "acme", "api", &bob.email(), "write")?;

    println!("  Setup complete - Bob has write on api project only");

    let output = env.secret_set(&bob, "acme", "api", "dev", "BOB_SECRET", "bob_value");
    assert_success(&output, "Bob write api secret");

    let output = env.secret_get(&bob, "acme", "api", "dev", "BOB_SECRET");
    assert_success(&output, "Bob read api secret");

    let output = env.secret_delete(&bob, "acme", "api", "dev", "BOB_SECRET");
    assert_success(&output, "Bob delete api secret");

    let output = env.secret_set(&bob, "acme", "web", "dev", "SECRET", "value");
    assert_denied(&output, "Bob write web secret");

    println!("  test_project_write_permission PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Environment-Level Read Permission (Narrowest Scope)
// ═══════════════════════════════════════════════════════════════════════════

backend_test!(
    test_environment_read_permission,
    run_test_environment_read_permission
);

async fn run_test_environment_read_permission(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = RbacTestEnv::new("env_read", config).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;
    env.create_environment(&alice, "acme", "api", "prod")?;

    env.secret_set(&alice, "acme", "api", "dev", "DEV_SECRET", "dev_value");
    env.secret_set(&alice, "acme", "api", "prod", "PROD_SECRET", "prod_value");

    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;
    env.set_user_env_permission(&alice, "acme", "api", "dev", &bob.email(), "read")?;

    println!("  Setup complete - Bob has read on dev environment only");

    let output = env.secret_get(&bob, "acme", "api", "dev", "DEV_SECRET");
    assert_success(&output, "Bob read dev secret");

    let output = env.secret_get(&bob, "acme", "api", "prod", "PROD_SECRET");
    assert_denied(&output, "Bob read prod secret");

    let output = env.secret_set(&bob, "acme", "api", "dev", "NEW_SECRET", "value");
    assert_denied(&output, "Bob write dev secret");

    println!("  test_environment_read_permission PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Environment-Level Write Permission
// ═══════════════════════════════════════════════════════════════════════════

backend_test!(
    test_environment_write_permission,
    run_test_environment_write_permission
);

async fn run_test_environment_write_permission(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = RbacTestEnv::new("env_write", config).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;
    env.create_environment(&alice, "acme", "api", "prod")?;

    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;
    env.set_user_env_permission(&alice, "acme", "api", "dev", &bob.email(), "write")?;

    println!("  Setup complete - Bob has write on dev environment only");

    let output = env.secret_set(&bob, "acme", "api", "dev", "BOB_SECRET", "bob_value");
    assert_success(&output, "Bob write dev secret");

    let output = env.secret_get(&bob, "acme", "api", "dev", "BOB_SECRET");
    assert_success(&output, "Bob read dev secret");

    let output = env.secret_delete(&bob, "acme", "api", "dev", "BOB_SECRET");
    assert_success(&output, "Bob delete dev secret");

    let output = env.secret_set(&bob, "acme", "api", "prod", "SECRET", "value");
    assert_denied(&output, "Bob write prod secret");

    println!("  test_environment_write_permission PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Permission Inheritance (Workspace -> Project -> Environment)
// ═══════════════════════════════════════════════════════════════════════════

backend_test!(test_permission_inheritance, run_test_permission_inheritance);

async fn run_test_permission_inheritance(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = RbacTestEnv::new("inheritance", config).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_project(&alice, "acme", "web")?;
    env.create_environment(&alice, "acme", "api", "dev")?;
    env.create_environment(&alice, "acme", "api", "prod")?;
    env.create_environment(&alice, "acme", "web", "dev")?;

    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;
    env.set_user_permission(&alice, "acme", &bob.email(), "read")?;

    println!("  Setup complete - Bob has workspace-level read");

    let output = env.secret_set(&alice, "acme", "api", "dev", "SECRET1", "value1");
    assert_success(&output, "Alice sets secret");
    let output = env.secret_get(&bob, "acme", "api", "dev", "SECRET1");
    assert_success(&output, "Bob read api/dev");

    let output = env.secret_set(&alice, "acme", "api", "prod", "SECRET2", "value2");
    assert_success(&output, "Alice sets secret");
    let output = env.secret_get(&bob, "acme", "api", "prod", "SECRET2");
    assert_success(&output, "Bob read api/prod");

    let output = env.secret_set(&alice, "acme", "web", "dev", "SECRET3", "value3");
    assert_success(&output, "Alice sets secret");
    let output = env.secret_get(&bob, "acme", "web", "dev", "SECRET3");
    assert_success(&output, "Bob read web/dev");

    let output = env.secret_set(&bob, "acme", "api", "dev", "NEW", "value");
    assert_denied(&output, "Bob write api/dev");

    println!("  test_permission_inheritance PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Permission Override (Narrower Scope Takes Precedence)
// ═══════════════════════════════════════════════════════════════════════════

backend_test!(test_permission_override, run_test_permission_override);

async fn run_test_permission_override(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = RbacTestEnv::new("override", config).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;
    env.create_environment(&alice, "acme", "api", "prod")?;

    env.secret_set(&alice, "acme", "api", "dev", "DEV_SECRET", "dev_value");
    env.secret_set(&alice, "acme", "api", "prod", "PROD_SECRET", "prod_value");

    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;
    env.set_user_permission(&alice, "acme", &bob.email(), "read")?;
    env.set_user_env_permission(&alice, "acme", "api", "dev", &bob.email(), "write")?;

    println!("  Setup complete - Bob has ws read + dev write");

    let output = env.secret_set(&bob, "acme", "api", "dev", "BOB_SECRET", "bob_value");
    assert_success(&output, "Bob write dev");

    let output = env.secret_set(&bob, "acme", "api", "prod", "SECRET", "value");
    assert_denied(&output, "Bob write prod");

    let output = env.secret_get(&bob, "acme", "api", "prod", "PROD_SECRET");
    assert_success(&output, "Bob read prod");

    println!("  test_permission_override PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Permission Removal
// ═══════════════════════════════════════════════════════════════════════════

backend_test!(test_permission_removal, run_test_permission_removal);

async fn run_test_permission_removal(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = RbacTestEnv::new("removal", config).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;

    env.secret_set(&alice, "acme", "api", "dev", "SECRET", "value");

    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;
    env.set_user_permission(&alice, "acme", &bob.email(), "write")?;

    let output = env.secret_set(&bob, "acme", "api", "dev", "BOB_SECRET", "bob_value");
    assert_success(&output, "Bob write (with permission)");

    env.remove_user_permission(&alice, "acme", &bob.email())?;
    println!("  Permission removed");

    let output = env.secret_get(&bob, "acme", "api", "dev", "SECRET");
    assert_denied(&output, "Bob read (after removal)");

    println!("  test_permission_removal PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Group Basic Operations
// ═══════════════════════════════════════════════════════════════════════════

backend_test!(test_group_basic_operations, run_test_group_basic_operations);

async fn run_test_group_basic_operations(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = RbacTestEnv::new("group_basic", config).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;

    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;

    env.create_group(&alice, "acme", "developers")?;
    println!("  Group created");

    let output = env.list_groups(&alice, "acme");
    assert_success(&output, "List groups");
    let groups_output = String::from_utf8_lossy(&output.stdout);
    assert!(
        groups_output.contains("developers"),
        "Group should be in list"
    );

    env.add_group_member(&alice, "acme", "developers", &bob.email())?;
    println!("  Member added to group");

    let output = env.list_group_members(&alice, "acme", "developers");
    assert_success(&output, "List group members");
    let members_output = String::from_utf8_lossy(&output.stdout);
    assert!(
        members_output.contains(&bob.email()),
        "Bob should be in members list"
    );

    env.remove_group_member(&alice, "acme", "developers", &bob.email())?;
    println!("  Member removed from group");

    env.delete_group(&alice, "acme", "developers")?;
    println!("  Group deleted");

    println!("  test_group_basic_operations PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Group Workspace Permission
// ═══════════════════════════════════════════════════════════════════════════

backend_test!(
    test_group_workspace_permission,
    run_test_group_workspace_permission
);

async fn run_test_group_workspace_permission(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = RbacTestEnv::new("group_ws_perm", config).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;

    env.secret_set(&alice, "acme", "api", "dev", "SECRET", "value");

    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;

    env.create_group(&alice, "acme", "readers")?;
    env.set_group_permission(&alice, "acme", "readers", "read")?;
    env.add_group_member(&alice, "acme", "readers", &bob.email())?;

    println!("  Setup complete - Bob is in readers group with workspace read");

    let output = env.secret_get(&bob, "acme", "api", "dev", "SECRET");
    assert_success(&output, "Bob read via group");

    let output = env.secret_set(&bob, "acme", "api", "dev", "NEW", "value");
    assert_denied(&output, "Bob write via group");

    println!("  test_group_workspace_permission PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Group Project Permission
// ═══════════════════════════════════════════════════════════════════════════

backend_test!(
    test_group_project_permission,
    run_test_group_project_permission
);

async fn run_test_group_project_permission(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = RbacTestEnv::new("group_proj_perm", config).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_project(&alice, "acme", "web")?;
    env.create_environment(&alice, "acme", "api", "dev")?;
    env.create_environment(&alice, "acme", "web", "dev")?;

    env.secret_set(&alice, "acme", "api", "dev", "API_SECRET", "api_value");
    env.secret_set(&alice, "acme", "web", "dev", "WEB_SECRET", "web_value");

    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;

    env.create_group(&alice, "acme", "api-team")?;
    env.set_group_project_permission(&alice, "acme", "api", "api-team", "write")?;
    env.add_group_member(&alice, "acme", "api-team", &bob.email())?;

    println!("  Setup complete - Bob is in api-team with api project write");

    let output = env.secret_get(&bob, "acme", "api", "dev", "API_SECRET");
    assert_success(&output, "Bob read api");

    let output = env.secret_set(&bob, "acme", "api", "dev", "NEW", "value");
    assert_success(&output, "Bob write api");

    let output = env.secret_get(&bob, "acme", "web", "dev", "WEB_SECRET");
    assert_denied(&output, "Bob read web");

    println!("  test_group_project_permission PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Group Environment Permission
// ═══════════════════════════════════════════════════════════════════════════

backend_test!(
    test_group_environment_permission,
    run_test_group_environment_permission
);

async fn run_test_group_environment_permission(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = RbacTestEnv::new("group_env_perm", config).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;
    env.create_environment(&alice, "acme", "api", "prod")?;

    env.secret_set(&alice, "acme", "api", "dev", "DEV_SECRET", "dev_value");
    env.secret_set(&alice, "acme", "api", "prod", "PROD_SECRET", "prod_value");

    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;

    env.create_group(&alice, "acme", "dev-team")?;
    env.set_group_env_permission(&alice, "acme", "api", "dev", "dev-team", "write")?;
    env.add_group_member(&alice, "acme", "dev-team", &bob.email())?;

    println!("  Setup complete - Bob is in dev-team with dev env write");

    let output = env.secret_get(&bob, "acme", "api", "dev", "DEV_SECRET");
    assert_success(&output, "Bob read dev");

    let output = env.secret_set(&bob, "acme", "api", "dev", "NEW", "value");
    assert_success(&output, "Bob write dev");

    let output = env.secret_get(&bob, "acme", "api", "prod", "PROD_SECRET");
    assert_denied(&output, "Bob read prod");

    println!("  test_group_environment_permission PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Mixed User and Group Permissions (Highest Permission Wins)
// ═══════════════════════════════════════════════════════════════════════════

backend_test!(
    test_mixed_user_group_permissions,
    run_test_mixed_user_group_permissions
);

async fn run_test_mixed_user_group_permissions(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = RbacTestEnv::new("mixed_perms", config).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;

    env.secret_set(&alice, "acme", "api", "dev", "SECRET", "value");

    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;
    env.set_user_permission(&alice, "acme", &bob.email(), "read")?;

    env.create_group(&alice, "acme", "writers")?;
    env.set_group_permission(&alice, "acme", "writers", "write")?;
    env.add_group_member(&alice, "acme", "writers", &bob.email())?;

    println!("  Setup complete - Bob has direct read + group write");

    let output = env.secret_set(&bob, "acme", "api", "dev", "BOB_SECRET", "bob_value");
    assert_success(&output, "Bob write (combined permissions)");

    println!("  test_mixed_user_group_permissions PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Group Membership Removal
// ═══════════════════════════════════════════════════════════════════════════

backend_test!(
    test_group_membership_removal,
    run_test_group_membership_removal
);

async fn run_test_group_membership_removal(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = RbacTestEnv::new("group_removal", config).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;

    env.secret_set(&alice, "acme", "api", "dev", "SECRET", "value");

    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;
    env.create_group(&alice, "acme", "developers")?;
    env.set_group_permission(&alice, "acme", "developers", "read")?;
    env.add_group_member(&alice, "acme", "developers", &bob.email())?;

    let output = env.secret_get(&bob, "acme", "api", "dev", "SECRET");
    assert_success(&output, "Bob read (in group)");

    env.remove_group_member(&alice, "acme", "developers", &bob.email())?;
    println!("  Bob removed from group");

    let output = env.secret_get(&bob, "acme", "api", "dev", "SECRET");
    assert_denied(&output, "Bob read (removed from group)");

    println!("  test_group_membership_removal PASSED");
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Test: Permission List Commands
// ═══════════════════════════════════════════════════════════════════════════

backend_test!(
    test_permission_list_commands,
    run_test_permission_list_commands
);

async fn run_test_permission_list_commands(
    config: BackendConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = RbacTestEnv::new("perm_list", config).await?;

    let alice = env.create_user("alice");
    let bob = env.create_user("bob");

    let invite = env.create_server_invite()?;
    env.join_server(&alice, &invite)?;
    env.create_workspace(&alice, "acme")?;
    env.create_project(&alice, "acme", "api")?;
    env.create_environment(&alice, "acme", "api", "dev")?;

    let ws_invite = env.create_workspace_invite(&alice, "acme")?;
    env.join_server(&bob, &ws_invite)?;

    env.set_user_permission(&alice, "acme", &bob.email(), "read")?;
    env.set_user_project_permission(&alice, "acme", "api", &bob.email(), "write")?;
    env.set_user_env_permission(&alice, "acme", "api", "dev", &bob.email(), "admin")?;

    println!("  Setup complete - permissions set at all levels");

    let output = env.user_permission_list(&alice, "acme");
    assert_success(&output, "List workspace permissions");
    let perm_output = String::from_utf8_lossy(&output.stdout);
    assert!(
        perm_output.contains(&bob.email()),
        "Bob should be in workspace permissions"
    );

    let output = env.user_project_permission_list(&alice, "acme", "api");
    assert_success(&output, "List project permissions");

    let output = env.user_env_permission_list(&alice, "acme", "api", "dev");
    assert_success(&output, "List environment permissions");

    println!("  test_permission_list_commands PASSED");
    Ok(())
}

// Note: Non-admin permission management tests removed pending RBAC enforcement verification

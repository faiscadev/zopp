//! Permission commands: set, get, list, remove for workspace/project/environment

use crate::config::PrincipalConfig;
use crate::grpc::{add_auth_metadata, setup_client};

#[cfg(test)]
use crate::client::MockPermissionClient;

use zopp_proto::{
    GetEffectivePermissionsRequest, GetUserWorkspacePermissionRequest,
    GetWorkspacePermissionRequest, ListUserWorkspacePermissionsRequest,
    ListWorkspacePermissionsRequest, PermissionList, RemoveUserWorkspacePermissionRequest,
    RemoveWorkspacePermissionRequest, Role, SetUserWorkspacePermissionRequest,
    SetWorkspacePermissionRequest, UserPermissionList,
};

#[cfg(test)]
use zopp_proto::{Permission, UserPermission};

/// Parse a role string into a Role enum value.
pub fn parse_role(role: &str) -> Result<i32, Box<dyn std::error::Error>> {
    match role.to_lowercase().as_str() {
        "admin" => Ok(Role::Admin as i32),
        "write" => Ok(Role::Write as i32),
        "read" => Ok(Role::Read as i32),
        _ => Err("Invalid role: must be admin, write, or read".into()),
    }
}

/// Convert a Role integer to a string for display.
pub fn role_to_string(role: i32) -> &'static str {
    match Role::try_from(role) {
        Ok(Role::Admin) => "admin",
        Ok(Role::Write) => "write",
        Ok(Role::Read) => "read",
        _ => "unknown",
    }
}

/// Inner implementation for list workspace permissions.
pub async fn permission_list_inner<C>(
    client: &mut C,
    principal: &PrincipalConfig,
    workspace_name: &str,
) -> Result<PermissionList, Box<dyn std::error::Error>>
where
    C: crate::client::PermissionClient,
{
    let mut request = tonic::Request::new(ListWorkspacePermissionsRequest {
        workspace_name: workspace_name.to_string(),
    });
    add_auth_metadata(
        &mut request,
        principal,
        "/zopp.ZoppService/ListWorkspacePermissions",
    )?;

    let response = client
        .list_workspace_permissions(request)
        .await?
        .into_inner();
    Ok(response)
}

/// Print permission list results.
pub fn print_permission_list(workspace: &str, permissions: &PermissionList) {
    if permissions.permissions.is_empty() {
        println!("No permissions found on workspace {}", workspace);
    } else {
        println!("Permissions on workspace {}:", workspace);
        for perm in &permissions.permissions {
            println!("  {} - {}", perm.principal_id, role_to_string(perm.role));
        }
    }
}

/// Print user permission list results.
pub fn print_user_permission_list(scope: &str, permissions: &UserPermissionList) {
    if permissions.permissions.is_empty() {
        println!("No user permissions found on {}", scope);
    } else {
        println!("User permissions on {}:", scope);
        for perm in &permissions.permissions {
            println!("  {} - {}", perm.user_email, role_to_string(perm.role));
        }
    }
}

pub async fn cmd_permission_set(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    principal: &str,
    role: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let role_enum = match role.to_lowercase().as_str() {
        "admin" => Role::Admin as i32,
        "write" => Role::Write as i32,
        "read" => Role::Read as i32,
        _ => return Err("Invalid role: must be admin, write, or read".into()),
    };

    let mut request = tonic::Request::new(SetWorkspacePermissionRequest {
        workspace_name: workspace.to_string(),
        principal_id: principal.to_string(),
        role: role_enum,
    });
    add_auth_metadata(
        &mut request,
        &auth_principal,
        "/zopp.ZoppService/SetWorkspacePermission",
    )?;

    client.set_workspace_permission(request).await?;
    println!(
        "Set {} permission for principal {} on workspace {}",
        role, principal, workspace
    );

    Ok(())
}

pub async fn cmd_permission_get(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    principal: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(GetWorkspacePermissionRequest {
        workspace_name: workspace.to_string(),
        principal_id: principal.to_string(),
    });
    add_auth_metadata(
        &mut request,
        &auth_principal,
        "/zopp.ZoppService/GetWorkspacePermission",
    )?;

    let response = client.get_workspace_permission(request).await?.into_inner();

    let role_str = match Role::try_from(response.role) {
        Ok(Role::Admin) => "admin",
        Ok(Role::Write) => "write",
        Ok(Role::Read) => "read",
        _ => "unknown",
    };

    println!(
        "Principal {} has {} permission on workspace {}",
        principal, role_str, workspace
    );

    Ok(())
}

pub async fn cmd_permission_list(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(ListWorkspacePermissionsRequest {
        workspace_name: workspace.to_string(),
    });
    add_auth_metadata(
        &mut request,
        &auth_principal,
        "/zopp.ZoppService/ListWorkspacePermissions",
    )?;

    let response = client
        .list_workspace_permissions(request)
        .await?
        .into_inner();

    if response.permissions.is_empty() {
        println!("No permissions found on workspace {}", workspace);
        return Ok(());
    }

    println!("Permissions on workspace {}:", workspace);
    for perm in response.permissions {
        let role_str = match Role::try_from(perm.role) {
            Ok(Role::Admin) => "admin",
            Ok(Role::Write) => "write",
            Ok(Role::Read) => "read",
            _ => "unknown",
        };
        println!("  {} - {}", perm.principal_id, role_str);
    }

    Ok(())
}

pub async fn cmd_permission_remove(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    principal: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(RemoveWorkspacePermissionRequest {
        workspace_name: workspace.to_string(),
        principal_id: principal.to_string(),
    });
    add_auth_metadata(
        &mut request,
        &auth_principal,
        "/zopp.ZoppService/RemoveWorkspacePermission",
    )?;

    client.remove_workspace_permission(request).await?;
    println!(
        "Removed permission for principal {} from workspace {}",
        principal, workspace
    );

    Ok(())
}

// ────────────────────────────────────── User Permissions ──────────────────────────────────────

pub async fn cmd_user_permission_set(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    email: &str,
    role: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let role_enum = match role.to_lowercase().as_str() {
        "admin" => Role::Admin as i32,
        "write" => Role::Write as i32,
        "read" => Role::Read as i32,
        _ => return Err("Invalid role: must be admin, write, or read".into()),
    };

    let mut request = tonic::Request::new(SetUserWorkspacePermissionRequest {
        workspace_name: workspace.to_string(),
        user_email: email.to_string(),
        role: role_enum,
    });
    add_auth_metadata(
        &mut request,
        &auth_principal,
        "/zopp.ZoppService/SetUserWorkspacePermission",
    )?;

    client.set_user_workspace_permission(request).await?;
    println!(
        "Set {} permission for user {} on workspace {}",
        role, email, workspace
    );

    Ok(())
}

pub async fn cmd_user_permission_get(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    email: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(GetUserWorkspacePermissionRequest {
        workspace_name: workspace.to_string(),
        user_email: email.to_string(),
    });
    add_auth_metadata(
        &mut request,
        &auth_principal,
        "/zopp.ZoppService/GetUserWorkspacePermission",
    )?;

    let response = client
        .get_user_workspace_permission(request)
        .await?
        .into_inner();

    let role_str = match Role::try_from(response.role) {
        Ok(Role::Admin) => "admin",
        Ok(Role::Write) => "write",
        Ok(Role::Read) => "read",
        _ => "unknown",
    };

    println!(
        "User {} has {} permission on workspace {}",
        email, role_str, workspace
    );

    Ok(())
}

pub async fn cmd_user_permission_list(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(ListUserWorkspacePermissionsRequest {
        workspace_name: workspace.to_string(),
    });
    add_auth_metadata(
        &mut request,
        &auth_principal,
        "/zopp.ZoppService/ListUserWorkspacePermissions",
    )?;

    let response = client
        .list_user_workspace_permissions(request)
        .await?
        .into_inner();

    if response.permissions.is_empty() {
        println!("No user permissions found on workspace {}", workspace);
        return Ok(());
    }

    println!("User permissions on workspace {}:", workspace);
    for perm in response.permissions {
        let role_str = match Role::try_from(perm.role) {
            Ok(Role::Admin) => "admin",
            Ok(Role::Write) => "write",
            Ok(Role::Read) => "read",
            _ => "unknown",
        };
        println!("  {} - {}", perm.user_email, role_str);
    }

    Ok(())
}

pub async fn cmd_user_permission_remove(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    email: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(RemoveUserWorkspacePermissionRequest {
        workspace_name: workspace.to_string(),
        user_email: email.to_string(),
    });
    add_auth_metadata(
        &mut request,
        &auth_principal,
        "/zopp.ZoppService/RemoveUserWorkspacePermission",
    )?;

    client.remove_user_workspace_permission(request).await?;
    println!(
        "Removed permission for user {} from workspace {}",
        email, workspace
    );

    Ok(())
}

// ────────────────────────────────────── User Project Permissions ──────────────────────────────────────

pub async fn cmd_user_project_permission_set(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    project: &str,
    email: &str,
    role: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let role_enum = match role.to_lowercase().as_str() {
        "admin" => Role::Admin as i32,
        "write" => Role::Write as i32,
        "read" => Role::Read as i32,
        _ => return Err("Invalid role: must be admin, write, or read".into()),
    };

    let mut request = tonic::Request::new(zopp_proto::SetUserProjectPermissionRequest {
        workspace_name: workspace.to_string(),
        project_name: project.to_string(),
        user_email: email.to_string(),
        role: role_enum,
    });
    add_auth_metadata(
        &mut request,
        &auth_principal,
        "/zopp.ZoppService/SetUserProjectPermission",
    )?;

    client.set_user_project_permission(request).await?;
    println!(
        "Set {} permission for user {} on project {}/{}",
        role, email, workspace, project
    );

    Ok(())
}

pub async fn cmd_user_project_permission_remove(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    project: &str,
    email: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(zopp_proto::RemoveUserProjectPermissionRequest {
        workspace_name: workspace.to_string(),
        project_name: project.to_string(),
        user_email: email.to_string(),
    });
    add_auth_metadata(
        &mut request,
        &auth_principal,
        "/zopp.ZoppService/RemoveUserProjectPermission",
    )?;

    client.remove_user_project_permission(request).await?;
    println!(
        "Removed permission for user {} from project {}/{}",
        email, workspace, project
    );

    Ok(())
}

// ────────────────────────────────────── User Environment Permissions ──────────────────────────────────────

pub async fn cmd_user_environment_permission_set(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    project: &str,
    environment: &str,
    email: &str,
    role: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let role_enum = match role.to_lowercase().as_str() {
        "admin" => Role::Admin as i32,
        "write" => Role::Write as i32,
        "read" => Role::Read as i32,
        _ => return Err("Invalid role: must be admin, write, or read".into()),
    };

    let mut request = tonic::Request::new(zopp_proto::SetUserEnvironmentPermissionRequest {
        workspace_name: workspace.to_string(),
        project_name: project.to_string(),
        environment_name: environment.to_string(),
        user_email: email.to_string(),
        role: role_enum,
    });
    add_auth_metadata(
        &mut request,
        &auth_principal,
        "/zopp.ZoppService/SetUserEnvironmentPermission",
    )?;

    client.set_user_environment_permission(request).await?;
    println!(
        "Set {} permission for user {} on environment {}/{}/{}",
        role, email, workspace, project, environment
    );

    Ok(())
}

pub async fn cmd_user_environment_permission_remove(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    project: &str,
    environment: &str,
    email: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(zopp_proto::RemoveUserEnvironmentPermissionRequest {
        workspace_name: workspace.to_string(),
        project_name: project.to_string(),
        environment_name: environment.to_string(),
        user_email: email.to_string(),
    });
    add_auth_metadata(
        &mut request,
        &auth_principal,
        "/zopp.ZoppService/RemoveUserEnvironmentPermission",
    )?;

    client.remove_user_environment_permission(request).await?;
    println!(
        "Removed permission for user {} from environment {}/{}/{}",
        email, workspace, project, environment
    );

    Ok(())
}

pub async fn cmd_user_project_permission_list(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    project: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(zopp_proto::ListUserProjectPermissionsRequest {
        workspace_name: workspace.to_string(),
        project_name: project.to_string(),
    });
    add_auth_metadata(
        &mut request,
        &auth_principal,
        "/zopp.ZoppService/ListUserProjectPermissions",
    )?;

    let response = client
        .list_user_project_permissions(request)
        .await?
        .into_inner();

    if response.permissions.is_empty() {
        println!(
            "No user permissions found on project {}/{}",
            workspace, project
        );
        return Ok(());
    }

    println!("User permissions on project {}/{}:", workspace, project);
    for perm in response.permissions {
        let role_str = match Role::try_from(perm.role) {
            Ok(Role::Admin) => "admin",
            Ok(Role::Write) => "write",
            Ok(Role::Read) => "read",
            _ => "unknown",
        };
        println!("  {} - {}", perm.user_email, role_str);
    }

    Ok(())
}

pub async fn cmd_user_environment_permission_list(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    project: &str,
    environment: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(zopp_proto::ListUserEnvironmentPermissionsRequest {
        workspace_name: workspace.to_string(),
        project_name: project.to_string(),
        environment_name: environment.to_string(),
    });
    add_auth_metadata(
        &mut request,
        &auth_principal,
        "/zopp.ZoppService/ListUserEnvironmentPermissions",
    )?;

    let response = client
        .list_user_environment_permissions(request)
        .await?
        .into_inner();

    if response.permissions.is_empty() {
        println!(
            "No user permissions found on environment {}/{}/{}",
            workspace, project, environment
        );
        return Ok(());
    }

    println!(
        "User permissions on environment {}/{}/{}:",
        workspace, project, environment
    );
    for perm in response.permissions {
        let role_str = match Role::try_from(perm.role) {
            Ok(Role::Admin) => "admin",
            Ok(Role::Write) => "write",
            Ok(Role::Read) => "read",
            _ => "unknown",
        };
        println!("  {} - {}", perm.user_email, role_str);
    }

    Ok(())
}

pub async fn cmd_user_project_permission_get(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    project: &str,
    email: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(zopp_proto::GetUserProjectPermissionRequest {
        workspace_name: workspace.to_string(),
        project_name: project.to_string(),
        user_email: email.to_string(),
    });
    add_auth_metadata(
        &mut request,
        &auth_principal,
        "/zopp.ZoppService/GetUserProjectPermission",
    )?;

    let response = client
        .get_user_project_permission(request)
        .await?
        .into_inner();

    let role_str = match Role::try_from(response.role) {
        Ok(Role::Admin) => "admin",
        Ok(Role::Write) => "write",
        Ok(Role::Read) => "read",
        _ => "unknown",
    };

    println!(
        "User {} has {} permission on project {}/{}",
        email, role_str, workspace, project
    );

    Ok(())
}

pub async fn cmd_user_environment_permission_get(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    project: &str,
    environment: &str,
    email: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(zopp_proto::GetUserEnvironmentPermissionRequest {
        workspace_name: workspace.to_string(),
        project_name: project.to_string(),
        environment_name: environment.to_string(),
        user_email: email.to_string(),
    });
    add_auth_metadata(
        &mut request,
        &auth_principal,
        "/zopp.ZoppService/GetUserEnvironmentPermission",
    )?;

    let response = client
        .get_user_environment_permission(request)
        .await?
        .into_inner();

    let role_str = match Role::try_from(response.role) {
        Ok(Role::Admin) => "admin",
        Ok(Role::Write) => "write",
        Ok(Role::Read) => "read",
        _ => "unknown",
    };

    println!(
        "User {} has {} permission on environment {}/{}/{}",
        email, role_str, workspace, project, environment
    );

    Ok(())
}

// ────────────────────────────────────── Principal Project Permissions ──────────────────────────────────────

pub async fn cmd_principal_project_permission_set(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    project: &str,
    principal: &str,
    role: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let role_enum = match role.to_lowercase().as_str() {
        "admin" => Role::Admin as i32,
        "write" => Role::Write as i32,
        "read" => Role::Read as i32,
        _ => return Err("Invalid role: must be admin, write, or read".into()),
    };

    let mut request = tonic::Request::new(zopp_proto::SetProjectPermissionRequest {
        workspace_name: workspace.to_string(),
        project_name: project.to_string(),
        principal_id: principal.to_string(),
        role: role_enum,
    });
    add_auth_metadata(
        &mut request,
        &auth_principal,
        "/zopp.ZoppService/SetProjectPermission",
    )?;

    client.set_project_permission(request).await?;
    println!(
        "Set {} permission for principal {} on project {}/{}",
        role, principal, workspace, project
    );

    Ok(())
}

pub async fn cmd_principal_project_permission_get(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    project: &str,
    principal: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(zopp_proto::GetProjectPermissionRequest {
        workspace_name: workspace.to_string(),
        project_name: project.to_string(),
        principal_id: principal.to_string(),
    });
    add_auth_metadata(
        &mut request,
        &auth_principal,
        "/zopp.ZoppService/GetProjectPermission",
    )?;

    let response = client.get_project_permission(request).await?.into_inner();

    let role_str = match Role::try_from(response.role) {
        Ok(Role::Admin) => "admin",
        Ok(Role::Write) => "write",
        Ok(Role::Read) => "read",
        _ => "unknown",
    };

    println!(
        "Principal {} has {} permission on project {}/{}",
        principal, role_str, workspace, project
    );

    Ok(())
}

pub async fn cmd_principal_project_permission_list(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    project: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(zopp_proto::ListProjectPermissionsRequest {
        workspace_name: workspace.to_string(),
        project_name: project.to_string(),
    });
    add_auth_metadata(
        &mut request,
        &auth_principal,
        "/zopp.ZoppService/ListProjectPermissions",
    )?;

    let response = client.list_project_permissions(request).await?.into_inner();

    if response.permissions.is_empty() {
        println!(
            "No principal permissions found on project {}/{}",
            workspace, project
        );
        return Ok(());
    }

    println!(
        "Principal permissions on project {}/{}:",
        workspace, project
    );
    for perm in response.permissions {
        let role_str = match Role::try_from(perm.role) {
            Ok(Role::Admin) => "admin",
            Ok(Role::Write) => "write",
            Ok(Role::Read) => "read",
            _ => "unknown",
        };
        println!("  {} - {}", perm.principal_id, role_str);
    }

    Ok(())
}

pub async fn cmd_principal_project_permission_remove(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    project: &str,
    principal: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(zopp_proto::RemoveProjectPermissionRequest {
        workspace_name: workspace.to_string(),
        project_name: project.to_string(),
        principal_id: principal.to_string(),
    });
    add_auth_metadata(
        &mut request,
        &auth_principal,
        "/zopp.ZoppService/RemoveProjectPermission",
    )?;

    client.remove_project_permission(request).await?;
    println!(
        "Removed permission for principal {} from project {}/{}",
        principal, workspace, project
    );

    Ok(())
}

// ────────────────────────────────────── Principal Environment Permissions ──────────────────────────────────────

pub async fn cmd_principal_environment_permission_set(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    project: &str,
    environment: &str,
    principal: &str,
    role: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let role_enum = match role.to_lowercase().as_str() {
        "admin" => Role::Admin as i32,
        "write" => Role::Write as i32,
        "read" => Role::Read as i32,
        _ => return Err("Invalid role: must be admin, write, or read".into()),
    };

    let mut request = tonic::Request::new(zopp_proto::SetEnvironmentPermissionRequest {
        workspace_name: workspace.to_string(),
        project_name: project.to_string(),
        environment_name: environment.to_string(),
        principal_id: principal.to_string(),
        role: role_enum,
    });
    add_auth_metadata(
        &mut request,
        &auth_principal,
        "/zopp.ZoppService/SetEnvironmentPermission",
    )?;

    client.set_environment_permission(request).await?;
    println!(
        "Set {} permission for principal {} on environment {}/{}/{}",
        role, principal, workspace, project, environment
    );

    Ok(())
}

pub async fn cmd_principal_environment_permission_get(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    project: &str,
    environment: &str,
    principal: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(zopp_proto::GetEnvironmentPermissionRequest {
        workspace_name: workspace.to_string(),
        project_name: project.to_string(),
        environment_name: environment.to_string(),
        principal_id: principal.to_string(),
    });
    add_auth_metadata(
        &mut request,
        &auth_principal,
        "/zopp.ZoppService/GetEnvironmentPermission",
    )?;

    let response = client
        .get_environment_permission(request)
        .await?
        .into_inner();

    let role_str = match Role::try_from(response.role) {
        Ok(Role::Admin) => "admin",
        Ok(Role::Write) => "write",
        Ok(Role::Read) => "read",
        _ => "unknown",
    };

    println!(
        "Principal {} has {} permission on environment {}/{}/{}",
        principal, role_str, workspace, project, environment
    );

    Ok(())
}

pub async fn cmd_principal_environment_permission_list(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    project: &str,
    environment: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(zopp_proto::ListEnvironmentPermissionsRequest {
        workspace_name: workspace.to_string(),
        project_name: project.to_string(),
        environment_name: environment.to_string(),
    });
    add_auth_metadata(
        &mut request,
        &auth_principal,
        "/zopp.ZoppService/ListEnvironmentPermissions",
    )?;

    let response = client
        .list_environment_permissions(request)
        .await?
        .into_inner();

    if response.permissions.is_empty() {
        println!(
            "No principal permissions found on environment {}/{}/{}",
            workspace, project, environment
        );
        return Ok(());
    }

    println!(
        "Principal permissions on environment {}/{}/{}:",
        workspace, project, environment
    );
    for perm in response.permissions {
        let role_str = match Role::try_from(perm.role) {
            Ok(Role::Admin) => "admin",
            Ok(Role::Write) => "write",
            Ok(Role::Read) => "read",
            _ => "unknown",
        };
        println!("  {} - {}", perm.principal_id, role_str);
    }

    Ok(())
}

pub async fn cmd_principal_environment_permission_remove(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    project: &str,
    environment: &str,
    principal: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(zopp_proto::RemoveEnvironmentPermissionRequest {
        workspace_name: workspace.to_string(),
        project_name: project.to_string(),
        environment_name: environment.to_string(),
        principal_id: principal.to_string(),
    });
    add_auth_metadata(
        &mut request,
        &auth_principal,
        "/zopp.ZoppService/RemoveEnvironmentPermission",
    )?;

    client.remove_environment_permission(request).await?;
    println!(
        "Removed permission for principal {} from environment {}/{}/{}",
        principal, workspace, project, environment
    );

    Ok(())
}

// ────────────────────────────────────── Effective Permissions ──────────────────────────────────────

pub async fn cmd_permission_effective(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    principal: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, auth_principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(GetEffectivePermissionsRequest {
        workspace_name: workspace.to_string(),
        principal_id: principal.to_string(),
    });
    add_auth_metadata(
        &mut request,
        &auth_principal,
        "/zopp.ZoppService/GetEffectivePermissions",
    )?;

    let response = client
        .get_effective_permissions(request)
        .await?
        .into_inner();

    let principal_type = if response.is_service_principal {
        "service"
    } else {
        "user"
    };

    println!(
        "Effective permissions for {} principal '{}' (ID: {}) in workspace '{}':",
        principal_type, response.principal_name, response.principal_id, workspace
    );

    // Show workspace-level permission
    if let Some(role) = response.workspace_role {
        let role_str = match Role::try_from(role) {
            Ok(Role::Admin) => "admin",
            Ok(Role::Write) => "write",
            Ok(Role::Read) => "read",
            _ => "unknown",
        };
        println!("  Workspace: {}", role_str);
    }

    // Show project and environment permissions
    if response.projects.is_empty() && response.workspace_role.is_none() {
        println!("  No permissions found");
    } else {
        for project in response.projects {
            // Project-level permission
            if let Some(role) = project.effective_role {
                let role_str = match Role::try_from(role) {
                    Ok(Role::Admin) => "admin",
                    Ok(Role::Write) => "write",
                    Ok(Role::Read) => "read",
                    _ => "unknown",
                };
                println!("  Project '{}': {}", project.project_name, role_str);
            }

            // Environment-level permissions
            for env in project.environments {
                let role_str = match Role::try_from(env.effective_role) {
                    Ok(Role::Admin) => "admin",
                    Ok(Role::Write) => "write",
                    Ok(Role::Read) => "read",
                    _ => "unknown",
                };
                println!(
                    "    Environment '{}/{}': {}",
                    project.project_name, env.environment_name, role_str
                );
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::{Response, Status};

    fn create_test_principal() -> PrincipalConfig {
        PrincipalConfig {
            id: "test-principal-id".to_string(),
            name: "test-principal".to_string(),
            private_key: "0".repeat(64),
            public_key: "1".repeat(64),
            x25519_private_key: Some("2".repeat(64)),
            x25519_public_key: Some("3".repeat(64)),
        }
    }

    #[test]
    fn test_parse_role_admin() {
        let result = parse_role("admin");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Role::Admin as i32);
    }

    #[test]
    fn test_parse_role_write() {
        let result = parse_role("write");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Role::Write as i32);
    }

    #[test]
    fn test_parse_role_read() {
        let result = parse_role("read");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Role::Read as i32);
    }

    #[test]
    fn test_parse_role_case_insensitive() {
        assert!(parse_role("ADMIN").is_ok());
        assert!(parse_role("Admin").is_ok());
        assert!(parse_role("WRITE").is_ok());
        assert!(parse_role("Write").is_ok());
        assert!(parse_role("READ").is_ok());
        assert!(parse_role("Read").is_ok());
    }

    #[test]
    fn test_parse_role_invalid() {
        let result = parse_role("invalid");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid role"));
    }

    #[test]
    fn test_role_to_string_admin() {
        assert_eq!(role_to_string(Role::Admin as i32), "admin");
    }

    #[test]
    fn test_role_to_string_write() {
        assert_eq!(role_to_string(Role::Write as i32), "write");
    }

    #[test]
    fn test_role_to_string_read() {
        assert_eq!(role_to_string(Role::Read as i32), "read");
    }

    #[test]
    fn test_role_to_string_unknown() {
        assert_eq!(role_to_string(999), "unknown");
    }

    #[tokio::test]
    async fn test_permission_list_inner_success() {
        let mut mock = MockPermissionClient::new();

        mock.expect_list_workspace_permissions().returning(|_| {
            Ok(Response::new(PermissionList {
                permissions: vec![
                    Permission {
                        principal_id: "principal-1".to_string(),
                        principal_name: "Principal One".to_string(),
                        role: Role::Admin as i32,
                    },
                    Permission {
                        principal_id: "principal-2".to_string(),
                        principal_name: "Principal Two".to_string(),
                        role: Role::Read as i32,
                    },
                ],
            }))
        });

        let principal = create_test_principal();
        let result = permission_list_inner(&mut mock, &principal, "my-workspace").await;

        assert!(result.is_ok());
        let permissions = result.unwrap();
        assert_eq!(permissions.permissions.len(), 2);
    }

    #[tokio::test]
    async fn test_permission_list_inner_empty() {
        let mut mock = MockPermissionClient::new();

        mock.expect_list_workspace_permissions().returning(|_| {
            Ok(Response::new(PermissionList {
                permissions: vec![],
            }))
        });

        let principal = create_test_principal();
        let result = permission_list_inner(&mut mock, &principal, "my-workspace").await;

        assert!(result.is_ok());
        let permissions = result.unwrap();
        assert!(permissions.permissions.is_empty());
    }

    #[tokio::test]
    async fn test_permission_list_inner_permission_denied() {
        let mut mock = MockPermissionClient::new();

        mock.expect_list_workspace_permissions()
            .returning(|_| Err(Status::permission_denied("Not authorized")));

        let principal = create_test_principal();
        let result = permission_list_inner(&mut mock, &principal, "my-workspace").await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_permission_list_inner_not_found() {
        let mut mock = MockPermissionClient::new();

        mock.expect_list_workspace_permissions()
            .returning(|_| Err(Status::not_found("Workspace not found")));

        let principal = create_test_principal();
        let result = permission_list_inner(&mut mock, &principal, "nonexistent").await;

        assert!(result.is_err());
    }

    #[test]
    fn test_print_permission_list_empty() {
        let permissions = PermissionList {
            permissions: vec![],
        };
        print_permission_list("my-workspace", &permissions);
    }

    #[test]
    fn test_print_permission_list_with_items() {
        let permissions = PermissionList {
            permissions: vec![
                Permission {
                    principal_id: "p1".to_string(),
                    principal_name: "Principal 1".to_string(),
                    role: Role::Admin as i32,
                },
                Permission {
                    principal_id: "p2".to_string(),
                    principal_name: "Principal 2".to_string(),
                    role: Role::Write as i32,
                },
            ],
        };
        print_permission_list("my-workspace", &permissions);
    }

    #[test]
    fn test_print_user_permission_list_empty() {
        let permissions = UserPermissionList {
            permissions: vec![],
        };
        print_user_permission_list("my-workspace", &permissions);
    }

    #[test]
    fn test_print_user_permission_list_with_items() {
        let permissions = UserPermissionList {
            permissions: vec![
                UserPermission {
                    user_id: "u1".to_string(),
                    user_email: "user1@example.com".to_string(),
                    role: Role::Admin as i32,
                },
                UserPermission {
                    user_id: "u2".to_string(),
                    user_email: "user2@example.com".to_string(),
                    role: Role::Read as i32,
                },
            ],
        };
        print_user_permission_list("my-workspace", &permissions);
    }
}

use crate::config::PrincipalConfig;
use crate::grpc::{add_auth_metadata, setup_client};

use zopp_proto::{
    AddGroupMemberRequest, CreateGroupRequest, DeleteGroupRequest, GroupList,
    ListGroupMembersRequest, ListGroupsRequest, RemoveGroupEnvironmentPermissionRequest,
    RemoveGroupMemberRequest, RemoveGroupProjectPermissionRequest,
    RemoveGroupWorkspacePermissionRequest, Role, SetGroupEnvironmentPermissionRequest,
    SetGroupProjectPermissionRequest, SetGroupWorkspacePermissionRequest, UpdateGroupRequest,
};

/// Inner implementation for group list that accepts a trait-bounded client.
pub async fn group_list_inner<C>(
    client: &mut C,
    principal: &PrincipalConfig,
    workspace_name: &str,
) -> Result<GroupList, Box<dyn std::error::Error>>
where
    C: crate::client::GroupClient,
{
    let mut request = tonic::Request::new(ListGroupsRequest {
        workspace_name: workspace_name.to_string(),
    });
    add_auth_metadata(&mut request, principal, "/zopp.ZoppService/ListGroups")?;

    let response = client.list_groups(request).await?.into_inner();
    Ok(response)
}

/// Print group list results.
pub fn print_group_list(groups: &GroupList) {
    if groups.groups.is_empty() {
        println!("No groups found");
    } else {
        println!("Groups:");
        for group in &groups.groups {
            println!("  {} - {}", group.name, group.description);
        }
    }
}

/// Inner implementation for group create that accepts a trait-bounded client.
pub async fn group_create_inner<C>(
    client: &mut C,
    principal: &PrincipalConfig,
    workspace_name: &str,
    name: &str,
    description: &str,
) -> Result<zopp_proto::Group, Box<dyn std::error::Error>>
where
    C: crate::client::GroupClient,
{
    let mut request = tonic::Request::new(CreateGroupRequest {
        workspace_name: workspace_name.to_string(),
        name: name.to_string(),
        description: description.to_string(),
    });
    add_auth_metadata(&mut request, principal, "/zopp.ZoppService/CreateGroup")?;

    let response = client.create_group(request).await?.into_inner();
    Ok(response)
}

/// Print group creation result.
pub fn print_group_created(group: &zopp_proto::Group) {
    println!("Created group: {}", group.name);
    println!("  ID: {}", group.id);
    if !group.description.is_empty() {
        println!("  Description: {}", group.description);
    }
}

/// Inner implementation for group delete that accepts a trait-bounded client.
pub async fn group_delete_inner<C>(
    client: &mut C,
    principal: &PrincipalConfig,
    workspace_name: &str,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>>
where
    C: crate::client::GroupClient,
{
    let mut request = tonic::Request::new(DeleteGroupRequest {
        workspace_name: workspace_name.to_string(),
        group_name: name.to_string(),
    });
    add_auth_metadata(&mut request, principal, "/zopp.ZoppService/DeleteGroup")?;

    client.delete_group(request).await?;
    Ok(())
}

pub async fn cmd_group_create(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: Option<&str>,
    name: String,
    description: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let workspace_name = workspace
        .map(|s| s.to_string())
        .ok_or("Workspace name required (use -w or --workspace)")?;

    let group = group_create_inner(
        &mut client,
        &principal,
        &workspace_name,
        &name,
        &description.unwrap_or_default(),
    )
    .await?;
    print_group_created(&group);

    Ok(())
}

pub async fn cmd_group_list(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let workspace_name = workspace
        .map(|s| s.to_string())
        .ok_or("Workspace name required (use -w or --workspace)")?;

    let groups = group_list_inner(&mut client, &principal, &workspace_name).await?;
    print_group_list(&groups);
    Ok(())
}

pub async fn cmd_group_delete(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: Option<&str>,
    name: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let workspace_name = workspace
        .map(|s| s.to_string())
        .ok_or("Workspace name required (use -w or --workspace)")?;

    group_delete_inner(&mut client, &principal, &workspace_name, &name).await?;
    println!("Deleted group: {}", name);

    Ok(())
}

pub async fn cmd_group_update(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: Option<&str>,
    name: String,
    new_name: Option<String>,
    description: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let workspace_name = workspace
        .map(|s| s.to_string())
        .ok_or("Workspace name required (use -w or --workspace)")?;

    if new_name.is_none() && description.is_none() {
        return Err("Either --name or --description must be provided".into());
    }

    let mut request = tonic::Request::new(UpdateGroupRequest {
        workspace_name,
        group_name: name.clone(),
        new_name: new_name.clone().unwrap_or_default(),
        new_description: description.clone().unwrap_or_default(),
    });
    add_auth_metadata(&mut request, &principal, "/zopp.ZoppService/UpdateGroup")?;

    let response = client.update_group(request).await?.into_inner();

    println!("Updated group: {}", response.name);
    if new_name.is_some() {
        println!("  New name: {}", response.name);
    }
    if description.is_some() {
        println!("  New description: {}", response.description);
    }

    Ok(())
}

pub async fn cmd_group_add_member(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: Option<&str>,
    group_name: String,
    user_email: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let workspace_name = workspace
        .map(|s| s.to_string())
        .ok_or("Workspace name required (use -w or --workspace)")?;

    let mut request = tonic::Request::new(AddGroupMemberRequest {
        workspace_name,
        group_name: group_name.clone(),
        user_email: user_email.clone(),
    });
    add_auth_metadata(&mut request, &principal, "/zopp.ZoppService/AddGroupMember")?;

    client.add_group_member(request).await?;
    println!("Added {} to group {}", user_email, group_name);

    Ok(())
}

pub async fn cmd_group_remove_member(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: Option<&str>,
    group_name: String,
    user_email: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let workspace_name = workspace
        .map(|s| s.to_string())
        .ok_or("Workspace name required (use -w or --workspace)")?;

    let mut request = tonic::Request::new(RemoveGroupMemberRequest {
        workspace_name,
        group_name: group_name.clone(),
        user_email: user_email.clone(),
    });
    add_auth_metadata(
        &mut request,
        &principal,
        "/zopp.ZoppService/RemoveGroupMember",
    )?;

    client.remove_group_member(request).await?;
    println!("Removed {} from group {}", user_email, group_name);

    Ok(())
}

pub async fn cmd_group_list_members(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: Option<&str>,
    group_name: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let workspace_name = workspace
        .map(|s| s.to_string())
        .ok_or("Workspace name required (use -w or --workspace)")?;

    let mut request = tonic::Request::new(ListGroupMembersRequest {
        workspace_name,
        group_name: group_name.clone(),
    });
    add_auth_metadata(
        &mut request,
        &principal,
        "/zopp.ZoppService/ListGroupMembers",
    )?;

    let response = client.list_group_members(request).await?.into_inner();

    if response.members.is_empty() {
        println!("No members in group {}", group_name);
        return Ok(());
    }

    println!("Members of group {}:", group_name);
    for member in response.members {
        println!("  {}", member.user_email);
    }

    Ok(())
}

pub async fn cmd_group_set_permission(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: Option<&str>,
    group_name: String,
    role: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let workspace_name = workspace
        .map(|s| s.to_string())
        .ok_or("Workspace name required (use -w or --workspace)")?;

    let role = match role.to_lowercase().as_str() {
        "admin" => Role::Admin as i32,
        "write" => Role::Write as i32,
        "read" => Role::Read as i32,
        _ => return Err("Invalid role: must be admin, write, or read".into()),
    };

    let mut request = tonic::Request::new(SetGroupWorkspacePermissionRequest {
        workspace_name,
        group_name: group_name.clone(),
        role,
    });
    add_auth_metadata(
        &mut request,
        &principal,
        "/zopp.ZoppService/SetGroupWorkspacePermission",
    )?;

    client.set_group_workspace_permission(request).await?;
    println!("Set permission for group {}", group_name);

    Ok(())
}

pub async fn cmd_group_remove_permission(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: Option<&str>,
    group_name: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let workspace_name = workspace
        .map(|s| s.to_string())
        .ok_or("Workspace name required (use -w or --workspace)")?;

    let mut request = tonic::Request::new(RemoveGroupWorkspacePermissionRequest {
        workspace_name,
        group_name: group_name.clone(),
    });
    add_auth_metadata(
        &mut request,
        &principal,
        "/zopp.ZoppService/RemoveGroupWorkspacePermission",
    )?;

    client.remove_group_workspace_permission(request).await?;
    println!("Removed permission for group {}", group_name);

    Ok(())
}

pub async fn cmd_group_set_project_permission(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: Option<&str>,
    project: &str,
    group_name: String,
    role: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let workspace_name = workspace
        .map(|s| s.to_string())
        .ok_or("Workspace name required (use -w or --workspace)")?;

    let role_enum = match role.to_lowercase().as_str() {
        "admin" => Role::Admin as i32,
        "write" => Role::Write as i32,
        "read" => Role::Read as i32,
        _ => return Err("Invalid role: must be admin, write, or read".into()),
    };

    let mut request = tonic::Request::new(SetGroupProjectPermissionRequest {
        workspace_name: workspace_name.clone(),
        project_name: project.to_string(),
        group_name: group_name.clone(),
        role: role_enum,
    });
    add_auth_metadata(
        &mut request,
        &principal,
        "/zopp.ZoppService/SetGroupProjectPermission",
    )?;

    client.set_group_project_permission(request).await?;
    println!(
        "Set {} permission for group {} on project {}/{}",
        role, group_name, workspace_name, project
    );

    Ok(())
}

pub async fn cmd_group_remove_project_permission(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: Option<&str>,
    project: &str,
    group_name: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let workspace_name = workspace
        .map(|s| s.to_string())
        .ok_or("Workspace name required (use -w or --workspace)")?;

    let mut request = tonic::Request::new(RemoveGroupProjectPermissionRequest {
        workspace_name: workspace_name.clone(),
        project_name: project.to_string(),
        group_name: group_name.clone(),
    });
    add_auth_metadata(
        &mut request,
        &principal,
        "/zopp.ZoppService/RemoveGroupProjectPermission",
    )?;

    client.remove_group_project_permission(request).await?;
    println!(
        "Removed permission for group {} from project {}/{}",
        group_name, workspace_name, project
    );

    Ok(())
}

pub async fn cmd_group_set_environment_permission(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: Option<&str>,
    project: &str,
    environment: &str,
    group_name: String,
    role: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let workspace_name = workspace
        .map(|s| s.to_string())
        .ok_or("Workspace name required (use -w or --workspace)")?;

    let role_enum = match role.to_lowercase().as_str() {
        "admin" => Role::Admin as i32,
        "write" => Role::Write as i32,
        "read" => Role::Read as i32,
        _ => return Err("Invalid role: must be admin, write, or read".into()),
    };

    let mut request = tonic::Request::new(SetGroupEnvironmentPermissionRequest {
        workspace_name: workspace_name.clone(),
        project_name: project.to_string(),
        environment_name: environment.to_string(),
        group_name: group_name.clone(),
        role: role_enum,
    });
    add_auth_metadata(
        &mut request,
        &principal,
        "/zopp.ZoppService/SetGroupEnvironmentPermission",
    )?;

    client.set_group_environment_permission(request).await?;
    println!(
        "Set {} permission for group {} on environment {}/{}/{}",
        role, group_name, workspace_name, project, environment
    );

    Ok(())
}

pub async fn cmd_group_remove_environment_permission(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: Option<&str>,
    project: &str,
    environment: &str,
    group_name: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let workspace_name = workspace
        .map(|s| s.to_string())
        .ok_or("Workspace name required (use -w or --workspace)")?;

    let mut request = tonic::Request::new(RemoveGroupEnvironmentPermissionRequest {
        workspace_name: workspace_name.clone(),
        project_name: project.to_string(),
        environment_name: environment.to_string(),
        group_name: group_name.clone(),
    });
    add_auth_metadata(
        &mut request,
        &principal,
        "/zopp.ZoppService/RemoveGroupEnvironmentPermission",
    )?;

    client.remove_group_environment_permission(request).await?;
    println!(
        "Removed permission for group {} from environment {}/{}/{}",
        group_name, workspace_name, project, environment
    );

    Ok(())
}

// ────────────────────────────────────── Group Permission Get/List ──────────────────────────────────────

pub async fn cmd_group_get_permission(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: Option<&str>,
    group_name: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let workspace_name = workspace
        .map(|s| s.to_string())
        .ok_or("Workspace name required (use -w or --workspace)")?;

    let mut request = tonic::Request::new(zopp_proto::GetGroupWorkspacePermissionRequest {
        workspace_name: workspace_name.clone(),
        group_name: group_name.clone(),
    });
    add_auth_metadata(
        &mut request,
        &principal,
        "/zopp.ZoppService/GetGroupWorkspacePermission",
    )?;

    let response = client
        .get_group_workspace_permission(request)
        .await?
        .into_inner();

    let role_str = match Role::try_from(response.role) {
        Ok(Role::Admin) => "admin",
        Ok(Role::Write) => "write",
        Ok(Role::Read) => "read",
        _ => "unknown",
    };

    println!(
        "Group {} has {} permission on workspace {}",
        group_name, role_str, workspace_name
    );

    Ok(())
}

pub async fn cmd_group_list_permissions(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let workspace_name = workspace
        .map(|s| s.to_string())
        .ok_or("Workspace name required (use -w or --workspace)")?;

    let mut request = tonic::Request::new(zopp_proto::ListGroupWorkspacePermissionsRequest {
        workspace_name: workspace_name.clone(),
    });
    add_auth_metadata(
        &mut request,
        &principal,
        "/zopp.ZoppService/ListGroupWorkspacePermissions",
    )?;

    let response = client
        .list_group_workspace_permissions(request)
        .await?
        .into_inner();

    if response.permissions.is_empty() {
        println!("No group permissions found on workspace {}", workspace_name);
        return Ok(());
    }

    println!("Group permissions on workspace {}:", workspace_name);
    for perm in response.permissions {
        let role_str = match Role::try_from(perm.role) {
            Ok(Role::Admin) => "admin",
            Ok(Role::Write) => "write",
            Ok(Role::Read) => "read",
            _ => "unknown",
        };
        println!("  {} - {}", perm.group_name, role_str);
    }

    Ok(())
}

pub async fn cmd_group_get_project_permission(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: Option<&str>,
    project: &str,
    group_name: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let workspace_name = workspace
        .map(|s| s.to_string())
        .ok_or("Workspace name required (use -w or --workspace)")?;

    let mut request = tonic::Request::new(zopp_proto::GetGroupProjectPermissionRequest {
        workspace_name: workspace_name.clone(),
        project_name: project.to_string(),
        group_name: group_name.clone(),
    });
    add_auth_metadata(
        &mut request,
        &principal,
        "/zopp.ZoppService/GetGroupProjectPermission",
    )?;

    let response = client
        .get_group_project_permission(request)
        .await?
        .into_inner();

    let role_str = match Role::try_from(response.role) {
        Ok(Role::Admin) => "admin",
        Ok(Role::Write) => "write",
        Ok(Role::Read) => "read",
        _ => "unknown",
    };

    println!(
        "Group {} has {} permission on project {}/{}",
        group_name, role_str, workspace_name, project
    );

    Ok(())
}

pub async fn cmd_group_list_project_permissions(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: Option<&str>,
    project: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let workspace_name = workspace
        .map(|s| s.to_string())
        .ok_or("Workspace name required (use -w or --workspace)")?;

    let mut request = tonic::Request::new(zopp_proto::ListGroupProjectPermissionsRequest {
        workspace_name: workspace_name.clone(),
        project_name: project.to_string(),
    });
    add_auth_metadata(
        &mut request,
        &principal,
        "/zopp.ZoppService/ListGroupProjectPermissions",
    )?;

    let response = client
        .list_group_project_permissions(request)
        .await?
        .into_inner();

    if response.permissions.is_empty() {
        println!(
            "No group permissions found on project {}/{}",
            workspace_name, project
        );
        return Ok(());
    }

    println!(
        "Group permissions on project {}/{}:",
        workspace_name, project
    );
    for perm in response.permissions {
        let role_str = match Role::try_from(perm.role) {
            Ok(Role::Admin) => "admin",
            Ok(Role::Write) => "write",
            Ok(Role::Read) => "read",
            _ => "unknown",
        };
        println!("  {} - {}", perm.group_name, role_str);
    }

    Ok(())
}

pub async fn cmd_group_get_environment_permission(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: Option<&str>,
    project: &str,
    environment: &str,
    group_name: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let workspace_name = workspace
        .map(|s| s.to_string())
        .ok_or("Workspace name required (use -w or --workspace)")?;

    let mut request = tonic::Request::new(zopp_proto::GetGroupEnvironmentPermissionRequest {
        workspace_name: workspace_name.clone(),
        project_name: project.to_string(),
        environment_name: environment.to_string(),
        group_name: group_name.clone(),
    });
    add_auth_metadata(
        &mut request,
        &principal,
        "/zopp.ZoppService/GetGroupEnvironmentPermission",
    )?;

    let response = client
        .get_group_environment_permission(request)
        .await?
        .into_inner();

    let role_str = match Role::try_from(response.role) {
        Ok(Role::Admin) => "admin",
        Ok(Role::Write) => "write",
        Ok(Role::Read) => "read",
        _ => "unknown",
    };

    println!(
        "Group {} has {} permission on environment {}/{}/{}",
        group_name, role_str, workspace_name, project, environment
    );

    Ok(())
}

pub async fn cmd_group_list_environment_permissions(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: Option<&str>,
    project: &str,
    environment: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let workspace_name = workspace
        .map(|s| s.to_string())
        .ok_or("Workspace name required (use -w or --workspace)")?;

    let mut request = tonic::Request::new(zopp_proto::ListGroupEnvironmentPermissionsRequest {
        workspace_name: workspace_name.clone(),
        project_name: project.to_string(),
        environment_name: environment.to_string(),
    });
    add_auth_metadata(
        &mut request,
        &principal,
        "/zopp.ZoppService/ListGroupEnvironmentPermissions",
    )?;

    let response = client
        .list_group_environment_permissions(request)
        .await?
        .into_inner();

    if response.permissions.is_empty() {
        println!(
            "No group permissions found on environment {}/{}/{}",
            workspace_name, project, environment
        );
        return Ok(());
    }

    println!(
        "Group permissions on environment {}/{}/{}:",
        workspace_name, project, environment
    );
    for perm in response.permissions {
        let role_str = match Role::try_from(perm.role) {
            Ok(Role::Admin) => "admin",
            Ok(Role::Write) => "write",
            Ok(Role::Read) => "read",
            _ => "unknown",
        };
        println!("  {} - {}", perm.group_name, role_str);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::MockGroupClient;
    use tonic::{Response, Status};
    use zopp_proto::{Group, GroupList};

    // Create a test principal config with valid hex keys
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

    #[tokio::test]
    async fn test_group_list_inner_success() {
        let mut mock = MockGroupClient::new();

        mock.expect_list_groups().returning(|_| {
            Ok(Response::new(GroupList {
                groups: vec![
                    Group {
                        id: "group-1".to_string(),
                        name: "developers".to_string(),
                        description: "Development team".to_string(),
                        workspace_id: "ws-1".to_string(),
                        created_at: "2024-01-01T00:00:00Z".to_string(),
                        updated_at: "2024-01-01T00:00:00Z".to_string(),
                    },
                    Group {
                        id: "group-2".to_string(),
                        name: "admins".to_string(),
                        description: "Admin team".to_string(),
                        workspace_id: "ws-1".to_string(),
                        created_at: "2024-01-01T00:00:00Z".to_string(),
                        updated_at: "2024-01-01T00:00:00Z".to_string(),
                    },
                ],
            }))
        });

        let principal = create_test_principal();
        let result = group_list_inner(&mut mock, &principal, "test-workspace").await;

        assert!(result.is_ok());
        let groups = result.unwrap();
        assert_eq!(groups.groups.len(), 2);
        assert_eq!(groups.groups[0].name, "developers");
        assert_eq!(groups.groups[1].name, "admins");
    }

    #[tokio::test]
    async fn test_group_list_inner_empty() {
        let mut mock = MockGroupClient::new();

        mock.expect_list_groups()
            .returning(|_| Ok(Response::new(GroupList { groups: vec![] })));

        let principal = create_test_principal();
        let result = group_list_inner(&mut mock, &principal, "test-workspace").await;

        assert!(result.is_ok());
        let groups = result.unwrap();
        assert!(groups.groups.is_empty());
    }

    #[tokio::test]
    async fn test_group_list_inner_grpc_error() {
        let mut mock = MockGroupClient::new();

        mock.expect_list_groups()
            .returning(|_| Err(Status::unavailable("Server unavailable")));

        let principal = create_test_principal();
        let result = group_list_inner(&mut mock, &principal, "test-workspace").await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("unavailable"));
    }

    #[tokio::test]
    async fn test_group_list_inner_permission_denied() {
        let mut mock = MockGroupClient::new();

        mock.expect_list_groups()
            .returning(|_| Err(Status::permission_denied("Not authorized")));

        let principal = create_test_principal();
        let result = group_list_inner(&mut mock, &principal, "test-workspace").await;

        assert!(result.is_err());
    }

    #[test]
    fn test_print_group_list_empty() {
        // This is a simple print test - just verify it doesn't panic
        let groups = GroupList { groups: vec![] };
        print_group_list(&groups);
    }

    #[test]
    fn test_print_group_list_with_items() {
        let groups = GroupList {
            groups: vec![
                Group {
                    id: "1".to_string(),
                    name: "team-a".to_string(),
                    description: "Team A".to_string(),
                    workspace_id: "ws".to_string(),
                    created_at: "2024-01-01T00:00:00Z".to_string(),
                    updated_at: "2024-01-01T00:00:00Z".to_string(),
                },
                Group {
                    id: "2".to_string(),
                    name: "team-b".to_string(),
                    description: "Team B".to_string(),
                    workspace_id: "ws".to_string(),
                    created_at: "2024-01-01T00:00:00Z".to_string(),
                    updated_at: "2024-01-01T00:00:00Z".to_string(),
                },
            ],
        };
        print_group_list(&groups);
    }

    #[tokio::test]
    async fn test_group_list_inner_internal_error() {
        let mut mock = MockGroupClient::new();

        mock.expect_list_groups()
            .returning(|_| Err(Status::internal("Database error")));

        let principal = create_test_principal();
        let result = group_list_inner(&mut mock, &principal, "test-workspace").await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_group_list_inner_single_group() {
        let mut mock = MockGroupClient::new();

        mock.expect_list_groups().returning(|_| {
            Ok(Response::new(GroupList {
                groups: vec![Group {
                    id: "only-group".to_string(),
                    name: "only-group".to_string(),
                    description: "Only group".to_string(),
                    workspace_id: "ws".to_string(),
                    created_at: "2024-01-01T00:00:00Z".to_string(),
                    updated_at: "2024-01-01T00:00:00Z".to_string(),
                }],
            }))
        });

        let principal = create_test_principal();
        let result = group_list_inner(&mut mock, &principal, "test-workspace").await;

        assert!(result.is_ok());
        let groups = result.unwrap();
        assert_eq!(groups.groups.len(), 1);
    }

    #[tokio::test]
    async fn test_group_create_inner_success() {
        let mut mock = MockGroupClient::new();

        mock.expect_create_group().returning(|_| {
            Ok(Response::new(Group {
                id: "new-group-id".to_string(),
                name: "new-group".to_string(),
                description: "A new group".to_string(),
                workspace_id: "ws-1".to_string(),
                created_at: "2024-01-01T00:00:00Z".to_string(),
                updated_at: "2024-01-01T00:00:00Z".to_string(),
            }))
        });

        let principal = create_test_principal();
        let result = group_create_inner(
            &mut mock,
            &principal,
            "test-workspace",
            "new-group",
            "A new group",
        )
        .await;

        assert!(result.is_ok());
        let group = result.unwrap();
        assert_eq!(group.name, "new-group");
        assert_eq!(group.description, "A new group");
    }

    #[tokio::test]
    async fn test_group_create_inner_permission_denied() {
        let mut mock = MockGroupClient::new();

        mock.expect_create_group()
            .returning(|_| Err(Status::permission_denied("Not authorized")));

        let principal = create_test_principal();
        let result = group_create_inner(
            &mut mock,
            &principal,
            "test-workspace",
            "new-group",
            "A new group",
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_group_create_inner_already_exists() {
        let mut mock = MockGroupClient::new();

        mock.expect_create_group()
            .returning(|_| Err(Status::already_exists("Group already exists")));

        let principal = create_test_principal();
        let result = group_create_inner(
            &mut mock,
            &principal,
            "test-workspace",
            "existing-group",
            "",
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_group_delete_inner_success() {
        let mut mock = MockGroupClient::new();

        mock.expect_delete_group()
            .returning(|_| Ok(Response::new(zopp_proto::Empty {})));

        let principal = create_test_principal();
        let result =
            group_delete_inner(&mut mock, &principal, "test-workspace", "group-to-delete").await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_group_delete_inner_not_found() {
        let mut mock = MockGroupClient::new();

        mock.expect_delete_group()
            .returning(|_| Err(Status::not_found("Group not found")));

        let principal = create_test_principal();
        let result =
            group_delete_inner(&mut mock, &principal, "test-workspace", "nonexistent-group").await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_group_delete_inner_permission_denied() {
        let mut mock = MockGroupClient::new();

        mock.expect_delete_group()
            .returning(|_| Err(Status::permission_denied("Not authorized")));

        let principal = create_test_principal();
        let result =
            group_delete_inner(&mut mock, &principal, "test-workspace", "some-group").await;

        assert!(result.is_err());
    }

    #[test]
    fn test_print_group_created() {
        // Test print function doesn't panic
        let group = Group {
            id: "test-id".to_string(),
            name: "test-group".to_string(),
            description: "Test description".to_string(),
            workspace_id: "ws".to_string(),
            created_at: "2024-01-01T00:00:00Z".to_string(),
            updated_at: "2024-01-01T00:00:00Z".to_string(),
        };
        print_group_created(&group);
    }

    #[test]
    fn test_print_group_created_no_description() {
        // Test print function doesn't panic with empty description
        let group = Group {
            id: "test-id".to_string(),
            name: "test-group".to_string(),
            description: "".to_string(),
            workspace_id: "ws".to_string(),
            created_at: "2024-01-01T00:00:00Z".to_string(),
            updated_at: "2024-01-01T00:00:00Z".to_string(),
        };
        print_group_created(&group);
    }
}

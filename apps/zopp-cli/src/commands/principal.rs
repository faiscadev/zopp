use crate::config::{get_current_principal, load_config, save_config, PrincipalConfig};
use crate::grpc::{add_auth_metadata, connect};
use ed25519_dalek::SigningKey;
use zopp_proto::{
    Empty, GetWorkspaceKeysRequest, GrantPrincipalWorkspaceAccessRequest,
    ListWorkspaceServicePrincipalsRequest, RegisterRequest, RemovePrincipalFromWorkspaceRequest,
    RenamePrincipalRequest, RevokeAllPrincipalPermissionsRequest, Role,
};

/// Validate create principal arguments
pub fn validate_create_args(
    is_service: bool,
    workspace: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    if is_service && workspace.is_none() {
        return Err("Service principals require --workspace flag".into());
    }
    if !is_service && workspace.is_some() {
        return Err("--workspace flag is only valid with --service".into());
    }
    Ok(())
}

/// Check if a principal with the given name already exists
pub fn principal_exists(principals: &[PrincipalConfig], name: &str) -> bool {
    principals.iter().any(|p| p.name == name)
}

/// Find principal by name in the list
pub fn find_principal_by_name<'a>(
    principals: &'a [PrincipalConfig],
    name: &str,
) -> Option<&'a PrincipalConfig> {
    principals.iter().find(|p| p.name == name)
}

/// Validate rename principal arguments
pub fn validate_rename_args(
    principals: &[PrincipalConfig],
    old_name: &str,
    new_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if !principal_exists(principals, old_name) {
        return Err(format!("Principal '{}' not found", old_name).into());
    }
    if principal_exists(principals, new_name) {
        return Err(format!("Principal '{}' already exists", new_name).into());
    }
    Ok(())
}

/// Validate that we can delete a principal (must have more than one)
pub fn validate_delete_args(
    principals: &[PrincipalConfig],
    name: &str,
) -> Result<usize, Box<dyn std::error::Error>> {
    if principals.len() == 1 {
        return Err("Cannot delete the only principal".into());
    }
    principals
        .iter()
        .position(|p| p.name == name)
        .ok_or_else(|| format!("Principal '{}' not found", name).into())
}

/// Convert Role enum to display string
pub fn role_to_display_string(role: i32) -> &'static str {
    match Role::try_from(role) {
        Ok(Role::Admin) => "admin",
        Ok(Role::Write) => "write",
        Ok(Role::Read) => "read",
        _ => "unknown",
    }
}

/// Get the current principal marker (* for current, space otherwise)
pub fn get_principal_marker(principal_name: &str, current: Option<&str>) -> &'static str {
    if Some(principal_name) == current {
        "*"
    } else {
        " "
    }
}

pub async fn cmd_principal_list() -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config()?;
    let current = config
        .current_principal
        .as_deref()
        .or_else(|| config.principals.first().map(|p| p.name.as_str()));

    println!("Principals:");
    for principal in &config.principals {
        let marker = if Some(principal.name.as_str()) == current {
            "*"
        } else {
            " "
        };
        println!("{} {} (ID: {})", marker, principal.name, principal.id);
    }
    Ok(())
}

pub async fn cmd_principal_current() -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config()?;
    let principal = get_current_principal(&config)?;
    println!("{}", principal.name);
    Ok(())
}

pub async fn cmd_principal_create(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    name: &str,
    is_service: bool,
    workspace: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = load_config()?;

    // Validate: --service requires --workspace
    if is_service && workspace.is_none() {
        return Err("Service principals require --workspace flag".into());
    }

    // Validate: --workspace without --service is not allowed (for now)
    if !is_service && workspace.is_some() {
        return Err("--workspace flag is only valid with --service".into());
    }

    if config.principals.iter().any(|p| p.name == name) {
        return Err(format!("Principal '{}' already exists", name).into());
    }

    // Generate new principal's keypairs
    let signing_key = SigningKey::generate(&mut rand_core::OsRng);
    let verifying_key = signing_key.verifying_key();
    let public_key = verifying_key.to_bytes().to_vec();

    let new_x25519_keypair = zopp_crypto::Keypair::generate();
    let new_x25519_public_bytes = new_x25519_keypair.public_key_bytes().to_vec();

    let mut client = connect(server, tls_ca_cert).await?;
    let caller_principal = get_current_principal(&config)?.clone();

    // For service principals, wrap KEK for the new principal
    let (ephemeral_pub, kek_wrapped, kek_nonce) = if let Some(ws_name) = workspace {
        // Get caller's wrapped KEK for this workspace
        let mut keys_request = tonic::Request::new(GetWorkspaceKeysRequest {
            workspace_name: ws_name.to_string(),
        });
        add_auth_metadata(
            &mut keys_request,
            &caller_principal,
            "/zopp.ZoppService/GetWorkspaceKeys",
        )?;
        let keys = client.get_workspace_keys(keys_request).await?.into_inner();

        // Unwrap KEK using caller's X25519 private key
        let caller_x25519_private = caller_principal
            .x25519_private_key
            .as_ref()
            .ok_or("Caller principal missing X25519 private key")?;
        let caller_x25519_bytes = hex::decode(caller_x25519_private)?;
        let mut caller_x25519_array = [0u8; 32];
        caller_x25519_array.copy_from_slice(&caller_x25519_bytes);
        let caller_keypair = zopp_crypto::Keypair::from_secret_bytes(&caller_x25519_array);

        let ephemeral_pub_key = zopp_crypto::public_key_from_bytes(&keys.ephemeral_pub)?;
        let shared_secret = caller_keypair.shared_secret(&ephemeral_pub_key);

        let aad = format!("workspace:{}", keys.workspace_id).into_bytes();
        let mut nonce_array = [0u8; 24];
        nonce_array.copy_from_slice(&keys.kek_nonce);
        let nonce = zopp_crypto::Nonce(nonce_array);

        let kek = zopp_crypto::unwrap_key(&keys.kek_wrapped, &nonce, &shared_secret, &aad)?;

        // Wrap KEK for the new service principal's X25519 public key
        let new_ephemeral_keypair = zopp_crypto::Keypair::generate();
        let new_principal_pubkey = zopp_crypto::public_key_from_bytes(&new_x25519_public_bytes)?;
        let new_shared_secret = new_ephemeral_keypair.shared_secret(&new_principal_pubkey);

        let (wrap_nonce, wrapped) = zopp_crypto::wrap_key(&kek, &new_shared_secret, &aad)?;

        (
            Some(new_ephemeral_keypair.public_key_bytes().to_vec()),
            Some(wrapped.0),
            Some(wrap_nonce.0.to_vec()),
        )
    } else {
        (None, None, None)
    };

    let mut request = tonic::Request::new(RegisterRequest {
        email: config.email.clone(),
        principal_name: name.to_string(),
        public_key,
        x25519_public_key: new_x25519_public_bytes.clone(),
        is_service,
        workspace_name: workspace.map(|s| s.to_string()),
        ephemeral_pub,
        kek_wrapped,
        kek_nonce,
    });
    add_auth_metadata(
        &mut request,
        &caller_principal,
        "/zopp.ZoppService/Register",
    )?;

    let response = client.register(request).await?.into_inner();

    let principal_id = response.principal_id.clone();
    config.principals.push(PrincipalConfig {
        id: response.principal_id.clone(),
        name: name.to_string(),
        private_key: hex::encode(signing_key.to_bytes()),
        public_key: hex::encode(verifying_key.to_bytes()),
        x25519_private_key: Some(hex::encode(new_x25519_keypair.secret_key_bytes())),
        x25519_public_key: Some(hex::encode(new_x25519_keypair.public_key_bytes())),
    });
    save_config(&config)?;

    if is_service {
        println!(
            "Service principal '{}' created (ID: {})",
            name, principal_id
        );
        println!("  Added to workspace: {}", workspace.unwrap());
        println!(
            "  Grant permissions with: zopp permission set -w {} --principal {} --role <role>",
            workspace.unwrap(),
            principal_id
        );
    } else {
        println!("Principal '{}' created (ID: {})", name, principal_id);

        // For device principals, grant KEK access to all workspaces the user has access to
        let mut ws_request = tonic::Request::new(Empty {});
        add_auth_metadata(
            &mut ws_request,
            &caller_principal,
            "/zopp.ZoppService/ListWorkspaces",
        )?;
        let workspaces = client
            .list_workspaces(ws_request)
            .await?
            .into_inner()
            .workspaces;

        if !workspaces.is_empty() {
            println!("  Granting access to workspaces...");
            let caller_x25519_private = caller_principal
                .x25519_private_key
                .as_ref()
                .ok_or("Caller principal missing X25519 private key")?;
            let caller_x25519_bytes = hex::decode(caller_x25519_private)?;
            let mut caller_x25519_array = [0u8; 32];
            caller_x25519_array.copy_from_slice(&caller_x25519_bytes);
            let caller_keypair = zopp_crypto::Keypair::from_secret_bytes(&caller_x25519_array);

            for ws in &workspaces {
                // Get caller's wrapped KEK for this workspace
                let mut keys_request = tonic::Request::new(GetWorkspaceKeysRequest {
                    workspace_name: ws.name.clone(),
                });
                add_auth_metadata(
                    &mut keys_request,
                    &caller_principal,
                    "/zopp.ZoppService/GetWorkspaceKeys",
                )?;
                let keys = client.get_workspace_keys(keys_request).await?.into_inner();

                // Unwrap KEK
                let ephemeral_pub_key = zopp_crypto::public_key_from_bytes(&keys.ephemeral_pub)?;
                let shared_secret = caller_keypair.shared_secret(&ephemeral_pub_key);
                let aad = format!("workspace:{}", keys.workspace_id).into_bytes();
                let mut nonce_array = [0u8; 24];
                nonce_array.copy_from_slice(&keys.kek_nonce);
                let nonce = zopp_crypto::Nonce(nonce_array);
                let kek = zopp_crypto::unwrap_key(&keys.kek_wrapped, &nonce, &shared_secret, &aad)?;

                // Wrap KEK for the new device principal
                let new_ephemeral_keypair = zopp_crypto::Keypair::generate();
                let new_principal_pubkey =
                    zopp_crypto::public_key_from_bytes(&new_x25519_public_bytes)?;
                let new_shared_secret = new_ephemeral_keypair.shared_secret(&new_principal_pubkey);
                let (wrap_nonce, wrapped) = zopp_crypto::wrap_key(&kek, &new_shared_secret, &aad)?;

                // Grant access via RPC
                let mut grant_request = tonic::Request::new(GrantPrincipalWorkspaceAccessRequest {
                    workspace_name: ws.name.clone(),
                    principal_id: principal_id.clone(),
                    ephemeral_pub: new_ephemeral_keypair.public_key_bytes().to_vec(),
                    kek_wrapped: wrapped.0,
                    kek_nonce: wrap_nonce.0.to_vec(),
                });
                add_auth_metadata(
                    &mut grant_request,
                    &caller_principal,
                    "/zopp.ZoppService/GrantPrincipalWorkspaceAccess",
                )?;
                client
                    .grant_principal_workspace_access(grant_request)
                    .await?;

                println!("    ✓ {}", ws.name);
            }
        }
    }
    Ok(())
}

pub async fn cmd_principal_use(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = load_config()?;

    if !config.principals.iter().any(|p| p.name == name) {
        return Err(format!("Principal '{}' not found", name).into());
    }

    config.current_principal = Some(name.to_string());
    save_config(&config)?;

    println!("✓ Switched to principal '{}'", name);
    Ok(())
}

pub async fn cmd_principal_rename(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    name: &str,
    new_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = load_config()?;

    if !config.principals.iter().any(|p| p.name == name) {
        return Err(format!("Principal '{}' not found", name).into());
    }

    if config.principals.iter().any(|p| p.name == new_name) {
        return Err(format!("Principal '{}' already exists", new_name).into());
    }

    let principal = config.principals.iter().find(|p| p.name == name).unwrap();

    let principal_id = principal.id.clone();

    let mut client = connect(server, tls_ca_cert).await?;
    let mut request = tonic::Request::new(RenamePrincipalRequest {
        principal_id: principal_id.clone(),
        new_name: new_name.to_string(),
    });
    add_auth_metadata(&mut request, principal, "/zopp.ZoppService/RenamePrincipal")?;

    client.rename_principal(request).await?;

    let principal = config
        .principals
        .iter_mut()
        .find(|p| p.name == name)
        .unwrap();
    principal.name = new_name.to_string();

    if config.current_principal.as_deref() == Some(name) {
        config.current_principal = Some(new_name.to_string());
    }
    save_config(&config)?;

    println!("✓ Principal renamed from '{}' to '{}'", name, new_name);
    Ok(())
}

pub async fn cmd_principal_delete(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = load_config()?;

    if config.principals.len() == 1 {
        return Err("Cannot delete the only principal".into());
    }

    let idx = config
        .principals
        .iter()
        .position(|p| p.name == name)
        .ok_or_else(|| format!("Principal '{}' not found", name))?;

    config.principals.remove(idx);

    if config.current_principal.as_deref() == Some(name) {
        config.current_principal = config.principals.first().map(|p| p.name.clone());
    }

    save_config(&config)?;

    println!("✓ Principal '{}' deleted", name);
    if let Some(current) = &config.current_principal {
        println!("Switched to principal '{}'", current);
    }
    Ok(())
}

pub async fn cmd_principal_service_list(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config()?;
    let principal = get_current_principal(&config)?;

    let mut client = connect(server, tls_ca_cert).await?;
    let mut request = tonic::Request::new(ListWorkspaceServicePrincipalsRequest {
        workspace_name: workspace.to_string(),
    });
    add_auth_metadata(
        &mut request,
        principal,
        "/zopp.ZoppService/ListWorkspaceServicePrincipals",
    )?;

    let response = client
        .list_workspace_service_principals(request)
        .await?
        .into_inner();

    if response.service_principals.is_empty() {
        println!("No service principals in workspace '{}'", workspace);
        return Ok(());
    }

    println!("Service principals in workspace '{}':", workspace);
    for sp in response.service_principals {
        println!();
        println!("  {} (ID: {})", sp.name, sp.id);
        println!("    Created: {}", sp.created_at);
        if sp.permissions.is_empty() {
            println!("    Permissions: none");
        } else {
            println!("    Permissions:");
            for perm in sp.permissions {
                let role = match Role::try_from(perm.role) {
                    Ok(Role::Admin) => "admin",
                    Ok(Role::Write) => "write",
                    Ok(Role::Read) => "read",
                    _ => "unknown",
                };
                println!("      {} -> {}", perm.scope, role);
            }
        }
    }
    Ok(())
}

pub async fn cmd_principal_workspace_remove(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    principal_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config()?;
    let principal = get_current_principal(&config)?;

    let mut client = connect(server, tls_ca_cert).await?;
    let mut request = tonic::Request::new(RemovePrincipalFromWorkspaceRequest {
        workspace_name: workspace.to_string(),
        principal_id: principal_id.to_string(),
    });
    add_auth_metadata(
        &mut request,
        principal,
        "/zopp.ZoppService/RemovePrincipalFromWorkspace",
    )?;

    client.remove_principal_from_workspace(request).await?;

    println!(
        "Principal {} removed from workspace '{}'",
        principal_id, workspace
    );
    Ok(())
}

pub async fn cmd_principal_revoke_all(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    principal_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config()?;
    let principal = get_current_principal(&config)?;

    let mut client = connect(server, tls_ca_cert).await?;
    let mut request = tonic::Request::new(RevokeAllPrincipalPermissionsRequest {
        workspace_name: workspace.to_string(),
        principal_id: principal_id.to_string(),
    });
    add_auth_metadata(
        &mut request,
        principal,
        "/zopp.ZoppService/RevokeAllPrincipalPermissions",
    )?;

    let response = client
        .revoke_all_principal_permissions(request)
        .await?
        .into_inner();

    println!(
        "Revoked {} permissions for principal {} in workspace '{}'",
        response.permissions_revoked, principal_id, workspace
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_principal(name: &str, id: &str) -> PrincipalConfig {
        PrincipalConfig {
            id: id.to_string(),
            name: name.to_string(),
            private_key: "0".repeat(64),
            public_key: "1".repeat(64),
            x25519_private_key: Some("2".repeat(64)),
            x25519_public_key: Some("3".repeat(64)),
        }
    }

    fn create_test_principals() -> Vec<PrincipalConfig> {
        vec![
            create_test_principal("laptop", "principal-1"),
            create_test_principal("desktop", "principal-2"),
        ]
    }

    // validate_create_args tests
    #[test]
    fn test_validate_create_args_service_with_workspace() {
        let result = validate_create_args(true, Some("my-workspace"));
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_create_args_device_without_workspace() {
        let result = validate_create_args(false, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_create_args_service_without_workspace() {
        let result = validate_create_args(true, None);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("require --workspace"));
    }

    #[test]
    fn test_validate_create_args_device_with_workspace() {
        let result = validate_create_args(false, Some("my-workspace"));
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("only valid with --service"));
    }

    // principal_exists tests
    #[test]
    fn test_principal_exists_found() {
        let principals = create_test_principals();
        assert!(principal_exists(&principals, "laptop"));
        assert!(principal_exists(&principals, "desktop"));
    }

    #[test]
    fn test_principal_exists_not_found() {
        let principals = create_test_principals();
        assert!(!principal_exists(&principals, "phone"));
        assert!(!principal_exists(&principals, ""));
    }

    #[test]
    fn test_principal_exists_empty_list() {
        let principals: Vec<PrincipalConfig> = vec![];
        assert!(!principal_exists(&principals, "laptop"));
    }

    #[test]
    fn test_principal_exists_case_sensitive() {
        let principals = create_test_principals();
        assert!(!principal_exists(&principals, "Laptop"));
        assert!(!principal_exists(&principals, "LAPTOP"));
    }

    // find_principal_by_name tests
    #[test]
    fn test_find_principal_by_name_found() {
        let principals = create_test_principals();
        let result = find_principal_by_name(&principals, "laptop");
        assert!(result.is_some());
        let principal = result.unwrap();
        assert_eq!(principal.name, "laptop");
        assert_eq!(principal.id, "principal-1");
    }

    #[test]
    fn test_find_principal_by_name_not_found() {
        let principals = create_test_principals();
        let result = find_principal_by_name(&principals, "phone");
        assert!(result.is_none());
    }

    #[test]
    fn test_find_principal_by_name_empty_list() {
        let principals: Vec<PrincipalConfig> = vec![];
        let result = find_principal_by_name(&principals, "laptop");
        assert!(result.is_none());
    }

    // validate_rename_args tests
    #[test]
    fn test_validate_rename_args_success() {
        let principals = create_test_principals();
        let result = validate_rename_args(&principals, "laptop", "new-laptop");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_rename_args_old_name_not_found() {
        let principals = create_test_principals();
        let result = validate_rename_args(&principals, "phone", "new-phone");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_validate_rename_args_new_name_exists() {
        let principals = create_test_principals();
        let result = validate_rename_args(&principals, "laptop", "desktop");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already exists"));
    }

    #[test]
    fn test_validate_rename_args_same_name() {
        let principals = create_test_principals();
        // This should fail because "laptop" already exists
        let result = validate_rename_args(&principals, "laptop", "laptop");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already exists"));
    }

    // validate_delete_args tests
    #[test]
    fn test_validate_delete_args_success() {
        let principals = create_test_principals();
        let result = validate_delete_args(&principals, "laptop");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_validate_delete_args_returns_correct_index() {
        let principals = create_test_principals();
        let result = validate_delete_args(&principals, "desktop");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1);
    }

    #[test]
    fn test_validate_delete_args_only_principal() {
        let principals = vec![create_test_principal("only-one", "principal-1")];
        let result = validate_delete_args(&principals, "only-one");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("only principal"));
    }

    #[test]
    fn test_validate_delete_args_not_found() {
        let principals = create_test_principals();
        let result = validate_delete_args(&principals, "phone");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    // role_to_display_string tests
    #[test]
    fn test_role_to_display_string_admin() {
        assert_eq!(role_to_display_string(Role::Admin as i32), "admin");
    }

    #[test]
    fn test_role_to_display_string_write() {
        assert_eq!(role_to_display_string(Role::Write as i32), "write");
    }

    #[test]
    fn test_role_to_display_string_read() {
        assert_eq!(role_to_display_string(Role::Read as i32), "read");
    }

    #[test]
    fn test_role_to_display_string_unknown() {
        assert_eq!(role_to_display_string(999), "unknown");
    }

    #[test]
    fn test_role_to_display_string_negative() {
        assert_eq!(role_to_display_string(-1), "unknown");
    }

    // get_principal_marker tests
    #[test]
    fn test_get_principal_marker_is_current() {
        assert_eq!(get_principal_marker("laptop", Some("laptop")), "*");
    }

    #[test]
    fn test_get_principal_marker_not_current() {
        assert_eq!(get_principal_marker("laptop", Some("desktop")), " ");
    }

    #[test]
    fn test_get_principal_marker_no_current() {
        assert_eq!(get_principal_marker("laptop", None), " ");
    }

    #[test]
    fn test_get_principal_marker_empty_current() {
        assert_eq!(get_principal_marker("laptop", Some("")), " ");
    }

    #[test]
    fn test_get_principal_marker_empty_name_matches_empty_current() {
        assert_eq!(get_principal_marker("", Some("")), "*");
    }
}

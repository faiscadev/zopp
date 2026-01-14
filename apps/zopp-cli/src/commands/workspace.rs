use crate::config::PrincipalConfig;
use crate::grpc::{add_auth_metadata, setup_client};

#[cfg(test)]
use crate::client::MockWorkspaceClient;

use zopp_proto::{
    CreateWorkspaceRequest, Empty, GetPrincipalRequest, GetWorkspaceKeysRequest,
    GrantPrincipalWorkspaceAccessRequest, WorkspaceList,
};

/// Inner implementation for workspace list that accepts a trait-bounded client.
/// This function is testable with mock clients.
pub async fn workspace_list_inner<C>(
    client: &mut C,
    principal: &PrincipalConfig,
) -> Result<WorkspaceList, Box<dyn std::error::Error>>
where
    C: crate::client::WorkspaceClient,
{
    let mut request = tonic::Request::new(Empty {});
    add_auth_metadata(&mut request, principal, "/zopp.ZoppService/ListWorkspaces")?;

    let response = client.list_workspaces(request).await?.into_inner();
    Ok(response)
}

/// Print workspace list results.
pub fn print_workspace_list(workspaces: &WorkspaceList) {
    if workspaces.workspaces.is_empty() {
        println!("No workspaces found.");
    } else {
        println!("Workspaces:");
        for ws in &workspaces.workspaces {
            println!("  {}", ws.name);
        }
    }
}

pub async fn cmd_workspace_list(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;
    let workspaces = workspace_list_inner(&mut client, &principal).await?;
    print_workspace_list(&workspaces);
    Ok(())
}

pub async fn cmd_workspace_create(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    use uuid::Uuid;
    let workspace_id = Uuid::now_v7();
    let workspace_id_str = workspace_id.to_string();

    let mut kek = [0u8; 32];
    use rand_core::RngCore;
    rand_core::OsRng.fill_bytes(&mut kek);

    // Get principal's X25519 keypair for wrapping the KEK
    let x25519_private_key = principal
        .x25519_private_key
        .as_ref()
        .ok_or("Principal missing X25519 private key")?;
    let x25519_private_bytes = hex::decode(x25519_private_key)?;
    let mut x25519_array = [0u8; 32];
    x25519_array.copy_from_slice(&x25519_private_bytes);
    let x25519_keypair = zopp_crypto::Keypair::from_secret_bytes(&x25519_array);

    let ephemeral_keypair = zopp_crypto::Keypair::generate();
    let ephemeral_pub = ephemeral_keypair.public_key_bytes().to_vec();

    let my_public = zopp_crypto::public_key_from_bytes(&x25519_keypair.public_key_bytes())?;
    let shared_secret = ephemeral_keypair.shared_secret(&my_public);

    let aad = format!("workspace:{}", workspace_id_str).into_bytes();
    let (nonce, wrapped) = zopp_crypto::wrap_key(&kek, &shared_secret, &aad)?;

    let mut request = tonic::Request::new(CreateWorkspaceRequest {
        id: workspace_id_str.clone(),
        name: name.to_string(),
        ephemeral_pub,
        kek_wrapped: wrapped.0,
        kek_nonce: nonce.0.to_vec(),
    });
    add_auth_metadata(
        &mut request,
        &principal,
        "/zopp.ZoppService/CreateWorkspace",
    )?;

    let response = client.create_workspace(request).await?.into_inner();

    println!("Workspace created!\n");
    println!("Name: {}", response.name);
    println!("ID:   {}", response.id);

    Ok(())
}

pub async fn cmd_workspace_grant_principal_access(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace: &str,
    principal_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, caller) = setup_client(server, tls_ca_cert).await?;

    // Step 1: Get target principal's X25519 public key
    let mut request = tonic::Request::new(GetPrincipalRequest {
        principal_id: principal_id.to_string(),
    });
    add_auth_metadata(&mut request, &caller, "/zopp.ZoppService/GetPrincipal")?;
    let target_principal = client.get_principal(request).await?.into_inner();

    if target_principal.x25519_public_key.is_empty() {
        return Err("Target principal has no X25519 public key".into());
    }

    // Step 2: Get caller's wrapped KEK for this workspace
    let mut request = tonic::Request::new(GetWorkspaceKeysRequest {
        workspace_name: workspace.to_string(),
    });
    add_auth_metadata(&mut request, &caller, "/zopp.ZoppService/GetWorkspaceKeys")?;
    let keys = client.get_workspace_keys(request).await?.into_inner();

    // Step 3: Unwrap KEK using caller's X25519 private key
    let caller_x25519_private = caller
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

    // Step 4: Wrap KEK for target principal's X25519 public key
    let new_ephemeral_keypair = zopp_crypto::Keypair::generate();
    let target_pubkey = zopp_crypto::public_key_from_bytes(&target_principal.x25519_public_key)?;
    let new_shared_secret = new_ephemeral_keypair.shared_secret(&target_pubkey);

    let (wrap_nonce, wrapped) = zopp_crypto::wrap_key(&kek, &new_shared_secret, &aad)?;

    // Step 5: Send to server
    let mut request = tonic::Request::new(GrantPrincipalWorkspaceAccessRequest {
        workspace_name: workspace.to_string(),
        principal_id: principal_id.to_string(),
        ephemeral_pub: new_ephemeral_keypair.public_key_bytes().to_vec(),
        kek_wrapped: wrapped.0,
        kek_nonce: wrap_nonce.0.to_vec(),
    });
    add_auth_metadata(
        &mut request,
        &caller,
        "/zopp.ZoppService/GrantPrincipalWorkspaceAccess",
    )?;

    client.grant_principal_workspace_access(request).await?;

    println!(
        "Granted workspace '{}' access to principal '{}'",
        workspace, principal_id
    );
    println!("  Principal name: {}", target_principal.name);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::{Response, Status};
    use zopp_proto::{Workspace, WorkspaceList};

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
    async fn test_workspace_list_inner_success() {
        let mut mock = MockWorkspaceClient::new();

        mock.expect_list_workspaces().returning(|_| {
            Ok(Response::new(WorkspaceList {
                workspaces: vec![
                    Workspace {
                        id: "ws-1".to_string(),
                        name: "workspace-one".to_string(),
                    },
                    Workspace {
                        id: "ws-2".to_string(),
                        name: "workspace-two".to_string(),
                    },
                ],
            }))
        });

        let principal = create_test_principal();
        let result = workspace_list_inner(&mut mock, &principal).await;

        assert!(result.is_ok());
        let workspaces = result.unwrap();
        assert_eq!(workspaces.workspaces.len(), 2);
        assert_eq!(workspaces.workspaces[0].name, "workspace-one");
        assert_eq!(workspaces.workspaces[1].name, "workspace-two");
    }

    #[tokio::test]
    async fn test_workspace_list_inner_empty() {
        let mut mock = MockWorkspaceClient::new();

        mock.expect_list_workspaces()
            .returning(|_| Ok(Response::new(WorkspaceList { workspaces: vec![] })));

        let principal = create_test_principal();
        let result = workspace_list_inner(&mut mock, &principal).await;

        assert!(result.is_ok());
        let workspaces = result.unwrap();
        assert!(workspaces.workspaces.is_empty());
    }

    #[tokio::test]
    async fn test_workspace_list_inner_grpc_error() {
        let mut mock = MockWorkspaceClient::new();

        mock.expect_list_workspaces()
            .returning(|_| Err(Status::unavailable("Server unavailable")));

        let principal = create_test_principal();
        let result = workspace_list_inner(&mut mock, &principal).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("unavailable"));
    }

    #[tokio::test]
    async fn test_workspace_list_inner_permission_denied() {
        let mut mock = MockWorkspaceClient::new();

        mock.expect_list_workspaces()
            .returning(|_| Err(Status::permission_denied("Not authorized")));

        let principal = create_test_principal();
        let result = workspace_list_inner(&mut mock, &principal).await;

        assert!(result.is_err());
    }

    #[test]
    fn test_print_workspace_list_empty() {
        // This is a simple print test - just verify it doesn't panic
        let workspaces = WorkspaceList { workspaces: vec![] };
        print_workspace_list(&workspaces);
    }

    #[test]
    fn test_print_workspace_list_with_items() {
        let workspaces = WorkspaceList {
            workspaces: vec![
                Workspace {
                    id: "1".to_string(),
                    name: "first".to_string(),
                },
                Workspace {
                    id: "2".to_string(),
                    name: "second".to_string(),
                },
            ],
        };
        print_workspace_list(&workspaces);
    }

    #[tokio::test]
    async fn test_workspace_list_inner_internal_error() {
        let mut mock = MockWorkspaceClient::new();

        mock.expect_list_workspaces()
            .returning(|_| Err(Status::internal("Database error")));

        let principal = create_test_principal();
        let result = workspace_list_inner(&mut mock, &principal).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_workspace_list_inner_single_workspace() {
        let mut mock = MockWorkspaceClient::new();

        mock.expect_list_workspaces().returning(|_| {
            Ok(Response::new(WorkspaceList {
                workspaces: vec![Workspace {
                    id: "only-ws".to_string(),
                    name: "only-workspace".to_string(),
                }],
            }))
        });

        let principal = create_test_principal();
        let result = workspace_list_inner(&mut mock, &principal).await;

        assert!(result.is_ok());
        let workspaces = result.unwrap();
        assert_eq!(workspaces.workspaces.len(), 1);
    }
}

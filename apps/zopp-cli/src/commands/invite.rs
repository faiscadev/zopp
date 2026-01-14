//! Invite commands: create, list, revoke

use crate::config::PrincipalConfig;
use crate::crypto::unwrap_workspace_kek;
use crate::grpc::{add_auth_metadata, setup_client};

#[cfg(test)]
use crate::client::MockInviteClient;

use zopp_proto::{InviteList, InviteToken, RevokeInviteRequest};

/// Inner implementation for invite list that accepts a trait-bounded client.
pub async fn invite_list_inner<C>(
    client: &mut C,
    principal: &PrincipalConfig,
) -> Result<InviteList, Box<dyn std::error::Error>>
where
    C: crate::client::InviteClient,
{
    let mut request = tonic::Request::new(zopp_proto::Empty {});
    add_auth_metadata(&mut request, principal, "/zopp.ZoppService/ListInvites")?;

    let response = client.list_invites(request).await?.into_inner();
    Ok(response)
}

/// Print invite list results.
pub fn print_invite_list(response: &InviteList) {
    if response.invites.is_empty() {
        println!("No active invites found.");
    } else {
        println!("Active workspace invites:\n");
        for invite in &response.invites {
            print_invite_summary(invite);
        }
    }
}

/// Print a summary of an invite.
pub fn print_invite_summary(invite: &InviteToken) {
    println!("ID:      {}", invite.id);
    println!("Token:   {}", invite.token);
    println!(
        "Expires: {}",
        chrono::DateTime::from_timestamp(invite.expires_at, 0)
            .map(|dt| dt.to_rfc3339())
            .unwrap_or_else(|| "Unknown".to_string())
    );
    println!();
}

/// Parse and validate an invite code, returning the token for revocation.
pub fn parse_invite_code(invite_code: &str) -> Result<String, Box<dyn std::error::Error>> {
    let secret_hex = invite_code
        .strip_prefix("inv_")
        .ok_or("Invalid invite code format (must start with inv_)")?;
    let invite_secret = hex::decode(secret_hex)?;
    if invite_secret.len() != 32 {
        return Err("Invalid invite code length".into());
    }
    let secret_hash = zopp_crypto::hash_sha256(&invite_secret);
    Ok(hex::encode(secret_hash))
}

/// Inner implementation for invite revoke that accepts a trait-bounded client.
pub async fn invite_revoke_inner<C>(
    client: &mut C,
    principal: &PrincipalConfig,
    token: &str,
) -> Result<(), Box<dyn std::error::Error>>
where
    C: crate::client::InviteClient,
{
    let mut request = tonic::Request::new(RevokeInviteRequest {
        token: token.to_string(),
    });
    add_auth_metadata(&mut request, principal, "/zopp.ZoppService/RevokeInvite")?;

    client.revoke_invite(request).await?;
    Ok(())
}

pub async fn cmd_invite_create(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace_name: &str,
    expires_hours: i64,
    plain: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let kek = unwrap_workspace_kek(&mut client, &principal, workspace_name).await?;

    let mut invite_secret = [0u8; 32];
    use rand_core::RngCore;
    rand_core::OsRng.fill_bytes(&mut invite_secret);
    let invite_secret_hex = format!("inv_{}", hex::encode(invite_secret));

    // Server never sees the plaintext secret
    let secret_hash = zopp_crypto::hash_sha256(&invite_secret);

    let mut ws_request = tonic::Request::new(zopp_proto::Empty {});
    add_auth_metadata(
        &mut ws_request,
        &principal,
        "/zopp.ZoppService/ListWorkspaces",
    )?;
    let workspaces = client.list_workspaces(ws_request).await?.into_inner();
    let workspace = workspaces
        .workspaces
        .iter()
        .find(|w| w.name == workspace_name)
        .ok_or_else(|| format!("Workspace '{}' not found", workspace_name))?;

    let dek_for_encryption = zopp_crypto::Dek::from_bytes(&invite_secret)?;
    let aad = format!("invite:workspace:{}", workspace.id).into_bytes();
    let (kek_nonce, kek_encrypted) = zopp_crypto::encrypt(&kek, &dek_for_encryption, &aad)?;

    let expires_at = chrono::Utc::now() + chrono::Duration::hours(expires_hours);

    let mut request = tonic::Request::new(zopp_proto::CreateInviteRequest {
        workspace_ids: vec![workspace.id.clone()],
        expires_at: expires_at.timestamp(),
        token: hex::encode(secret_hash), // Hash as token for lookup
        kek_encrypted: kek_encrypted.0,
        kek_nonce: kek_nonce.0.to_vec(),
    });
    add_auth_metadata(&mut request, &principal, "/zopp.ZoppService/CreateInvite")?;

    let _response = client.create_invite(request).await?.into_inner();

    if plain {
        println!("{}", invite_secret_hex);
    } else {
        println!("Workspace invite created!\n");
        println!("Invite code: {}", invite_secret_hex);
        println!("Expires:     {}", expires_at);
        println!("\n⚠️  Share this invite code with the invitee via secure channel");
        println!(
            "   The server does NOT have the plaintext - it's needed to decrypt the workspace key"
        );
    }

    Ok(())
}

pub async fn cmd_invite_list(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;
    let response = invite_list_inner(&mut client, &principal).await?;
    print_invite_list(&response);
    Ok(())
}

pub async fn cmd_invite_revoke(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    invite_code: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let token = parse_invite_code(invite_code)?;

    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;
    invite_revoke_inner(&mut client, &principal, &token).await?;

    println!("Invite revoked");

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

    fn create_test_invite() -> InviteToken {
        InviteToken {
            id: "invite-1".to_string(),
            token: "abc123".to_string(),
            workspace_ids: vec!["ws-1".to_string()],
            created_at: 1704060000, // 2024-01-01 00:00:00 UTC
            expires_at: 1704067200, // 2024-01-01 02:00:00 UTC
            kek_encrypted: vec![1, 2, 3],
            kek_nonce: vec![4, 5, 6],
            invite_secret: String::new(),
        }
    }

    #[tokio::test]
    async fn test_invite_list_inner_success() {
        let mut mock = MockInviteClient::new();

        mock.expect_list_invites().returning(|_| {
            Ok(Response::new(InviteList {
                invites: vec![
                    InviteToken {
                        id: "invite-1".to_string(),
                        token: "token1".to_string(),
                        workspace_ids: vec!["ws-1".to_string()],
                        created_at: 1704060000,
                        expires_at: 1704067200,
                        kek_encrypted: vec![],
                        kek_nonce: vec![],
                        invite_secret: String::new(),
                    },
                    InviteToken {
                        id: "invite-2".to_string(),
                        token: "token2".to_string(),
                        workspace_ids: vec!["ws-1".to_string()],
                        created_at: 1704140000,
                        expires_at: 1704153600,
                        kek_encrypted: vec![],
                        kek_nonce: vec![],
                        invite_secret: String::new(),
                    },
                ],
            }))
        });

        let principal = create_test_principal();
        let result = invite_list_inner(&mut mock, &principal).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.invites.len(), 2);
    }

    #[tokio::test]
    async fn test_invite_list_inner_empty() {
        let mut mock = MockInviteClient::new();

        mock.expect_list_invites()
            .returning(|_| Ok(Response::new(InviteList { invites: vec![] })));

        let principal = create_test_principal();
        let result = invite_list_inner(&mut mock, &principal).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert!(response.invites.is_empty());
    }

    #[tokio::test]
    async fn test_invite_list_inner_permission_denied() {
        let mut mock = MockInviteClient::new();

        mock.expect_list_invites()
            .returning(|_| Err(Status::permission_denied("Not authorized")));

        let principal = create_test_principal();
        let result = invite_list_inner(&mut mock, &principal).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_invite_revoke_inner_success() {
        let mut mock = MockInviteClient::new();

        mock.expect_revoke_invite()
            .returning(|_| Ok(Response::new(zopp_proto::Empty {})));

        let principal = create_test_principal();
        let result = invite_revoke_inner(&mut mock, &principal, "some-token").await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_invite_revoke_inner_not_found() {
        let mut mock = MockInviteClient::new();

        mock.expect_revoke_invite()
            .returning(|_| Err(Status::not_found("Invite not found")));

        let principal = create_test_principal();
        let result = invite_revoke_inner(&mut mock, &principal, "nonexistent-token").await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_invite_revoke_inner_permission_denied() {
        let mut mock = MockInviteClient::new();

        mock.expect_revoke_invite()
            .returning(|_| Err(Status::permission_denied("Not authorized")));

        let principal = create_test_principal();
        let result = invite_revoke_inner(&mut mock, &principal, "some-token").await;

        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invite_code_valid() {
        // Create a valid 32-byte hex string
        let secret = [0u8; 32];
        let invite_code = format!("inv_{}", hex::encode(secret));

        let result = parse_invite_code(&invite_code);
        assert!(result.is_ok());

        // Verify the result is the SHA256 hash of the secret
        let expected_hash = zopp_crypto::hash_sha256(&secret);
        assert_eq!(result.unwrap(), hex::encode(expected_hash));
    }

    #[test]
    fn test_parse_invite_code_missing_prefix() {
        let secret = [0u8; 32];
        let invite_code = hex::encode(secret); // Missing "inv_" prefix

        let result = parse_invite_code(&invite_code);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must start with inv_"));
    }

    #[test]
    fn test_parse_invite_code_invalid_hex() {
        let invite_code = "inv_notvalidhex";

        let result = parse_invite_code(invite_code);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invite_code_wrong_length() {
        // Only 16 bytes instead of 32
        let short_secret = [0u8; 16];
        let invite_code = format!("inv_{}", hex::encode(short_secret));

        let result = parse_invite_code(&invite_code);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid invite code length"));
    }

    #[test]
    fn test_print_invite_list_empty() {
        let response = InviteList { invites: vec![] };
        print_invite_list(&response);
    }

    #[test]
    fn test_print_invite_list_with_items() {
        let response = InviteList {
            invites: vec![create_test_invite()],
        };
        print_invite_list(&response);
    }

    #[test]
    fn test_print_invite_summary() {
        let invite = create_test_invite();
        print_invite_summary(&invite);
    }

    #[test]
    fn test_print_invite_summary_unknown_timestamp() {
        let invite = InviteToken {
            id: "invite-1".to_string(),
            token: "token".to_string(),
            workspace_ids: vec![],
            created_at: 0,
            expires_at: 0,
            kek_encrypted: vec![],
            kek_nonce: vec![],
            invite_secret: String::new(),
        };
        print_invite_summary(&invite);
    }
}

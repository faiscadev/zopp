use crate::crypto::unwrap_workspace_kek;
use crate::grpc::{add_auth_metadata, setup_client};

pub async fn cmd_invite_create(
    server: &str,
    workspace_name: &str,
    expires_hours: i64,
    plain: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server).await?;

    // 1. Unwrap the workspace KEK
    let kek = unwrap_workspace_kek(&mut client, &principal, workspace_name).await?;

    // 2. Generate random invite secret (32 bytes, displayed as hex with prefix)
    let mut invite_secret = [0u8; 32];
    use rand_core::RngCore;
    rand_core::OsRng.fill_bytes(&mut invite_secret);
    let invite_secret_hex = format!("inv_{}", hex::encode(invite_secret));

    // 3. Hash the secret for server lookup (server never sees plaintext secret)
    let secret_hash = zopp_crypto::hash_sha256(&invite_secret);

    // 4. Get workspace ID first (needed for AAD)
    let mut ws_request = tonic::Request::new(zopp_proto::Empty {});
    add_auth_metadata(&mut ws_request, &principal)?;
    let workspaces = client.list_workspaces(ws_request).await?.into_inner();
    let workspace = workspaces
        .workspaces
        .iter()
        .find(|w| w.name == workspace_name)
        .ok_or_else(|| format!("Workspace '{}' not found", workspace_name))?;

    // 5. Encrypt the KEK with the invite secret (using workspace ID in AAD)
    let dek_for_encryption = zopp_crypto::Dek::from_bytes(&invite_secret)?;
    let aad = format!("invite:workspace:{}", workspace.id).into_bytes();
    let (kek_nonce, kek_encrypted) = zopp_crypto::encrypt(&kek, &dek_for_encryption, &aad)?;

    // 6. Calculate expiration time
    let expires_at = chrono::Utc::now() + chrono::Duration::hours(expires_hours);

    // 7. Send invite to server (with hashed secret as token, not plaintext secret)
    let mut request = tonic::Request::new(zopp_proto::CreateInviteRequest {
        workspace_ids: vec![workspace.id.clone()],
        expires_at: expires_at.timestamp(),
        token: hex::encode(secret_hash), // Hash as token for lookup
        kek_encrypted: kek_encrypted.0,
        kek_nonce: kek_nonce.0.to_vec(),
    });
    add_auth_metadata(&mut request, &principal)?;

    let _response = client.create_invite(request).await?.into_inner();

    if plain {
        println!("{}", invite_secret_hex);
    } else {
        println!("✓ Workspace invite created!\n");
        println!("Invite code: {}", invite_secret_hex);
        println!("Expires:     {}", expires_at);
        println!("\n⚠️  Share this invite code with the invitee via secure channel");
        println!(
            "   The server does NOT have the plaintext - it's needed to decrypt the workspace key"
        );
    }

    Ok(())
}

pub async fn cmd_invite_list(server: &str) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server).await?;

    let mut request = tonic::Request::new(zopp_proto::Empty {});
    add_auth_metadata(&mut request, &principal)?;

    let response = client.list_invites(request).await?.into_inner();

    if response.invites.is_empty() {
        println!("No active invites found.");
    } else {
        println!("Active workspace invites:\n");
        for invite in response.invites {
            println!("ID:      {}", invite.id);
            println!("Token:   {}", invite.token);
            println!(
                "Expires: {}",
                chrono::DateTime::from_timestamp(invite.expires_at, 0).unwrap()
            );
            println!();
        }
    }

    Ok(())
}

pub async fn cmd_invite_revoke(
    server: &str,
    invite_code: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let secret_hex = invite_code
        .strip_prefix("inv_")
        .ok_or("Invalid invite code format (must start with inv_)")?;
    let invite_secret = hex::decode(secret_hex)?;
    if invite_secret.len() != 32 {
        return Err("Invalid invite code length".into());
    }
    let secret_hash = zopp_crypto::hash_sha256(&invite_secret);
    let token = hex::encode(secret_hash);

    let (mut client, principal) = setup_client(server).await?;

    let mut request = tonic::Request::new(zopp_proto::RevokeInviteRequest { token });
    add_auth_metadata(&mut request, &principal)?;

    client.revoke_invite(request).await?;

    println!("✓ Invite revoked");

    Ok(())
}

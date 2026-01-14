use crate::config::{save_config, CliConfig, PrincipalConfig};
use crate::grpc::connect;
use ed25519_dalek::SigningKey;
use zopp_proto::JoinRequest;

/// Check if an invite code is a workspace invite (starts with "inv_")
pub fn is_workspace_invite(invite_code: &str) -> bool {
    invite_code.starts_with("inv_")
}

/// Parse and validate a workspace invite code, returning the invite secret
pub fn parse_workspace_invite_secret(
    invite_code: &str,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let secret_hex = invite_code
        .strip_prefix("inv_")
        .ok_or("Invalid invite code format (must start with inv_)")?;
    let invite_secret = hex::decode(secret_hex)?;
    if invite_secret.len() != 32 {
        return Err("Invalid invite code length".into());
    }
    let mut secret_array = [0u8; 32];
    secret_array.copy_from_slice(&invite_secret);
    Ok(secret_array)
}

/// Get the server token for an invite code
/// For workspace invites, this is the SHA256 hash of the secret
/// For bootstrap invites, this is the invite code itself
pub fn get_server_token(invite_code: &str) -> Result<String, Box<dyn std::error::Error>> {
    if is_workspace_invite(invite_code) {
        let secret = parse_workspace_invite_secret(invite_code)?;
        let secret_hash = zopp_crypto::hash_sha256(&secret);
        Ok(hex::encode(secret_hash))
    } else {
        Ok(invite_code.to_string())
    }
}

/// Get the default principal name (hostname)
pub fn get_default_principal_name() -> Result<String, Box<dyn std::error::Error>> {
    Ok(hostname::get()?.to_string_lossy().to_string())
}

/// Resolve principal name, using provided name or defaulting to hostname
pub fn resolve_principal_name(
    principal_name: Option<&str>,
) -> Result<String, Box<dyn std::error::Error>> {
    match principal_name {
        Some(name) => Ok(name.to_string()),
        None => get_default_principal_name(),
    }
}

pub async fn cmd_join(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    invite_code: &str,
    email: &str,
    principal_name: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Use provided principal name or default to hostname
    let principal_name = match principal_name {
        Some(name) => name.to_string(),
        None => hostname::get()?.to_string_lossy().to_string(),
    };

    let signing_key = SigningKey::generate(&mut rand_core::OsRng);
    let verifying_key = signing_key.verifying_key();
    let public_key = verifying_key.to_bytes().to_vec();

    let x25519_keypair = zopp_crypto::Keypair::generate();
    let x25519_public_bytes = x25519_keypair.public_key_bytes().to_vec();

    let mut client = connect(server, tls_ca_cert).await?;

    let is_workspace_invite = invite_code.starts_with("inv_");

    let (ephemeral_pub, kek_wrapped, kek_nonce) = if is_workspace_invite {
        let secret_hex = invite_code
            .strip_prefix("inv_")
            .ok_or("Invalid invite code format")?;
        let invite_secret = hex::decode(secret_hex)?;
        if invite_secret.len() != 32 {
            return Err("Invalid invite code length".into());
        }
        let mut secret_array = [0u8; 32];
        secret_array.copy_from_slice(&invite_secret);

        let secret_hash = zopp_crypto::hash_sha256(&secret_array);
        let secret_hash_hex = hex::encode(secret_hash);

        let invite = client
            .get_invite(zopp_proto::GetInviteRequest {
                token: secret_hash_hex,
            })
            .await?
            .into_inner();

        if invite.kek_encrypted.is_empty() {
            return Err("Invalid workspace invite (no encrypted KEK)".into());
        }

        let dek_for_decryption = zopp_crypto::Dek::from_bytes(&secret_array)?;

        let workspace_id = invite
            .workspace_ids
            .first()
            .ok_or("Invite has no workspace IDs")?;

        let aad = format!("invite:workspace:{}", workspace_id).into_bytes();

        let mut nonce_array = [0u8; 24];
        nonce_array.copy_from_slice(&invite.kek_nonce);
        let nonce = zopp_crypto::Nonce(nonce_array);

        let kek_decrypted =
            zopp_crypto::decrypt(&invite.kek_encrypted, &nonce, &dek_for_decryption, &aad)?;
        let ephemeral_keypair = zopp_crypto::Keypair::generate();
        let my_public = zopp_crypto::public_key_from_bytes(&x25519_keypair.public_key_bytes())?;
        let shared_secret = ephemeral_keypair.shared_secret(&my_public);

        let wrap_aad = format!("workspace:{}", workspace_id).into_bytes();
        let (wrap_nonce, wrapped) =
            zopp_crypto::wrap_key(&kek_decrypted, &shared_secret, &wrap_aad)?;

        (
            ephemeral_keypair.public_key_bytes().to_vec(),
            wrapped.0,
            wrap_nonce.0.to_vec(),
        )
    } else {
        (vec![], vec![], vec![])
    };

    let server_token = if is_workspace_invite {
        let secret_hex = invite_code.strip_prefix("inv_").unwrap();
        let invite_secret = hex::decode(secret_hex)?;
        let mut secret_array = [0u8; 32];
        secret_array.copy_from_slice(&invite_secret);
        let secret_hash = zopp_crypto::hash_sha256(&secret_array);
        hex::encode(secret_hash)
    } else {
        invite_code.to_string()
    };

    let response = client
        .join(JoinRequest {
            invite_token: server_token,
            email: email.to_string(),
            principal_name: principal_name.clone(),
            public_key,
            x25519_public_key: x25519_public_bytes,
            ephemeral_pub,
            kek_wrapped,
            kek_nonce,
        })
        .await?
        .into_inner();

    println!("✓ Joined successfully!\n");
    println!("User ID:      {}", response.user_id);
    println!("Principal ID: {}", response.principal_id);
    println!("Principal:    {}", principal_name);
    println!("\nWorkspaces:");
    for ws in &response.workspaces {
        println!("  - {} ({})", ws.name, ws.id);
    }

    // Save config
    let config = CliConfig {
        user_id: response.user_id,
        email: email.to_string(),
        principals: vec![PrincipalConfig {
            id: response.principal_id,
            name: principal_name.clone(),
            private_key: hex::encode(signing_key.to_bytes()),
            public_key: hex::encode(verifying_key.to_bytes()),
            x25519_private_key: Some(hex::encode(x25519_keypair.secret_key_bytes())),
            x25519_public_key: Some(hex::encode(x25519_keypair.public_key_bytes())),
        }],
        current_principal: Some(principal_name),
    };
    save_config(&config)?;

    println!(
        "\nConfig saved to: {}",
        dirs::home_dir()
            .expect("Failed to get home directory")
            .join(".zopp")
            .join("config.json")
            .display()
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_workspace_invite_true() {
        assert!(is_workspace_invite("inv_abc123"));
        assert!(is_workspace_invite(
            "inv_0000000000000000000000000000000000000000000000000000000000000000"
        ));
    }

    #[test]
    fn test_is_workspace_invite_false() {
        assert!(!is_workspace_invite("bootstrap-token"));
        assert!(!is_workspace_invite(""));
        assert!(!is_workspace_invite("inv")); // Missing underscore
        assert!(!is_workspace_invite("INV_abc")); // Case sensitive
    }

    #[test]
    fn test_parse_workspace_invite_secret_valid() {
        let secret = [0u8; 32];
        let invite_code = format!("inv_{}", hex::encode(secret));
        let result = parse_workspace_invite_secret(&invite_code);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), secret);
    }

    #[test]
    fn test_parse_workspace_invite_secret_valid_nonzero() {
        let mut secret = [0u8; 32];
        secret[0] = 0xAB;
        secret[31] = 0xCD;
        let invite_code = format!("inv_{}", hex::encode(secret));
        let result = parse_workspace_invite_secret(&invite_code);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), secret);
    }

    #[test]
    fn test_parse_workspace_invite_secret_missing_prefix() {
        let secret = [0u8; 32];
        let invite_code = hex::encode(secret);
        let result = parse_workspace_invite_secret(&invite_code);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must start with inv_"));
    }

    #[test]
    fn test_parse_workspace_invite_secret_invalid_hex() {
        let result = parse_workspace_invite_secret("inv_notvalidhex");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_workspace_invite_secret_wrong_length_short() {
        let short = [0u8; 16];
        let invite_code = format!("inv_{}", hex::encode(short));
        let result = parse_workspace_invite_secret(&invite_code);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("length"));
    }

    #[test]
    fn test_parse_workspace_invite_secret_wrong_length_long() {
        let long = [0u8; 64];
        let invite_code = format!("inv_{}", hex::encode(long));
        let result = parse_workspace_invite_secret(&invite_code);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("length"));
    }

    #[test]
    fn test_get_server_token_bootstrap() {
        let result = get_server_token("bootstrap-token");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "bootstrap-token");
    }

    #[test]
    fn test_get_server_token_bootstrap_preserves_case() {
        let result = get_server_token("Bootstrap-Token-123");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "Bootstrap-Token-123");
    }

    #[test]
    fn test_get_server_token_workspace_invite() {
        let secret = [0u8; 32];
        let invite_code = format!("inv_{}", hex::encode(secret));
        let result = get_server_token(&invite_code);
        assert!(result.is_ok());
        // Should be SHA256 hash, not the original secret
        let expected_hash = zopp_crypto::hash_sha256(&secret);
        assert_eq!(result.unwrap(), hex::encode(expected_hash));
    }

    #[test]
    fn test_get_server_token_workspace_invite_different_secrets() {
        let secret1 = [1u8; 32];
        let secret2 = [2u8; 32];
        let invite1 = format!("inv_{}", hex::encode(secret1));
        let invite2 = format!("inv_{}", hex::encode(secret2));

        let token1 = get_server_token(&invite1).unwrap();
        let token2 = get_server_token(&invite2).unwrap();

        // Different secrets should produce different tokens
        assert_ne!(token1, token2);
    }

    #[test]
    fn test_get_server_token_invalid_workspace_invite() {
        // Invalid workspace invite (wrong length) should error
        let result = get_server_token("inv_abc123");
        assert!(result.is_err());
    }

    #[test]
    fn test_get_default_principal_name() {
        let result = get_default_principal_name();
        assert!(result.is_ok());
        assert!(!result.unwrap().is_empty());
    }

    #[test]
    fn test_resolve_principal_name_with_provided() {
        let result = resolve_principal_name(Some("my-laptop"));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "my-laptop");
    }

    #[test]
    fn test_resolve_principal_name_with_empty_string() {
        let result = resolve_principal_name(Some(""));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "");
    }

    #[test]
    fn test_resolve_principal_name_with_none() {
        let result = resolve_principal_name(None);
        assert!(result.is_ok());
        // Should return hostname
        let hostname = get_default_principal_name().unwrap();
        assert_eq!(result.unwrap(), hostname);
    }

    #[test]
    fn test_resolve_principal_name_with_special_chars() {
        let result = resolve_principal_name(Some("my-principal_123"));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "my-principal_123");
    }
}

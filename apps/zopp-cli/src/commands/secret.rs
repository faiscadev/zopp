//! Secret commands: set, get, list, delete, export, import, run

use crate::config::PrincipalConfig;
use crate::crypto::fetch_and_decrypt_secrets;
use crate::grpc::{add_auth_metadata, setup_client};
use zopp_secrets::SecretContext;

#[cfg(test)]
use crate::client::MockSecretClient;

use zopp_proto::SecretList;

/// Helper to create a SecretContext for a given environment
async fn create_secret_context(
    client: &mut zopp_proto::zopp_service_client::ZoppServiceClient<tonic::transport::Channel>,
    principal: &crate::config::PrincipalConfig,
    workspace_name: &str,
    project_name: &str,
    environment_name: &str,
) -> Result<SecretContext, Box<dyn std::error::Error>> {
    // Get workspace keys
    let mut request = tonic::Request::new(zopp_proto::GetWorkspaceKeysRequest {
        workspace_name: workspace_name.to_string(),
    });
    add_auth_metadata(
        &mut request,
        principal,
        "/zopp.ZoppService/GetWorkspaceKeys",
    )?;
    let workspace_keys = client.get_workspace_keys(request).await?.into_inner();

    // Get environment
    let mut request = tonic::Request::new(zopp_proto::GetEnvironmentRequest {
        workspace_name: workspace_name.to_string(),
        project_name: project_name.to_string(),
        environment_name: environment_name.to_string(),
    });
    add_auth_metadata(&mut request, principal, "/zopp.ZoppService/GetEnvironment")?;
    let environment = client.get_environment(request).await?.into_inner();

    // Extract X25519 private key
    let x25519_private_key = principal
        .x25519_private_key
        .as_ref()
        .ok_or("Principal missing X25519 private key")?;
    let x25519_private_bytes = hex::decode(x25519_private_key)?;
    let mut x25519_array = [0u8; 32];
    x25519_array.copy_from_slice(&x25519_private_bytes);

    // Create SecretContext
    Ok(SecretContext::new(
        x25519_array,
        workspace_keys,
        environment,
        workspace_name.to_string(),
        project_name.to_string(),
        environment_name.to_string(),
    )?)
}

/// Inner implementation for secret list that accepts a trait-bounded client.
pub async fn secret_list_inner<C>(
    client: &mut C,
    principal: &PrincipalConfig,
    workspace_name: &str,
    project_name: &str,
    environment_name: &str,
) -> Result<SecretList, Box<dyn std::error::Error>>
where
    C: crate::client::SecretClient,
{
    let mut request = tonic::Request::new(zopp_proto::ListSecretsRequest {
        workspace_name: workspace_name.to_string(),
        project_name: project_name.to_string(),
        environment_name: environment_name.to_string(),
    });
    add_auth_metadata(&mut request, principal, "/zopp.ZoppService/ListSecrets")?;

    let response = client.list_secrets(request).await?.into_inner();
    Ok(response)
}

/// Print secret list results.
pub fn print_secret_list(secrets: &SecretList) {
    if secrets.secrets.is_empty() {
        println!("No secrets found");
    } else {
        println!("Secrets:");
        for secret in &secrets.secrets {
            println!("  {}", secret.key);
        }
    }
}

/// Inner implementation for secret delete that accepts a trait-bounded client.
pub async fn secret_delete_inner<C>(
    client: &mut C,
    principal: &PrincipalConfig,
    workspace_name: &str,
    project_name: &str,
    environment_name: &str,
    key: &str,
) -> Result<(), Box<dyn std::error::Error>>
where
    C: crate::client::SecretClient,
{
    let mut request = tonic::Request::new(zopp_proto::DeleteSecretRequest {
        workspace_name: workspace_name.to_string(),
        project_name: project_name.to_string(),
        environment_name: environment_name.to_string(),
        key: key.to_string(),
    });
    add_auth_metadata(&mut request, principal, "/zopp.ZoppService/DeleteSecret")?;

    client.delete_secret(request).await?;
    Ok(())
}

/// Parse .env content into a list of key-value pairs.
pub fn parse_env_content(content: &str) -> Vec<(String, String)> {
    let mut secrets = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            secrets.push((key.trim().to_string(), value.trim().to_string()));
        }
    }
    secrets
}

/// Format secrets as .env content.
pub fn format_env_content(secrets: &std::collections::BTreeMap<String, String>) -> String {
    secrets
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("\n")
}

pub async fn cmd_secret_set(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace_name: &str,
    project_name: &str,
    environment_name: &str,
    key: &str,
    value: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let ctx = create_secret_context(
        &mut client,
        &principal,
        workspace_name,
        project_name,
        environment_name,
    )
    .await?;

    let encrypted = ctx.encrypt_secret(key, value)?;

    let mut request = tonic::Request::new(zopp_proto::UpsertSecretRequest {
        workspace_name: workspace_name.to_string(),
        project_name: project_name.to_string(),
        environment_name: environment_name.to_string(),
        key: key.to_string(),
        nonce: encrypted.nonce,
        ciphertext: encrypted.ciphertext,
    });
    add_auth_metadata(&mut request, &principal, "/zopp.ZoppService/UpsertSecret")?;

    client.upsert_secret(request).await?;

    println!("Secret '{}' set", key);

    Ok(())
}

pub async fn cmd_secret_get(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace_name: &str,
    project_name: &str,
    environment_name: &str,
    key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let mut request = tonic::Request::new(zopp_proto::GetSecretRequest {
        workspace_name: workspace_name.to_string(),
        project_name: project_name.to_string(),
        environment_name: environment_name.to_string(),
        key: key.to_string(),
    });
    add_auth_metadata(&mut request, &principal, "/zopp.ZoppService/GetSecret")?;

    let response = client.get_secret(request).await?.into_inner();

    let ctx = create_secret_context(
        &mut client,
        &principal,
        workspace_name,
        project_name,
        environment_name,
    )
    .await?;

    let value = ctx.decrypt_secret(&response)?;

    println!("{}", value);

    Ok(())
}

pub async fn cmd_secret_list(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace_name: &str,
    project_name: &str,
    environment_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;
    let response = secret_list_inner(
        &mut client,
        &principal,
        workspace_name,
        project_name,
        environment_name,
    )
    .await?;
    print_secret_list(&response);
    Ok(())
}

pub async fn cmd_secret_delete(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace_name: &str,
    project_name: &str,
    environment_name: &str,
    key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;
    secret_delete_inner(
        &mut client,
        &principal,
        workspace_name,
        project_name,
        environment_name,
        key,
    )
    .await?;
    println!("Secret '{}' deleted", key);
    Ok(())
}

pub async fn cmd_secret_export(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace_name: &str,
    project_name: &str,
    environment_name: &str,
    output: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    // Fetch and decrypt all secrets
    let secret_data = fetch_and_decrypt_secrets(
        &mut client,
        &principal,
        workspace_name,
        project_name,
        environment_name,
    )
    .await?;

    if secret_data.is_empty() {
        return Err("No secrets to export".into());
    }

    // Format as .env (BTreeMap is already sorted)
    let env_content = format_env_content(&secret_data);

    // Write to file or stdout
    if let Some(path) = output {
        std::fs::write(path, env_content)?;
        println!("✓ Exported {} secrets to {}", secret_data.len(), path);
    } else {
        println!("{}", env_content);
    }

    Ok(())
}

pub async fn cmd_secret_import(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace_name: &str,
    project_name: &str,
    environment_name: &str,
    input: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Read .env content from file or stdin
    let content = if let Some(path) = input {
        std::fs::read_to_string(path)?
    } else {
        use std::io::Read;
        let mut buffer = String::new();
        std::io::stdin().read_to_string(&mut buffer)?;
        buffer
    };

    // Parse .env format (KEY=value, skip comments and empty lines)
    let secrets = parse_env_content(&content);

    if secrets.is_empty() {
        return Err("No secrets found in input".into());
    }

    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    // Create SecretContext once
    let ctx = create_secret_context(
        &mut client,
        &principal,
        workspace_name,
        project_name,
        environment_name,
    )
    .await?;

    for (key, value) in &secrets {
        let encrypted = ctx.encrypt_secret(key, value)?;

        let mut request = tonic::Request::new(zopp_proto::UpsertSecretRequest {
            workspace_name: workspace_name.to_string(),
            project_name: project_name.to_string(),
            environment_name: environment_name.to_string(),
            key: key.clone(),
            nonce: encrypted.nonce,
            ciphertext: encrypted.ciphertext,
        });
        add_auth_metadata(&mut request, &principal, "/zopp.ZoppService/UpsertSecret")?;

        client.upsert_secret(request).await?;
    }

    println!("Imported {} secrets", secrets.len());

    Ok(())
}

pub async fn cmd_secret_run(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace_name: &str,
    project_name: &str,
    environment_name: &str,
    command: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    if command.is_empty() {
        return Err("No command specified".into());
    }

    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    // Fetch and decrypt all secrets
    let env_vars = fetch_and_decrypt_secrets(
        &mut client,
        &principal,
        workspace_name,
        project_name,
        environment_name,
    )
    .await?;

    // Execute command with injected environment variables
    let status = std::process::Command::new(&command[0])
        .args(&command[1..])
        .envs(&env_vars)
        .status()?;

    std::process::exit(status.code().unwrap_or(1));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use tonic::{Response, Status};
    use zopp_proto::Secret;

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
    async fn test_secret_list_inner_success() {
        let mut mock = MockSecretClient::new();

        mock.expect_list_secrets().returning(|_| {
            Ok(Response::new(SecretList {
                secrets: vec![
                    Secret {
                        key: "API_KEY".to_string(),
                        nonce: vec![1, 2, 3],
                        ciphertext: vec![4, 5, 6],
                    },
                    Secret {
                        key: "DB_PASSWORD".to_string(),
                        nonce: vec![7, 8, 9],
                        ciphertext: vec![10, 11, 12],
                    },
                ],
                version: 1,
            }))
        });

        let principal = create_test_principal();
        let result = secret_list_inner(
            &mut mock,
            &principal,
            "my-workspace",
            "my-project",
            "development",
        )
        .await;

        assert!(result.is_ok());
        let secrets = result.unwrap();
        assert_eq!(secrets.secrets.len(), 2);
        assert_eq!(secrets.secrets[0].key, "API_KEY");
        assert_eq!(secrets.secrets[1].key, "DB_PASSWORD");
    }

    #[tokio::test]
    async fn test_secret_list_inner_empty() {
        let mut mock = MockSecretClient::new();

        mock.expect_list_secrets().returning(|_| {
            Ok(Response::new(SecretList {
                secrets: vec![],
                version: 0,
            }))
        });

        let principal = create_test_principal();
        let result = secret_list_inner(
            &mut mock,
            &principal,
            "my-workspace",
            "my-project",
            "development",
        )
        .await;

        assert!(result.is_ok());
        let secrets = result.unwrap();
        assert!(secrets.secrets.is_empty());
    }

    #[tokio::test]
    async fn test_secret_list_inner_permission_denied() {
        let mut mock = MockSecretClient::new();

        mock.expect_list_secrets()
            .returning(|_| Err(Status::permission_denied("Not authorized")));

        let principal = create_test_principal();
        let result = secret_list_inner(
            &mut mock,
            &principal,
            "my-workspace",
            "my-project",
            "development",
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_secret_list_inner_not_found() {
        let mut mock = MockSecretClient::new();

        mock.expect_list_secrets()
            .returning(|_| Err(Status::not_found("Environment not found")));

        let principal = create_test_principal();
        let result = secret_list_inner(
            &mut mock,
            &principal,
            "my-workspace",
            "my-project",
            "nonexistent",
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_secret_delete_inner_success() {
        let mut mock = MockSecretClient::new();

        mock.expect_delete_secret()
            .returning(|_| Ok(Response::new(zopp_proto::Empty {})));

        let principal = create_test_principal();
        let result = secret_delete_inner(
            &mut mock,
            &principal,
            "my-workspace",
            "my-project",
            "development",
            "API_KEY",
        )
        .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_secret_delete_inner_not_found() {
        let mut mock = MockSecretClient::new();

        mock.expect_delete_secret()
            .returning(|_| Err(Status::not_found("Secret not found")));

        let principal = create_test_principal();
        let result = secret_delete_inner(
            &mut mock,
            &principal,
            "my-workspace",
            "my-project",
            "development",
            "NONEXISTENT_KEY",
        )
        .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_secret_delete_inner_permission_denied() {
        let mut mock = MockSecretClient::new();

        mock.expect_delete_secret()
            .returning(|_| Err(Status::permission_denied("Not authorized")));

        let principal = create_test_principal();
        let result = secret_delete_inner(
            &mut mock,
            &principal,
            "my-workspace",
            "my-project",
            "development",
            "API_KEY",
        )
        .await;

        assert!(result.is_err());
    }

    #[test]
    fn test_print_secret_list_empty() {
        let secrets = SecretList {
            secrets: vec![],
            version: 0,
        };
        print_secret_list(&secrets);
    }

    #[test]
    fn test_print_secret_list_with_items() {
        let secrets = SecretList {
            secrets: vec![
                Secret {
                    key: "API_KEY".to_string(),
                    nonce: vec![],
                    ciphertext: vec![],
                },
                Secret {
                    key: "DB_PASSWORD".to_string(),
                    nonce: vec![],
                    ciphertext: vec![],
                },
            ],
            version: 1,
        };
        print_secret_list(&secrets);
    }

    #[test]
    fn test_parse_env_content_simple() {
        let content = "API_KEY=secret123\nDB_PASSWORD=pass456";
        let secrets = parse_env_content(content);

        assert_eq!(secrets.len(), 2);
        assert_eq!(secrets[0], ("API_KEY".to_string(), "secret123".to_string()));
        assert_eq!(
            secrets[1],
            ("DB_PASSWORD".to_string(), "pass456".to_string())
        );
    }

    #[test]
    fn test_parse_env_content_with_comments() {
        let content =
            "# This is a comment\nAPI_KEY=secret123\n# Another comment\nDB_PASSWORD=pass456";
        let secrets = parse_env_content(content);

        assert_eq!(secrets.len(), 2);
    }

    #[test]
    fn test_parse_env_content_with_empty_lines() {
        let content = "API_KEY=secret123\n\n\nDB_PASSWORD=pass456\n";
        let secrets = parse_env_content(content);

        assert_eq!(secrets.len(), 2);
    }

    #[test]
    fn test_parse_env_content_with_whitespace() {
        let content = "  API_KEY = secret123  \n  DB_PASSWORD = pass456  ";
        let secrets = parse_env_content(content);

        assert_eq!(secrets.len(), 2);
        assert_eq!(secrets[0], ("API_KEY".to_string(), "secret123".to_string()));
        assert_eq!(
            secrets[1],
            ("DB_PASSWORD".to_string(), "pass456".to_string())
        );
    }

    #[test]
    fn test_parse_env_content_empty() {
        let content = "";
        let secrets = parse_env_content(content);

        assert!(secrets.is_empty());
    }

    #[test]
    fn test_parse_env_content_only_comments() {
        let content = "# Comment 1\n# Comment 2";
        let secrets = parse_env_content(content);

        assert!(secrets.is_empty());
    }

    #[test]
    fn test_parse_env_content_value_with_equals() {
        let content = "DATABASE_URL=postgres://user:pass@host/db?ssl=true";
        let secrets = parse_env_content(content);

        assert_eq!(secrets.len(), 1);
        assert_eq!(
            secrets[0],
            (
                "DATABASE_URL".to_string(),
                "postgres://user:pass@host/db?ssl=true".to_string()
            )
        );
    }

    #[test]
    fn test_format_env_content() {
        let mut secrets = BTreeMap::new();
        secrets.insert("API_KEY".to_string(), "secret123".to_string());
        secrets.insert("DB_PASSWORD".to_string(), "pass456".to_string());

        let content = format_env_content(&secrets);

        // BTreeMap is sorted alphabetically
        assert_eq!(content, "API_KEY=secret123\nDB_PASSWORD=pass456");
    }

    #[test]
    fn test_format_env_content_empty() {
        let secrets = BTreeMap::new();
        let content = format_env_content(&secrets);

        assert_eq!(content, "");
    }

    #[test]
    fn test_format_env_content_single() {
        let mut secrets = BTreeMap::new();
        secrets.insert("SINGLE_KEY".to_string(), "value".to_string());

        let content = format_env_content(&secrets);

        assert_eq!(content, "SINGLE_KEY=value");
    }
}

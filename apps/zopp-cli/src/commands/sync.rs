use crate::crypto::fetch_and_decrypt_secrets;
use crate::grpc::setup_client;
use crate::k8s::load_k8s_config;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::{api::PostParams, Api, Client};
use std::collections::BTreeMap;

/// Check if a K8s secret is managed by zopp
pub fn is_managed_by_zopp(secret: &Secret) -> bool {
    secret
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get("app.kubernetes.io/managed-by"))
        .map(|s| s.as_str())
        == Some("zopp")
}

/// Build labels for a zopp-managed secret
pub fn build_sync_labels() -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    labels.insert(
        "app.kubernetes.io/managed-by".to_string(),
        "zopp".to_string(),
    );
    labels
}

/// Build annotations for a zopp-synced secret
pub fn build_sync_annotations(
    workspace_name: &str,
    project_name: &str,
    environment_name: &str,
    principal_id: &str,
    synced_at: &str,
) -> BTreeMap<String, String> {
    let mut annotations = BTreeMap::new();
    annotations.insert("zopp.dev/workspace".to_string(), workspace_name.to_string());
    annotations.insert("zopp.dev/project".to_string(), project_name.to_string());
    annotations.insert(
        "zopp.dev/environment".to_string(),
        environment_name.to_string(),
    );
    annotations.insert("zopp.dev/synced-at".to_string(), synced_at.to_string());
    annotations.insert("zopp.dev/synced-by".to_string(), principal_id.to_string());
    annotations
}

/// Build a K8s Secret with zopp metadata
#[allow(clippy::too_many_arguments)]
pub fn build_k8s_secret(
    secret_name: &str,
    namespace: &str,
    secret_data: BTreeMap<String, String>,
    workspace_name: &str,
    project_name: &str,
    environment_name: &str,
    principal_id: &str,
    synced_at: &str,
) -> Secret {
    Secret {
        metadata: ObjectMeta {
            name: Some(secret_name.to_string()),
            namespace: Some(namespace.to_string()),
            labels: Some(build_sync_labels()),
            annotations: Some(build_sync_annotations(
                workspace_name,
                project_name,
                environment_name,
                principal_id,
                synced_at,
            )),
            ..Default::default()
        },
        string_data: Some(secret_data),
        ..Default::default()
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn cmd_sync_k8s(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace_name: &str,
    project_name: &str,
    environment_name: &str,
    namespace: &str,
    secret_name: &str,
    kubeconfig_path: Option<&std::path::Path>,
    context: Option<&str>,
    force: bool,
    dry_run: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let secret_data = fetch_and_decrypt_secrets(
        &mut client,
        &principal,
        workspace_name,
        project_name,
        environment_name,
    )
    .await?;

    println!("✓ Fetched {} secrets from zopp", secret_data.len());

    let k8s_config = load_k8s_config(kubeconfig_path, context).await?;

    let k8s_client = Client::try_from(k8s_config)?;
    let secrets_api: Api<Secret> = Api::namespaced(k8s_client, namespace);

    match secrets_api.get(secret_name).await {
        Ok(existing_secret) => {
            // Secret exists, check if managed by zopp
            let managed_by = existing_secret
                .metadata
                .labels
                .as_ref()
                .and_then(|labels| labels.get("app.kubernetes.io/managed-by"))
                .map(|s| s.as_str());

            if managed_by != Some("zopp") && !force {
                return Err(format!(
                    "Secret '{}' in namespace '{}' exists but is not managed by zopp. Use --force to take ownership.",
                    secret_name, namespace
                )
                .into());
            }

            println!("✓ Secret exists, updating...");
        }
        Err(kube::Error::Api(api_err)) if api_err.code == 404 => {
            println!("✓ Secret does not exist, will create...");
        }
        Err(e) => return Err(e.into()),
    }

    let synced_at = chrono::Utc::now().to_rfc3339();
    let mut labels = BTreeMap::new();
    labels.insert(
        "app.kubernetes.io/managed-by".to_string(),
        "zopp".to_string(),
    );

    let mut annotations = BTreeMap::new();
    annotations.insert("zopp.dev/workspace".to_string(), workspace_name.to_string());
    annotations.insert("zopp.dev/project".to_string(), project_name.to_string());
    annotations.insert(
        "zopp.dev/environment".to_string(),
        environment_name.to_string(),
    );
    annotations.insert("zopp.dev/synced-at".to_string(), synced_at.clone());
    annotations.insert("zopp.dev/synced-by".to_string(), principal.id.clone());

    let secret = Secret {
        metadata: ObjectMeta {
            name: Some(secret_name.to_string()),
            namespace: Some(namespace.to_string()),
            labels: Some(labels),
            annotations: Some(annotations),
            ..Default::default()
        },
        string_data: Some(secret_data),
        ..Default::default()
    };

    if dry_run {
        println!("\n🔍 Dry run - showing what would be synced:\n");

        match secrets_api.get(secret_name).await {
            Ok(existing) => {
                println!(
                    "Would UPDATE existing Secret '{}/{}':",
                    namespace, secret_name
                );

                let existing_data = existing.data.as_ref();
                let new_data = secret.string_data.as_ref().unwrap();

                // Show changes
                for (key, new_value) in new_data {
                    if let Some(existing_data_map) = existing_data {
                        if let Some(existing_value) = existing_data_map.get(key) {
                            let existing_str = String::from_utf8_lossy(&existing_value.0);
                            if existing_str != *new_value {
                                println!("  ~ {} (changed)", key);
                            } else {
                                println!("  = {} (unchanged)", key);
                            }
                        } else {
                            println!("  + {} (new)", key);
                        }
                    } else {
                        println!("  + {} (new)", key);
                    }
                }

                // Show deletions
                if let Some(existing_data_map) = existing_data {
                    for key in existing_data_map.keys() {
                        if !new_data.contains_key(key) {
                            println!("  - {} (would be removed)", key);
                        }
                    }
                }
            }
            Err(_) => {
                println!("Would CREATE new Secret '{}/{}':", namespace, secret_name);
                for key in secret.string_data.as_ref().unwrap().keys() {
                    println!("  + {}", key);
                }
            }
        }

        println!("\nNo changes applied (dry run)");
    } else {
        match secrets_api.get(secret_name).await {
            Ok(_) => {
                // Update existing
                secrets_api
                    .replace(secret_name, &PostParams::default(), &secret)
                    .await?;
                println!(
                    "✓ Updated Secret '{}/{}' with {} secrets",
                    namespace,
                    secret_name,
                    secret.string_data.as_ref().unwrap().len()
                );
            }
            Err(_) => {
                // Create new
                secrets_api.create(&PostParams::default(), &secret).await?;
                println!(
                    "✓ Created Secret '{}/{}' with {} secrets",
                    namespace,
                    secret_name,
                    secret.string_data.as_ref().unwrap().len()
                );
            }
        }

        println!("✓ Synced at: {}", synced_at);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_secret_with_labels(labels: Option<BTreeMap<String, String>>) -> Secret {
        Secret {
            metadata: ObjectMeta {
                name: Some("test-secret".to_string()),
                labels,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    // is_managed_by_zopp tests
    #[test]
    fn test_is_managed_by_zopp_true() {
        let mut labels = BTreeMap::new();
        labels.insert(
            "app.kubernetes.io/managed-by".to_string(),
            "zopp".to_string(),
        );
        let secret = create_secret_with_labels(Some(labels));
        assert!(is_managed_by_zopp(&secret));
    }

    #[test]
    fn test_is_managed_by_zopp_false_different_manager() {
        let mut labels = BTreeMap::new();
        labels.insert(
            "app.kubernetes.io/managed-by".to_string(),
            "helm".to_string(),
        );
        let secret = create_secret_with_labels(Some(labels));
        assert!(!is_managed_by_zopp(&secret));
    }

    #[test]
    fn test_is_managed_by_zopp_false_no_label() {
        let labels = BTreeMap::new();
        let secret = create_secret_with_labels(Some(labels));
        assert!(!is_managed_by_zopp(&secret));
    }

    #[test]
    fn test_is_managed_by_zopp_false_no_labels() {
        let secret = create_secret_with_labels(None);
        assert!(!is_managed_by_zopp(&secret));
    }

    #[test]
    fn test_is_managed_by_zopp_case_sensitive() {
        let mut labels = BTreeMap::new();
        labels.insert(
            "app.kubernetes.io/managed-by".to_string(),
            "ZOPP".to_string(),
        );
        let secret = create_secret_with_labels(Some(labels));
        assert!(!is_managed_by_zopp(&secret));
    }

    // build_sync_labels tests
    #[test]
    fn test_build_sync_labels() {
        let labels = build_sync_labels();
        assert_eq!(labels.len(), 1);
        assert_eq!(
            labels.get("app.kubernetes.io/managed-by"),
            Some(&"zopp".to_string())
        );
    }

    // build_sync_annotations tests
    #[test]
    fn test_build_sync_annotations() {
        let annotations = build_sync_annotations(
            "my-workspace",
            "my-project",
            "production",
            "principal-123",
            "2024-01-01T00:00:00Z",
        );

        assert_eq!(annotations.len(), 5);
        assert_eq!(
            annotations.get("zopp.dev/workspace"),
            Some(&"my-workspace".to_string())
        );
        assert_eq!(
            annotations.get("zopp.dev/project"),
            Some(&"my-project".to_string())
        );
        assert_eq!(
            annotations.get("zopp.dev/environment"),
            Some(&"production".to_string())
        );
        assert_eq!(
            annotations.get("zopp.dev/synced-at"),
            Some(&"2024-01-01T00:00:00Z".to_string())
        );
        assert_eq!(
            annotations.get("zopp.dev/synced-by"),
            Some(&"principal-123".to_string())
        );
    }

    #[test]
    fn test_build_sync_annotations_empty_values() {
        let annotations = build_sync_annotations("", "", "", "", "");
        assert_eq!(annotations.len(), 5);
        assert_eq!(annotations.get("zopp.dev/workspace"), Some(&"".to_string()));
    }

    #[test]
    fn test_build_sync_annotations_special_chars() {
        let annotations = build_sync_annotations(
            "my-workspace/prod",
            "my-project:v1",
            "prod-env",
            "principal@123",
            "2024-01-01T00:00:00+00:00",
        );

        assert_eq!(
            annotations.get("zopp.dev/workspace"),
            Some(&"my-workspace/prod".to_string())
        );
        assert_eq!(
            annotations.get("zopp.dev/project"),
            Some(&"my-project:v1".to_string())
        );
    }

    // build_k8s_secret tests
    #[test]
    fn test_build_k8s_secret() {
        let mut secret_data = BTreeMap::new();
        secret_data.insert("API_KEY".to_string(), "secret123".to_string());
        secret_data.insert("DB_PASS".to_string(), "dbpass".to_string());

        let secret = build_k8s_secret(
            "my-secret",
            "default",
            secret_data,
            "workspace",
            "project",
            "production",
            "principal-1",
            "2024-01-01T00:00:00Z",
        );

        assert_eq!(secret.metadata.name, Some("my-secret".to_string()));
        assert_eq!(secret.metadata.namespace, Some("default".to_string()));

        // Check labels
        let labels = secret.metadata.labels.unwrap();
        assert_eq!(
            labels.get("app.kubernetes.io/managed-by"),
            Some(&"zopp".to_string())
        );

        // Check annotations
        let annotations = secret.metadata.annotations.unwrap();
        assert_eq!(
            annotations.get("zopp.dev/workspace"),
            Some(&"workspace".to_string())
        );

        // Check data
        let data = secret.string_data.unwrap();
        assert_eq!(data.len(), 2);
        assert_eq!(data.get("API_KEY"), Some(&"secret123".to_string()));
        assert_eq!(data.get("DB_PASS"), Some(&"dbpass".to_string()));
    }

    #[test]
    fn test_build_k8s_secret_empty_data() {
        let secret_data = BTreeMap::new();

        let secret = build_k8s_secret(
            "empty-secret",
            "kube-system",
            secret_data,
            "ws",
            "proj",
            "dev",
            "p1",
            "2024-01-01T00:00:00Z",
        );

        assert_eq!(secret.metadata.name, Some("empty-secret".to_string()));
        assert_eq!(secret.metadata.namespace, Some("kube-system".to_string()));
        assert!(secret.string_data.unwrap().is_empty());
    }

    #[test]
    fn test_build_k8s_secret_is_managed_by_zopp() {
        let secret = build_k8s_secret(
            "test",
            "default",
            BTreeMap::new(),
            "ws",
            "proj",
            "env",
            "p1",
            "2024-01-01T00:00:00Z",
        );

        // The built secret should be recognized as managed by zopp
        assert!(is_managed_by_zopp(&secret));
    }
}

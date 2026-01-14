use crate::crypto::fetch_and_decrypt_secrets;
use crate::grpc::setup_client;
use crate::k8s::load_k8s_config;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::ByteString;
use kube::{Api, Client};
use std::collections::BTreeMap;

/// Represents the diff between zopp secrets and k8s secrets
#[derive(Debug, Default, PartialEq)]
pub struct SecretDiff {
    pub added: Vec<String>,   // in zopp but not in k8s
    pub removed: Vec<String>, // in k8s but not in zopp
    pub changed: Vec<String>, // different values
}

impl SecretDiff {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }
}

/// Compare zopp secrets with k8s secret data
pub fn compare_secrets(
    zopp_secrets: &BTreeMap<String, String>,
    k8s_data: Option<&BTreeMap<String, ByteString>>,
) -> SecretDiff {
    let mut diff = SecretDiff::default();

    // Check for new or changed secrets
    for (key, zopp_value) in zopp_secrets {
        if let Some(k8s_map) = k8s_data {
            if let Some(k8s_value) = k8s_map.get(key) {
                let k8s_str = String::from_utf8_lossy(&k8s_value.0);
                if k8s_str != *zopp_value {
                    diff.changed.push(key.clone());
                }
            } else {
                diff.added.push(key.clone());
            }
        } else {
            diff.added.push(key.clone());
        }
    }

    // Check for secrets in k8s but not in zopp
    if let Some(k8s_map) = k8s_data {
        for key in k8s_map.keys() {
            if !zopp_secrets.contains_key(key) {
                diff.removed.push(key.clone());
            }
        }
    }

    // Sort for consistent output
    diff.added.sort();
    diff.removed.sort();
    diff.changed.sort();

    diff
}

/// Print diff output to stdout
pub fn print_diff(diff: &SecretDiff) {
    for key in &diff.added {
        println!("  + {} (exists in zopp, not in k8s)", key);
    }
    for key in &diff.changed {
        println!("  ~ {} (value differs)", key);
    }
    for key in &diff.removed {
        println!("  - {} (exists in k8s, not in zopp)", key);
    }
    if diff.is_empty() {
        println!("  ✓ No differences - secrets are in sync");
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn cmd_diff_k8s(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    workspace_name: &str,
    project_name: &str,
    environment_name: &str,
    namespace: &str,
    secret_name: &str,
    kubeconfig_path: Option<&std::path::Path>,
    context: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut client, principal) = setup_client(server, tls_ca_cert).await?;

    let zopp_secrets = fetch_and_decrypt_secrets(
        &mut client,
        &principal,
        workspace_name,
        project_name,
        environment_name,
    )
    .await?;

    let k8s_config = load_k8s_config(kubeconfig_path, context).await?;

    let k8s_client = Client::try_from(k8s_config)?;
    let secrets_api: Api<Secret> = Api::namespaced(k8s_client, namespace);

    println!(
        "Comparing zopp → k8s Secret '{}/{}':\n",
        namespace, secret_name
    );

    match secrets_api.get(secret_name).await {
        Ok(existing) => {
            let existing_data = existing.data.as_ref();
            let mut has_changes = false;

            // Check for new or changed secrets
            for (key, zopp_value) in &zopp_secrets {
                if let Some(existing_data_map) = existing_data {
                    if let Some(existing_value) = existing_data_map.get(key) {
                        let existing_str = String::from_utf8_lossy(&existing_value.0);
                        if existing_str != *zopp_value {
                            println!("  ~ {} (value differs)", key);
                            has_changes = true;
                        }
                    } else {
                        println!("  + {} (exists in zopp, not in k8s)", key);
                        has_changes = true;
                    }
                } else {
                    println!("  + {} (exists in zopp, not in k8s)", key);
                    has_changes = true;
                }
            }

            // Check for secrets in k8s but not in zopp
            if let Some(existing_data_map) = existing_data {
                for key in existing_data_map.keys() {
                    if !zopp_secrets.contains_key(key) {
                        println!("  - {} (exists in k8s, not in zopp)", key);
                        has_changes = true;
                    }
                }
            }

            if !has_changes {
                println!("  ✓ No differences - secrets are in sync");
            }
        }
        Err(kube::Error::Api(api_err)) if api_err.code == 404 => {
            println!(
                "Secret does not exist in k8s. Would create with {} keys:",
                zopp_secrets.len()
            );
            for key in zopp_secrets.keys() {
                println!("  + {}", key);
            }
        }
        Err(e) => return Err(e.into()),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_bytestring(s: &str) -> ByteString {
        ByteString(s.as_bytes().to_vec())
    }

    fn make_k8s_data(pairs: &[(&str, &str)]) -> BTreeMap<String, ByteString> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), make_bytestring(v)))
            .collect()
    }

    fn make_zopp_secrets(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    // SecretDiff tests
    #[test]
    fn test_secret_diff_is_empty_when_default() {
        let diff = SecretDiff::default();
        assert!(diff.is_empty());
    }

    #[test]
    fn test_secret_diff_is_empty_when_has_added() {
        let diff = SecretDiff {
            added: vec!["key".to_string()],
            ..Default::default()
        };
        assert!(!diff.is_empty());
    }

    #[test]
    fn test_secret_diff_is_empty_when_has_removed() {
        let diff = SecretDiff {
            removed: vec!["key".to_string()],
            ..Default::default()
        };
        assert!(!diff.is_empty());
    }

    #[test]
    fn test_secret_diff_is_empty_when_has_changed() {
        let diff = SecretDiff {
            changed: vec!["key".to_string()],
            ..Default::default()
        };
        assert!(!diff.is_empty());
    }

    // compare_secrets tests
    #[test]
    fn test_compare_secrets_empty_both() {
        let zopp: BTreeMap<String, String> = BTreeMap::new();
        let diff = compare_secrets(&zopp, None);
        assert!(diff.is_empty());
    }

    #[test]
    fn test_compare_secrets_zopp_only() {
        let zopp = make_zopp_secrets(&[("API_KEY", "secret123"), ("DB_PASS", "dbpass")]);
        let diff = compare_secrets(&zopp, None);

        assert_eq!(diff.added, vec!["API_KEY", "DB_PASS"]);
        assert!(diff.removed.is_empty());
        assert!(diff.changed.is_empty());
    }

    #[test]
    fn test_compare_secrets_zopp_only_empty_k8s() {
        let zopp = make_zopp_secrets(&[("API_KEY", "secret123")]);
        let k8s: BTreeMap<String, ByteString> = BTreeMap::new();
        let diff = compare_secrets(&zopp, Some(&k8s));

        assert_eq!(diff.added, vec!["API_KEY"]);
        assert!(diff.removed.is_empty());
        assert!(diff.changed.is_empty());
    }

    #[test]
    fn test_compare_secrets_k8s_only() {
        let zopp: BTreeMap<String, String> = BTreeMap::new();
        let k8s = make_k8s_data(&[("OLD_KEY", "oldvalue")]);
        let diff = compare_secrets(&zopp, Some(&k8s));

        assert!(diff.added.is_empty());
        assert_eq!(diff.removed, vec!["OLD_KEY"]);
        assert!(diff.changed.is_empty());
    }

    #[test]
    fn test_compare_secrets_same() {
        let zopp = make_zopp_secrets(&[("API_KEY", "secret123"), ("DB_PASS", "dbpass")]);
        let k8s = make_k8s_data(&[("API_KEY", "secret123"), ("DB_PASS", "dbpass")]);
        let diff = compare_secrets(&zopp, Some(&k8s));

        assert!(diff.is_empty());
    }

    #[test]
    fn test_compare_secrets_changed() {
        let zopp = make_zopp_secrets(&[("API_KEY", "new_value")]);
        let k8s = make_k8s_data(&[("API_KEY", "old_value")]);
        let diff = compare_secrets(&zopp, Some(&k8s));

        assert!(diff.added.is_empty());
        assert!(diff.removed.is_empty());
        assert_eq!(diff.changed, vec!["API_KEY"]);
    }

    #[test]
    fn test_compare_secrets_mixed() {
        let zopp =
            make_zopp_secrets(&[("SAME", "value"), ("CHANGED", "new"), ("ADDED", "new_key")]);
        let k8s = make_k8s_data(&[("SAME", "value"), ("CHANGED", "old"), ("REMOVED", "gone")]);
        let diff = compare_secrets(&zopp, Some(&k8s));

        assert_eq!(diff.added, vec!["ADDED"]);
        assert_eq!(diff.removed, vec!["REMOVED"]);
        assert_eq!(diff.changed, vec!["CHANGED"]);
    }

    #[test]
    fn test_compare_secrets_sorted_output() {
        let zopp = make_zopp_secrets(&[("Z_KEY", "z"), ("A_KEY", "a"), ("M_KEY", "m")]);
        let diff = compare_secrets(&zopp, None);

        // Should be sorted alphabetically
        assert_eq!(diff.added, vec!["A_KEY", "M_KEY", "Z_KEY"]);
    }

    #[test]
    fn test_compare_secrets_unicode_values() {
        let zopp = make_zopp_secrets(&[("KEY", "こんにちは")]);
        let k8s = make_k8s_data(&[("KEY", "こんにちは")]);
        let diff = compare_secrets(&zopp, Some(&k8s));

        assert!(diff.is_empty());
    }

    #[test]
    fn test_compare_secrets_unicode_values_differ() {
        let zopp = make_zopp_secrets(&[("KEY", "hello")]);
        let k8s = make_k8s_data(&[("KEY", "世界")]);
        let diff = compare_secrets(&zopp, Some(&k8s));

        assert_eq!(diff.changed, vec!["KEY"]);
    }

    #[test]
    fn test_compare_secrets_empty_values() {
        let zopp = make_zopp_secrets(&[("KEY", "")]);
        let k8s = make_k8s_data(&[("KEY", "")]);
        let diff = compare_secrets(&zopp, Some(&k8s));

        assert!(diff.is_empty());
    }

    #[test]
    fn test_compare_secrets_empty_vs_nonempty() {
        let zopp = make_zopp_secrets(&[("KEY", "value")]);
        let k8s = make_k8s_data(&[("KEY", "")]);
        let diff = compare_secrets(&zopp, Some(&k8s));

        assert_eq!(diff.changed, vec!["KEY"]);
    }

    // print_diff tests (just ensure no panic)
    #[test]
    fn test_print_diff_empty() {
        let diff = SecretDiff::default();
        print_diff(&diff);
    }

    #[test]
    fn test_print_diff_all_types() {
        let diff = SecretDiff {
            added: vec!["NEW".to_string()],
            removed: vec!["OLD".to_string()],
            changed: vec!["UPDATED".to_string()],
        };
        print_diff(&diff);
    }
}

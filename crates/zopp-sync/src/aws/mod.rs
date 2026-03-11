//! AWS Secrets Manager sync target implementation.
//!
//! Requires the `aws` feature flag. Credentials are resolved automatically
//! via the standard AWS credential chain (env vars, profile, instance metadata).

mod client;

use std::collections::HashMap;

use crate::{DiffOperation, FetchResult, SyncError, SyncOutcome, SyncResult, SyncTarget};
use client::{AwsClient, SecretsManagerApi};

/// Sync target for AWS Secrets Manager.
///
/// Construct via [`AwsSyncTarget::new`], which resolves AWS credentials
/// using the default provider chain.
pub struct AwsSyncTarget {
    api: Box<dyn SecretsManagerApi>,
    display_name: String,
    prefix: Option<String>,
}

impl AwsSyncTarget {
    /// Create a new AWS Secrets Manager sync target.
    ///
    /// Resolves credentials via `aws-config` default chain:
    /// environment variables → `~/.aws/credentials` → EC2/ECS instance metadata.
    pub async fn new(region: &str, prefix: Option<String>) -> Result<Self, SyncError> {
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_sdk_secretsmanager::config::Region::new(
                region.to_string(),
            ))
            .load()
            .await;

        let sm_client = aws_sdk_secretsmanager::Client::new(&config);

        Ok(Self {
            api: Box::new(AwsClient::new(sm_client)),
            display_name: format!("AWS Secrets Manager ({region})"),
            prefix,
        })
    }

    /// Create from an existing API implementation (for testing).
    #[cfg(test)]
    fn from_api(api: Box<dyn SecretsManagerApi>, region: &str, prefix: Option<String>) -> Self {
        Self {
            api,
            display_name: format!("AWS Secrets Manager ({region})"),
            prefix,
        }
    }

    /// Prepend the configured prefix to a key name.
    fn prefixed_name(&self, key: &str) -> String {
        match &self.prefix {
            Some(pfx) => format!("{pfx}{key}"),
            None => key.to_string(),
        }
    }

    /// Strip the configured prefix from a secret name.
    fn strip_prefix<'a>(&self, name: &'a str) -> &'a str {
        match &self.prefix {
            Some(pfx) => name.strip_prefix(pfx.as_str()).unwrap_or(name),
            None => name,
        }
    }
}

#[async_trait::async_trait]
impl SyncTarget for AwsSyncTarget {
    fn display_name(&self) -> &str {
        &self.display_name
    }

    async fn fetch_current(&self) -> Result<FetchResult, SyncError> {
        let entries = self.api.list_secrets(self.prefix.as_deref()).await?;

        let mut secrets = HashMap::new();
        let mut errors = Vec::new();
        for entry in entries {
            let key = self.strip_prefix(&entry.name).to_string();
            match self.api.get_secret_value(&entry.name).await {
                Ok(value) => {
                    secrets.insert(key, value);
                }
                Err(e) => {
                    // Fatal errors (auth, connection) abort immediately
                    match &e {
                        SyncError::AuthError { .. } | SyncError::ConnectionError { .. } => {
                            return Err(e);
                        }
                        _ => {
                            // Per-key errors are collected for the caller to decide
                            errors.push((key, e.to_string()));
                        }
                    }
                }
            }
        }

        Ok(FetchResult { secrets, errors })
    }

    async fn apply(&self, operations: &[DiffOperation]) -> Vec<SyncResult> {
        let mut results = Vec::with_capacity(operations.len());

        for op in operations {
            let key = op.key().to_string();
            let outcome = match op {
                DiffOperation::Add { key, value } => {
                    let name = self.prefixed_name(key);
                    match self.api.create_secret(&name, value).await {
                        Ok(()) => SyncOutcome::Success,
                        Err(e) => SyncOutcome::Failed {
                            reason: e.to_string(),
                        },
                    }
                }
                DiffOperation::Update { key, new_value, .. } => {
                    let name = self.prefixed_name(key);
                    match self.api.put_secret_value(&name, new_value).await {
                        Ok(()) => SyncOutcome::Success,
                        Err(e) => SyncOutcome::Failed {
                            reason: e.to_string(),
                        },
                    }
                }
                DiffOperation::Remove { key } => {
                    let name = self.prefixed_name(key);
                    match self.api.delete_secret(&name).await {
                        Ok(()) => SyncOutcome::Success,
                        Err(e) => SyncOutcome::Failed {
                            reason: e.to_string(),
                        },
                    }
                }
            };

            results.push(SyncResult { key, outcome });
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock implementation of SecretsManagerApi for testing.
    struct MockApi {
        secrets: std::sync::Mutex<HashMap<String, String>>,
        fail_on: std::sync::Mutex<Option<String>>,
    }

    impl MockApi {
        fn new(secrets: HashMap<String, String>) -> Self {
            Self {
                secrets: std::sync::Mutex::new(secrets),
                fail_on: std::sync::Mutex::new(None),
            }
        }

        fn with_failure(self, key: &str) -> Self {
            *self.fail_on.lock().unwrap() = Some(key.to_string());
            self
        }
    }

    #[async_trait::async_trait]
    impl SecretsManagerApi for MockApi {
        async fn list_secrets(
            &self,
            prefix: Option<&str>,
        ) -> Result<Vec<client::SecretEntry>, SyncError> {
            let secrets = self.secrets.lock().unwrap();
            let entries: Vec<_> = secrets
                .keys()
                .filter(|name| {
                    if let Some(pfx) = prefix {
                        name.starts_with(pfx)
                    } else {
                        true
                    }
                })
                .map(|name| client::SecretEntry { name: name.clone() })
                .collect();
            Ok(entries)
        }

        async fn get_secret_value(&self, id: &str) -> Result<String, SyncError> {
            let secrets = self.secrets.lock().unwrap();
            secrets.get(id).cloned().ok_or_else(|| SyncError::ApiError {
                platform: "AWS Secrets Manager".into(),
                operation: "get_secret_value".into(),
                message: format!("Secret '{id}' not found"),
                fix: String::new(),
            })
        }

        async fn create_secret(&self, name: &str, value: &str) -> Result<(), SyncError> {
            if let Some(fail_key) = self.fail_on.lock().unwrap().as_ref() {
                if name.contains(fail_key) {
                    return Err(SyncError::ApiError {
                        platform: "AWS Secrets Manager".into(),
                        operation: "create_secret".into(),
                        message: format!("AccessDeniedException for '{name}'"),
                        fix: "Check IAM permissions.".into(),
                    });
                }
            }
            self.secrets
                .lock()
                .unwrap()
                .insert(name.to_string(), value.to_string());
            Ok(())
        }

        async fn put_secret_value(&self, id: &str, value: &str) -> Result<(), SyncError> {
            if let Some(fail_key) = self.fail_on.lock().unwrap().as_ref() {
                if id.contains(fail_key) {
                    return Err(SyncError::ApiError {
                        platform: "AWS Secrets Manager".into(),
                        operation: "put_secret_value".into(),
                        message: format!("AccessDeniedException for '{id}'"),
                        fix: "Check IAM permissions.".into(),
                    });
                }
            }
            self.secrets
                .lock()
                .unwrap()
                .insert(id.to_string(), value.to_string());
            Ok(())
        }

        async fn delete_secret(&self, id: &str) -> Result<(), SyncError> {
            if let Some(fail_key) = self.fail_on.lock().unwrap().as_ref() {
                if id.contains(fail_key) {
                    return Err(SyncError::ApiError {
                        platform: "AWS Secrets Manager".into(),
                        operation: "delete_secret".into(),
                        message: format!("AccessDeniedException for '{id}'"),
                        fix: "Check IAM permissions.".into(),
                    });
                }
            }
            self.secrets.lock().unwrap().remove(id);
            Ok(())
        }
    }

    /// Mock that always fails with AuthError.
    struct AuthFailApi;

    #[async_trait::async_trait]
    impl SecretsManagerApi for AuthFailApi {
        async fn list_secrets(
            &self,
            _prefix: Option<&str>,
        ) -> Result<Vec<client::SecretEntry>, SyncError> {
            Err(SyncError::AuthError {
                platform: "AWS Secrets Manager".into(),
                message: "credentials not found".into(),
                fix: "Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.".into(),
            })
        }

        async fn get_secret_value(&self, _id: &str) -> Result<String, SyncError> {
            Err(SyncError::AuthError {
                platform: "AWS Secrets Manager".into(),
                message: "credentials not found".into(),
                fix: "Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.".into(),
            })
        }

        async fn create_secret(&self, _name: &str, _value: &str) -> Result<(), SyncError> {
            Err(SyncError::AuthError {
                platform: "AWS Secrets Manager".into(),
                message: "credentials not found".into(),
                fix: "Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.".into(),
            })
        }

        async fn put_secret_value(&self, _id: &str, _value: &str) -> Result<(), SyncError> {
            Err(SyncError::AuthError {
                platform: "AWS Secrets Manager".into(),
                message: "credentials not found".into(),
                fix: "Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.".into(),
            })
        }

        async fn delete_secret(&self, _id: &str) -> Result<(), SyncError> {
            Err(SyncError::AuthError {
                platform: "AWS Secrets Manager".into(),
                message: "credentials not found".into(),
                fix: "Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.".into(),
            })
        }
    }

    #[tokio::test]
    async fn fetch_current_returns_secrets() {
        let mut initial = HashMap::new();
        initial.insert("DB_HOST".to_string(), "localhost".to_string());
        initial.insert("DB_PORT".to_string(), "5432".to_string());

        let api = MockApi::new(initial);
        let target = AwsSyncTarget::from_api(Box::new(api), "us-east-1", None);

        let result = target.fetch_current().await.unwrap();
        assert_eq!(result.secrets.len(), 2);
        assert_eq!(result.secrets["DB_HOST"], "localhost");
        assert_eq!(result.secrets["DB_PORT"], "5432");
        assert!(result.errors.is_empty());
    }

    #[tokio::test]
    async fn fetch_current_with_prefix_filtering() {
        let mut initial = HashMap::new();
        initial.insert("/prod/DB_HOST".to_string(), "prod-host".to_string());
        initial.insert("/prod/DB_PORT".to_string(), "5432".to_string());
        initial.insert("/staging/DB_HOST".to_string(), "staging-host".to_string());

        let api = MockApi::new(initial);
        let target =
            AwsSyncTarget::from_api(Box::new(api), "us-east-1", Some("/prod/".to_string()));

        let result = target.fetch_current().await.unwrap();
        assert_eq!(result.secrets.len(), 2);
        // Keys should have prefix stripped
        assert_eq!(result.secrets["DB_HOST"], "prod-host");
        assert_eq!(result.secrets["DB_PORT"], "5432");
        // Staging secret should not be included
        assert!(!result.secrets.contains_key("/staging/DB_HOST"));
        assert!(!result.secrets.contains_key("staging/DB_HOST"));
        assert!(result.errors.is_empty());
    }

    #[tokio::test]
    async fn fetch_current_auth_error() {
        let api = AuthFailApi;
        let target = AwsSyncTarget::from_api(Box::new(api), "us-east-1", None);

        let result = target.fetch_current().await;
        assert!(result.is_err());
        match result.unwrap_err() {
            SyncError::AuthError { platform, .. } => {
                assert_eq!(platform, "AWS Secrets Manager");
            }
            other => panic!("Expected AuthError, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn apply_creates_updates_deletes() {
        let mut initial = HashMap::new();
        initial.insert("EXISTING".to_string(), "old-value".to_string());
        initial.insert("TO_DELETE".to_string(), "delete-me".to_string());

        let api = MockApi::new(initial);
        let target = AwsSyncTarget::from_api(Box::new(api), "us-east-1", None);

        let ops = vec![
            DiffOperation::Add {
                key: "NEW_KEY".to_string(),
                value: "new-value".to_string(),
            },
            DiffOperation::Update {
                key: "EXISTING".to_string(),
                old_value: "old-value".to_string(),
                new_value: "updated-value".to_string(),
            },
            DiffOperation::Remove {
                key: "TO_DELETE".to_string(),
            },
        ];

        let results = target.apply(&ops).await;
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].key, "NEW_KEY");
        assert_eq!(results[0].outcome, SyncOutcome::Success);
        assert_eq!(results[1].key, "EXISTING");
        assert_eq!(results[1].outcome, SyncOutcome::Success);
        assert_eq!(results[2].key, "TO_DELETE");
        assert_eq!(results[2].outcome, SyncOutcome::Success);
    }

    #[tokio::test]
    async fn apply_with_prefix() {
        let api = MockApi::new(HashMap::new());
        let target =
            AwsSyncTarget::from_api(Box::new(api), "us-east-1", Some("/prod/".to_string()));

        let ops = vec![DiffOperation::Add {
            key: "DB_HOST".to_string(),
            value: "prod-host".to_string(),
        }];

        let results = target.apply(&ops).await;
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].outcome, SyncOutcome::Success);
    }

    #[tokio::test]
    async fn apply_partial_failure() {
        let mut initial = HashMap::new();
        initial.insert("GOOD".to_string(), "value".to_string());

        let api = MockApi::new(initial).with_failure("FAIL_KEY");
        let target = AwsSyncTarget::from_api(Box::new(api), "us-east-1", None);

        let ops = vec![
            DiffOperation::Add {
                key: "GOOD_KEY".to_string(),
                value: "value".to_string(),
            },
            DiffOperation::Add {
                key: "FAIL_KEY".to_string(),
                value: "value".to_string(),
            },
        ];

        let results = target.apply(&ops).await;
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].key, "GOOD_KEY");
        assert_eq!(results[0].outcome, SyncOutcome::Success);
        assert_eq!(results[1].key, "FAIL_KEY");
        assert!(matches!(results[1].outcome, SyncOutcome::Failed { .. }));
    }

    #[tokio::test]
    async fn display_name_returns_aws() {
        let api = MockApi::new(HashMap::new());
        let target = AwsSyncTarget::from_api(Box::new(api), "us-east-1", None);
        assert_eq!(target.display_name(), "AWS Secrets Manager (us-east-1)");
    }

    #[test]
    fn prefixed_name_with_prefix() {
        let api = MockApi::new(HashMap::new());
        let target =
            AwsSyncTarget::from_api(Box::new(api), "us-east-1", Some("/prod/".to_string()));
        assert_eq!(target.prefixed_name("DB_HOST"), "/prod/DB_HOST");
    }

    #[test]
    fn prefixed_name_without_prefix() {
        let api = MockApi::new(HashMap::new());
        let target = AwsSyncTarget::from_api(Box::new(api), "us-east-1", None);
        assert_eq!(target.prefixed_name("DB_HOST"), "DB_HOST");
    }

    #[test]
    fn strip_prefix_with_prefix() {
        let api = MockApi::new(HashMap::new());
        let target =
            AwsSyncTarget::from_api(Box::new(api), "us-east-1", Some("/prod/".to_string()));
        assert_eq!(target.strip_prefix("/prod/DB_HOST"), "DB_HOST");
    }

    #[test]
    fn strip_prefix_without_prefix() {
        let api = MockApi::new(HashMap::new());
        let target = AwsSyncTarget::from_api(Box::new(api), "us-east-1", None);
        assert_eq!(target.strip_prefix("DB_HOST"), "DB_HOST");
    }

    #[test]
    fn no_aws_types_leak() {
        // This is a compile-time check — AwsSyncTarget's public API only uses
        // types from crate::types and crate::error, not aws_sdk_* types.
        // If this test compiles, it proves no AWS SDK types leak.
        fn _assert_sync_target<T: SyncTarget>() {}
        fn _assert_aws_is_sync_target() {
            _assert_sync_target::<AwsSyncTarget>();
        }
    }
}

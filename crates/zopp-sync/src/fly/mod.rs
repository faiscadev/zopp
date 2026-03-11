//! Fly sync target implementation.
//!
//! Requires the `fly` feature flag. Credentials are read from the
//! `FLY_API_TOKEN` environment variable.
//!
//! **Important:** Fly secrets are write-only — the API returns secret labels
//! but not their values. This means `fetch_current()` returns only key names
//! (with empty-string values). The diff engine will see every zopp secret as
//! an "update" since values can't be compared. Use `--force` to push all
//! values, or rely on add/remove detection for key-level changes.

mod client;

use std::collections::HashMap;

use crate::{DiffOperation, FetchResult, SyncError, SyncOutcome, SyncResult, SyncTarget};
use client::{FlyApi, FlyClient};

/// Sync target for Fly apps.
///
/// Construct via [`FlySyncTarget::new`], which reads `FLY_API_TOKEN`
/// from the environment.
pub struct FlySyncTarget {
    api: Box<dyn FlyApi>,
    app: String,
    display_name: String,
}

impl FlySyncTarget {
    /// Create a new Fly sync target.
    ///
    /// Reads `FLY_API_TOKEN` from the environment. Returns `SyncError::AuthError`
    /// if the token is not set.
    pub fn new(app: String) -> Result<Self, SyncError> {
        let token = std::env::var("FLY_API_TOKEN").map_err(|_| SyncError::AuthError {
            platform: "Fly".into(),
            message: "FLY_API_TOKEN not set".into(),
            fix: "Set FLY_API_TOKEN. Generate one at https://fly.io/user/personal_access_tokens"
                .into(),
        })?;

        let display_name = format!("Fly ({app})");
        Ok(Self {
            api: Box::new(FlyClient::new(token)),
            app,
            display_name,
        })
    }

    /// Create from an existing API implementation (for testing).
    #[cfg(test)]
    fn from_api(api: Box<dyn FlyApi>, app: &str) -> Self {
        Self {
            api,
            app: app.to_string(),
            display_name: format!("Fly ({app})"),
        }
    }
}

#[async_trait::async_trait]
impl SyncTarget for FlySyncTarget {
    fn display_name(&self) -> &str {
        &self.display_name
    }

    async fn fetch_current(&self) -> Result<FetchResult, SyncError> {
        let entries = self.api.list_secrets(&self.app).await?;

        // Fly only returns labels, not values. We store empty strings as
        // placeholders so the diff engine can detect add/remove operations.
        let secrets: HashMap<String, String> = entries
            .into_iter()
            .map(|entry| (entry.label, String::new()))
            .collect();

        Ok(FetchResult {
            secrets,
            errors: Vec::new(),
        })
    }

    async fn apply(&self, operations: &[DiffOperation]) -> Vec<SyncResult> {
        let mut results = Vec::with_capacity(operations.len());

        // Batch all adds and updates into a single set_secrets call.
        let to_set: Vec<(&str, &str)> = operations
            .iter()
            .filter_map(|op| match op {
                DiffOperation::Add { key, value } => Some((key.as_str(), value.as_str())),
                DiffOperation::Update { key, new_value, .. } => {
                    Some((key.as_str(), new_value.as_str()))
                }
                DiffOperation::Remove { .. } => None,
            })
            .collect();

        // Apply adds/updates as a batch
        let batch_result = if !to_set.is_empty() {
            self.api.set_secrets(&self.app, &to_set).await
        } else {
            Ok(())
        };

        // Record results for adds/updates
        for op in operations {
            match op {
                DiffOperation::Add { key, .. } | DiffOperation::Update { key, .. } => {
                    let outcome = match &batch_result {
                        Ok(()) => SyncOutcome::Success,
                        Err(e) => SyncOutcome::Failed {
                            reason: e.to_string(),
                        },
                    };
                    results.push(SyncResult {
                        key: key.clone(),
                        outcome,
                    });
                }
                DiffOperation::Remove { .. } => {} // handled below
            }
        }

        // Process removes individually
        for op in operations {
            if let DiffOperation::Remove { key } = op {
                let outcome = match self.api.unset_secret(&self.app, key).await {
                    Ok(()) => SyncOutcome::Success,
                    Err(e) => SyncOutcome::Failed {
                        reason: e.to_string(),
                    },
                };
                results.push(SyncResult {
                    key: key.clone(),
                    outcome,
                });
            }
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock implementation of FlyApi for testing.
    struct MockApi {
        labels: std::sync::Mutex<Vec<String>>,
        fail_on_set: std::sync::Mutex<bool>,
        fail_on_unset: std::sync::Mutex<Option<String>>,
    }

    impl MockApi {
        fn new(labels: Vec<String>) -> Self {
            Self {
                labels: std::sync::Mutex::new(labels),
                fail_on_set: std::sync::Mutex::new(false),
                fail_on_unset: std::sync::Mutex::new(None),
            }
        }

        fn with_set_failure(self) -> Self {
            *self.fail_on_set.lock().unwrap() = true;
            self
        }

        fn with_unset_failure(self, key: &str) -> Self {
            *self.fail_on_unset.lock().unwrap() = Some(key.to_string());
            self
        }
    }

    #[async_trait::async_trait]
    impl FlyApi for MockApi {
        async fn list_secrets(&self, _app: &str) -> Result<Vec<client::SecretEntry>, SyncError> {
            let labels = self.labels.lock().unwrap();
            Ok(labels
                .iter()
                .map(|l| client::SecretEntry { label: l.clone() })
                .collect())
        }

        async fn set_secrets(&self, _app: &str, secrets: &[(&str, &str)]) -> Result<(), SyncError> {
            if *self.fail_on_set.lock().unwrap() {
                return Err(SyncError::ApiError {
                    platform: "Fly".into(),
                    operation: "set_secrets".into(),
                    message: "Batch set failed".into(),
                    fix: String::new(),
                });
            }
            let mut labels = self.labels.lock().unwrap();
            for (key, _) in secrets {
                if !labels.contains(&key.to_string()) {
                    labels.push(key.to_string());
                }
            }
            Ok(())
        }

        async fn unset_secret(&self, _app: &str, label: &str) -> Result<(), SyncError> {
            if let Some(fail_key) = self.fail_on_unset.lock().unwrap().as_ref() {
                if label == fail_key {
                    return Err(SyncError::ApiError {
                        platform: "Fly".into(),
                        operation: "unset_secret".into(),
                        message: format!("Failed to unset '{label}'"),
                        fix: String::new(),
                    });
                }
            }
            let mut labels = self.labels.lock().unwrap();
            labels.retain(|l| l != label);
            Ok(())
        }
    }

    /// Mock that always fails with AuthError on list.
    struct AuthFailApi;

    #[async_trait::async_trait]
    impl FlyApi for AuthFailApi {
        async fn list_secrets(&self, _app: &str) -> Result<Vec<client::SecretEntry>, SyncError> {
            Err(SyncError::AuthError {
                platform: "Fly".into(),
                message: "FLY_API_TOKEN invalid".into(),
                fix:
                    "Set FLY_API_TOKEN. Generate one at https://fly.io/user/personal_access_tokens"
                        .into(),
            })
        }

        async fn set_secrets(
            &self,
            _app: &str,
            _secrets: &[(&str, &str)],
        ) -> Result<(), SyncError> {
            Err(SyncError::AuthError {
                platform: "Fly".into(),
                message: "FLY_API_TOKEN invalid".into(),
                fix: String::new(),
            })
        }

        async fn unset_secret(&self, _app: &str, _label: &str) -> Result<(), SyncError> {
            Err(SyncError::AuthError {
                platform: "Fly".into(),
                message: "FLY_API_TOKEN invalid".into(),
                fix: String::new(),
            })
        }
    }

    #[tokio::test]
    async fn fetch_current_returns_labels_with_empty_values() {
        let api = MockApi::new(vec!["DB_HOST".into(), "DB_PORT".into()]);
        let target = FlySyncTarget::from_api(Box::new(api), "myapp");

        let result = target.fetch_current().await.unwrap();
        assert_eq!(result.secrets.len(), 2);
        assert_eq!(result.secrets["DB_HOST"], "");
        assert_eq!(result.secrets["DB_PORT"], "");
        assert!(result.errors.is_empty());
    }

    #[tokio::test]
    async fn fetch_current_empty_app() {
        let api = MockApi::new(vec![]);
        let target = FlySyncTarget::from_api(Box::new(api), "myapp");

        let result = target.fetch_current().await.unwrap();
        assert!(result.secrets.is_empty());
        assert!(result.errors.is_empty());
    }

    #[tokio::test]
    async fn fetch_current_auth_error() {
        let api = AuthFailApi;
        let target = FlySyncTarget::from_api(Box::new(api), "myapp");

        let result = target.fetch_current().await;
        assert!(result.is_err());
        match result.unwrap_err() {
            SyncError::AuthError { platform, .. } => {
                assert_eq!(platform, "Fly");
            }
            other => panic!("Expected AuthError, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn apply_creates_updates_deletes() {
        let api = MockApi::new(vec!["EXISTING".into(), "TO_DELETE".into()]);
        let target = FlySyncTarget::from_api(Box::new(api), "myapp");

        let ops = vec![
            DiffOperation::Add {
                key: "NEW_KEY".to_string(),
                value: "new-value".to_string(),
            },
            DiffOperation::Update {
                key: "EXISTING".to_string(),
                old_value: String::new(),
                new_value: "updated-value".to_string(),
            },
            DiffOperation::Remove {
                key: "TO_DELETE".to_string(),
            },
        ];

        let results = target.apply(&ops).await;
        assert_eq!(results.len(), 3);

        // Adds/updates come first (batched), then removes
        assert_eq!(results[0].key, "NEW_KEY");
        assert_eq!(results[0].outcome, SyncOutcome::Success);
        assert_eq!(results[1].key, "EXISTING");
        assert_eq!(results[1].outcome, SyncOutcome::Success);
        assert_eq!(results[2].key, "TO_DELETE");
        assert_eq!(results[2].outcome, SyncOutcome::Success);
    }

    #[tokio::test]
    async fn apply_batch_set_failure() {
        let api = MockApi::new(vec![]).with_set_failure();
        let target = FlySyncTarget::from_api(Box::new(api), "myapp");

        let ops = vec![
            DiffOperation::Add {
                key: "KEY_A".to_string(),
                value: "val-a".to_string(),
            },
            DiffOperation::Add {
                key: "KEY_B".to_string(),
                value: "val-b".to_string(),
            },
        ];

        let results = target.apply(&ops).await;
        assert_eq!(results.len(), 2);
        assert!(matches!(results[0].outcome, SyncOutcome::Failed { .. }));
        assert!(matches!(results[1].outcome, SyncOutcome::Failed { .. }));
    }

    #[tokio::test]
    async fn apply_unset_failure() {
        let api = MockApi::new(vec!["GOOD".into(), "FAIL".into()]).with_unset_failure("FAIL");
        let target = FlySyncTarget::from_api(Box::new(api), "myapp");

        let ops = vec![
            DiffOperation::Remove {
                key: "GOOD".to_string(),
            },
            DiffOperation::Remove {
                key: "FAIL".to_string(),
            },
        ];

        let results = target.apply(&ops).await;
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].key, "GOOD");
        assert_eq!(results[0].outcome, SyncOutcome::Success);
        assert_eq!(results[1].key, "FAIL");
        assert!(matches!(results[1].outcome, SyncOutcome::Failed { .. }));
    }

    #[tokio::test]
    async fn apply_empty_operations() {
        let api = MockApi::new(vec![]);
        let target = FlySyncTarget::from_api(Box::new(api), "myapp");

        let results = target.apply(&[]).await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn display_name_returns_fly_app() {
        let api = MockApi::new(vec![]);
        let target = FlySyncTarget::from_api(Box::new(api), "myapp");
        assert_eq!(target.display_name(), "Fly (myapp)");
    }

    #[test]
    fn no_fly_types_leak() {
        // Compile-time check — FlySyncTarget's public API only uses
        // types from crate::types and crate::error, not reqwest types.
        fn _assert_sync_target<T: SyncTarget>() {}
        fn _assert_fly_is_sync_target() {
            _assert_sync_target::<FlySyncTarget>();
        }
    }
}

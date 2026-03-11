use crate::SyncError;

const PLATFORM: &str = "Fly";
const BASE_URL: &str = "https://api.machines.dev";

/// Represents a secret entry from the Fly API (name only — Fly secrets are write-only).
pub(crate) struct SecretEntry {
    pub label: String,
}

/// Thin abstraction over the Fly Machines API.
///
/// This trait is internal to the `fly` module and exists solely for testability.
/// The real implementation uses `reqwest`; tests provide a mock.
#[async_trait::async_trait]
pub(crate) trait FlyApi: Send + Sync {
    /// List all secret labels for an app (Fly does NOT return values).
    async fn list_secrets(&self, app: &str) -> Result<Vec<SecretEntry>, SyncError>;

    /// Set (create or update) secrets on an app. Fly's API is batch-oriented.
    async fn set_secrets(&self, app: &str, secrets: &[(&str, &str)]) -> Result<(), SyncError>;

    /// Unset (delete) a single secret from an app.
    async fn unset_secret(&self, app: &str, label: &str) -> Result<(), SyncError>;
}

/// Real Fly API client using `reqwest`.
pub(crate) struct FlyClient {
    http: reqwest::Client,
    token: String,
}

impl FlyClient {
    pub fn new(token: String) -> Self {
        Self {
            http: reqwest::Client::new(),
            token,
        }
    }
}

/// Map an HTTP response status (or reqwest error) to a `SyncError`.
fn map_http_error(status: reqwest::StatusCode, body: &str, operation: &str) -> SyncError {
    match status.as_u16() {
        401 => SyncError::AuthError {
            platform: PLATFORM.into(),
            message: format!("HTTP 401 Unauthorized: {body}"),
            fix: "Check FLY_API_TOKEN. Generate one at https://fly.io/user/personal_access_tokens"
                .into(),
        },
        403 => SyncError::AuthError {
            platform: PLATFORM.into(),
            message: format!("HTTP 403 Forbidden: {body}"),
            fix: "Your Fly API token lacks permission for this app. \
                  Verify the token has access to the target organization and app."
                .into(),
        },
        404 => SyncError::ApiError {
            platform: PLATFORM.into(),
            operation: operation.into(),
            message: format!("HTTP 404 Not Found: {body}"),
            fix: "Verify the app name is correct and exists in your Fly organization.".into(),
        },
        429 => SyncError::ApiError {
            platform: PLATFORM.into(),
            operation: operation.into(),
            message: "Rate limited by Fly API".into(),
            fix: "Wait a moment and retry. The Fly API has rate limits.".into(),
        },
        500..=599 => SyncError::ApiError {
            platform: PLATFORM.into(),
            operation: operation.into(),
            message: format!("HTTP {status}: {body}"),
            fix: "Fly API server error. Retry in a few moments.".into(),
        },
        _ => SyncError::ApiError {
            platform: PLATFORM.into(),
            operation: operation.into(),
            message: format!("HTTP {status}: {body}"),
            fix: "Check Fly API documentation for this error.".into(),
        },
    }
}

/// Map a reqwest transport error to a `SyncError`.
fn map_reqwest_error(err: &reqwest::Error) -> SyncError {
    if err.is_timeout() {
        return SyncError::ConnectionError {
            platform: PLATFORM.into(),
            message: format!("Request timed out: {err}"),
            fix: "Check your network connection and try again.".into(),
        };
    }
    if err.is_connect() {
        return SyncError::ConnectionError {
            platform: PLATFORM.into(),
            message: format!("Connection failed: {err}"),
            fix: "Check your network connection. Fly API is at api.machines.dev.".into(),
        };
    }
    SyncError::ConnectionError {
        platform: PLATFORM.into(),
        message: format!("{err}"),
        fix: "Check your network connection and try again.".into(),
    }
}

#[async_trait::async_trait]
impl FlyApi for FlyClient {
    async fn list_secrets(&self, app: &str) -> Result<Vec<SecretEntry>, SyncError> {
        let url = format!("{BASE_URL}/v1/apps/{app}/secrets");
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| map_reqwest_error(&e))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(map_http_error(status, &body, "list_secrets"));
        }

        // Fly returns an array of objects with "Label" and "Type" fields.
        let entries: Vec<serde_json::Value> =
            resp.json().await.map_err(|e| SyncError::ApiError {
                platform: PLATFORM.into(),
                operation: "list_secrets".into(),
                message: format!("Failed to parse response: {e}"),
                fix: "This may indicate a Fly API change. Check Fly API docs.".into(),
            })?;

        Ok(entries
            .into_iter()
            .filter_map(|v| {
                v.get("Label")
                    .and_then(|l| l.as_str())
                    .map(|l| SecretEntry {
                        label: l.to_string(),
                    })
            })
            .collect())
    }

    async fn set_secrets(&self, app: &str, secrets: &[(&str, &str)]) -> Result<(), SyncError> {
        let url = format!("{BASE_URL}/v1/apps/{app}/secrets");

        let body: Vec<serde_json::Value> = secrets
            .iter()
            .map(|(label, value)| {
                serde_json::json!({
                    "label": label,
                    "type": "opaque",
                    "value": value,
                })
            })
            .collect();

        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .map_err(|e| map_reqwest_error(&e))?;

        let status = resp.status();
        if !status.is_success() {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(map_http_error(status, &body_text, "set_secrets"));
        }

        Ok(())
    }

    async fn unset_secret(&self, app: &str, label: &str) -> Result<(), SyncError> {
        let url = format!("{BASE_URL}/v1/apps/{app}/secrets/{label}");
        let resp = self
            .http
            .delete(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| map_reqwest_error(&e))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(map_http_error(status, &body, "unset_secret"));
        }

        Ok(())
    }
}

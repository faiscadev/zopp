use std::time::Duration;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::SyncError;

const PLATFORM: &str = "Fly";
const BASE_URL: &str = "https://api.machines.dev";

/// Maximum number of retries for transient errors (429, 5xx).
const MAX_RETRIES: u32 = 3;

/// Base delay for exponential backoff (doubles each retry: 1s, 2s, 4s).
const BASE_BACKOFF_MS: u64 = 1000;

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

/// Sensitive token wrapper that is zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
struct ApiToken(String);

/// Real Fly API client using `reqwest`.
pub(crate) struct FlyClient {
    http: reqwest::Client,
    token: ApiToken,
}

impl FlyClient {
    pub fn new(token: String) -> Self {
        Self {
            http: reqwest::Client::new(),
            token: ApiToken(token),
        }
    }
}

/// Percent-encode a path segment for safe URL construction.
fn encode_path_segment(s: &str) -> String {
    // Encode everything except unreserved characters (RFC 3986)
    let mut encoded = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                encoded.push_str(&format!("%{byte:02X}"));
            }
        }
    }
    encoded
}

/// Check if an HTTP status code is retryable (429 rate limit or 5xx server error).
fn is_retryable(status: reqwest::StatusCode) -> bool {
    status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

/// Map an HTTP response status to a `SyncError`.
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

/// Send an HTTP request with retry logic for transient errors (429, 5xx).
/// Returns the response on success, or the last error on exhaustion.
async fn send_with_retry(
    builder_fn: impl Fn() -> reqwest::RequestBuilder,
) -> Result<reqwest::Response, SyncError> {
    let mut last_error = None;

    for attempt in 0..=MAX_RETRIES {
        let resp = builder_fn()
            .send()
            .await
            .map_err(|e| map_reqwest_error(&e))?;

        if resp.status().is_success() || !is_retryable(resp.status()) {
            return Ok(resp);
        }

        // Retryable error — save for potential final error, then backoff
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();

        if attempt < MAX_RETRIES {
            let delay = Duration::from_millis(BASE_BACKOFF_MS * 2u64.pow(attempt));
            tokio::time::sleep(delay).await;
        }

        last_error = Some((status, body));
    }

    // All retries exhausted
    let (status, body) = last_error.unwrap();
    Err(map_http_error(status, &body, "request"))
}

#[async_trait::async_trait]
impl FlyApi for FlyClient {
    async fn list_secrets(&self, app: &str) -> Result<Vec<SecretEntry>, SyncError> {
        let app_encoded = encode_path_segment(app);
        let url = format!("{BASE_URL}/v1/apps/{app_encoded}/secrets");

        let resp = send_with_retry(|| self.http.get(&url).bearer_auth(&self.token.0)).await?;

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
        let app_encoded = encode_path_segment(app);
        let url = format!("{BASE_URL}/v1/apps/{app_encoded}/secrets");

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

        let resp =
            send_with_retry(|| self.http.post(&url).bearer_auth(&self.token.0).json(&body)).await?;

        let status = resp.status();
        if !status.is_success() {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(map_http_error(status, &body_text, "set_secrets"));
        }

        Ok(())
    }

    async fn unset_secret(&self, app: &str, label: &str) -> Result<(), SyncError> {
        let app_encoded = encode_path_segment(app);
        let label_encoded = encode_path_segment(label);
        let url = format!("{BASE_URL}/v1/apps/{app_encoded}/secrets/{label_encoded}");

        let resp = send_with_retry(|| self.http.delete(&url).bearer_auth(&self.token.0)).await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(map_http_error(status, &body, "unset_secret"));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_path_segment_simple() {
        assert_eq!(encode_path_segment("myapp"), "myapp");
    }

    #[test]
    fn encode_path_segment_special_chars() {
        assert_eq!(encode_path_segment("my/app"), "my%2Fapp");
        assert_eq!(encode_path_segment("my app"), "my%20app");
    }

    #[test]
    fn encode_path_segment_preserves_unreserved() {
        assert_eq!(encode_path_segment("a-b_c.d~e"), "a-b_c.d~e");
    }

    #[test]
    fn is_retryable_429() {
        assert!(is_retryable(reqwest::StatusCode::TOO_MANY_REQUESTS));
    }

    #[test]
    fn is_retryable_500() {
        assert!(is_retryable(reqwest::StatusCode::INTERNAL_SERVER_ERROR));
    }

    #[test]
    fn is_retryable_502() {
        assert!(is_retryable(reqwest::StatusCode::BAD_GATEWAY));
    }

    #[test]
    fn not_retryable_400() {
        assert!(!is_retryable(reqwest::StatusCode::BAD_REQUEST));
    }

    #[test]
    fn not_retryable_401() {
        assert!(!is_retryable(reqwest::StatusCode::UNAUTHORIZED));
    }

    #[test]
    fn not_retryable_200() {
        assert!(!is_retryable(reqwest::StatusCode::OK));
    }
}

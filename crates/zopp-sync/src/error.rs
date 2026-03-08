use thiserror::Error;

/// Structured error type for sync operations.
///
/// Every variant includes actionable user instructions via the `fix` field.
/// Platform-specific API errors are mapped to these variants — raw API error
/// types are never exposed to the user.
#[derive(Debug, Error)]
pub enum SyncError {
    /// Platform credentials not found or invalid.
    #[error("Error: [{platform}] authentication — {message}")]
    AuthError {
        platform: String,
        message: String,
        fix: String,
    },

    /// API call failed (rate limit, permission, etc.).
    #[error("Error: [{platform}] {operation} — {message}")]
    ApiError {
        platform: String,
        operation: String,
        message: String,
        fix: String,
    },

    /// Network connectivity failure.
    #[error("Error: [{platform}] connection — {message}")]
    ConnectionError {
        platform: String,
        message: String,
        fix: String,
    },

    /// zopp-side error (can't fetch/decrypt secrets).
    #[error("Error: [zopp] source — {message}")]
    SourceError { message: String, fix: String },
}

impl SyncError {
    /// Returns the fix instruction for this error, if available.
    pub fn fix(&self) -> &str {
        match self {
            SyncError::AuthError { fix, .. }
            | SyncError::ApiError { fix, .. }
            | SyncError::ConnectionError { fix, .. }
            | SyncError::SourceError { fix, .. } => fix,
        }
    }

    /// Returns the platform name associated with this error.
    pub fn platform(&self) -> &str {
        match self {
            SyncError::AuthError { platform, .. }
            | SyncError::ApiError { platform, .. }
            | SyncError::ConnectionError { platform, .. } => platform,
            SyncError::SourceError { .. } => "zopp",
        }
    }

    /// Formats the error with the fix instruction on a second line.
    pub fn display_with_fix(&self) -> String {
        let fix = self.fix();
        if fix.is_empty() {
            format!("{self}")
        } else {
            format!("{self}\n  Fix: {fix}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_error_display() {
        let err = SyncError::AuthError {
            platform: "AWS Secrets Manager".into(),
            message: "credentials not found".into(),
            fix: "Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY".into(),
        };
        assert_eq!(
            err.to_string(),
            "Error: [AWS Secrets Manager] authentication — credentials not found"
        );
        assert_eq!(err.platform(), "AWS Secrets Manager");
        assert_eq!(err.fix(), "Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY");
    }

    #[test]
    fn api_error_display() {
        let err = SyncError::ApiError {
            platform: "Fly".into(),
            operation: "set secret".into(),
            message: "rate limited".into(),
            fix: "Wait and retry".into(),
        };
        assert_eq!(
            err.to_string(),
            "Error: [Fly] set secret — rate limited"
        );
    }

    #[test]
    fn connection_error_display() {
        let err = SyncError::ConnectionError {
            platform: "GCP".into(),
            message: "timeout".into(),
            fix: "Check your network connection".into(),
        };
        assert_eq!(err.to_string(), "Error: [GCP] connection — timeout");
        assert_eq!(err.fix(), "Check your network connection");
    }

    #[test]
    fn source_error_display() {
        let err = SyncError::SourceError {
            message: "failed to decrypt".into(),
            fix: "Check your principal keys".into(),
        };
        assert_eq!(err.to_string(), "Error: [zopp] source — failed to decrypt");
        assert_eq!(err.platform(), "zopp");
    }

    #[test]
    fn display_with_fix_includes_fix() {
        let err = SyncError::AuthError {
            platform: "AWS".into(),
            message: "no creds".into(),
            fix: "export AWS_ACCESS_KEY_ID=...".into(),
        };
        let output = err.display_with_fix();
        assert!(output.contains("Fix: export AWS_ACCESS_KEY_ID=..."));
    }

    #[test]
    fn display_with_fix_empty_fix() {
        let err = SyncError::SourceError {
            message: "something broke".into(),
            fix: String::new(),
        };
        let output = err.display_with_fix();
        assert!(!output.contains("Fix:"));
    }
}

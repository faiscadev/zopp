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
    ConnectionError { platform: String, message: String },

    /// zopp-side error (can't fetch/decrypt secrets).
    #[error("Error: [zopp] source — {message}")]
    SourceError { message: String },
}

impl SyncError {
    /// Returns the fix instruction for this error, if available.
    pub fn fix(&self) -> Option<&str> {
        match self {
            SyncError::AuthError { fix, .. } | SyncError::ApiError { fix, .. } => Some(fix),
            SyncError::ConnectionError { .. } | SyncError::SourceError { .. } => None,
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
        match self.fix() {
            Some(fix) => format!("{self}\n  Fix: {fix}"),
            None => format!("{self}"),
        }
    }
}

use std::collections::HashMap;

use serde::Serialize;

/// Type alias for a set of secrets (key-name → plaintext-value).
pub type SyncSecrets = HashMap<String, String>;

/// A single diff operation computed by the diff engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum DiffOperation {
    /// Secret exists in source but not in target.
    Add { key: String, value: String },
    /// Secret exists in both but with different values.
    Update {
        key: String,
        old_value: String,
        new_value: String,
    },
    /// Secret exists in target but not in source.
    Remove { key: String },
}

impl DiffOperation {
    /// Returns the secret key affected by this operation.
    pub fn key(&self) -> &str {
        match self {
            DiffOperation::Add { key, .. }
            | DiffOperation::Update { key, .. }
            | DiffOperation::Remove { key } => key,
        }
    }
}

/// The result of applying a single sync operation to one secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SyncResult {
    pub key: String,
    pub outcome: SyncOutcome,
}

/// Whether a single secret sync succeeded or failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum SyncOutcome {
    Success,
    Failed { reason: String },
}

/// Result of fetching current secrets from a target.
///
/// Contains successfully fetched secrets alongside any per-key errors
/// encountered during fetch. Fatal errors (auth, connection) are returned
/// as `Err(SyncError)` from `fetch_current` itself — only non-fatal
/// per-key errors appear here.
#[derive(Debug, Clone)]
pub struct FetchResult {
    /// Successfully fetched secrets (key → value).
    pub secrets: HashMap<String, String>,
    /// Per-key errors encountered during fetch (key, error description).
    pub errors: Vec<(String, String)>,
}

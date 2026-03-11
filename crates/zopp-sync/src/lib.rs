//! Sync framework for zopp — defines the `SyncTarget` trait, `DiffEngine`,
//! and shared types used by all sync target implementations.
//!
//! Each sync target (AWS, GCP, Fly, etc.) is gated behind a feature flag
//! and implements the [`SyncTarget`] trait.

#[cfg(feature = "aws")]
pub mod aws;
pub mod diff;
pub mod error;
#[cfg(feature = "fly")]
pub mod fly;
pub mod types;

pub use diff::diff;
pub use error::SyncError;
pub use types::*;

/// Trait implemented by each sync target (e.g., AWS Secrets Manager, Fly).
///
/// The CLI constructs a target with resolved credentials, then calls
/// `fetch_current()` to get the target's current state, runs the shared
/// diff engine, and calls `apply()` with the resulting operations.
#[async_trait::async_trait]
pub trait SyncTarget: Send + Sync {
    /// Human-readable name for output (e.g., "AWS Secrets Manager", "Fly").
    fn display_name(&self) -> &str;

    /// Fetch current secrets from the target platform.
    ///
    /// Returns a [`FetchResult`] containing successfully fetched secrets and
    /// any per-key errors. Fatal errors (auth, connection) are returned as
    /// `Err(SyncError)` — the caller decides how to handle partial failures.
    async fn fetch_current(&self) -> Result<FetchResult, SyncError>;

    /// Apply a set of diff operations to the target platform.
    ///
    /// Returns per-secret results — each secret gets its own success/failure
    /// status. Partial failures are expected and reported individually.
    async fn apply(&self, operations: &[DiffOperation]) -> Vec<SyncResult>;
}

//! Event bus abstraction for zopp secret change notifications.
//!
//! This crate defines the EventBus trait that allows different implementations
//! for event broadcasting across server replicas:
//! - Memory (single server, tokio broadcast channels)
//! - Redis (multi-server, Redis pub/sub)
//! - Postgres (multi-server, PostgreSQL LISTEN/NOTIFY)

use async_trait::async_trait;
use futures::Stream;
use serde::{Deserialize, Serialize};
use std::pin::Pin;
use thiserror::Error;
use zopp_storage::EnvironmentId;

/// Type of secret change event
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventType {
    Created,
    Updated,
    Deleted,
}

/// Event representing a change to a secret in an environment
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecretChangeEvent {
    pub event_type: EventType,
    pub key: String,
    pub version: i64,
    pub timestamp: i64,
}

/// Error type for event bus operations
#[derive(Debug, Error)]
pub enum EventBusError {
    #[error("backend error: {0}")]
    Backend(String),
}

/// Stream of secret change events
pub type EventStream = Pin<Box<dyn Stream<Item = SecretChangeEvent> + Send>>;

/// Event bus trait for publishing and subscribing to secret change events.
///
/// Implementations can be:
/// - In-memory (single server): tokio broadcast channels
/// - Redis: Redis pub/sub
/// - Postgres: PostgreSQL LISTEN/NOTIFY
#[async_trait]
pub trait EventBus: Send + Sync {
    /// Publish a secret change event to all watchers of this environment.
    ///
    /// This is called after a secret is created, updated, or deleted.
    /// The event is broadcast to all active subscribers for this environment.
    async fn publish(
        &self,
        env_id: &EnvironmentId,
        event: SecretChangeEvent,
    ) -> Result<(), EventBusError>;

    /// Subscribe to secret change events for an environment.
    ///
    /// Returns a stream that yields events as they occur.
    /// The stream will continue until dropped or the connection is closed.
    async fn subscribe(&self, env_id: &EnvironmentId) -> Result<EventStream, EventBusError>;
}

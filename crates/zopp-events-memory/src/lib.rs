//! In-memory event bus implementation using tokio broadcast channels.
//!
//! This implementation is suitable for:
//! - Single server deployments
//! - Development and testing
//! - Simple deployments that don't require horizontal scaling
//!
//! For multi-replica deployments, use Redis or Postgres event bus instead.

use async_trait::async_trait;
use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;
use zopp_events::{EventBus, EventBusError, EventStream, SecretChangeEvent};
use zopp_storage::EnvironmentId;

const CHANNEL_CAPACITY: usize = 100;

/// In-memory event bus using tokio broadcast channels.
///
/// Events are only broadcast within a single process.
/// If you have multiple server replicas, they will NOT receive each other's events.
pub struct MemoryEventBus {
    channels: Arc<DashMap<EnvironmentId, broadcast::Sender<SecretChangeEvent>>>,
}

impl MemoryEventBus {
    pub fn new() -> Self {
        Self {
            channels: Arc::new(DashMap::new()),
        }
    }

    /// Get or create a broadcast channel for an environment
    fn get_or_create_channel(
        &self,
        env_id: &EnvironmentId,
    ) -> broadcast::Sender<SecretChangeEvent> {
        self.channels
            .entry(env_id.clone())
            .or_insert_with(|| broadcast::channel(CHANNEL_CAPACITY).0)
            .clone()
    }
}

impl Default for MemoryEventBus {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EventBus for MemoryEventBus {
    async fn publish(
        &self,
        env_id: &EnvironmentId,
        event: SecretChangeEvent,
    ) -> Result<(), EventBusError> {
        let tx = self.get_or_create_channel(env_id);

        // Ignore error if no receivers (this is fine)
        let _ = tx.send(event);

        Ok(())
    }

    async fn subscribe(&self, env_id: &EnvironmentId) -> Result<EventStream, EventBusError> {
        let tx = self.get_or_create_channel(env_id);
        let rx = tx.subscribe();

        // Convert BroadcastStream to our EventStream type
        // Filter out lagged errors (happens when receiver can't keep up)
        // Client fell behind, they should do a full resync
        let stream = BroadcastStream::new(rx).filter_map(|result| result.ok());

        Ok(Box::pin(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;
    use uuid::Uuid;
    use zopp_events::EventType;
    use zopp_storage::EnvironmentId;

    #[tokio::test]
    async fn publish_and_subscribe() {
        let bus = MemoryEventBus::new();
        let env_id = EnvironmentId(Uuid::new_v4());

        // Subscribe first
        let mut stream = bus.subscribe(&env_id).await.unwrap();

        // Publish event
        let event = SecretChangeEvent {
            event_type: EventType::Created,
            key: "API_KEY".to_string(),
            version: 1,
            timestamp: 12345,
        };
        bus.publish(&env_id, event.clone()).await.unwrap();

        // Receive event
        let received = tokio::time::timeout(std::time::Duration::from_millis(100), stream.next())
            .await
            .expect("timeout")
            .expect("stream ended");

        assert_eq!(received.key, "API_KEY");
        assert_eq!(received.version, 1);
        assert_eq!(received.event_type, EventType::Created);
    }

    #[tokio::test]
    async fn multiple_subscribers() {
        let bus = MemoryEventBus::new();
        let env_id = EnvironmentId(Uuid::new_v4());

        // Multiple subscribers
        let mut stream1 = bus.subscribe(&env_id).await.unwrap();
        let mut stream2 = bus.subscribe(&env_id).await.unwrap();

        // Publish event
        let event = SecretChangeEvent {
            event_type: EventType::Updated,
            key: "SECRET".to_string(),
            version: 2,
            timestamp: 67890,
        };
        bus.publish(&env_id, event).await.unwrap();

        // Both should receive
        let recv1 = stream1.next().await.unwrap();
        let recv2 = stream2.next().await.unwrap();

        assert_eq!(recv1.key, "SECRET");
        assert_eq!(recv2.key, "SECRET");
    }

    #[tokio::test]
    async fn publish_before_subscribe_is_lost() {
        let bus = MemoryEventBus::new();
        let env_id = EnvironmentId(Uuid::new_v4());

        // Publish before subscribing
        let event = SecretChangeEvent {
            event_type: EventType::Deleted,
            key: "OLD".to_string(),
            version: 3,
            timestamp: 99999,
        };
        bus.publish(&env_id, event).await.unwrap();

        // Subscribe after - should not receive the old event
        let mut stream = bus.subscribe(&env_id).await.unwrap();

        // Should timeout (no event)
        let result =
            tokio::time::timeout(std::time::Duration::from_millis(50), stream.next()).await;

        assert!(
            result.is_err(),
            "Should not receive event published before subscription"
        );
    }
}

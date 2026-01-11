//! PostgreSQL event bus implementation using LISTEN/NOTIFY.
//!
//! This implementation is suitable for:
//! - Multi-replica deployments where events must be shared across servers
//! - Production environments using PostgreSQL as the primary database
//!
//! Events are broadcast via PostgreSQL's native pub/sub mechanism.
//! Each environment gets its own channel: `zopp_env_<uuid>`.

use async_trait::async_trait;
use futures::StreamExt;
use sqlx::postgres::{PgListener, PgPool};
use sqlx::Executor;
use zopp_events::{EventBus, EventBusError, EventStream, SecretChangeEvent};
use zopp_storage::EnvironmentId;

/// PostgreSQL event bus using LISTEN/NOTIFY.
///
/// Events are published via NOTIFY and received via LISTEN.
/// Each subscriber gets its own PgListener connection (required by PostgreSQL).
pub struct PostgresEventBus {
    pool: PgPool,
}

impl PostgresEventBus {
    /// Create a new PostgreSQL event bus.
    ///
    /// The pool is used for NOTIFY operations (publishing).
    /// Each subscriber will create its own connection for LISTEN.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Connect to a PostgreSQL database and create an event bus.
    pub async fn connect(database_url: &str) -> Result<Self, EventBusError> {
        let pool = PgPool::connect(database_url).await.map_err(|e| {
            EventBusError::Backend(format!("Failed to connect to PostgreSQL: {}", e))
        })?;
        Ok(Self::new(pool))
    }

    /// Get the channel name for an environment.
    ///
    /// PostgreSQL channel names cannot contain hyphens, so we replace them with underscores.
    fn channel_name(env_id: &EnvironmentId) -> String {
        format!("zopp_env_{}", env_id.0.to_string().replace('-', "_"))
    }
}

#[async_trait]
impl EventBus for PostgresEventBus {
    async fn publish(
        &self,
        env_id: &EnvironmentId,
        event: SecretChangeEvent,
    ) -> Result<(), EventBusError> {
        let channel = Self::channel_name(env_id);
        let payload = serde_json::to_string(&event)
            .map_err(|e| EventBusError::Backend(format!("Failed to serialize event: {}", e)))?;

        // Use pg_notify function for proper escaping
        self.pool
            .execute(
                sqlx::query("SELECT pg_notify($1, $2)")
                    .bind(&channel)
                    .bind(&payload),
            )
            .await
            .map_err(|e| EventBusError::Backend(format!("Failed to publish event: {}", e)))?;

        Ok(())
    }

    async fn subscribe(&self, env_id: &EnvironmentId) -> Result<EventStream, EventBusError> {
        let channel = Self::channel_name(env_id);

        // Each subscriber needs its own PgListener connection
        let mut listener = PgListener::connect_with(&self.pool)
            .await
            .map_err(|e| EventBusError::Backend(format!("Failed to create listener: {}", e)))?;

        listener
            .listen(&channel)
            .await
            .map_err(|e| EventBusError::Backend(format!("Failed to listen on channel: {}", e)))?;

        // Convert PgListener into a stream of SecretChangeEvent
        let stream = listener
            .into_stream()
            .filter_map(|notification| async move {
                notification
                    .ok()
                    .and_then(|n| serde_json::from_str::<SecretChangeEvent>(n.payload()).ok())
            });

        Ok(Box::pin(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;
    use uuid::Uuid;
    use zopp_events::EventType;

    // These tests require a running PostgreSQL instance on port 5433.
    // Start with: docker run --name zopp-test-pg -e POSTGRES_PASSWORD=postgres -p 5433:5432 -d postgres:16
    //
    // Or set TEST_DATABASE_URL to override the default.

    fn get_test_database_url() -> String {
        std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5433/postgres".to_string())
    }

    async fn connect_or_fail() -> PostgresEventBus {
        let url = get_test_database_url();
        PostgresEventBus::connect(&url)
            .await
            .unwrap_or_else(|e| panic!("PostgreSQL required at {}. Start with: docker run --name zopp-test-pg -e POSTGRES_PASSWORD=postgres -p 5433:5432 -d postgres:16. Error: {}", url, e))
    }

    #[tokio::test]
    async fn publish_and_subscribe() {
        let bus = connect_or_fail().await;
        let env_id = EnvironmentId(Uuid::new_v4());

        // Subscribe first
        let mut stream = bus.subscribe(&env_id).await.unwrap();

        // Give the listener time to set up
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Publish event
        let event = SecretChangeEvent {
            event_type: EventType::Created,
            key: "API_KEY".to_string(),
            version: 1,
            timestamp: 12345,
        };
        bus.publish(&env_id, event.clone()).await.unwrap();

        // Receive event
        let received = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
            .await
            .expect("timeout")
            .expect("stream ended");

        assert_eq!(received.key, "API_KEY");
        assert_eq!(received.version, 1);
        assert_eq!(received.event_type, EventType::Created);
    }

    #[tokio::test]
    async fn multiple_subscribers() {
        let bus = connect_or_fail().await;
        let env_id = EnvironmentId(Uuid::new_v4());

        // Multiple subscribers
        let mut stream1 = bus.subscribe(&env_id).await.unwrap();
        let mut stream2 = bus.subscribe(&env_id).await.unwrap();

        // Give the listeners time to set up
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Publish event
        let event = SecretChangeEvent {
            event_type: EventType::Updated,
            key: "SECRET".to_string(),
            version: 2,
            timestamp: 67890,
        };
        bus.publish(&env_id, event).await.unwrap();

        // Both should receive
        let recv1 = tokio::time::timeout(std::time::Duration::from_secs(5), stream1.next())
            .await
            .expect("timeout")
            .expect("stream ended");
        let recv2 = tokio::time::timeout(std::time::Duration::from_secs(5), stream2.next())
            .await
            .expect("timeout")
            .expect("stream ended");

        assert_eq!(recv1.key, "SECRET");
        assert_eq!(recv2.key, "SECRET");
    }

    #[tokio::test]
    async fn cross_environment_isolation() {
        let bus = connect_or_fail().await;
        let env_a = EnvironmentId(Uuid::new_v4());
        let env_b = EnvironmentId(Uuid::new_v4());

        // Subscribe to env_a only
        let mut stream_a = bus.subscribe(&env_a).await.unwrap();

        // Give the listener time to set up
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Publish to env_b (should NOT be received by stream_a)
        let event_b = SecretChangeEvent {
            event_type: EventType::Created,
            key: "ENV_B_SECRET".to_string(),
            version: 1,
            timestamp: 11111,
        };
        bus.publish(&env_b, event_b).await.unwrap();

        // Publish to env_a (should be received)
        let event_a = SecretChangeEvent {
            event_type: EventType::Created,
            key: "ENV_A_SECRET".to_string(),
            version: 1,
            timestamp: 22222,
        };
        bus.publish(&env_a, event_a).await.unwrap();

        // Should receive env_a event, not env_b
        let received = tokio::time::timeout(std::time::Duration::from_secs(5), stream_a.next())
            .await
            .expect("timeout")
            .expect("stream ended");

        assert_eq!(received.key, "ENV_A_SECRET");
    }

    #[test]
    fn channel_name_format() {
        let env_id =
            EnvironmentId(Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap());
        let channel = PostgresEventBus::channel_name(&env_id);
        assert_eq!(channel, "zopp_env_550e8400_e29b_41d4_a716_446655440000");
    }
}

//! Unit tests for server logic using real SQLite in-memory database.

use crate::backend::StoreBackend;
use crate::server::{extract_signature, ZoppServer};
use chrono::{Duration, Utc};
use ed25519_dalek::{Signer, SigningKey};
use prost::Message;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tonic::metadata::MetadataValue;
use tonic::Request;
use zopp_events_memory::MemoryEventBus;
use zopp_storage::*;
use zopp_store_sqlite::SqliteStore;

/// Test helper: Create a ZoppServer with in-memory SQLite
async fn create_test_server() -> ZoppServer {
    let store = Arc::new(SqliteStore::open_in_memory().await.unwrap());
    let events = Arc::new(MemoryEventBus::new());
    ZoppServer::new_sqlite(store, events)
}

/// Test helper: Generate a random Ed25519 keypair and return (public_key, private_key)
fn generate_keypair() -> (Vec<u8>, SigningKey) {
    let signing_key = SigningKey::generate(&mut rand_core::OsRng);
    let public_key = signing_key.verifying_key().to_bytes().to_vec();
    (public_key, signing_key)
}

/// Test helper: Generate a random X25519 keypair
fn generate_x25519_keypair() -> (Vec<u8>, [u8; 32]) {
    use rand_core::RngCore;
    let mut private_key = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut private_key);
    let secret = x25519_dalek::StaticSecret::from(private_key);
    let public = x25519_dalek::PublicKey::from(&secret);
    (public.as_bytes().to_vec(), private_key)
}

/// Test helper: Create a user with principal for testing
async fn create_test_user(
    server: &ZoppServer,
    email: &str,
    principal_name: &str,
) -> (UserId, PrincipalId, SigningKey) {
    let (public_key, signing_key) = generate_keypair();
    let (x25519_public, _) = generate_x25519_keypair();

    let (user_id, principal_id) = server
        .store
        .create_user(&CreateUserParams {
            email: email.to_string(),
            principal: Some(CreatePrincipalData {
                name: principal_name.to_string(),
                public_key,
                x25519_public_key: Some(x25519_public),
                is_service: false,
            }),
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    (user_id, principal_id.unwrap(), signing_key)
}

/// Test helper: Create a workspace owned by a user
async fn create_test_workspace(
    server: &ZoppServer,
    owner_user_id: &UserId,
    name: &str,
) -> WorkspaceId {
    let workspace_id = WorkspaceId(uuid::Uuid::now_v7());
    server
        .store
        .create_workspace(&CreateWorkspaceParams {
            id: workspace_id.clone(),
            name: name.to_string(),
            owner_user_id: owner_user_id.clone(),
            kdf_salt: vec![0u8; 16],
            m_cost_kib: 64 * 1024,
            t_cost: 3,
            p_cost: 1,
        })
        .await
        .unwrap();
    workspace_id
}

/// Test helper: Create a project in a workspace
async fn create_test_project(
    server: &ZoppServer,
    workspace_id: &WorkspaceId,
    name: &str,
) -> ProjectId {
    server
        .store
        .create_project(&CreateProjectParams {
            workspace_id: workspace_id.clone(),
            name: name.to_string(),
        })
        .await
        .unwrap()
}

/// Test helper: Create an environment in a project
async fn create_test_environment(
    server: &ZoppServer,
    project_id: &ProjectId,
    name: &str,
) -> EnvironmentId {
    server
        .store
        .create_env(&CreateEnvParams {
            project_id: project_id.clone(),
            name: name.to_string(),
            dek_wrapped: vec![0u8; 32],
            dek_nonce: vec![0u8; 24],
        })
        .await
        .unwrap()
}

/// Test helper: Create a signed request with proper authentication metadata
fn create_signed_request<T: Message + Default>(
    principal_id: &PrincipalId,
    signing_key: &SigningKey,
    method: &str,
    request_body: T,
) -> Request<T> {
    let body_bytes = request_body.encode_to_vec();
    let mut hasher = Sha256::new();
    hasher.update(method.as_bytes());
    hasher.update(&body_bytes);
    let request_hash = hasher.finalize().to_vec();

    let timestamp = Utc::now().timestamp();

    // Build message: method + hash + timestamp
    let mut message = Vec::new();
    message.extend_from_slice(method.as_bytes());
    message.extend_from_slice(&request_hash);
    message.extend_from_slice(&timestamp.to_le_bytes());

    let signature = signing_key.sign(&message);

    let mut request = Request::new(request_body);
    request.metadata_mut().insert(
        "principal-id",
        MetadataValue::try_from(principal_id.0.to_string()).unwrap(),
    );
    request.metadata_mut().insert(
        "timestamp",
        MetadataValue::try_from(timestamp.to_string()).unwrap(),
    );
    request.metadata_mut().insert(
        "signature",
        MetadataValue::try_from(hex::encode(signature.to_bytes())).unwrap(),
    );
    request.metadata_mut().insert(
        "request-hash",
        MetadataValue::try_from(hex::encode(&request_hash)).unwrap(),
    );

    request
}

// ================== extract_signature tests ==================

#[tokio::test]
async fn extract_signature_valid_metadata() {
    let principal_id = PrincipalId(uuid::Uuid::now_v7());
    let timestamp = Utc::now().timestamp();
    let signature = vec![0u8; 64];
    let request_hash = vec![1u8; 32];

    let mut request = Request::new(zopp_proto::Empty {});
    request.metadata_mut().insert(
        "principal-id",
        MetadataValue::try_from(principal_id.0.to_string()).unwrap(),
    );
    request.metadata_mut().insert(
        "timestamp",
        MetadataValue::try_from(timestamp.to_string()).unwrap(),
    );
    request.metadata_mut().insert(
        "signature",
        MetadataValue::try_from(hex::encode(&signature)).unwrap(),
    );
    request.metadata_mut().insert(
        "request-hash",
        MetadataValue::try_from(hex::encode(&request_hash)).unwrap(),
    );

    let (extracted_pid, extracted_ts, extracted_sig, extracted_hash) =
        extract_signature(&request).unwrap();

    assert_eq!(extracted_pid.0, principal_id.0);
    assert_eq!(extracted_ts, timestamp);
    assert_eq!(extracted_sig, signature);
    assert_eq!(extracted_hash, request_hash);
}

#[tokio::test]
async fn extract_signature_missing_principal_id() {
    let request = Request::new(zopp_proto::Empty {});
    let result = extract_signature(&request);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .message()
        .contains("Missing principal-id"));
}

#[tokio::test]
async fn extract_signature_invalid_principal_id_format() {
    let mut request = Request::new(zopp_proto::Empty {});
    request.metadata_mut().insert(
        "principal-id",
        MetadataValue::try_from("not-a-uuid").unwrap(),
    );
    let result = extract_signature(&request);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .message()
        .contains("Invalid principal-id"));
}

#[tokio::test]
async fn extract_signature_missing_timestamp() {
    let mut request = Request::new(zopp_proto::Empty {});
    request.metadata_mut().insert(
        "principal-id",
        MetadataValue::try_from(uuid::Uuid::now_v7().to_string()).unwrap(),
    );
    let result = extract_signature(&request);
    assert!(result.is_err());
    assert!(result.unwrap_err().message().contains("Missing timestamp"));
}

#[tokio::test]
async fn extract_signature_invalid_timestamp_format() {
    let mut request = Request::new(zopp_proto::Empty {});
    request.metadata_mut().insert(
        "principal-id",
        MetadataValue::try_from(uuid::Uuid::now_v7().to_string()).unwrap(),
    );
    request.metadata_mut().insert(
        "timestamp",
        MetadataValue::try_from("not-a-number").unwrap(),
    );
    let result = extract_signature(&request);
    assert!(result.is_err());
    assert!(result.unwrap_err().message().contains("Invalid timestamp"));
}

#[tokio::test]
async fn extract_signature_missing_signature() {
    let mut request = Request::new(zopp_proto::Empty {});
    request.metadata_mut().insert(
        "principal-id",
        MetadataValue::try_from(uuid::Uuid::now_v7().to_string()).unwrap(),
    );
    request
        .metadata_mut()
        .insert("timestamp", MetadataValue::try_from("12345").unwrap());
    let result = extract_signature(&request);
    assert!(result.is_err());
    assert!(result.unwrap_err().message().contains("Missing signature"));
}

#[tokio::test]
async fn extract_signature_invalid_signature_hex() {
    let mut request = Request::new(zopp_proto::Empty {});
    request.metadata_mut().insert(
        "principal-id",
        MetadataValue::try_from(uuid::Uuid::now_v7().to_string()).unwrap(),
    );
    request
        .metadata_mut()
        .insert("timestamp", MetadataValue::try_from("12345").unwrap());
    request
        .metadata_mut()
        .insert("signature", MetadataValue::try_from("not-hex!").unwrap());
    let result = extract_signature(&request);
    assert!(result.is_err());
    assert!(result.unwrap_err().message().contains("Invalid signature"));
}

#[tokio::test]
async fn extract_signature_missing_request_hash() {
    let mut request = Request::new(zopp_proto::Empty {});
    request.metadata_mut().insert(
        "principal-id",
        MetadataValue::try_from(uuid::Uuid::now_v7().to_string()).unwrap(),
    );
    request
        .metadata_mut()
        .insert("timestamp", MetadataValue::try_from("12345").unwrap());
    request.metadata_mut().insert(
        "signature",
        MetadataValue::try_from(hex::encode([0u8; 64])).unwrap(),
    );
    let result = extract_signature(&request);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .message()
        .contains("Missing request-hash"));
}

// ================== verify_signature_and_get_principal tests ==================

#[tokio::test]
async fn verify_signature_valid() {
    let server = create_test_server().await;
    let (_, principal_id, signing_key) =
        create_test_user(&server, "test@example.com", "laptop").await;

    let method = "/zopp.ZoppService/TestMethod";
    let request_body = zopp_proto::Empty {};
    let request = create_signed_request(&principal_id, &signing_key, method, request_body);

    // Extract values from request
    let (_, timestamp, signature, request_hash) = extract_signature(&request).unwrap();

    // Verify signature
    let principal = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature,
            method,
            &request_body,
            &request_hash,
        )
        .await
        .unwrap();

    assert_eq!(principal.id.0, principal_id.0);
}

#[tokio::test]
async fn verify_signature_timestamp_too_old() {
    let server = create_test_server().await;
    let (_, principal_id, signing_key) =
        create_test_user(&server, "test@example.com", "laptop").await;

    let method = "/zopp.ZoppService/TestMethod";
    let request_body = zopp_proto::Empty {};

    // Create a request with old timestamp
    let body_bytes = request_body.encode_to_vec();
    let mut hasher = Sha256::new();
    hasher.update(method.as_bytes());
    hasher.update(&body_bytes);
    let request_hash = hasher.finalize().to_vec();

    let old_timestamp = (Utc::now() - Duration::seconds(120)).timestamp();

    let mut message = Vec::new();
    message.extend_from_slice(method.as_bytes());
    message.extend_from_slice(&request_hash);
    message.extend_from_slice(&old_timestamp.to_le_bytes());
    let signature = signing_key.sign(&message);

    let result = server
        .verify_signature_and_get_principal(
            &principal_id,
            old_timestamp,
            &signature.to_bytes(),
            method,
            &request_body,
            &request_hash,
        )
        .await;

    assert!(result.is_err());
    assert!(result.unwrap_err().message().contains("too old"));
}

#[tokio::test]
async fn verify_signature_timestamp_too_future() {
    let server = create_test_server().await;
    let (_, principal_id, signing_key) =
        create_test_user(&server, "test@example.com", "laptop").await;

    let method = "/zopp.ZoppService/TestMethod";
    let request_body = zopp_proto::Empty {};

    let body_bytes = request_body.encode_to_vec();
    let mut hasher = Sha256::new();
    hasher.update(method.as_bytes());
    hasher.update(&body_bytes);
    let request_hash = hasher.finalize().to_vec();

    let future_timestamp = (Utc::now() + Duration::seconds(120)).timestamp();

    let mut message = Vec::new();
    message.extend_from_slice(method.as_bytes());
    message.extend_from_slice(&request_hash);
    message.extend_from_slice(&future_timestamp.to_le_bytes());
    let signature = signing_key.sign(&message);

    let result = server
        .verify_signature_and_get_principal(
            &principal_id,
            future_timestamp,
            &signature.to_bytes(),
            method,
            &request_body,
            &request_hash,
        )
        .await;

    assert!(result.is_err());
    assert!(result.unwrap_err().message().contains("future"));
}

#[tokio::test]
async fn verify_signature_hash_mismatch() {
    let server = create_test_server().await;
    let (_, principal_id, signing_key) =
        create_test_user(&server, "test@example.com", "laptop").await;

    let method = "/zopp.ZoppService/TestMethod";
    let request_body = zopp_proto::Empty {};

    // Provide wrong hash
    let wrong_hash = vec![0u8; 32];
    let timestamp = Utc::now().timestamp();

    let mut message = Vec::new();
    message.extend_from_slice(method.as_bytes());
    message.extend_from_slice(&wrong_hash);
    message.extend_from_slice(&timestamp.to_le_bytes());
    let signature = signing_key.sign(&message);

    let result = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature.to_bytes(),
            method,
            &request_body,
            &wrong_hash,
        )
        .await;

    assert!(result.is_err());
    assert!(result.unwrap_err().message().contains("hash mismatch"));
}

#[tokio::test]
async fn verify_signature_invalid_principal() {
    let server = create_test_server().await;
    let fake_principal_id = PrincipalId(uuid::Uuid::now_v7());
    let signing_key = SigningKey::generate(&mut rand_core::OsRng);

    let method = "/zopp.ZoppService/TestMethod";
    let request_body = zopp_proto::Empty {};

    let body_bytes = request_body.encode_to_vec();
    let mut hasher = Sha256::new();
    hasher.update(method.as_bytes());
    hasher.update(&body_bytes);
    let request_hash = hasher.finalize().to_vec();

    let timestamp = Utc::now().timestamp();

    let mut message = Vec::new();
    message.extend_from_slice(method.as_bytes());
    message.extend_from_slice(&request_hash);
    message.extend_from_slice(&timestamp.to_le_bytes());
    let signature = signing_key.sign(&message);

    let result = server
        .verify_signature_and_get_principal(
            &fake_principal_id,
            timestamp,
            &signature.to_bytes(),
            method,
            &request_body,
            &request_hash,
        )
        .await;

    assert!(result.is_err());
    assert!(result.unwrap_err().message().contains("Invalid principal"));
}

#[tokio::test]
async fn verify_signature_wrong_key() {
    let server = create_test_server().await;
    let (_, principal_id, _) = create_test_user(&server, "test@example.com", "laptop").await;

    // Use a different signing key
    let wrong_signing_key = SigningKey::generate(&mut rand_core::OsRng);

    let method = "/zopp.ZoppService/TestMethod";
    let request_body = zopp_proto::Empty {};

    let body_bytes = request_body.encode_to_vec();
    let mut hasher = Sha256::new();
    hasher.update(method.as_bytes());
    hasher.update(&body_bytes);
    let request_hash = hasher.finalize().to_vec();

    let timestamp = Utc::now().timestamp();

    let mut message = Vec::new();
    message.extend_from_slice(method.as_bytes());
    message.extend_from_slice(&request_hash);
    message.extend_from_slice(&timestamp.to_le_bytes());
    let signature = wrong_signing_key.sign(&message);

    let result = server
        .verify_signature_and_get_principal(
            &principal_id,
            timestamp,
            &signature.to_bytes(),
            method,
            &request_body,
            &request_hash,
        )
        .await;

    assert!(result.is_err());
    assert!(result.unwrap_err().message().contains("Invalid signature"));
}

// ================== Permission checking tests ==================

#[tokio::test]
async fn check_permission_workspace_owner_has_admin() {
    let server = create_test_server().await;
    let (user_id, principal_id, _) = create_test_user(&server, "owner@example.com", "laptop").await;
    let workspace_id = create_test_workspace(&server, &user_id, "my-workspace").await;
    let project_id = create_test_project(&server, &workspace_id, "my-project").await;
    let env_id = create_test_environment(&server, &project_id, "production").await;

    // Owner should have Admin access even without explicit permissions
    let result = server
        .check_permission(
            &principal_id,
            &workspace_id,
            &project_id,
            &env_id,
            Role::Admin,
        )
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn check_permission_user_permission_read() {
    let server = create_test_server().await;

    // Create owner
    let (owner_user_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
    let workspace_id = create_test_workspace(&server, &owner_user_id, "my-workspace").await;
    let project_id = create_test_project(&server, &workspace_id, "my-project").await;
    let env_id = create_test_environment(&server, &project_id, "production").await;

    // Create another user with Read permission
    let (other_user_id, other_principal_id, _) =
        create_test_user(&server, "other@example.com", "phone").await;

    // Add user to workspace
    server
        .store
        .add_user_to_workspace(&workspace_id, &other_user_id)
        .await
        .unwrap();

    // Grant user Read permission on environment
    server
        .store
        .set_user_environment_permission(&env_id, &other_user_id, Role::Read)
        .await
        .unwrap();

    // Check Read permission - should succeed
    let result = server
        .check_permission(
            &other_principal_id,
            &workspace_id,
            &project_id,
            &env_id,
            Role::Read,
        )
        .await;
    assert!(result.is_ok());

    // Check Write permission - should fail
    let result = server
        .check_permission(
            &other_principal_id,
            &workspace_id,
            &project_id,
            &env_id,
            Role::Write,
        )
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn check_permission_user_permission_write() {
    let server = create_test_server().await;

    // Create owner
    let (owner_user_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
    let workspace_id = create_test_workspace(&server, &owner_user_id, "my-workspace").await;
    let project_id = create_test_project(&server, &workspace_id, "my-project").await;
    let env_id = create_test_environment(&server, &project_id, "production").await;

    // Create another user with Write permission
    let (other_user_id, other_principal_id, _) =
        create_test_user(&server, "other@example.com", "phone").await;

    server
        .store
        .add_user_to_workspace(&workspace_id, &other_user_id)
        .await
        .unwrap();
    server
        .store
        .set_user_environment_permission(&env_id, &other_user_id, Role::Write)
        .await
        .unwrap();

    // Check Write permission - should succeed
    let result = server
        .check_permission(
            &other_principal_id,
            &workspace_id,
            &project_id,
            &env_id,
            Role::Write,
        )
        .await;
    assert!(result.is_ok());

    // Check Read permission - should also succeed (Write includes Read)
    let result = server
        .check_permission(
            &other_principal_id,
            &workspace_id,
            &project_id,
            &env_id,
            Role::Read,
        )
        .await;
    assert!(result.is_ok());

    // Check Admin permission - should fail
    let result = server
        .check_permission(
            &other_principal_id,
            &workspace_id,
            &project_id,
            &env_id,
            Role::Admin,
        )
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn check_permission_no_permission_denied() {
    let server = create_test_server().await;

    // Create owner
    let (owner_user_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
    let workspace_id = create_test_workspace(&server, &owner_user_id, "my-workspace").await;
    let project_id = create_test_project(&server, &workspace_id, "my-project").await;
    let env_id = create_test_environment(&server, &project_id, "production").await;

    // Create another user without any permissions
    let (_, other_principal_id, _) = create_test_user(&server, "other@example.com", "phone").await;

    // Should be denied
    let result = server
        .check_permission(
            &other_principal_id,
            &workspace_id,
            &project_id,
            &env_id,
            Role::Read,
        )
        .await;
    assert!(result.is_err());
    assert!(result.unwrap_err().message().contains("No permissions"));
}

#[tokio::test]
async fn check_permission_workspace_level_inherits() {
    let server = create_test_server().await;

    // Create owner
    let (owner_user_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
    let workspace_id = create_test_workspace(&server, &owner_user_id, "my-workspace").await;
    let project_id = create_test_project(&server, &workspace_id, "my-project").await;
    let env_id = create_test_environment(&server, &project_id, "production").await;

    // Create another user with workspace-level Write
    let (other_user_id, other_principal_id, _) =
        create_test_user(&server, "other@example.com", "phone").await;

    server
        .store
        .add_user_to_workspace(&workspace_id, &other_user_id)
        .await
        .unwrap();
    server
        .store
        .set_user_workspace_permission(&workspace_id, &other_user_id, Role::Write)
        .await
        .unwrap();

    // Workspace Write should inherit to environment
    let result = server
        .check_permission(
            &other_principal_id,
            &workspace_id,
            &project_id,
            &env_id,
            Role::Write,
        )
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn check_permission_principal_restricts_user() {
    let server = create_test_server().await;

    // Create owner
    let (owner_user_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
    let workspace_id = create_test_workspace(&server, &owner_user_id, "my-workspace").await;
    let project_id = create_test_project(&server, &workspace_id, "my-project").await;
    let env_id = create_test_environment(&server, &project_id, "production").await;

    // Create user with workspace-level Admin
    let (other_user_id, other_principal_id, _) =
        create_test_user(&server, "other@example.com", "phone").await;

    server
        .store
        .add_user_to_workspace(&workspace_id, &other_user_id)
        .await
        .unwrap();
    server
        .store
        .set_user_workspace_permission(&workspace_id, &other_user_id, Role::Admin)
        .await
        .unwrap();

    // Grant principal only Read (this should RESTRICT the effective permission)
    server
        .store
        .set_workspace_permission(&workspace_id, &other_principal_id, Role::Read)
        .await
        .unwrap();

    // Should only have Read despite user having Admin
    // (principal permission acts as ceiling)
    let result = server
        .check_permission(
            &other_principal_id,
            &workspace_id,
            &project_id,
            &env_id,
            Role::Write,
        )
        .await;
    assert!(result.is_err());

    // Read should work
    let result = server
        .check_permission(
            &other_principal_id,
            &workspace_id,
            &project_id,
            &env_id,
            Role::Read,
        )
        .await;
    assert!(result.is_ok());
}

// ================== Service account permission tests ==================

#[tokio::test]
async fn check_permission_service_account_with_permission() {
    let server = create_test_server().await;

    // Create owner
    let (owner_user_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
    let workspace_id = create_test_workspace(&server, &owner_user_id, "my-workspace").await;
    let project_id = create_test_project(&server, &workspace_id, "my-project").await;
    let env_id = create_test_environment(&server, &project_id, "production").await;

    // Create service principal (no user_id)
    let (public_key, _) = generate_keypair();
    let (x25519_public, _) = generate_x25519_keypair();
    let service_principal_id = server
        .store
        .create_principal(&CreatePrincipalParams {
            user_id: None,
            name: "ci-service".to_string(),
            public_key,
            x25519_public_key: Some(x25519_public),
        })
        .await
        .unwrap();

    // Add service principal to workspace
    server
        .store
        .add_workspace_principal(&AddWorkspacePrincipalParams {
            workspace_id: workspace_id.clone(),
            principal_id: service_principal_id.clone(),
            ephemeral_pub: vec![0u8; 32],
            kek_wrapped: vec![0u8; 32],
            kek_nonce: vec![0u8; 24],
        })
        .await
        .unwrap();

    // Grant service principal Write permission
    server
        .store
        .set_workspace_permission(&workspace_id, &service_principal_id, Role::Write)
        .await
        .unwrap();

    // Should have Write access
    let result = server
        .check_permission(
            &service_principal_id,
            &workspace_id,
            &project_id,
            &env_id,
            Role::Write,
        )
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn check_permission_service_account_without_permission() {
    let server = create_test_server().await;

    // Create owner
    let (owner_user_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
    let workspace_id = create_test_workspace(&server, &owner_user_id, "my-workspace").await;
    let project_id = create_test_project(&server, &workspace_id, "my-project").await;
    let env_id = create_test_environment(&server, &project_id, "production").await;

    // Create service principal without any permissions
    let (public_key, _) = generate_keypair();
    let (x25519_public, _) = generate_x25519_keypair();
    let service_principal_id = server
        .store
        .create_principal(&CreatePrincipalParams {
            user_id: None,
            name: "ci-service".to_string(),
            public_key,
            x25519_public_key: Some(x25519_public),
        })
        .await
        .unwrap();

    // Should be denied
    let result = server
        .check_permission(
            &service_principal_id,
            &workspace_id,
            &project_id,
            &env_id,
            Role::Read,
        )
        .await;
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .message()
        .contains("No permissions found for service account"));
}

// ================== check_workspace_permission tests ==================

#[tokio::test]
async fn check_workspace_permission_owner() {
    let server = create_test_server().await;
    let (user_id, principal_id, _) = create_test_user(&server, "owner@example.com", "laptop").await;
    let workspace_id = create_test_workspace(&server, &user_id, "my-workspace").await;

    let result = server
        .check_workspace_permission(&principal_id, &workspace_id, Role::Admin)
        .await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn check_workspace_permission_user_with_permission() {
    let server = create_test_server().await;

    let (owner_user_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
    let workspace_id = create_test_workspace(&server, &owner_user_id, "my-workspace").await;

    let (other_user_id, other_principal_id, _) =
        create_test_user(&server, "other@example.com", "phone").await;

    server
        .store
        .add_user_to_workspace(&workspace_id, &other_user_id)
        .await
        .unwrap();
    server
        .store
        .set_user_workspace_permission(&workspace_id, &other_user_id, Role::Write)
        .await
        .unwrap();

    let result = server
        .check_workspace_permission(&other_principal_id, &workspace_id, Role::Write)
        .await;
    assert!(result.is_ok());
}

// ================== Group permission tests ==================

#[tokio::test]
async fn check_permission_via_group() {
    let server = create_test_server().await;

    // Create owner and workspace
    let (owner_user_id, _, _) = create_test_user(&server, "owner@example.com", "laptop").await;
    let workspace_id = create_test_workspace(&server, &owner_user_id, "my-workspace").await;
    let project_id = create_test_project(&server, &workspace_id, "my-project").await;
    let env_id = create_test_environment(&server, &project_id, "production").await;

    // Create a group
    let group_id = server
        .store
        .create_group(&CreateGroupParams {
            workspace_id: workspace_id.clone(),
            name: "developers".to_string(),
            description: Some("Dev team".to_string()),
        })
        .await
        .unwrap();

    // Create user and add to group
    let (other_user_id, other_principal_id, _) =
        create_test_user(&server, "other@example.com", "phone").await;
    server
        .store
        .add_user_to_workspace(&workspace_id, &other_user_id)
        .await
        .unwrap();
    server
        .store
        .add_group_member(&group_id, &other_user_id)
        .await
        .unwrap();

    // Grant group Write permission on environment
    server
        .store
        .set_group_environment_permission(&env_id, &group_id, Role::Write)
        .await
        .unwrap();

    // User should have Write permission via group
    let result = server
        .check_permission(
            &other_principal_id,
            &workspace_id,
            &project_id,
            &env_id,
            Role::Write,
        )
        .await;
    assert!(result.is_ok());
}

// ================== Join flow tests ==================

#[tokio::test]
async fn test_server_invite_joins_user_without_creating_workspace() {
    use zopp_proto::zopp_service_server::ZoppService;
    use zopp_proto::JoinRequest;

    let server = create_test_server().await;

    // Create a server invite (no workspaces)
    let mut invite_secret = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut invite_secret);
    let secret_hash = zopp_crypto::hash_sha256(&invite_secret);
    let invite = server
        .store
        .create_invite(&CreateInviteParams {
            workspace_ids: vec![],
            token: hex::encode(secret_hash),
            kek_encrypted: None,
            kek_nonce: None,
            expires_at: Utc::now() + chrono::Duration::hours(24),
            created_by_user_id: None,
        })
        .await
        .unwrap();

    // Generate keypair for join
    let (public_key, _signing_key) = generate_keypair();
    let (x25519_public_key, _) = generate_x25519_keypair();

    // Join using server invite
    let request = tonic::Request::new(JoinRequest {
        invite_token: invite.token.clone(),
        email: "test@example.com".to_string(),
        principal_name: "test-laptop".to_string(),
        public_key,
        x25519_public_key,
        ephemeral_pub: vec![],
        kek_wrapped: vec![],
        kek_nonce: vec![],
    });

    let response = server.join(request).await.unwrap().into_inner();

    assert!(!response.user_id.is_empty());
    assert!(!response.principal_id.is_empty());
    assert_eq!(
        response.workspaces.len(),
        0,
        "No workspaces should be created automatically"
    );

    let user_id = UserId(uuid::Uuid::parse_str(&response.user_id).unwrap());

    let workspaces = server.store.list_workspaces(&user_id).await.unwrap();
    assert_eq!(
        workspaces.len(),
        0,
        "User should not have access to any workspaces yet"
    );
}

// ================== StoreBackend tests ==================

#[tokio::test]
async fn store_backend_create_user() {
    let store = Arc::new(SqliteStore::open_in_memory().await.unwrap());
    let backend = StoreBackend::Sqlite(store);

    let (public_key, _) = generate_keypair();
    let (x25519_public, _) = generate_x25519_keypair();

    let (user_id, principal_id) = backend
        .create_user(&CreateUserParams {
            email: "test@example.com".to_string(),
            principal: Some(CreatePrincipalData {
                name: "laptop".to_string(),
                public_key,
                x25519_public_key: Some(x25519_public),
                is_service: false,
            }),
            workspace_ids: vec![],
        })
        .await
        .unwrap();

    // Verify user was created
    let user = backend.get_user_by_id(&user_id).await.unwrap();
    assert_eq!(user.email, "test@example.com");

    // Verify principal was created
    let principal = backend.get_principal(&principal_id.unwrap()).await.unwrap();
    assert_eq!(principal.name, "laptop");
}

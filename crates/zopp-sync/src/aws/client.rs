use crate::SyncError;

/// Internal entry representing a secret listed from AWS Secrets Manager.
pub(crate) struct SecretEntry {
    pub name: String,
}

/// Thin abstraction over the AWS Secrets Manager API.
///
/// This trait is internal to the `aws` module and exists solely for testability.
/// The real implementation wraps the AWS SDK client; tests provide a mock.
#[async_trait::async_trait]
pub(crate) trait SecretsManagerApi: Send + Sync {
    /// List all secrets, optionally filtering by name prefix.
    async fn list_secrets(&self, prefix: Option<&str>) -> Result<Vec<SecretEntry>, SyncError>;

    /// Get the plaintext value of a single secret by name/ARN.
    async fn get_secret_value(&self, id: &str) -> Result<String, SyncError>;

    /// Create a new secret with the given name and string value.
    async fn create_secret(&self, name: &str, value: &str) -> Result<(), SyncError>;

    /// Update an existing secret's value.
    async fn put_secret_value(&self, id: &str, value: &str) -> Result<(), SyncError>;

    /// Delete a secret (force delete, no recovery window).
    async fn delete_secret(&self, id: &str) -> Result<(), SyncError>;
}

/// Real AWS SDK client wrapper.
pub(crate) struct AwsClient {
    client: aws_sdk_secretsmanager::Client,
}

impl AwsClient {
    pub fn new(client: aws_sdk_secretsmanager::Client) -> Self {
        Self { client }
    }
}

const PLATFORM: &str = "AWS Secrets Manager";

/// Map an AWS SDK error to a `SyncError`.
fn map_sdk_error<E: std::fmt::Display>(
    err: aws_sdk_secretsmanager::error::SdkError<E>,
    operation: &str,
) -> SyncError {
    let message = format!("{err}");

    // Check for auth-related errors in the message
    if message.contains("AccessDeniedException")
        || message.contains("UnrecognizedClientException")
        || message.contains("InvalidClientTokenId")
        || message.contains("SignatureDoesNotMatch")
        || message.contains("No credentials in the property bag")
        || message.contains("failed to load credentials")
    {
        return SyncError::AuthError {
            platform: PLATFORM.into(),
            message,
            fix: "Check AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables, \
                  configure ~/.aws/credentials, or ensure EC2/ECS instance metadata is available."
                .into(),
        };
    }

    // Check for connectivity errors
    if message.contains("dispatch failure")
        || message.contains("timeout")
        || message.contains("connection")
    {
        return SyncError::ConnectionError {
            platform: PLATFORM.into(),
            message,
            fix: "Check your network connection and verify the AWS region is correct.".into(),
        };
    }

    SyncError::ApiError {
        platform: PLATFORM.into(),
        operation: operation.into(),
        message,
        fix: "Check IAM permissions for the Secrets Manager actions.".into(),
    }
}

#[async_trait::async_trait]
impl SecretsManagerApi for AwsClient {
    async fn list_secrets(&self, prefix: Option<&str>) -> Result<Vec<SecretEntry>, SyncError> {
        let mut entries = Vec::new();

        let mut builder = self.client.list_secrets();
        if let Some(pfx) = prefix {
            builder = builder.filters(
                aws_sdk_secretsmanager::types::Filter::builder()
                    .key(aws_sdk_secretsmanager::types::FilterNameStringType::Name)
                    .values(pfx)
                    .build(),
            );
        }

        let mut paginator = builder.into_paginator().send();

        while let Some(page) = paginator.next().await {
            let page = page.map_err(|e| map_sdk_error(e, "list_secrets"))?;
            for secret in page.secret_list() {
                let name: &str = match secret.name() {
                    Some(n) => n,
                    None => continue,
                };
                entries.push(SecretEntry {
                    name: name.to_string(),
                });
            }
        }

        Ok(entries)
    }

    async fn get_secret_value(&self, id: &str) -> Result<String, SyncError> {
        let resp = self
            .client
            .get_secret_value()
            .secret_id(id)
            .send()
            .await
            .map_err(|e| map_sdk_error(e, "get_secret_value"))?;

        resp.secret_string()
            .map(|s| s.to_string())
            .ok_or_else(|| SyncError::ApiError {
                platform: PLATFORM.into(),
                operation: "get_secret_value".into(),
                message: format!("Secret '{id}' is binary, not a string secret"),
                fix: "zopp only supports string secrets. Convert the secret to a string value."
                    .into(),
            })
    }

    async fn create_secret(&self, name: &str, value: &str) -> Result<(), SyncError> {
        self.client
            .create_secret()
            .name(name)
            .secret_string(value)
            .send()
            .await
            .map_err(|e| map_sdk_error(e, "create_secret"))?;
        Ok(())
    }

    async fn put_secret_value(&self, id: &str, value: &str) -> Result<(), SyncError> {
        self.client
            .put_secret_value()
            .secret_id(id)
            .secret_string(value)
            .send()
            .await
            .map_err(|e| map_sdk_error(e, "put_secret_value"))?;
        Ok(())
    }

    async fn delete_secret(&self, id: &str) -> Result<(), SyncError> {
        self.client
            .delete_secret()
            .secret_id(id)
            .force_delete_without_recovery(true)
            .send()
            .await
            .map_err(|e| map_sdk_error(e, "delete_secret"))?;
        Ok(())
    }
}

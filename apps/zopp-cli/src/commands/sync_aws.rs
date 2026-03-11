use std::collections::HashMap;

use crate::crypto::fetch_and_decrypt_secrets;
use crate::grpc::setup_client;
use crate::output::{
    diff_item, diff_summary, error_block, exit_codes, header, output_json, per_item_failure,
    per_item_success, summary, DiffJsonChange, DiffJsonOutput, DiffJsonSummary, SyncCommonArgs,
    SyncJsonOutput, SyncJsonResult, SyncJsonSummary,
};
use zopp_sync::aws::AwsSyncTarget;
use zopp_sync::{DiffOperation, SyncOutcome, SyncTarget};

pub async fn cmd_sync_aws(
    server: &str,
    tls_ca_cert: Option<&std::path::Path>,
    common: &SyncCommonArgs,
    region: &str,
    prefix: Option<&str>,
) -> i32 {
    let config = common.to_output_config();

    // 1. Resolve workspace/project/environment
    let (workspace, project, environment) = match crate::config::resolve_context(
        common.workspace.as_ref(),
        common.project.as_ref(),
        common.environment.as_ref(),
    ) {
        Ok(ctx) => ctx,
        Err(e) => {
            error_block(
                &config,
                "zopp config",
                &e.to_string(),
                "Check zopp.toml or pass -w, -p, -e flags",
            );
            return exit_codes::CONFIG_ERROR;
        }
    };

    // 2. Fetch and decrypt zopp secrets
    let (mut client, principal, secrets) = match setup_client(server, tls_ca_cert).await {
        Ok(c) => c,
        Err(e) => {
            error_block(
                &config,
                "zopp connection",
                &e.to_string(),
                "Check server address and credentials",
            );
            return exit_codes::CONNECTION_ERROR;
        }
    };

    let zopp_secrets = match fetch_and_decrypt_secrets(
        &mut client,
        &principal,
        &secrets,
        &workspace,
        &project,
        &environment,
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            error_block(
                &config,
                "zopp secrets",
                &e.to_string(),
                "Verify workspace, project, and environment exist",
            );
            return exit_codes::CONFIG_ERROR;
        }
    };

    let source_label = format!("zopp/{workspace}/{project}/{environment}");
    let zopp_map: HashMap<String, String> = zopp_secrets.into_iter().collect();

    // 3. Create AWS sync target
    let target = match AwsSyncTarget::new(region, prefix.map(String::from)).await {
        Ok(t) => t,
        Err(e) => {
            error_block(&config, e.platform(), &e.to_string(), e.fix());
            return match &e {
                zopp_sync::SyncError::AuthError { .. } => exit_codes::CONFIG_ERROR,
                zopp_sync::SyncError::ConnectionError { .. } => exit_codes::CONNECTION_ERROR,
                _ => exit_codes::TOTAL_FAILURE,
            };
        }
    };

    let target_label = target.display_name().to_string();

    // 4. Fetch current state from AWS
    let fetch_result = match target.fetch_current().await {
        Ok(s) => s,
        Err(e) => {
            error_block(&config, e.platform(), &e.to_string(), e.fix());
            return match &e {
                zopp_sync::SyncError::AuthError { .. } => exit_codes::CONFIG_ERROR,
                zopp_sync::SyncError::ConnectionError { .. } => exit_codes::CONNECTION_ERROR,
                _ => exit_codes::TOTAL_FAILURE,
            };
        }
    };

    // Report per-key fetch errors
    for (key, err) in &fetch_result.errors {
        error_block(
            &config,
            "AWS Secrets Manager",
            &format!("Failed to fetch secret '{key}': {err}"),
            "Check secret permissions in AWS",
        );
    }

    // 5. Compute diff
    let operations = zopp_sync::diff(&zopp_map, &fetch_result.secrets);

    // 6. Dry-run or no changes: show diff output
    if common.dry_run || operations.is_empty() {
        header(&config, "Diff", &source_label, &target_label);

        let mut adds = 0usize;
        let mut updates = 0usize;
        let mut removes = 0usize;

        for op in &operations {
            match op {
                DiffOperation::Add { .. } => {
                    diff_item(&config, '+', op.key());
                    adds += 1;
                }
                DiffOperation::Update { .. } => {
                    diff_item(&config, '~', op.key());
                    updates += 1;
                }
                DiffOperation::Remove { .. } => {
                    diff_item(&config, '-', op.key());
                    removes += 1;
                }
            }
        }

        diff_summary(&config, adds, updates, removes);

        if config.json {
            let command = if common.dry_run {
                "sync --dry-run"
            } else {
                "sync"
            };
            let json_output = DiffJsonOutput {
                command: command.into(),
                target: target_label,
                source: source_label,
                changes: operations
                    .iter()
                    .map(|op| DiffJsonChange {
                        key: op.key().to_string(),
                        operation: match op {
                            DiffOperation::Add { .. } => "add",
                            DiffOperation::Update { .. } => "update",
                            DiffOperation::Remove { .. } => "remove",
                        }
                        .into(),
                    })
                    .collect(),
                summary: DiffJsonSummary {
                    adds,
                    updates,
                    removes,
                    total: adds + updates + removes,
                },
            };
            output_json(&json_output);
        }

        return exit_codes::SUCCESS;
    }

    // 7. Apply changes
    header(&config, "Syncing", &source_label, &target_label);

    let results = target.apply(&operations).await;
    let total = results.len();
    let mut succeeded = 0usize;
    let mut failed = 0usize;

    let mut json_results = Vec::new();

    for result in &results {
        match &result.outcome {
            SyncOutcome::Success => {
                succeeded += 1;
                let action = operation_action(&operations, &result.key);
                per_item_success(&config, &result.key, action);
                if config.json {
                    json_results.push(SyncJsonResult {
                        key: result.key.clone(),
                        status: "synced".into(),
                        error: None,
                        fix: None,
                    });
                }
            }
            SyncOutcome::Failed { reason } => {
                failed += 1;
                per_item_failure(&config, &result.key, reason, None);
                if config.json {
                    json_results.push(SyncJsonResult {
                        key: result.key.clone(),
                        status: "failed".into(),
                        error: Some(reason.clone()),
                        fix: None,
                    });
                }
            }
        }
    }

    summary(&config, total, succeeded, failed, &target_label);

    if config.json {
        let json_output = SyncJsonOutput {
            command: "sync".into(),
            target: target_label,
            source: source_label,
            results: json_results,
            summary: SyncJsonSummary {
                total,
                synced: succeeded,
                failed,
            },
        };
        output_json(&json_output);
    }

    exit_codes::from_results(total, failed)
}

/// Look up the operation type for a given key to produce a human-readable action word.
fn operation_action(operations: &[DiffOperation], key: &str) -> &'static str {
    for op in operations {
        if op.key() == key {
            return match op {
                DiffOperation::Add { .. } => "created",
                DiffOperation::Update { .. } => "updated",
                DiffOperation::Remove { .. } => "deleted",
            };
        }
    }
    "synced"
}

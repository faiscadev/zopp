use std::collections::HashMap;

use crate::crypto::fetch_and_decrypt_secrets;
use crate::grpc::setup_client;
use crate::output::{
    error_block, exit_codes, output_json, status_table, StatusEntry, StatusJsonEntry,
    StatusJsonOutput, SyncCommonArgs,
};
use zopp_sync::aws::AwsSyncTarget;
use zopp_sync::{DiffOperation, SyncTarget};

pub async fn cmd_sync_status(
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

    let zopp_map: HashMap<String, String> = zopp_secrets.into_iter().collect();
    let zopp_count = zopp_map.len();

    // 3. Query each target and build status entries
    let mut entries = Vec::new();
    let mut has_error = false;

    // AWS target
    let aws_entry = match build_aws_status(&zopp_map, zopp_count, region, prefix).await {
        Ok(entry) => entry,
        Err(entry) => {
            has_error = true;
            entry
        }
    };
    entries.push(aws_entry);

    // 4. Output
    status_table(&config, &entries);

    if config.json {
        let json_output = StatusJsonOutput {
            command: "status".into(),
            targets: entries
                .iter()
                .map(|e| StatusJsonEntry {
                    target: e.target.clone(),
                    status: e.status.clone(),
                    detail: e.detail.clone(),
                })
                .collect(),
        };
        output_json(&json_output);
    }

    if has_error {
        exit_codes::TOTAL_FAILURE
    } else {
        exit_codes::SUCCESS
    }
}

/// Build a StatusEntry for the AWS target. Returns Ok for success, Err for error entries.
async fn build_aws_status(
    zopp_map: &HashMap<String, String>,
    zopp_count: usize,
    region: &str,
    prefix: Option<&str>,
) -> Result<StatusEntry, StatusEntry> {
    // Create AWS sync target
    let target = match AwsSyncTarget::new(region, prefix.map(String::from)).await {
        Ok(t) => t,
        Err(e) => {
            return Err(StatusEntry {
                target: format!("AWS Secrets Manager ({region})"),
                status: "error".into(),
                detail: e.to_string(),
            });
        }
    };

    let target_name = target.display_name().to_string();

    // Fetch current state from AWS
    let aws_secrets = match target.fetch_current().await {
        Ok(s) => s,
        Err(e) => {
            return Err(StatusEntry {
                target: target_name,
                status: "error".into(),
                detail: e.to_string(),
            });
        }
    };

    // Compute diff
    let operations = zopp_sync::diff(zopp_map, &aws_secrets);

    if operations.is_empty() {
        Ok(StatusEntry {
            target: target_name,
            status: "in-sync".into(),
            detail: format!("{zopp_count} secrets"),
        })
    } else {
        let mut adds = 0usize;
        let mut updates = 0usize;
        let mut removes = 0usize;
        for op in &operations {
            match op {
                DiffOperation::Add { .. } => adds += 1,
                DiffOperation::Update { .. } => updates += 1,
                DiffOperation::Remove { .. } => removes += 1,
            }
        }
        Ok(StatusEntry {
            target: target_name,
            status: "drifted".into(),
            detail: format_drift_detail(adds, updates, removes),
        })
    }
}

fn format_drift_detail(adds: usize, updates: usize, removes: usize) -> String {
    let mut parts = Vec::new();
    if adds > 0 {
        parts.push(format!("{adds} added"));
    }
    if updates > 0 {
        parts.push(format!("{updates} updated"));
    }
    if removes > 0 {
        parts.push(format!("{removes} removed"));
    }
    parts.join(", ")
}

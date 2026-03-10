use serde::Serialize;

#[derive(Serialize)]
pub struct SyncJsonOutput {
    pub command: String,
    pub target: String,
    pub source: String,
    pub results: Vec<SyncJsonResult>,
    pub summary: SyncJsonSummary,
}

#[derive(Serialize)]
pub struct SyncJsonResult {
    pub key: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
}

#[derive(Serialize)]
pub struct SyncJsonSummary {
    pub total: usize,
    pub synced: usize,
    pub failed: usize,
}

#[derive(Serialize)]
pub struct DiffJsonOutput {
    pub command: String,
    pub target: String,
    pub source: String,
    pub changes: Vec<DiffJsonChange>,
    pub summary: DiffJsonSummary,
}

#[derive(Serialize)]
pub struct DiffJsonChange {
    pub key: String,
    /// One of "add", "update", or "remove".
    pub operation: String,
}

#[derive(Serialize)]
pub struct DiffJsonSummary {
    pub adds: usize,
    pub updates: usize,
    pub removes: usize,
    pub total: usize,
}

#[derive(Serialize)]
pub struct StatusJsonOutput {
    pub command: String,
    pub targets: Vec<StatusJsonEntry>,
}

#[derive(Serialize)]
pub struct StatusJsonEntry {
    pub target: String,
    pub status: String,
    pub detail: String,
}

/// Serialize the given value as pretty-printed JSON and write to stdout.
pub fn output_json<T: Serialize>(value: &T) {
    println!(
        "{}",
        serde_json::to_string_pretty(value).expect("JSON serialization failed")
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sync_json_output_serializes() {
        let output = SyncJsonOutput {
            command: "sync".into(),
            target: "k8s/production".into(),
            source: "zopp".into(),
            results: vec![SyncJsonResult {
                key: "DB_HOST".into(),
                status: "synced".into(),
                error: None,
                fix: None,
            }],
            summary: SyncJsonSummary {
                total: 1,
                synced: 1,
                failed: 0,
            },
        };
        let json = serde_json::to_string_pretty(&output).unwrap();
        assert!(json.contains("\"command\": \"sync\""));
        assert!(json.contains("\"key\": \"DB_HOST\""));
        // error/fix should be absent due to skip_serializing_if
        assert!(!json.contains("\"error\""));
        assert!(!json.contains("\"fix\""));
    }

    #[test]
    fn test_sync_json_result_with_error() {
        let result = SyncJsonResult {
            key: "DB_HOST".into(),
            status: "failed".into(),
            error: Some("not found".into()),
            fix: Some("check config".into()),
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"error\":\"not found\""));
        assert!(json.contains("\"fix\":\"check config\""));
    }

    #[test]
    fn test_diff_json_output_serializes() {
        let output = DiffJsonOutput {
            command: "diff".into(),
            target: "k8s/production".into(),
            source: "zopp".into(),
            changes: vec![DiffJsonChange {
                key: "NEW_KEY".into(),
                operation: "add".into(),
            }],
            summary: DiffJsonSummary {
                adds: 1,
                updates: 0,
                removes: 0,
                total: 1,
            },
        };
        let json = serde_json::to_string_pretty(&output).unwrap();
        assert!(json.contains("\"operation\": \"add\""));
    }

    #[test]
    fn test_status_json_output_serializes() {
        let output = StatusJsonOutput {
            command: "status".into(),
            targets: vec![StatusJsonEntry {
                target: "k8s/production".into(),
                status: "in-sync".into(),
                detail: "all secrets match".into(),
            }],
        };
        let json = serde_json::to_string_pretty(&output).unwrap();
        assert!(json.contains("\"status\": \"in-sync\""));
    }
}

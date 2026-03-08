use std::collections::HashMap;

use crate::types::DiffOperation;

/// Computes the diff between source secrets (zopp) and target secrets (platform).
///
/// Returns a sorted list of [`DiffOperation`] entries representing the changes
/// needed to bring the target in sync with the source. Operations are sorted
/// alphabetically by key for deterministic output.
pub fn diff(source: &HashMap<String, String>, target: &HashMap<String, String>) -> Vec<DiffOperation> {
    let mut operations = Vec::new();

    // Keys in source but not in target → Add
    // Keys in both with different values → Update
    for (key, source_value) in source {
        match target.get(key) {
            None => operations.push(DiffOperation::Add {
                key: key.clone(),
                value: source_value.clone(),
            }),
            Some(target_value) if target_value != source_value => {
                operations.push(DiffOperation::Update {
                    key: key.clone(),
                    old_value: target_value.clone(),
                    new_value: source_value.clone(),
                });
            }
            Some(_) => {} // identical — no operation
        }
    }

    // Keys in target but not in source → Remove
    for key in target.keys() {
        if !source.contains_key(key) {
            operations.push(DiffOperation::Remove { key: key.clone() });
        }
    }

    // Sort by key for deterministic output
    operations.sort_by(|a, b| a.key().cmp(b.key()));

    operations
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn empty_source_and_target() {
        let result = diff(&map(&[]), &map(&[]));
        assert!(result.is_empty());
    }

    #[test]
    fn identical_sets() {
        let secrets = map(&[("DB_URL", "postgres://localhost"), ("API_KEY", "secret123")]);
        let result = diff(&secrets, &secrets);
        assert!(result.is_empty());
    }

    #[test]
    fn adds_only() {
        let source = map(&[("NEW_KEY", "value1"), ("ANOTHER", "value2")]);
        let target = map(&[]);
        let result = diff(&source, &target);
        assert_eq!(result.len(), 2);
        assert_eq!(
            result[0],
            DiffOperation::Add {
                key: "ANOTHER".into(),
                value: "value2".into(),
            }
        );
        assert_eq!(
            result[1],
            DiffOperation::Add {
                key: "NEW_KEY".into(),
                value: "value1".into(),
            }
        );
    }

    #[test]
    fn removes_only() {
        let source = map(&[]);
        let target = map(&[("OLD_KEY", "stale"), ("LEGACY", "removed")]);
        let result = diff(&source, &target);
        assert_eq!(result.len(), 2);
        assert_eq!(
            result[0],
            DiffOperation::Remove {
                key: "LEGACY".into(),
            }
        );
        assert_eq!(
            result[1],
            DiffOperation::Remove {
                key: "OLD_KEY".into(),
            }
        );
    }

    #[test]
    fn updates_only() {
        let source = map(&[("DB_URL", "postgres://new-host")]);
        let target = map(&[("DB_URL", "postgres://old-host")]);
        let result = diff(&source, &target);
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0],
            DiffOperation::Update {
                key: "DB_URL".into(),
                old_value: "postgres://old-host".into(),
                new_value: "postgres://new-host".into(),
            }
        );
    }

    #[test]
    fn mixed_operations() {
        let source = map(&[
            ("KEEP", "same"),
            ("UPDATE_ME", "new-val"),
            ("BRAND_NEW", "fresh"),
        ]);
        let target = map(&[
            ("KEEP", "same"),
            ("UPDATE_ME", "old-val"),
            ("DEPRECATED", "gone"),
        ]);
        let result = diff(&source, &target);
        assert_eq!(result.len(), 3);
        // Sorted alphabetically by key
        assert_eq!(
            result[0],
            DiffOperation::Add {
                key: "BRAND_NEW".into(),
                value: "fresh".into(),
            }
        );
        assert_eq!(
            result[1],
            DiffOperation::Remove {
                key: "DEPRECATED".into(),
            }
        );
        assert_eq!(
            result[2],
            DiffOperation::Update {
                key: "UPDATE_ME".into(),
                old_value: "old-val".into(),
                new_value: "new-val".into(),
            }
        );
    }

    #[test]
    fn deterministic_ordering() {
        let source = map(&[("Z_KEY", "z"), ("A_KEY", "a"), ("M_KEY", "m")]);
        let target = map(&[]);
        let result = diff(&source, &target);
        let keys: Vec<&str> = result.iter().map(|op| op.key()).collect();
        assert_eq!(keys, vec!["A_KEY", "M_KEY", "Z_KEY"]);
    }

    #[test]
    fn unicode_keys() {
        let source = map(&[("数据库", "value"), ("clé", "valeur")]);
        let target = map(&[]);
        let result = diff(&source, &target);
        assert_eq!(result.len(), 2);
        // Both are adds, sorted by key
        assert!(result.iter().all(|op| matches!(op, DiffOperation::Add { .. })));
    }

    #[test]
    fn special_characters_in_values() {
        let source = map(&[("KEY", "value with\nnewlines\tand\ttabs")]);
        let target = map(&[("KEY", "old value")]);
        let result = diff(&source, &target);
        assert_eq!(result.len(), 1);
        assert!(matches!(&result[0], DiffOperation::Update { new_value, .. } if new_value.contains('\n')));
    }

    #[test]
    fn single_key() {
        let source = map(&[("ONLY", "one")]);
        let target = map(&[]);
        let result = diff(&source, &target);
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0],
            DiffOperation::Add {
                key: "ONLY".into(),
                value: "one".into(),
            }
        );
    }

    #[test]
    fn empty_string_values() {
        let source = map(&[("EMPTY", "")]);
        let target = map(&[("EMPTY", "was-something")]);
        let result = diff(&source, &target);
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0],
            DiffOperation::Update {
                key: "EMPTY".into(),
                old_value: "was-something".into(),
                new_value: "".into(),
            }
        );
    }

    #[test]
    fn diff_operation_key_accessor() {
        let add = DiffOperation::Add {
            key: "k1".into(),
            value: "v".into(),
        };
        let update = DiffOperation::Update {
            key: "k2".into(),
            old_value: "a".into(),
            new_value: "b".into(),
        };
        let remove = DiffOperation::Remove { key: "k3".into() };
        assert_eq!(add.key(), "k1");
        assert_eq!(update.key(), "k2");
        assert_eq!(remove.key(), "k3");
    }
}

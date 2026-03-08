use super::config::OutputConfig;
use console::style;
use std::fmt::Write as _;

/// Symbols used for output items (success, failure, warning).
pub struct Symbols {
    pub success: &'static str,
    pub failure: &'static str,
    pub warning: &'static str,
}

impl Symbols {
    /// Return Unicode symbols when TTY, ASCII fallbacks otherwise.
    pub fn for_config(config: &OutputConfig) -> Self {
        if config.is_tty {
            Self {
                success: "\u{2713}",
                failure: "\u{2717}",
                warning: "\u{26A0}",
            }
        } else {
            Self {
                success: "[ok]",
                failure: "[FAIL]",
                warning: "[WARN]",
            }
        }
    }
}

/// Entry for the status table.
pub struct StatusEntry {
    pub target: String,
    pub status: String,
    pub detail: String,
}

/// Print a header line: `{verb}: {source} -> {target}`.
pub fn header(config: &OutputConfig, verb: &str, source: &str, target: &str) {
    if config.quiet || config.json {
        return;
    }
    if config.use_color() {
        println!("{}: {} -> {}", verb, source, style(target).cyan());
    } else {
        println!("{verb}: {source} -> {target}");
    }
}

/// Print a per-item success line.
pub fn per_item_success(config: &OutputConfig, key: &str, action: &str) {
    if config.quiet || config.json {
        return;
    }
    let symbols = Symbols::for_config(config);
    let width = 30;
    if config.use_color() {
        println!(
            "  {} {:<width$} {}",
            style(symbols.success).green(),
            key,
            action,
            width = width
        );
    } else {
        println!(
            "  {} {:<width$} {}",
            symbols.success,
            key,
            action,
            width = width
        );
    }
}

/// Print a per-item failure line, with optional fix suggestion.
pub fn per_item_failure(config: &OutputConfig, key: &str, error: &str, fix: Option<&str>) {
    if config.quiet || config.json {
        return;
    }
    let symbols = Symbols::for_config(config);
    let width = 30;
    if config.use_color() {
        println!(
            "  {} {:<width$} {}",
            style(symbols.failure).red(),
            key,
            error,
            width = width
        );
    } else {
        println!(
            "  {} {:<width$} {}",
            symbols.failure,
            key,
            error,
            width = width
        );
    }
    if let Some(fix) = fix {
        println!("    Fix: {fix}");
    }
}

/// Print a diff item line with colored symbol (+/~/- for add/update/remove).
pub fn diff_item(config: &OutputConfig, symbol: char, key: &str) {
    if config.quiet || config.json {
        return;
    }
    if config.use_color() {
        let styled_symbol = match symbol {
            '+' => style(symbol).green(),
            '~' => style(symbol).yellow(),
            '-' => style(symbol).red(),
            _ => style(symbol),
        };
        println!("  {styled_symbol} {key}");
    } else {
        println!("  {symbol} {key}");
    }
}

/// Print a diff summary line showing counts of adds, updates, and removes.
pub fn diff_summary(config: &OutputConfig, adds: usize, updates: usize, removes: usize) {
    if config.quiet || config.json {
        return;
    }
    if adds == 0 && updates == 0 && removes == 0 {
        println!("No changes. Target is in sync.");
        return;
    }
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
    println!("{}", parts.join(", "));
}

/// Print a summary line with success/failure counts.
pub fn summary(config: &OutputConfig, total: usize, succeeded: usize, failed: usize, target: &str) {
    if config.quiet || config.json {
        return;
    }
    let symbols = Symbols::for_config(config);
    if failed == 0 {
        // All succeeded
        let msg = format!("{} {succeeded}/{total} synced to {target}", symbols.success);
        if config.use_color() {
            println!("{}", style(msg).green());
        } else {
            println!("{msg}");
        }
    } else if failed == total {
        // All failed
        let msg = format!("{} 0/{total} synced to {target}", symbols.failure);
        if config.use_color() {
            println!("{}", style(msg).red());
        } else {
            println!("{msg}");
        }
    } else {
        // Partial failure
        let msg = format!(
            "{} {succeeded}/{total} synced to {target} ({failed} failed)",
            symbols.warning
        );
        if config.use_color() {
            println!("{}", style(msg).yellow());
        } else {
            println!("{msg}");
        }
    }
}

/// Print a status table with aligned columns, truncated to terminal width.
pub fn status_table(config: &OutputConfig, entries: &[StatusEntry]) {
    if config.quiet || config.json {
        return;
    }
    if entries.is_empty() {
        return;
    }

    let target_width = entries
        .iter()
        .map(|e| e.target.len())
        .max()
        .unwrap_or(6)
        .max(6);
    let status_width = entries
        .iter()
        .map(|e| e.status.len())
        .max()
        .unwrap_or(6)
        .max(6);
    let max_width = config.terminal_width as usize;

    // Header
    let header_line = format!(
        "{:<target_width$}  {:<status_width$}  DETAIL",
        "TARGET",
        "STATUS",
        target_width = target_width,
        status_width = status_width,
    );
    println!("{}", truncate_to_width(&header_line, max_width));

    // Separator
    let sep = format!(
        "{:<target_width$}  {:<status_width$}  {}",
        "-".repeat(target_width),
        "-".repeat(status_width),
        "------",
        target_width = target_width,
        status_width = status_width,
    );
    println!("{}", truncate_to_width(&sep, max_width));

    for entry in entries {
        let line = format!(
            "{:<target_width$}  {:<status_width$}  {}",
            entry.target,
            entry.status,
            entry.detail,
            target_width = target_width,
            status_width = status_width,
        );
        println!("{}", truncate_to_width(&line, max_width));
    }
}

/// Print a structured error block.
pub fn error_block(config: &OutputConfig, context: &str, problem: &str, fix: &str) {
    if config.json {
        return;
    }
    if config.use_color() {
        eprintln!("{} {context}", style("Error:").red().bold());
    } else {
        eprintln!("Error: {context}");
    }
    eprintln!("  Problem: {problem}");
    eprintln!("  Fix: {fix}");
}

fn truncate_to_width(s: &str, max_width: usize) -> String {
    if s.len() <= max_width {
        s.to_string()
    } else if max_width > 3 {
        let mut result = String::with_capacity(max_width);
        let _ = write!(result, "{}...", &s[..max_width - 3]);
        result
    } else {
        s[..max_width].to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn non_tty_config() -> OutputConfig {
        OutputConfig {
            json: false,
            no_color: false,
            verbose: false,
            quiet: false,
            is_tty: false,
            terminal_width: 80,
        }
    }

    fn tty_config() -> OutputConfig {
        OutputConfig {
            json: false,
            no_color: false,
            verbose: false,
            quiet: false,
            is_tty: true,
            terminal_width: 80,
        }
    }

    #[test]
    fn test_symbols_for_tty() {
        let config = tty_config();
        let symbols = Symbols::for_config(&config);
        assert_eq!(symbols.success, "\u{2713}");
        assert_eq!(symbols.failure, "\u{2717}");
        assert_eq!(symbols.warning, "\u{26A0}");
    }

    #[test]
    fn test_symbols_for_non_tty() {
        let config = non_tty_config();
        let symbols = Symbols::for_config(&config);
        assert_eq!(symbols.success, "[ok]");
        assert_eq!(symbols.failure, "[FAIL]");
        assert_eq!(symbols.warning, "[WARN]");
    }

    #[test]
    fn test_truncate_to_width_no_truncation() {
        assert_eq!(truncate_to_width("hello", 10), "hello");
    }

    #[test]
    fn test_truncate_to_width_truncation() {
        assert_eq!(truncate_to_width("hello world", 8), "hello...");
    }

    #[test]
    fn test_truncate_to_width_exact() {
        assert_eq!(truncate_to_width("hello", 5), "hello");
    }

    #[test]
    fn test_truncate_to_width_very_small() {
        assert_eq!(truncate_to_width("hello", 3), "hel");
    }

    #[test]
    fn test_quiet_mode_header_is_noop() {
        let mut config = non_tty_config();
        config.quiet = true;
        // Should not panic or print anything
        header(&config, "Sync", "zopp", "k8s/production");
    }

    #[test]
    fn test_json_mode_header_is_noop() {
        let mut config = non_tty_config();
        config.json = true;
        header(&config, "Sync", "zopp", "k8s/production");
    }

    #[test]
    fn test_quiet_mode_per_item_success_is_noop() {
        let mut config = non_tty_config();
        config.quiet = true;
        per_item_success(&config, "DB_HOST", "synced");
    }

    #[test]
    fn test_quiet_mode_per_item_failure_is_noop() {
        let mut config = non_tty_config();
        config.quiet = true;
        per_item_failure(&config, "DB_HOST", "not found", Some("check config"));
    }

    #[test]
    fn test_quiet_mode_diff_item_is_noop() {
        let mut config = non_tty_config();
        config.quiet = true;
        diff_item(&config, '+', "NEW_KEY");
    }

    #[test]
    fn test_quiet_mode_diff_summary_is_noop() {
        let mut config = non_tty_config();
        config.quiet = true;
        diff_summary(&config, 1, 2, 3);
    }

    #[test]
    fn test_quiet_mode_summary_is_noop() {
        let mut config = non_tty_config();
        config.quiet = true;
        summary(&config, 3, 3, 0, "target");
    }

    #[test]
    fn test_quiet_mode_status_table_is_noop() {
        let mut config = non_tty_config();
        config.quiet = true;
        status_table(
            &config,
            &[StatusEntry {
                target: "t".into(),
                status: "ok".into(),
                detail: "d".into(),
            }],
        );
    }

    #[test]
    fn test_error_block_not_suppressed_in_quiet() {
        let mut config = non_tty_config();
        config.quiet = true;
        // error_block should still print in quiet mode (goes to stderr)
        error_block(&config, "ctx", "problem", "fix");
    }

    #[test]
    fn test_error_block_suppressed_in_json() {
        let mut config = non_tty_config();
        config.json = true;
        // Should not print anything
        error_block(&config, "ctx", "problem", "fix");
    }
}

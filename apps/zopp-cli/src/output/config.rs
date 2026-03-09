/// Configuration for CLI output formatting.
#[derive(Debug, Clone)]
pub struct OutputConfig {
    /// Output as JSON instead of human-readable text.
    pub json: bool,
    /// Disable colored output.
    pub no_color: bool,
    /// Show additional details.
    pub verbose: bool,
    /// Only show errors.
    pub quiet: bool,
    /// Whether stdout is a TTY (auto-detected).
    pub is_tty: bool,
    /// Terminal width in columns (auto-detected, default 80).
    pub terminal_width: u16,
}

impl OutputConfig {
    /// Create a new `OutputConfig` with the given flags, auto-detecting TTY and terminal width.
    pub fn new(json: bool, no_color: bool, verbose: bool, quiet: bool) -> Self {
        let is_tty = console::Term::stdout().is_term();
        let terminal_width = terminal_size::terminal_size()
            .map(|(w, _)| w.0)
            .unwrap_or(80);

        Self {
            json,
            no_color,
            verbose,
            quiet,
            is_tty,
            terminal_width,
        }
    }

    /// Whether color/ANSI codes should be applied.
    pub fn use_color(&self) -> bool {
        !self.no_color && self.is_tty
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_stores_flags() {
        let config = OutputConfig::new(true, true, true, true);
        assert!(config.json);
        assert!(config.no_color);
        assert!(config.verbose);
        assert!(config.quiet);
    }

    #[test]
    fn test_new_default_flags() {
        let config = OutputConfig::new(false, false, false, false);
        assert!(!config.json);
        assert!(!config.no_color);
        assert!(!config.verbose);
        assert!(!config.quiet);
    }

    #[test]
    fn test_no_color_stored() {
        let config = OutputConfig::new(false, true, false, false);
        assert!(config.no_color);
    }

    #[test]
    fn test_terminal_width_positive() {
        let config = OutputConfig::new(false, false, false, false);
        assert!(config.terminal_width > 0);
    }

    #[test]
    fn test_use_color_no_color_flag() {
        let mut config = OutputConfig::new(false, true, false, false);
        config.is_tty = true;
        assert!(!config.use_color());
    }

    #[test]
    fn test_use_color_not_tty() {
        let mut config = OutputConfig::new(false, false, false, false);
        config.is_tty = false;
        assert!(!config.use_color());
    }

    #[test]
    fn test_use_color_tty_and_color() {
        let mut config = OutputConfig::new(false, false, false, false);
        config.is_tty = true;
        assert!(config.use_color());
    }
}

use clap::Parser;

/// Common arguments shared by diff subcommands.
///
/// Unlike `SyncCommonArgs`, this does not include `--dry-run` or `--force`
/// since diff is read-only.
#[derive(Parser, Debug)]
pub struct DiffCommonArgs {
    /// Workspace name (overrides zopp.toml)
    #[arg(short, long)]
    pub workspace: Option<String>,
    /// Project name (overrides zopp.toml)
    #[arg(short, long)]
    pub project: Option<String>,
    /// Environment name (overrides zopp.toml)
    #[arg(short, long)]
    pub environment: Option<String>,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
    /// Disable colored output
    #[arg(long)]
    pub no_color: bool,
    /// Show additional details
    #[arg(long, conflicts_with = "quiet")]
    pub verbose: bool,
    /// Only show errors
    #[arg(long, conflicts_with = "verbose")]
    pub quiet: bool,
}

impl DiffCommonArgs {
    pub fn to_output_config(&self) -> super::OutputConfig {
        super::OutputConfig::new(self.json, self.no_color, self.verbose, self.quiet)
    }
}

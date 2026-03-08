use clap::Parser;

/// Common arguments shared by sync subcommands.
#[derive(Parser, Debug)]
pub struct SyncCommonArgs {
    /// Workspace name (overrides zopp.toml)
    #[arg(short, long)]
    pub workspace: Option<String>,
    /// Project name (overrides zopp.toml)
    #[arg(short, long)]
    pub project: Option<String>,
    /// Environment name (overrides zopp.toml)
    #[arg(short, long)]
    pub environment: Option<String>,
    /// Show what would change without applying
    #[arg(long)]
    pub dry_run: bool,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
    /// Disable colored output
    #[arg(long)]
    pub no_color: bool,
    /// Show additional details
    #[arg(long)]
    pub verbose: bool,
    /// Only show errors
    #[arg(long)]
    pub quiet: bool,
    /// Force sync even if target not managed by zopp
    #[arg(long)]
    pub force: bool,
}

impl SyncCommonArgs {
    pub fn to_output_config(&self) -> super::OutputConfig {
        super::OutputConfig::new(self.json, self.no_color, self.verbose, self.quiet)
    }
}

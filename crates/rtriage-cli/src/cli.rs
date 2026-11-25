//! Command-line arguments.

use std::num::{NonZeroU64, NonZeroUsize};
use std::path::PathBuf;

use clap::{ArgAction, Parser, ValueEnum};

/// Fast static malware triage for PE and ELF binaries.
///
/// Never executes, loads or emulates the files it analyzes.
#[derive(Debug, Parser)]
#[command(name = "rtriage", version, about, long_about = None)]
pub struct Cli {
    /// Files to triage.
    #[arg(required = true, value_name = "FILE")]
    pub files: Vec<PathBuf>,

    /// Output format.
    #[arg(short = 'f', long, value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,

    /// Write the report to PATH instead of stdout.
    #[arg(short, long, value_name = "PATH")]
    pub output: Option<PathBuf>,

    /// Minimum string length, in characters.
    #[arg(long, value_name = "N", default_value = "5")]
    pub strings_min: NonZeroUsize,

    /// Include every extracted string, not only classified ones (URLs, IPs, paths, ...).
    #[arg(long)]
    pub all_strings: bool,

    /// Maximum file size to analyze, in bytes [default: 536870912 (512 MiB)].
    #[arg(long, value_name = "BYTES")]
    pub max_size: Option<u64>,

    /// Show how the risk score was computed (every finding, cap and suppression).
    #[arg(long)]
    pub explain: bool,

    /// Only show findings at or above this severity (the score always uses all).
    #[arg(long, value_enum, value_name = "LEVEL", default_value_t = MinSeverity::Info)]
    pub min_severity: MinSeverity,

    /// Replace the bundled API behavior rules with this TOML file
    /// (same format as rules/api_groups.toml).
    #[arg(long, value_name = "FILE")]
    pub api_rules: Option<PathBuf>,

    /// Hard time limit per file, in seconds (must be > 0). When it expires the
    /// remaining analyzers are skipped and the report is marked partial.
    #[arg(long, value_name = "SECONDS", default_value = "30")]
    pub timeout: NonZeroU64,

    /// Disable colored output (NO_COLOR is honored too).
    #[arg(long)]
    pub no_color: bool,

    /// More diagnostics on stderr (-v info, -vv debug, -vvv trace).
    #[arg(short, long, action = ArgAction::Count, conflicts_with = "quiet")]
    pub verbose: u8,

    /// Only print errors on stderr.
    #[arg(short, long)]
    pub quiet: bool,
}

/// Report output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Human-readable report.
    Text,
    /// Versioned JSON (see docs/output-schema.md).
    Json,
}

/// Severity filter for displayed findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum MinSeverity {
    /// Everything (default).
    Info,
    /// Low and above.
    Low,
    /// Medium and above.
    Medium,
    /// High only.
    High,
}

impl From<MinSeverity> for rtriage_core::Severity {
    fn from(m: MinSeverity) -> Self {
        match m {
            MinSeverity::Info => Self::Info,
            MinSeverity::Low => Self::Low,
            MinSeverity::Medium => Self::Medium,
            MinSeverity::High => Self::High,
        }
    }
}

impl Cli {
    /// `true` unless `--no-color` or a non-empty `NO_COLOR` is set.
    pub fn color_allowed(&self) -> bool {
        !self.no_color && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn defaults() {
        let cli = Cli::try_parse_from(["rtriage", "a.exe"]).unwrap();
        assert_eq!(cli.format, OutputFormat::Text);
        assert_eq!(cli.strings_min.get(), 5);
        assert!(!cli.all_strings);
        assert_eq!(cli.max_size, None);
        assert_eq!(cli.timeout.get(), 30);
        assert!(!cli.explain);
        assert_eq!(cli.min_severity, MinSeverity::Info);
    }

    #[test]
    fn min_severity_values() {
        let cli = Cli::try_parse_from(["rtriage", "--min-severity", "medium", "a"]).unwrap();
        assert_eq!(cli.min_severity, MinSeverity::Medium);
        assert!(Cli::try_parse_from(["rtriage", "--min-severity", "critical", "a"]).is_err());
    }

    #[test]
    fn rejects_zero_timeout() {
        assert!(Cli::try_parse_from(["rtriage", "--timeout", "0", "a"]).is_err());
        assert!(Cli::try_parse_from(["rtriage", "--timeout", "-1", "a"]).is_err());
    }

    #[test]
    fn requires_a_file() {
        assert!(Cli::try_parse_from(["rtriage"]).is_err());
    }

    #[test]
    fn rejects_zero_strings_min() {
        assert!(Cli::try_parse_from(["rtriage", "--strings-min", "0", "a"]).is_err());
    }

    #[test]
    fn quiet_conflicts_with_verbose() {
        assert!(Cli::try_parse_from(["rtriage", "-q", "-v", "a"]).is_err());
    }
}

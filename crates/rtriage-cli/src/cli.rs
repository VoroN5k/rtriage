//! Command-line arguments.

use std::num::{NonZeroU64, NonZeroUsize};
use std::path::PathBuf;

use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};

/// Fast static malware triage for PE and ELF binaries.
///
/// Never executes, loads or emulates the files it analyzes.
#[derive(Debug, Parser)]
#[command(
    name = "rtriage",
    version,
    about,
    long_about = None,
    subcommand_negates_reqs = true
)]
pub struct Cli {
    /// Batch mode (`scan`); without a subcommand, full reports are printed.
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Files or directories to triage (directories are walked recursively).
    /// One file is analyzed in-process; several files or any directory go
    /// through isolated worker processes. A file named `scan` needs `./scan`.
    #[arg(required_unless_present = "worker", value_name = "FILE")]
    pub files: Vec<PathBuf>,

    /// Worker processes for directories and multi-file runs
    /// [default: CPU count, at most 64].
    #[arg(short, long, value_name = "N", global = true, value_parser = clap::value_parser!(u64).range(1..=64))]
    pub jobs: Option<u64>,

    /// Output format.
    #[arg(short = 'f', long, value_enum, default_value_t = OutputFormat::Text, global = true)]
    pub format: OutputFormat,

    /// Write the report to PATH instead of stdout.
    #[arg(short, long, value_name = "PATH", global = true)]
    pub output: Option<PathBuf>,

    /// Minimum string length, in characters.
    #[arg(long, value_name = "N", default_value = "5", global = true)]
    pub strings_min: NonZeroUsize,

    /// Include every extracted string, not only classified ones (URLs, IPs, paths, ...).
    #[arg(long, global = true)]
    pub all_strings: bool,

    /// Maximum file size to analyze, in bytes [default: 536870912 (512 MiB)].
    #[arg(long, value_name = "BYTES", global = true)]
    pub max_size: Option<u64>,

    /// Show how the risk score was computed (every finding, cap and suppression).
    #[arg(long, global = true)]
    pub explain: bool,

    /// Defang URLs, domains, IPs and emails in text output (hxxp://, 1[.]2[.]3[.]4).
    /// JSON always has both the raw value and `value_defanged`; Markdown is
    /// always defanged (this flag changes nothing there, see --no-defang).
    #[arg(long, global = true)]
    pub defang: bool,

    /// Markdown only: show URLs, domains, IPs and emails as found, not
    /// defanged. A usage error with other formats.
    #[arg(long, global = true)]
    pub no_defang: bool,

    /// Markdown only: document limit in characters [default: 60000; 0 = no
    /// limit]. Output is cut on a line boundary with a note; failed and
    /// skipped files are always listed. A usage error with other formats.
    #[arg(long, value_name = "N", global = true)]
    pub md_limit: Option<usize>,

    /// Exit with code 3 if any file's risk is at or above this level (for CI
    /// gates). Takes precedence over exit code 1 for failed files.
    #[arg(long, value_enum, value_name = "LEVEL", global = true)]
    pub fail_on: Option<FailOn>,

    /// Only show findings at or above this severity (the score always uses all).
    #[arg(long, value_enum, value_name = "LEVEL", default_value_t = MinSeverity::Info, global = true)]
    pub min_severity: MinSeverity,

    /// Directory with your own rules, layered over the bundled ones. Known files:
    /// api_groups.toml, elf_api_groups.toml, packers.toml (replace the bundled
    /// ones unless they set include_defaults = true), ioc_allowlist.toml (always
    /// added), yara.toml (YARA settings and limits) and a yara/ directory of
    /// rule files (added). Missing files fall back to the bundled rules.
    #[arg(long, value_name = "DIR", global = true)]
    pub rules_dir: Option<PathBuf>,

    /// Extra YARA rules: a rule file, or a directory searched for *.yar / *.yara
    /// (repeatable). Added to the bundled rules and `<rules-dir>/yara/`. Needs a
    /// build with the `yara` feature.
    #[arg(long, value_name = "PATH", global = true, action = ArgAction::Append, conflicts_with = "no_yara")]
    pub yara: Vec<PathBuf>,

    /// Do not run YARA at all (not even the bundled rules).
    #[arg(long, global = true)]
    pub no_yara: bool,

    /// Hard time limit per file, in seconds (must be > 0). When it expires the
    /// remaining analyzers are skipped and the report is marked partial.
    #[arg(long, value_name = "SECONDS", default_value = "30", global = true)]
    pub timeout: NonZeroU64,

    /// Disable colored output (NO_COLOR is honored too).
    #[arg(long, global = true)]
    pub no_color: bool,

    /// More diagnostics on stderr (-v info, -vv debug, -vvv trace).
    #[arg(short, long, action = ArgAction::Count, conflicts_with = "quiet", global = true)]
    pub verbose: u8,

    /// Only print errors on stderr.
    #[arg(short, long, global = true)]
    pub quiet: bool,

    /// Internal: run as a worker process speaking the line protocol on
    /// stdin/stdout (see docs/robustness.md). Not for interactive use.
    #[arg(long, hide = true, conflicts_with = "files")]
    pub worker: bool,

    /// Internal: a worker renders text bodies with ANSI colors (ignored
    /// outside `--worker`).
    #[arg(long, hide = true)]
    pub worker_color: bool,

    /// Internal: a worker renders JSON bodies on one line (for NDJSON).
    #[arg(long, hide = true)]
    pub worker_compact: bool,

    /// Internal: the parent sends compiled YARA rules before the first request.
    #[arg(long, hide = true)]
    pub worker_yara: bool,

    /// Internal: a worker sends summaries only, no rendered body.
    #[arg(long, hide = true)]
    pub worker_summary_only: bool,
}

/// Subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Batch triage in isolated worker processes: a table sorted by risk
    /// (JSON: NDJSON ending in one summary line).
    Scan(ScanArgs),
    /// Interactive view of one file: findings and their evidence, sections,
    /// imports, strings, IOCs and the score breakdown.
    #[cfg(feature = "tui")]
    Tui(TuiArgs),
}

/// `rtriage tui` arguments (analysis options such as --rules-dir, --yara,
/// --timeout and --max-size apply; output options are ignored).
#[cfg(feature = "tui")]
#[derive(Debug, Args)]
pub struct TuiArgs {
    /// File to analyze.
    #[arg(value_name = "FILE")]
    pub path: PathBuf,
}

/// `rtriage scan` arguments (all other options apply too).
#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Files or directories to scan.
    #[arg(required = true, value_name = "PATH")]
    pub paths: Vec<PathBuf>,

    /// Also emit every full report: text before the table, JSON as one
    /// NDJSON `report` line each (completion order).
    #[arg(long)]
    pub full: bool,
}

/// Report output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Human-readable report.
    Text,
    /// Versioned JSON (see docs/output-schema.md).
    Json,
    /// Markdown for tickets, issues and wikis: every value from the file in
    /// code spans, IOCs defanged.
    Md,
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

/// Risk threshold for `--fail-on`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FailOn {
    /// Low, medium or high risk.
    Low,
    /// Medium or high risk.
    Medium,
    /// High risk only.
    High,
}

impl From<FailOn> for rtriage_core::RiskLevel {
    fn from(f: FailOn) -> Self {
        match f {
            FailOn::Low => Self::Low,
            FailOn::Medium => Self::Medium,
            FailOn::High => Self::High,
        }
    }
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
    /// Options that only make sense with `-f md`.
    ///
    /// # Errors
    /// The first such option given with another format.
    pub fn check_md_options(&self) -> Result<(), String> {
        if self.format == OutputFormat::Md {
            return Ok(());
        }
        for (given, flag) in [
            (self.no_defang, "--no-defang"),
            (self.md_limit.is_some(), "--md-limit"),
        ] {
            if given {
                return Err(format!("{flag} only applies to Markdown output (-f md)"));
            }
        }
        Ok(())
    }

    /// The Markdown document limit: `None` = unlimited.
    pub fn md_limit(&self) -> Option<usize> {
        match self.md_limit {
            None => Some(crate::output::md::DEFAULT_LIMIT),
            Some(0) => None,
            Some(n) => Some(n),
        }
    }

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
    fn worker_mode_needs_no_files_and_is_hidden() {
        let cli = Cli::try_parse_from(["rtriage", "--worker"]).unwrap();
        assert!(cli.worker && cli.files.is_empty());
        assert!(Cli::try_parse_from(["rtriage", "--worker", "a.exe"]).is_err());
        let help = Cli::command().render_long_help().to_string();
        assert!(!help.contains("--worker"));
    }

    #[cfg(feature = "tui")]
    #[test]
    fn tui_subcommand_takes_one_file_and_analysis_options() {
        let cli = Cli::try_parse_from(["rtriage", "tui", "a.exe", "--timeout", "5", "--no-yara"])
            .unwrap();
        let Some(Command::Tui(args)) = &cli.command else {
            panic!("no tui");
        };
        assert_eq!(args.path, PathBuf::from("a.exe"));
        assert_eq!(cli.timeout.get(), 5);
        assert!(cli.no_yara);
        assert!(Cli::try_parse_from(["rtriage", "tui"]).is_err());
        assert!(Cli::try_parse_from(["rtriage", "tui", "a", "b"]).is_err());
    }

    #[test]
    fn scan_subcommand_and_global_options() {
        let cli =
            Cli::try_parse_from(["rtriage", "scan", "dir", "--full", "-f", "json", "-j", "4"])
                .unwrap();
        let Some(Command::Scan(args)) = &cli.command else {
            panic!("no scan");
        };
        assert_eq!(args.paths, [PathBuf::from("dir")]);
        assert!(args.full);
        assert_eq!((cli.format, cli.jobs), (OutputFormat::Json, Some(4)));
        // Options before the subcommand work too.
        let cli = Cli::try_parse_from(["rtriage", "--explain", "scan", "d"]).unwrap();
        assert!(cli.explain && cli.command.is_some());
        assert!(Cli::try_parse_from(["rtriage", "scan"]).is_err());
        // Plain mode is unchanged; `./scan` is a file.
        let cli = Cli::try_parse_from(["rtriage", "./scan", "b"]).unwrap();
        assert!(cli.command.is_none() && cli.files.len() == 2);
    }

    #[test]
    fn yara_flags() {
        let cli =
            Cli::try_parse_from(["rtriage", "--yara", "a.yar", "--yara", "dir", "f"]).unwrap();
        assert_eq!(cli.yara, [PathBuf::from("a.yar"), PathBuf::from("dir")]);
        assert!(Cli::try_parse_from(["rtriage", "--yara", "a.yar", "--no-yara", "f"]).is_err());
        assert!(
            Cli::try_parse_from(["rtriage", "scan", "d", "--no-yara"])
                .unwrap()
                .no_yara
        );
    }

    #[test]
    fn jobs_are_bounded() {
        for bad in ["0", "65", "-1"] {
            assert!(
                Cli::try_parse_from(["rtriage", "-j", bad, "a"]).is_err(),
                "{bad}"
            );
        }
        assert_eq!(
            Cli::try_parse_from(["rtriage", "-j", "64", "a"])
                .unwrap()
                .jobs,
            Some(64)
        );
    }

    #[test]
    fn md_options() {
        let cli = Cli::try_parse_from(["rtriage", "-f", "md", "a"]).unwrap();
        assert_eq!(cli.format, OutputFormat::Md);
        assert_eq!(cli.md_limit(), Some(crate::output::md::DEFAULT_LIMIT));
        assert!(cli.check_md_options().is_ok());
        let cli = Cli::try_parse_from(["rtriage", "-f", "md", "--md-limit", "0", "a"]).unwrap();
        assert_eq!(cli.md_limit(), None);
        let cli = Cli::try_parse_from(["rtriage", "--no-defang", "a"]).unwrap();
        assert!(cli.check_md_options().unwrap_err().contains("--no-defang"));
        assert!(Cli::try_parse_from(["rtriage", "--md-limit", "-1", "a"]).is_err());
    }

    #[test]
    fn quiet_conflicts_with_verbose() {
        assert!(Cli::try_parse_from(["rtriage", "-q", "-v", "a"]).is_err());
    }
}

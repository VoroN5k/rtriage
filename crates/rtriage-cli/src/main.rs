//! `rtriage` binary: thin CLI layer over `rtriage-core`.
#![forbid(unsafe_code)]

mod cli;
mod output;
mod sanitize;
mod worker;

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::process::ExitCode;

use anstream::{AutoStream, ColorChoice};
use anyhow::Context;
use clap::Parser;
use rtriage_core::rules_dir::{RulesDir, KNOWN_FILES};
use rtriage_core::walk::{self, WalkOptions};
use rtriage_core::{Config, Registry, RiskLevel};
use tracing::level_filters::LevelFilter;

use crate::cli::{Cli, OutputFormat};
use crate::output::text::TextOptions;
use crate::output::{Failure, Run, SkippedPath};
use crate::sanitize::sanitize;

/// At least one file could not be analyzed, or output could not be written.
const EXIT_RUNTIME_ERROR: u8 = 1;
/// Invalid invocation or configuration (clap uses the same code).
const EXIT_USAGE: u8 = 2;
/// `--fail-on` threshold met by at least one file.
const EXIT_RISK: u8 = 3;

fn main() -> ExitCode {
    // clap exits with code 2 on usage errors.
    let cli = Cli::parse();
    install_panic_hook();
    init_logging(&cli);
    let config = match build_config(&cli) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("error: {}", sanitize(&format!("{err:#}")));
            return ExitCode::from(EXIT_USAGE);
        }
    };
    if cli.worker {
        return worker::run_worker(&cli, &config);
    }
    match run(&cli, &config) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {}", sanitize(&format!("{err:#}")));
            ExitCode::from(EXIT_RUNTIME_ERROR)
        }
    }
}

fn run(cli: &Cli, config: &Config) -> anyhow::Result<ExitCode> {
    let registry = Registry::default();
    let mut result = Run {
        reports: Vec::new(),
        failures: Vec::new(),
        skipped: Vec::new(),
    };

    let walk = walk::collect(&cli.files, WalkOptions::default());
    for e in &walk.errors {
        let failure = Failure {
            path: e.path.to_string_lossy().into_owned(),
            error: format!("cannot read directory: {}", e.error),
        };
        eprintln!(
            "error: {}: {}",
            sanitize(&failure.path),
            sanitize(&failure.error)
        );
        result.failures.push(failure);
    }
    if walk.limit_reached() {
        eprintln!(
            "warning: stopped after {} files (file limit); the rest is listed under skipped",
            walk.files.len()
        );
    }
    if walk.walked_directories && walk.files.is_empty() && walk.errors.is_empty() {
        eprintln!("warning: no files found");
    }
    result.skipped = walk
        .skipped
        .iter()
        .map(|s| SkippedPath {
            path: s.path.to_string_lossy().into_owned(),
            reason: s.reason,
        })
        .collect();

    for path in &walk.files {
        match triage(path, &registry, config) {
            Ok(mut report) => {
                output::prepare(&mut report, cli.all_strings, cli.min_severity.into());
                result.reports.push(report);
            }
            Err(failure) => {
                // Errors are printed even with --quiet.
                eprintln!(
                    "error: {}: {}",
                    sanitize(&failure.path),
                    sanitize(&failure.error)
                );
                result.failures.push(failure);
            }
        }
    }

    write_output(cli, &result)?;

    let fail_on = cli.fail_on.map(RiskLevel::from);
    let code = exit_code(&result, fail_on);
    for w in exit_warnings(&result, code) {
        eprintln!("warning: {w}");
    }
    Ok(ExitCode::from(code))
}

/// Exit code for a finished run: [`EXIT_RISK`] if `--fail-on` is met, else
/// [`EXIT_RUNTIME_ERROR`] if any file failed, else 0 (priority 3 > 1 > 0).
fn exit_code(run: &Run, fail_on: Option<RiskLevel>) -> u8 {
    let risky = fail_on.is_some_and(|level| run.reports.iter().any(|r| r.risk.level >= level));
    if risky {
        EXIT_RISK
    } else if !run.failures.is_empty() {
        EXIT_RUNTIME_ERROR
    } else {
        0
    }
}

/// Things a gate (`--fail-on`, exit codes) can hide: failed files masked by
/// code 3, and partial reports whose risk may be underestimated.
fn exit_warnings(run: &Run, code: u8) -> Vec<String> {
    let mut out = Vec::new();
    if code == EXIT_RISK && !run.failures.is_empty() {
        out.push(format!(
            "{} file(s) could not be analyzed; exit code 3 (--fail-on) takes precedence over 1",
            run.failures.len()
        ));
    }
    let partial = run
        .reports
        .iter()
        .filter(|r| {
            r.errors
                .iter()
                .any(|e| matches!(e.error, rtriage_core::AnalysisError::Timeout { .. }))
        })
        .count();
    if partial > 0 {
        out.push(format!(
            "{partial} report(s) timed out and are partial; their risk may be underestimated"
        ));
    }
    out
}

fn build_config(cli: &Cli) -> anyhow::Result<Config> {
    let mut config = Config {
        strings_min_len: cli.strings_min,
        ..Config::default()
    };
    if let Some(max) = cli.max_size {
        config.limits.max_file_size = max;
    }
    config.limits.max_analysis_time = std::time::Duration::from_secs(cli.timeout.get());
    if let Some(dir) = &cli.rules_dir {
        let rules = RulesDir::load(dir).context("cannot load rules")?;
        if rules.loaded.is_empty() {
            eprintln!(
                "warning: {}: no known rules files ({}); using the bundled rules",
                sanitize(&dir.to_string_lossy()),
                KNOWN_FILES.join(", ")
            );
        }
        for name in &rules.ignored {
            eprintln!(
                "warning: ignoring unknown rules file {} (known: {})",
                sanitize(name),
                KNOWN_FILES.join(", ")
            );
        }
        tracing::info!(loaded = ?rules.loaded, "rules directory");
        rules.apply(&mut config);
    }
    Ok(config)
}

/// Loads and analyzes one file. Directories get a dedicated message.
fn triage(
    path: &Path,
    registry: &Registry,
    config: &Config,
) -> Result<rtriage_core::Report, Failure> {
    let shown = path.to_string_lossy().into_owned();
    tracing::info!(path = %sanitize(&shown), "analyzing");
    if path.is_dir() {
        return Err(Failure {
            path: shown,
            error: "is a directory".into(),
        });
    }
    let input = rtriage_core::load(path, &config.limits).map_err(|e| Failure {
        path: shown,
        error: e.to_string(),
    })?;
    Ok(registry.analyze(&input, config))
}

fn write_output(cli: &Cli, run: &Run) -> anyhow::Result<()> {
    match &cli.output {
        // Files never get ANSI styles.
        Some(path) => {
            let file = File::create(path)
                .with_context(|| format!("cannot create output file {}", path.display()))?;
            let mut out = BufWriter::new(file);
            render(cli, run, &mut out, false).and_then(|()| out.flush())
        }
        None => {
            // AutoStream strips styles when stdout is not a terminal or NO_COLOR
            // is set, and enables ANSI support on legacy Windows consoles.
            let choice = if cli.color_allowed() {
                ColorChoice::Auto
            } else {
                ColorChoice::Never
            };
            let mut out = AutoStream::new(io::stdout().lock(), choice);
            render(cli, run, &mut out, true).and_then(|()| out.flush())
        }
    }
    .context("cannot write report")
}

fn render(cli: &Cli, run: &Run, out: &mut dyn Write, color: bool) -> io::Result<()> {
    match cli.format {
        OutputFormat::Text => output::text::render(
            run,
            out,
            TextOptions {
                color,
                all_strings: cli.all_strings,
                explain: cli.explain,
                defang: cli.defang,
            },
        ),
        OutputFormat::Json => output::json::render(run, out),
    }
}

/// Replaces the default panic hook, which would print the panic payload
/// (possibly containing file-derived text) to the terminal unescaped.
/// Panics inside third-party parsers are caught by the core and reported as
/// analysis errors; this hook only controls what reaches stderr.
fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let payload = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| (*s).to_owned())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "non-string panic payload".to_owned());
        let location = info
            .location()
            .map(|l| format!(" at {}:{}", l.file(), l.line()))
            .unwrap_or_default();
        eprintln!(
            "rtriage: internal panic{}: {}",
            sanitize(&location),
            sanitize(&payload)
        );
    }));
}

fn init_logging(cli: &Cli) {
    let level = match (cli.quiet, cli.verbose) {
        (true, _) => LevelFilter::ERROR,
        (false, 0) => LevelFilter::WARN,
        (false, 1) => LevelFilter::INFO,
        (false, 2) => LevelFilter::DEBUG,
        (false, _) => LevelFilter::TRACE,
    };
    tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_max_level(level)
        .with_target(false)
        .without_time()
        .with_ansi(cli.color_allowed() && io::IsTerminal::is_terminal(&io::stderr()))
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtriage_core::{Deadline, Input};

    fn report(level: RiskLevel) -> rtriage_core::Report {
        let mut r =
            Registry::default().analyze(&Input::from_bytes("t", b"x".to_vec()), &Config::default());
        r.risk.level = level;
        r
    }

    fn run(levels: &[RiskLevel], failures: usize) -> Run {
        Run {
            reports: levels.iter().map(|l| report(*l)).collect(),
            failures: (0..failures)
                .map(|i| Failure {
                    path: format!("f{i}"),
                    error: "gone".into(),
                })
                .collect(),
            skipped: Vec::new(),
        }
    }

    #[test]
    fn priority_is_risk_then_failure_then_success() {
        use RiskLevel::*;
        assert_eq!(exit_code(&run(&[Low], 0), None), 0);
        assert_eq!(exit_code(&run(&[High], 1), None), EXIT_RUNTIME_ERROR);
        assert_eq!(exit_code(&run(&[Medium], 0), Some(Medium)), EXIT_RISK);
        assert_eq!(exit_code(&run(&[Medium], 0), Some(High)), 0);
        assert_eq!(
            exit_code(&run(&[CleanLooking, High], 0), Some(Low)),
            EXIT_RISK
        );
        // 3 beats 1.
        assert_eq!(exit_code(&run(&[High], 2), Some(Medium)), EXIT_RISK);
        assert_eq!(exit_code(&run(&[Low], 2), Some(Medium)), EXIT_RUNTIME_ERROR);
        // No reports at all: a gate cannot be met.
        assert_eq!(exit_code(&run(&[], 0), Some(Low)), 0);
    }

    #[test]
    fn masked_failures_and_partial_reports_are_warned_about() {
        let masked = run(&[RiskLevel::High], 1);
        let w = exit_warnings(&masked, EXIT_RISK);
        assert!(
            w.iter().any(|w| w.contains("could not be analyzed")),
            "{w:?}"
        );
        assert!(exit_warnings(&masked, EXIT_RUNTIME_ERROR).is_empty());

        let partial = Registry::default().analyze_with_deadline(
            &Input::from_bytes("t", b"x".to_vec()),
            &Config::default(),
            Deadline::expired(),
        );
        let r = Run {
            reports: vec![partial],
            failures: Vec::new(),
            skipped: Vec::new(),
        };
        let w = exit_warnings(&r, 0);
        assert!(w.iter().any(|w| w.contains("partial")), "{w:?}");
    }
}

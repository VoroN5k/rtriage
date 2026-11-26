//! `rtriage` binary: thin CLI layer over `rtriage-core`.
#![forbid(unsafe_code)]

mod cli;
mod modes;
mod output;
mod pool;
mod worker;

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anstream::{AutoStream, ColorChoice};
use anyhow::Context;
use clap::Parser;
use rtriage_core::rules_dir::{RulesDir, KNOWN_FILES, YARA_DIR};
use rtriage_core::walk::{self, WalkOptions};
use rtriage_core::yara_sources::YaraLoadLimits;
use rtriage_core::{Config, Registry, RiskLevel};
use tracing::level_filters::LevelFilter;

use crate::cli::{Cli, Command, OutputFormat};
use crate::output::text::TextOptions;
use crate::output::{Failure, FailureKind, Run, SkippedPath};
use rtriage_sanitize::sanitize;

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
    let (mut config, plan) = match build_config(&cli) {
        Ok(setup) => setup,
        Err(err) => {
            eprintln!("error: {}", sanitize(&format!("{err:#}")));
            return ExitCode::from(EXIT_USAGE);
        }
    };
    if cli.worker {
        // Workers get compiled YARA rules from the parent, never from disk.
        return worker::run_worker(&cli, config);
    }
    if let Err(err) = setup_yara(&cli, &plan, &mut config) {
        eprintln!("error: {}", sanitize(&format!("{err:#}")));
        return ExitCode::from(EXIT_USAGE);
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
    let (paths, scan) = match &cli.command {
        Some(Command::Scan(args)) => (args.paths.as_slice(), Some(args)),
        #[cfg(feature = "tui")]
        Some(Command::Tui(args)) => return Ok(tui(&args.path, config)),
        None => (cli.files.as_slice(), None),
    };
    let walk = walk::collect(paths, WalkOptions::default());
    let mut failures: Vec<Failure> = walk
        .errors
        .iter()
        .map(|e| Failure {
            path: e.path.to_string_lossy().into_owned(),
            kind: FailureKind::Io,
            error: format!("cannot read directory: {}", e.error),
        })
        .collect();
    for f in &failures {
        report_failure(f);
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
    let skipped: Vec<SkippedPath> = walk
        .skipped
        .iter()
        .map(|s| SkippedPath {
            path: s.path.to_string_lossy().into_owned(),
            reason: s.reason,
        })
        .collect();

    let gate = if let Some(scan) = scan {
        modes::scan(cli, config, scan, &walk.files, &mut failures, &skipped)?
    } else if let ([single], false) = (walk.files.as_slice(), walk.walked_directories) {
        in_process(cli, config, single, &mut failures, skipped)?
    } else {
        modes::full_reports(cli, config, &walk.files, &mut failures, &skipped)?
    };

    let fail_on = cli.fail_on.map(RiskLevel::from);
    let code = exit_code(&gate.levels, &failures, fail_on);
    for w in exit_warnings(&failures, gate.partial, code) {
        eprintln!("warning: {w}");
    }
    Ok(ExitCode::from(code))
}

/// `rtriage tui <FILE>`: 0 after a normal quit, 2 without a terminal, 1 if
/// the file cannot be loaded or the terminal fails.
#[cfg(feature = "tui")]
fn tui(path: &Path, config: &Config) -> ExitCode {
    let opts = rtriage_tui::TuiOptions {
        config: config.clone(),
        registry: Registry::default(),
    };
    match rtriage_tui::run(path, opts) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            let code = match err {
                rtriage_tui::TuiError::NotATty => EXIT_USAGE,
                _ => EXIT_RUNTIME_ERROR,
            };
            eprintln!(
                "error: {}: {}",
                sanitize(&path.to_string_lossy()),
                sanitize(&err.to_string())
            );
            ExitCode::from(code)
        }
    }
}

/// What the exit code is computed from.
#[derive(Debug, Default)]
pub(crate) struct Gate {
    /// Risk level of every analyzed file.
    pub levels: Vec<RiskLevel>,
    /// Reports that timed out and are partial.
    pub partial: usize,
}

/// Prints a failure as it happens (even with `--quiet`).
pub(crate) fn report_failure(f: &Failure) {
    eprintln!("error: {}: {}", sanitize(&f.path), sanitize(&f.error));
}

/// A single file, analyzed in this process.
fn in_process(
    cli: &Cli,
    config: &Config,
    path: &Path,
    failures: &mut Vec<Failure>,
    skipped: Vec<SkippedPath>,
) -> anyhow::Result<Gate> {
    let registry = Registry::default();
    let mut result = Run {
        reports: Vec::new(),
        failures: std::mem::take(failures),
        skipped,
    };
    match triage(path, &registry, config) {
        Ok(mut report) => {
            output::prepare(&mut report, cli.all_strings, cli.min_severity.into());
            result.reports.push(report);
        }
        Err(failure) => {
            report_failure(&failure);
            result.failures.push(failure);
        }
    }
    write_output(cli, &result)?;
    let gate = Gate {
        levels: result.reports.iter().map(|r| r.risk.level).collect(),
        partial: result
            .reports
            .iter()
            .filter(|r| worker::Summary::of(r).partial)
            .count(),
    };
    *failures = result.failures;
    Ok(gate)
}

/// Exit code for a finished run: [`EXIT_RISK`] if `--fail-on` is met, else
/// [`EXIT_RUNTIME_ERROR`] if any file failed, else 0 (priority 3 > 1 > 0).
fn exit_code(levels: &[RiskLevel], failures: &[Failure], fail_on: Option<RiskLevel>) -> u8 {
    let risky = fail_on.is_some_and(|gate| levels.iter().any(|l| *l >= gate));
    if risky {
        EXIT_RISK
    } else if !failures.is_empty() {
        EXIT_RUNTIME_ERROR
    } else {
        0
    }
}

/// Things exit codes can hide: failures masked by code 3, files the
/// isolation layer had to stop, and partial reports.
fn exit_warnings(failures: &[Failure], partial: usize, code: u8) -> Vec<String> {
    let mut out = Vec::new();
    if code == EXIT_RISK && !failures.is_empty() {
        out.push(format!(
            "{} file(s) could not be analyzed; exit code 3 (--fail-on) takes precedence over 1",
            failures.len()
        ));
    }
    let isolated: Vec<String> = [
        FailureKind::Crashed,
        FailureKind::TimedOut,
        FailureKind::InvalidResponse,
    ]
    .iter()
    .filter_map(|k| {
        let n = failures.iter().filter(|f| f.kind == *k).count();
        (n > 0).then(|| format!("{n} {}", output::kind_name(*k)))
    })
    .collect();
    if !isolated.is_empty() {
        out.push(format!(
            "worker isolation stopped files: {} (see failures)",
            isolated.join(", ")
        ));
    }
    if partial > 0 {
        out.push(format!(
            "{partial} report(s) timed out and are partial; their risk may be underestimated"
        ));
    }
    out
}
/// Where this run's YARA rules come from (used by the parent only).
#[derive(Debug, Clone)]
pub(crate) struct YaraPlan {
    /// Compile the bundled rules (`yara.toml` `include_bundled`).
    include_bundled: bool,
    /// Loading bounds from `yara.toml`.
    load: YaraLoadLimits,
    /// `<rules-dir>/yara/`, then every `--yara`.
    paths: Vec<PathBuf>,
}

fn build_config(cli: &Cli) -> anyhow::Result<(Config, YaraPlan)> {
    let mut config = Config {
        strings_min_len: cli.strings_min,
        ..Config::default()
    };
    if let Some(max) = cli.max_size {
        config.limits.max_file_size = max;
    }
    config.limits.max_analysis_time = std::time::Duration::from_secs(cli.timeout.get());
    let mut plan = YaraPlan {
        include_bundled: true,
        load: YaraLoadLimits::default(),
        paths: Vec::new(),
    };
    if let Some(dir) = &cli.rules_dir {
        let rules = RulesDir::load(dir).context("cannot load rules")?;
        if rules.loaded.is_empty() && rules.yara_dir.is_none() {
            eprintln!(
                "warning: {}: no known rules files ({}) and no {}/ directory; using the bundled rules",
                sanitize(&dir.to_string_lossy()),
                KNOWN_FILES.join(", "),
                YARA_DIR
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
        if let Some(s) = rules.yara_settings {
            plan.include_bundled = s.include_bundled;
            plan.load = s.load;
        }
        if let Some(d) = &rules.yara_dir {
            plan.paths.push(d.clone());
        }
        rules.apply(&mut config);
    }
    plan.paths.extend(cli.yara.iter().cloned());
    Ok((config, plan))
}

/// Compiles this run's YARA rules into `config` (bundled, `<rules-dir>/yara/`,
/// `--yara`), once, in the parent.
#[cfg(feature = "yara")]
fn setup_yara(cli: &Cli, plan: &YaraPlan, config: &mut Config) -> anyhow::Result<()> {
    if cli.no_yara {
        return Ok(());
    }
    let mut sources = if plan.include_bundled {
        rtriage_core::yara_sources::bundled_sources()
    } else {
        Vec::new()
    };
    sources.extend(
        rtriage_core::yara_sources::load_sources(&plan.paths, plan.load)
            .context("cannot load YARA rules")?,
    );
    if sources.is_empty() {
        return Ok(());
    }
    let rules =
        rtriage_core::yara::YaraRules::compile(&sources).context("cannot compile YARA rules")?;
    tracing::info!(
        rules = rules.len(),
        files = sources.len(),
        "YARA rules compiled"
    );
    config.yara = Some(std::sync::Arc::new(rules));
    Ok(())
}

/// Without the `yara` feature, user rules cannot run: say so instead of
/// silently ignoring them.
#[cfg(not(feature = "yara"))]
fn setup_yara(cli: &Cli, plan: &YaraPlan, _config: &mut Config) -> anyhow::Result<()> {
    if cli.no_yara || plan.paths.is_empty() {
        return Ok(());
    }
    let given: Vec<String> = plan
        .paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    anyhow::bail!(
        "YARA rules were given ({}), but this rtriage was built without YARA support \
         (cargo feature `yara`); pass --no-yara to run without them",
        given.join(", ")
    )
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
            kind: FailureKind::Io,
            error: "is a directory".into(),
        });
    }
    let input = rtriage_core::load(path, &config.limits).map_err(|e| Failure {
        path: shown,
        kind: FailureKind::from(&e),
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
    // Log lines would be drawn over the TUI; with stderr redirected they are fine.
    #[cfg(feature = "tui")]
    let level = if matches!(cli.command, Some(Command::Tui(_)))
        && io::IsTerminal::is_terminal(&io::stderr())
    {
        LevelFilter::OFF
    } else {
        level
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

    fn failures(kinds: &[FailureKind]) -> Vec<Failure> {
        kinds
            .iter()
            .enumerate()
            .map(|(i, k)| Failure {
                path: format!("f{i}"),
                kind: *k,
                error: "gone".into(),
            })
            .collect()
    }

    #[test]
    fn priority_is_risk_then_failure_then_success() {
        use RiskLevel::*;
        let none = failures(&[]);
        let two = failures(&[FailureKind::Io, FailureKind::Crashed]);
        assert_eq!(exit_code(&[Low], &none, None), 0);
        assert_eq!(exit_code(&[High], &two, None), EXIT_RUNTIME_ERROR);
        assert_eq!(exit_code(&[Medium], &none, Some(Medium)), EXIT_RISK);
        assert_eq!(exit_code(&[Medium], &none, Some(High)), 0);
        assert_eq!(
            exit_code(&[CleanLooking, High], &none, Some(Low)),
            EXIT_RISK
        );
        // 3 beats 1.
        assert_eq!(exit_code(&[High], &two, Some(Medium)), EXIT_RISK);
        assert_eq!(exit_code(&[Low], &two, Some(Medium)), EXIT_RUNTIME_ERROR);
        // No reports at all: a gate cannot be met.
        assert_eq!(exit_code(&[], &none, Some(Low)), 0);
    }

    #[test]
    fn masked_isolated_and_partial_are_warned_about() {
        let f = failures(&[FailureKind::Io]);
        let w = exit_warnings(&f, 0, EXIT_RISK);
        assert!(
            w.iter().any(|w| w.contains("could not be analyzed")),
            "{w:?}"
        );
        assert!(exit_warnings(&f, 0, EXIT_RUNTIME_ERROR).is_empty());

        let f = failures(&[
            FailureKind::Crashed,
            FailureKind::Crashed,
            FailureKind::TimedOut,
            FailureKind::InvalidResponse,
            FailureKind::TooLarge,
        ]);
        let w = exit_warnings(&f, 0, EXIT_RUNTIME_ERROR);
        assert_eq!(
            w,
            ["worker isolation stopped files: 2 crashed, 1 timed_out, 1 invalid_response (see failures)"]
        );
        let w = exit_warnings(&[], 3, 0);
        assert!(
            w.iter().any(|w| w.contains("3 report(s) timed out")),
            "{w:?}"
        );
    }
}

//! `rtriage` binary: thin CLI layer over `rtriage-core`.
#![forbid(unsafe_code)]

mod cli;
mod output;
mod sanitize;

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::process::ExitCode;

use anstream::{AutoStream, ColorChoice};
use anyhow::Context;
use clap::Parser;
use rtriage_core::rules::ApiRuleSet;
use rtriage_core::{Config, Registry};
use tracing::level_filters::LevelFilter;

use crate::cli::{Cli, OutputFormat};
use crate::output::text::TextOptions;
use crate::output::{Failure, Run};
use crate::sanitize::sanitize;

/// At least one file could not be analyzed, or output could not be written.
const EXIT_RUNTIME_ERROR: u8 = 1;
/// Invalid invocation or configuration (clap uses the same code).
const EXIT_USAGE: u8 = 2;

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
    };

    for path in &cli.files {
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

    Ok(if result.failures.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EXIT_RUNTIME_ERROR)
    })
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
    if let Some(path) = &cli.api_rules {
        config.api_rules = Some(std::sync::Arc::new(load_api_rules(path)?));
    }
    Ok(config)
}

/// Reads and validates a custom API rules file, refusing oversized files
/// before reading them.
fn load_api_rules(path: &Path) -> anyhow::Result<ApiRuleSet> {
    let context = || format!("cannot load API rules {}", path.display());
    let len = std::fs::metadata(path).with_context(context)?.len();
    let limit = rtriage_core::rules::MAX_RULES_FILE_SIZE;
    if usize::try_from(len).map_or(true, |l| l > limit) {
        anyhow::bail!(
            "{}: file is {len} bytes, over the {limit}-byte limit",
            context()
        );
    }
    let text = std::fs::read_to_string(path).with_context(context)?;
    ApiRuleSet::parse(&text).with_context(context)
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
            error: "is a directory; directory scanning arrives with `rtriage scan`".into(),
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

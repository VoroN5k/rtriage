//! `rtriage` binary: thin CLI layer over `rtriage-core`.
#![forbid(unsafe_code)]

mod cli;
mod output;
mod sanitize;

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::process::ExitCode;

use anyhow::Context;
use clap::Parser;
use rtriage_core::{Config, Registry};
use tracing::level_filters::LevelFilter;

use crate::cli::{Cli, OutputFormat};
use crate::output::{Failure, Run};
use crate::sanitize::sanitize;

/// At least one file could not be analyzed, or output could not be written.
const EXIT_RUNTIME_ERROR: u8 = 1;

fn main() -> ExitCode {
    // clap exits with code 2 on usage errors.
    let cli = Cli::parse();
    init_logging(&cli);
    match run(&cli) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {}", sanitize(&format!("{err:#}")));
            ExitCode::from(EXIT_RUNTIME_ERROR)
        }
    }
}

fn run(cli: &Cli) -> anyhow::Result<ExitCode> {
    let config = build_config(cli);
    let registry = Registry::default();
    let mut result = Run {
        reports: Vec::new(),
        failures: Vec::new(),
    };

    for path in &cli.files {
        match triage(path, &registry, &config) {
            Ok(mut report) => {
                output::prepare(&mut report, cli.all_strings);
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

fn build_config(cli: &Cli) -> Config {
    let mut config = Config {
        strings_min_len: cli.strings_min,
        ..Config::default()
    };
    if let Some(max) = cli.max_size {
        config.limits.max_file_size = max;
    }
    config
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
    let mut out: Box<dyn Write> = match &cli.output {
        Some(path) => {
            Box::new(BufWriter::new(File::create(path).with_context(|| {
                format!("cannot create output file {}", path.display())
            })?))
        }
        None => Box::new(io::stdout().lock()),
    };
    match cli.format {
        OutputFormat::Json => output::json::render(run, &mut *out),
    }
    .and_then(|()| out.flush())
    .context("cannot write report")
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

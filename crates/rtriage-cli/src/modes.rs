//! Multi-file modes, both running files in isolated worker processes:
//!
//! - **full reports** (`rtriage <DIR>`, several files): every report in input
//!   order, as the in-process output would show it;
//! - **scan** (`rtriage scan`): a compact table sorted by risk; JSON is
//!   NDJSON ending in one `summary` line. Only compact rows are kept in
//!   memory; full reports (`--full`) are streamed out as they finish,
//!   except in Markdown, where they follow the table in its order and only
//!   the top-ranked ones the document limit can show are held (all of them
//!   with `--md-limit 0`).

use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::time::Duration;

use anstream::{AutoStream, ColorChoice};
use anyhow::Context;
use clap::ValueEnum;

use crate::cli::{Cli, OutputFormat, ScanArgs};
use crate::output::markdown::{Document, HeldBodies};
use crate::output::{json, text, Failure, SkippedPath};
use crate::pool::{self, Outcome, PoolOptions, GRACE};
use crate::worker::{Spawn, Summary, DEFAULT_MAX_RESPONSE_LINE};
use crate::{report_failure, Gate};
use rtriage_core::{Config, RiskLevel};

/// Time a new worker may take to send `ready`.
const START_TIMEOUT: Duration = Duration::from_secs(30);

/// Every report in input order (bodies held only until their turn).
pub fn full_reports(
    cli: &Cli,
    config: &Config,
    files: &[PathBuf],
    failures: &mut Vec<Failure>,
    skipped: &[SkippedPath],
) -> anyhow::Result<Gate> {
    let (mut out, color) = open_output(cli)?;
    let opts = pool_options(cli, worker_spawn(cli, config, color, WorkerBody::Full)?);
    let mut gate = Gate::default();
    let mut order = Reorder::default();
    let mut printed = 0usize;
    let json = cli.format == OutputFormat::Json;
    if json {
        json::begin_document(&mut out)?;
    }
    // Markdown goes through one document (and its budget) end to end.
    let mut sink = if cli.format == OutputFormat::Md {
        Sink::Md(Document::new(out, cli.md_limit())?)
    } else {
        Sink::Plain(out)
    };
    let result = pool::run(files, &opts, |o| {
        match o {
            Outcome::Report {
                index,
                summary,
                body,
            } => {
                gate.levels.push(summary.level);
                gate.partial += usize::from(summary.partial);
                order.put(index, Some(body));
            }
            Outcome::Failure { index, failure } => {
                report_failure(&failure);
                failures.push(failure);
                order.put(index, None);
            }
        }
        for body in order.ready() {
            match &mut sink {
                Sink::Md(doc) => doc.report(&body)?,
                Sink::Plain(out) if json => {
                    json::document_report(out, &body, printed == 0)?;
                }
                Sink::Plain(out) => {
                    if printed > 0 {
                        text::write_separator(out)?;
                    }
                    out.write_all(body.as_bytes())?;
                }
            }
            printed += 1;
        }
        Ok(())
    });
    result.context("batch analysis stopped")?;
    let mut out = match sink {
        Sink::Md(doc) => doc.finish(failures, skipped)?,
        Sink::Plain(mut out) => {
            if json {
                json::end_document(&mut out, failures, skipped)?;
            } else {
                text::render_tail(failures, skipped, &mut out, color, printed > 0)?;
            }
            out
        }
    };
    out.flush().context("cannot write report")?;
    Ok(gate)
}

/// Where full reports go.
enum Sink {
    /// Text or JSON, written directly.
    Plain(Box<dyn Write>),
    /// One Markdown document under a character budget.
    Md(Document<Box<dyn Write>>),
}

/// The batch table (or NDJSON).
pub fn scan(
    cli: &Cli,
    config: &Config,
    args: &ScanArgs,
    files: &[PathBuf],
    failures: &mut Vec<Failure>,
    skipped: &[SkippedPath],
) -> anyhow::Result<Gate> {
    let (mut out, color) = open_output(cli)?;
    let json = cli.format == OutputFormat::Json;
    let body = match (args.full, json) {
        (false, _) => WorkerBody::None,
        (true, true) => WorkerBody::Compact,
        (true, false) => WorkerBody::Full,
    };
    let opts = pool_options(cli, worker_spawn(cli, config, color, body)?);
    let mut rows: Vec<Summary> = Vec::new();
    let mut printed = 0usize;
    // Markdown puts the table first, so `--full` bodies wait (bounded by
    // the document limit; see HeldBodies).
    let md = cli.format == OutputFormat::Md;
    let mut held: HeldBodies<HeldKey> = HeldBodies::new(cli.md_limit());
    let result = pool::run(files, &opts, |o| {
        match o {
            Outcome::Report {
                index,
                summary,
                body,
            } => {
                if args.full {
                    if md {
                        let (level, score, path) = rank(&summary);
                        held.push((level, score, path.to_owned(), index), body);
                    } else if json {
                        json::ndjson_report(&mut out, &body)?;
                    } else {
                        if printed > 0 {
                            text::write_separator(&mut out)?;
                        }
                        out.write_all(body.as_bytes())?;
                    }
                    printed += 1;
                }
                rows.push(summary);
            }
            Outcome::Failure { failure, .. } => {
                report_failure(&failure);
                if json {
                    json::ndjson_failure(&mut out, &failure)?;
                }
                failures.push(failure);
            }
        }
        Ok(())
    });
    result.context("batch analysis stopped")?;
    sort_rows(&mut rows);
    let gate = Gate {
        levels: rows.iter().map(|r| r.level).collect(),
        partial: rows.iter().filter(|r| r.partial).count(),
    };
    if md {
        let mut doc = Document::new(out, cli.md_limit())?;
        doc.scan_table(&rows, failures.len())?;
        doc.held(held)?;
        doc.finish(failures, skipped)?
            .flush()
            .context("cannot write report")?;
        return Ok(gate);
    }
    if json {
        json::ndjson_summary(&mut out, &rows, failures, skipped)?;
    } else {
        if printed > 0 {
            text::write_separator(&mut out)?;
        }
        text::render_scan(&rows, failures, skipped, &mut out, color)?;
    }
    out.flush().context("cannot write report")?;
    Ok(gate)
}

/// Level descending, then score descending, then path ascending: the
/// riskiest file first. Level comes first because a rule's `risk_floor` can
/// raise it above what the score gives; without floors this equals sorting
/// by score.
pub fn sort_rows(rows: &mut [Summary]) {
    rows.sort_by(|a, b| rank(a).cmp(&rank(b)));
}

/// The table order as a key: smaller sorts first.
fn rank(s: &Summary) -> (Reverse<RiskLevel>, Reverse<u32>, &str) {
    (Reverse(s.level), Reverse(s.score), s.path.as_str())
}

/// [`rank`] owned, plus the input index so equal rows stay distinct.
type HeldKey = (Reverse<RiskLevel>, Reverse<u32>, String, usize);

/// stdout (through [`AutoStream`], which strips styles for non-terminals) or
/// the `-o` file (never styled). The flag says whether styles may be emitted.
fn open_output(cli: &Cli) -> anyhow::Result<(Box<dyn Write>, bool)> {
    match &cli.output {
        Some(path) => {
            let file = File::create(path)
                .with_context(|| format!("cannot create output file {}", path.display()))?;
            Ok((Box::new(BufWriter::new(file)), false))
        }
        None => {
            let choice = if cli.color_allowed() {
                ColorChoice::Auto
            } else {
                ColorChoice::Never
            };
            let color = cli.color_allowed();
            Ok((
                Box::new(AutoStream::new(io::stdout().lock(), choice)),
                color,
            ))
        }
    }
}

/// What workers render as the response body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkerBody {
    /// The report in the run's format (pretty JSON or text).
    Full,
    /// JSON on one line (NDJSON).
    Compact,
    /// Nothing: only the summary is needed.
    None,
}

/// The worker command line: the run's analysis and rendering options, never
/// the file list (paths go over stdin).
fn worker_spawn(
    cli: &Cli,
    config: &Config,
    color: bool,
    body: WorkerBody,
) -> anyhow::Result<Spawn> {
    let exe = std::env::current_exe().context("cannot locate the rtriage executable")?;
    let mut args: Vec<OsString> = vec!["--worker".into()];
    let mut push = |a: &str| args.push(a.into());
    push("-f");
    push(match cli.format {
        OutputFormat::Text => "text",
        OutputFormat::Json => "json",
        OutputFormat::Md => "md",
    });
    push("--strings-min");
    push(&cli.strings_min.to_string());
    push("--timeout");
    push(&cli.timeout.to_string());
    push("--min-severity");
    let sev = cli.min_severity.to_possible_value();
    push(sev.as_ref().map_or("info", |v| v.get_name()));
    if let Some(max) = cli.max_size {
        push("--max-size");
        push(&max.to_string());
    }
    for (on, flag) in [
        (cli.all_strings, "--all-strings"),
        (cli.explain, "--explain"),
        (cli.defang, "--defang"),
        (cli.no_defang, "--no-defang"),
        (color, "--worker-color"),
        (body == WorkerBody::Compact, "--worker-compact"),
        (body == WorkerBody::None, "--worker-summary-only"),
    ] {
        if on {
            push(flag);
        }
    }
    for _ in 0..cli.verbose {
        push("-v");
    }
    if let Some(dir) = &cli.rules_dir {
        args.push("--rules-dir".into());
        args.push(dir.as_os_str().to_owned());
    }
    let rules = compiled_rules(config)?;
    if rules.is_some() {
        args.push("--worker-yara".into());
    }
    Ok(Spawn {
        exe,
        args,
        env: worker_env(),
        max_line: DEFAULT_MAX_RESPONSE_LINE,
        show_stderr: cli.verbose > 0,
        rules,
    })
}

/// The run's compiled YARA rules, serialized once for every worker.
#[cfg(feature = "yara")]
fn compiled_rules(config: &Config) -> anyhow::Result<Option<std::sync::Arc<Vec<u8>>>> {
    config
        .yara
        .as_ref()
        .map(|r| r.serialize().map(std::sync::Arc::new))
        .transpose()
        .context("cannot hand YARA rules to worker processes")
}

#[cfg(not(feature = "yara"))]
fn compiled_rules(_config: &Config) -> anyhow::Result<Option<std::sync::Arc<Vec<u8>>>> {
    Ok(None)
}

/// The only environment a worker gets.
fn worker_env() -> Vec<(String, String)> {
    let mut keep: Vec<&str> = Vec::new();
    if cfg!(windows) {
        // Needed by the Windows loader and crypto/random APIs.
        keep.push("SystemRoot");
    }
    if cfg!(feature = "test-hooks") {
        keep.push("RTRIAGE_TEST_WORKER");
    }
    keep.into_iter()
        .filter_map(|k| std::env::var(k).ok().map(|v| (k.to_owned(), v)))
        .collect()
}

fn pool_options(cli: &Cli, spawn: Spawn) -> PoolOptions {
    let cpus = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
    PoolOptions {
        spawn,
        jobs: cli
            .jobs
            .and_then(|j| usize::try_from(j).ok())
            .unwrap_or(cpus)
            .min(pool::MAX_JOBS),
        file_timeout: Duration::from_secs(cli.timeout.get()).saturating_add(GRACE),
        start_timeout: START_TIMEOUT,
    }
}

/// Releases bodies in input order as soon as every earlier file finished.
/// Holds only bodies that finished ahead of a slower earlier file.
#[derive(Default)]
struct Reorder {
    next: usize,
    pending: BTreeMap<usize, Option<String>>,
}

impl Reorder {
    fn put(&mut self, index: usize, body: Option<String>) {
        self.pending.insert(index, body);
    }

    fn ready(&mut self) -> Vec<String> {
        let mut out = Vec::new();
        while let Some(body) = self.pending.remove(&self.next) {
            self.next += 1;
            out.extend(body);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtriage_core::{Format, RiskLevel};

    fn row(path: &str, score: u32) -> Summary {
        Summary {
            path: path.into(),
            format: Format::Pe,
            size: 1,
            score,
            level: RiskLevel::Low,
            top_finding: None,
            packed: false,
            partial: false,
            errors: 0,
        }
    }

    #[test]
    fn floored_level_sorts_above_score() {
        let mut floored = row("z", 0);
        floored.level = RiskLevel::High;
        let mut rows = vec![row("a", 25), floored];
        sort_rows(&mut rows);
        assert_eq!(rows[0].path, "z");
    }

    #[test]
    fn rows_sort_by_score_then_path() {
        let mut rows = vec![row("b", 10), row("a", 10), row("c", 66), row("d", 0)];
        sort_rows(&mut rows);
        let order: Vec<_> = rows.iter().map(|r| r.path.as_str()).collect();
        assert_eq!(order, ["c", "a", "b", "d"]);
    }

    #[test]
    fn reorder_releases_in_input_order() {
        let mut r = Reorder::default();
        r.put(2, Some("c".into()));
        assert!(r.ready().is_empty());
        r.put(0, Some("a".into()));
        assert_eq!(r.ready(), ["a"]);
        r.put(1, None); // a failure releases what waited behind it
        assert_eq!(r.ready(), ["c"]);
        assert!(r.pending.is_empty());
    }
}

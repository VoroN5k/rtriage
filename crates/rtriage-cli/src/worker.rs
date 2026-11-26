//! Worker processes: the hidden `--worker` mode and the parent-side client.
//!
//! Protocol version [`PROTOCOL`], one JSON object per line (see
//! `docs/robustness.md`, "Process isolation"):
//!
//! - worker → parent, once at start: `{"type":"ready","protocol":1}`
//! - parent → worker: `{"id":N,"path":{"utf8":"..."}}` (or `{"unix":[bytes]}`
//!   / `{"windows":[u16]}` for paths that are not valid UTF-8)
//! - worker → parent, one per request, in order:
//!   `{"type":"report","id":N,"summary":{...},"body":"..."}` or
//!   `{"type":"failure","id":N,"error":"..."}`
//! - EOF on the worker's stdin: it exits with code 0.
//!
//! The worker takes the next request only after answering the current one,
//! so the parent always knows which file is in flight. The body is the
//! report already rendered with the run's options (text or JSON); the parent
//! only ever parses the small [`Summary`].

use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitCode, Stdio};
use std::sync::mpsc;
use std::thread::JoinHandle;

use rtriage_core::{Config, Format, Registry, Report, RiskLevel, Severity};
use serde::{Deserialize, Serialize};

use crate::cli::{Cli, OutputFormat};
use crate::output::{self, text::TextOptions, FailureKind};

/// Worker protocol version, checked by the parent on `ready`.
pub const PROTOCOL: u32 = 1;
/// Longest request line a worker accepts (paths only).
pub const MAX_REQUEST_LINE: usize = 1 << 20;
/// Default longest response line the parent accepts (one rendered report).
pub const DEFAULT_MAX_RESPONSE_LINE: usize = 64 << 20;
/// Exit code of a worker that received a malformed request.
pub const EXIT_PROTOCOL: u8 = 2;

// ------------------------------------------------------------------ wire types

/// A path in a form that survives JSON without loss.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WirePath {
    /// Valid UTF-8.
    Utf8(String),
    /// Raw bytes of a Unix path that is not valid UTF-8.
    Unix(Vec<u8>),
    /// UTF-16 units of a Windows path that is not valid UTF-16 text.
    Windows(Vec<u16>),
}

impl WirePath {
    /// Encodes `path`, losslessly.
    pub fn from_path(path: &Path) -> Self {
        if let Some(s) = path.to_str() {
            return WirePath::Utf8(s.to_owned());
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            WirePath::Unix(path.as_os_str().as_bytes().to_vec())
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            WirePath::Windows(path.as_os_str().encode_wide().collect())
        }
        #[cfg(not(any(unix, windows)))]
        {
            WirePath::Utf8(path.to_string_lossy().into_owned())
        }
    }

    /// Decodes; `None` for a raw form of another platform.
    pub fn into_path(self) -> Option<PathBuf> {
        match self {
            WirePath::Utf8(s) => Some(PathBuf::from(s)),
            #[cfg(unix)]
            WirePath::Unix(bytes) => {
                use std::os::unix::ffi::OsStringExt;
                Some(PathBuf::from(std::ffi::OsString::from_vec(bytes)))
            }
            #[cfg(windows)]
            WirePath::Windows(units) => {
                use std::os::windows::ffi::OsStringExt;
                Some(PathBuf::from(std::ffi::OsString::from_wide(&units)))
            }
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }
}

/// Parent → worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// Correlates the response.
    pub id: u64,
    /// File to analyze.
    pub path: WirePath,
}

/// The few report fields the parent needs (table, sorting, `--fail-on`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Summary {
    /// Path (lossy UTF-8).
    pub path: String,
    /// Detected format.
    pub format: Format,
    /// File size in bytes.
    pub size: u64,
    /// Risk score.
    pub score: u32,
    /// Risk level.
    pub level: RiskLevel,
    /// Highest-ranked finding that scored, if any.
    pub top_finding: Option<TopFinding>,
    /// `analysis_limited` contains `packed`.
    pub packed: bool,
    /// At least one analyzer timed out: the report is partial.
    pub partial: bool,
    /// Number of analyzer errors.
    pub errors: usize,
}

/// The finding shown in a summary row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopFinding {
    /// Finding ID.
    pub id: String,
    /// Finding title.
    pub title: String,
    /// Severity.
    pub severity: Severity,
}

impl Summary {
    /// Summary of `report` (computed before display filtering).
    pub fn of(report: &Report) -> Self {
        // Findings are sorted severity↓, confidence↓, id↑; take the first that
        // scored, else the first at all.
        let scored = |f: &&rtriage_core::Finding| {
            report
                .risk
                .breakdown
                .iter()
                .any(|e| e.id == f.id && e.points > 0)
        };
        let top = report
            .findings
            .iter()
            .find(scored)
            .or_else(|| report.findings.iter().find(|f| f.suppressed.is_none()));
        Summary {
            path: report.file.path.clone(),
            format: report.file.format,
            size: report.file.size,
            score: report.risk.score,
            level: report.risk.level,
            top_finding: top.map(|f| TopFinding {
                id: f.id.to_owned(),
                title: f.title.clone(),
                severity: f.severity,
            }),
            packed: !report.analysis_limited.is_empty(),
            partial: report
                .errors
                .iter()
                .any(|e| matches!(e.error, rtriage_core::AnalysisError::Timeout { .. })),
            errors: report.errors.len(),
        }
    }
}

/// Worker → parent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Response {
    /// Sent once, before any request is read.
    Ready {
        /// [`PROTOCOL`].
        protocol: u32,
    },
    /// A file was analyzed.
    Report {
        /// Request ID.
        id: u64,
        /// Parsed by the parent.
        summary: Summary,
        /// The report rendered for the run's output format; opaque to the parent.
        body: String,
    },
    /// A file could not be analyzed.
    Failure {
        /// Request ID.
        id: u64,
        /// Failure kind (`io` / `too_large` from a worker).
        kind: FailureKind,
        /// Human-readable reason.
        error: String,
    },
}

// ------------------------------------------------------------------ bounded lines

/// One line read with a length bound.
#[derive(Debug, PartialEq, Eq)]
pub enum Line {
    /// A complete line without its terminator.
    Data(Vec<u8>),
    /// More than the limit before a newline; the reader is left mid-line.
    TooLong,
    /// End of input (a final unterminated line is returned as `Line` first).
    Eof,
}

/// Reads one `\n`-terminated line of at most `limit` bytes.
///
/// # Errors
/// I/O errors from `reader`.
pub fn read_line_bounded(reader: &mut impl BufRead, limit: usize) -> io::Result<Line> {
    let mut buf = Vec::new();
    let cap = u64::try_from(limit).unwrap_or(u64::MAX).saturating_add(1);
    let n = reader.by_ref().take(cap).read_until(b'\n', &mut buf)?;
    if n == 0 {
        return Ok(Line::Eof);
    }
    if buf.last() == Some(&b'\n') {
        buf.pop();
        if buf.last() == Some(&b'\r') {
            buf.pop();
        }
        return Ok(Line::Data(buf));
    }
    if buf.len() > limit {
        return Ok(Line::TooLong);
    }
    Ok(Line::Data(buf)) // last line without a newline
}

// ------------------------------------------------------------------ worker side

/// Runs the worker loop on stdin/stdout. Never returns an error: protocol
/// violations end the process with [`EXIT_PROTOCOL`].
pub fn run_worker(cli: &Cli, config: &Config) -> ExitCode {
    #[cfg(feature = "test-hooks")]
    test_hooks::at_start();
    let registry = Registry::default();
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    if send(&mut out, &Response::Ready { protocol: PROTOCOL }).is_err() {
        return ExitCode::from(EXIT_PROTOCOL);
    }
    loop {
        let line = match read_line_bounded(&mut input, MAX_REQUEST_LINE) {
            Ok(Line::Data(l)) if l.is_empty() => continue,
            Ok(Line::Data(l)) => l,
            Ok(Line::Eof) => return ExitCode::SUCCESS,
            Ok(Line::TooLong) | Err(_) => return protocol_error("unreadable or oversized request"),
        };
        let Ok(req) = serde_json::from_slice::<Request>(&line) else {
            return protocol_error("malformed request");
        };
        let response = handle(cli, config, &registry, req);
        if send(&mut out, &response).is_err() {
            // Parent went away.
            return ExitCode::from(EXIT_PROTOCOL);
        }
    }
}

fn protocol_error(what: &str) -> ExitCode {
    eprintln!("rtriage worker: {what}");
    ExitCode::from(EXIT_PROTOCOL)
}

fn send(out: &mut impl Write, response: &Response) -> io::Result<()> {
    serde_json::to_writer(&mut *out, response)?;
    out.write_all(b"\n")?;
    out.flush()
}

fn handle(cli: &Cli, config: &Config, registry: &Registry, req: Request) -> Response {
    let Some(path) = req.path.into_path() else {
        return Response::Failure {
            id: req.id,
            kind: FailureKind::Io,
            error: "path encoding is not supported on this platform".into(),
        };
    };
    #[cfg(feature = "test-hooks")]
    test_hooks::before(&path);
    match crate::triage(&path, registry, config) {
        Ok(mut report) => {
            let summary = Summary::of(&report);
            output::prepare(&mut report, cli.all_strings, cli.min_severity.into());
            Response::Report {
                id: req.id,
                summary,
                body: render_body(cli, &report),
            }
        }
        Err(f) => Response::Failure {
            id: req.id,
            kind: f.kind,
            error: f.error,
        },
    }
}

/// The report rendered as the run's output format (empty with
/// `--worker-summary-only`).
fn render_body(cli: &Cli, report: &Report) -> String {
    if cli.worker_summary_only {
        return String::new();
    }
    match cli.format {
        OutputFormat::Text => output::text::render_report_string(
            report,
            TextOptions {
                color: cli.worker_color,
                all_strings: cli.all_strings,
                explain: cli.explain,
                defang: cli.defang,
            },
        ),
        OutputFormat::Json if cli.worker_compact => {
            serde_json::to_string(report).unwrap_or_default()
        }
        OutputFormat::Json => serde_json::to_string_pretty(report).unwrap_or_default(),
    }
}

/// Deterministic misbehaviour for tests of the parent's isolation (cargo
/// feature `test-hooks`, never in release builds). `RTRIAGE_TEST_WORKER` is
/// `crash:<name>`, `hang:<name>` or `spam:<name>`; it fires when the file
/// name equals `<name>`.
#[cfg(feature = "test-hooks")]
mod test_hooks {
    use std::io::Write;
    use std::path::Path;

    /// Environment variable read by the hooks (forwarded by the parent).
    pub const VAR: &str = "RTRIAGE_TEST_WORKER";

    /// `startfail:1`: die before `ready` (the parent must give up).
    pub fn at_start() {
        if std::env::var(VAR).is_ok_and(|s| s.split(',').any(|r| r == "startfail:1")) {
            std::process::exit(9);
        }
    }

    pub fn before(path: &Path) {
        let Ok(spec) = std::env::var(VAR) else {
            return;
        };
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
        for rule in spec.split(',') {
            let Some((what, target)) = rule.split_once(':') else {
                continue;
            };
            if name.as_deref() != Some(target) {
                continue;
            }
            match what {
                "crash" => std::process::abort(),
                "hang" => loop {
                    std::thread::sleep(std::time::Duration::from_secs(3600));
                },
                "spam" => {
                    // An endless line: the parent must cut it off.
                    let mut out = std::io::stdout().lock();
                    let chunk = [b'x'; 1 << 16];
                    while out.write_all(&chunk).is_ok() {}
                    std::process::exit(0);
                }
                _ => {}
            }
        }
    }
}

// ------------------------------------------------------------------ parent side

/// What the parent hears from a worker.
#[derive(Debug)]
pub enum Event {
    /// A well-formed message.
    Message(Response),
    /// A line over the limit: the worker is misbehaving; kill it.
    TooLong,
    /// A line that is not a valid response.
    Invalid(String),
    /// stdout closed (the worker exited or crashed).
    Closed,
}

/// Identifies the worker an event came from: pool slot and that slot's
/// generation (bumped on every respawn, so stale events are ignored).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tag {
    /// Pool slot.
    pub slot: usize,
    /// Respawn generation of the slot.
    pub generation: u64,
}

/// How to start workers.
#[derive(Debug, Clone)]
pub struct Spawn {
    /// The rtriage executable.
    pub exe: PathBuf,
    /// Arguments, including `--worker`.
    pub args: Vec<std::ffi::OsString>,
    /// The only environment variables the worker gets.
    pub env: Vec<(String, String)>,
    /// Longest accepted response line.
    pub max_line: usize,
    /// Let the worker's stderr through (verbose runs).
    pub show_stderr: bool,
}

/// A running worker process.
pub struct Worker {
    child: Child,
    stdin: Option<ChildStdin>,
    reader: Option<JoinHandle<()>>,
}

impl Worker {
    /// Starts a worker; its stdout is read by a dedicated thread that sends
    /// tagged events to `tx`, with lines capped at `spawn.max_line` bytes.
    ///
    /// # Errors
    /// Spawn failures.
    pub fn spawn(spawn: &Spawn, tag: Tag, tx: mpsc::Sender<(Tag, Event)>) -> io::Result<Worker> {
        let mut cmd = Command::new(&spawn.exe);
        cmd.args(&spawn.args)
            .env_clear()
            .envs(spawn.env.iter().map(|(k, v)| (k, v)))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(if spawn.show_stderr {
                Stdio::inherit()
            } else {
                Stdio::null()
            });
        let mut child = cmd.spawn()?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("worker stdout not captured"))?;
        let stdin = child.stdin.take();
        let max_line = spawn.max_line;
        let reader = std::thread::Builder::new()
            .name(format!("rtriage-worker-{}", tag.slot))
            .spawn(move || read_events(io::BufReader::new(stdout), max_line, tag, &tx))?;
        Ok(Worker {
            child,
            stdin,
            reader: Some(reader),
        })
    }

    /// Sends one request.
    ///
    /// # Errors
    /// The worker's stdin is closed or broken.
    pub fn send(&mut self, req: &Request) -> io::Result<()> {
        let stdin = self
            .stdin
            .as_mut()
            .ok_or_else(|| io::Error::other("worker stdin already closed"))?;
        serde_json::to_writer(&mut *stdin, req)?;
        stdin.write_all(b"\n")?;
        stdin.flush()
    }

    /// Closes stdin (the worker then exits on its own) and waits for it.
    pub fn finish(mut self) -> Option<std::process::ExitStatus> {
        drop(self.stdin.take());
        let status = self.child.wait().ok();
        self.join_reader();
        status
    }

    /// Kills the worker and reaps it.
    pub fn kill(mut self) -> Option<std::process::ExitStatus> {
        drop(self.stdin.take());
        let _ = self.child.kill();
        let status = self.child.wait().ok();
        self.join_reader();
        status
    }

    fn join_reader(&mut self) {
        if let Some(r) = self.reader.take() {
            let _ = r.join();
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        // Never leave a worker running behind an early return.
        if self.reader.is_some() {
            let _ = self.child.kill();
            let _ = self.child.wait();
            self.join_reader();
        }
    }
}

/// Reader thread: turns stdout lines into events until EOF or a bad line.
fn read_events(
    mut reader: impl BufRead,
    max_line: usize,
    tag: Tag,
    tx: &mpsc::Sender<(Tag, Event)>,
) {
    loop {
        let event = match read_line_bounded(&mut reader, max_line) {
            Ok(Line::Data(l)) if l.is_empty() => continue,
            Ok(Line::Data(l)) => match serde_json::from_slice::<Response>(&l) {
                Ok(r) => Event::Message(r),
                Err(e) => Event::Invalid(e.to_string()),
            },
            Ok(Line::TooLong) => Event::TooLong,
            Ok(Line::Eof) | Err(_) => Event::Closed,
        };
        let stop = !matches!(event, Event::Message(_));
        if tx.send((tag, event)).is_err() || stop {
            return;
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn lines(input: &[u8], limit: usize) -> Vec<Line> {
        let mut r = io::BufReader::new(input);
        let mut out = Vec::new();
        loop {
            let l = read_line_bounded(&mut r, limit).unwrap();
            let end = matches!(l, Line::Eof | Line::TooLong);
            out.push(l);
            if end {
                return out;
            }
        }
    }

    #[test]
    fn bounded_lines() {
        assert_eq!(
            lines(b"ab\r\ncd\nef", 10),
            [
                Line::Data(b"ab".to_vec()),
                Line::Data(b"cd".to_vec()),
                Line::Data(b"ef".to_vec()),
                Line::Eof
            ]
        );
        // Exactly at the limit is fine; one byte more is not.
        assert_eq!(lines(b"12345\n", 5)[0], Line::Data(b"12345".to_vec()));
        assert_eq!(lines(b"123456\n", 5)[0], Line::TooLong);
        assert_eq!(lines(b"123456", 5)[0], Line::TooLong);
    }

    #[test]
    fn reader_stops_on_bad_lines() {
        let tag = Tag {
            slot: 0,
            generation: 0,
        };
        let (tx, rx) = mpsc::channel();
        let input =
            b"{\"type\":\"ready\",\"protocol\":1}\nnot json\n{\"type\":\"ready\",\"protocol\":1}\n";
        read_events(io::BufReader::new(&input[..]), 1024, tag, &tx);
        let got: Vec<_> = rx.try_iter().map(|(_, e)| e).collect();
        assert!(matches!(
            got[0],
            Event::Message(Response::Ready { protocol: 1 })
        ));
        assert!(matches!(got[1], Event::Invalid(_)));
        assert_eq!(got.len(), 2, "nothing is read after a bad line");

        let (tx, rx) = mpsc::channel();
        read_events(io::BufReader::new(&[b'x'; 100][..]), 10, tag, &tx);
        assert!(matches!(rx.try_iter().next(), Some((_, Event::TooLong))));
    }

    #[test]
    fn wire_paths_roundtrip() {
        let p = PathBuf::from("dir/файл.bin");
        assert_eq!(
            WirePath::from_path(&p),
            WirePath::Utf8("dir/файл.bin".into())
        );
        assert_eq!(WirePath::from_path(&p).into_path(), Some(p));
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let raw = PathBuf::from(std::ffi::OsStr::from_bytes(b"bad\xffname"));
            let w = WirePath::from_path(&raw);
            assert_eq!(w, WirePath::Unix(b"bad\xffname".to_vec()));
            assert_eq!(w.into_path(), Some(raw));
            assert_eq!(WirePath::Windows(vec![0xD800]).into_path(), None);
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStringExt;
            let raw = PathBuf::from(std::ffi::OsString::from_wide(&[0x61, 0xD800, 0x62]));
            let w = WirePath::from_path(&raw);
            assert_eq!(w, WirePath::Windows(vec![0x61, 0xD800, 0x62]));
            assert_eq!(w.into_path(), Some(raw));
            assert_eq!(WirePath::Unix(vec![0xff]).into_path(), None);
        }
    }

    #[test]
    fn messages_have_a_stable_shape() {
        let req = Request {
            id: 7,
            path: WirePath::Utf8("a.exe".into()),
        };
        assert_eq!(
            serde_json::to_string(&req).unwrap(),
            r#"{"id":7,"path":{"utf8":"a.exe"}}"#
        );
        assert_eq!(
            serde_json::to_string(&Response::Ready { protocol: 1 }).unwrap(),
            r#"{"type":"ready","protocol":1}"#
        );
        assert!(serde_json::from_str::<Request>(r#"{"id":1,"path":{"utf8":"a"},"x":1}"#).is_err());
    }
}

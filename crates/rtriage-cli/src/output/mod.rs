//! Report renderers.

mod common;
pub mod json;
// Wired into the CLI in the Markdown steps that follow (M6.1 task 4).
#[allow(dead_code)]
pub mod md;
pub mod text;

use rtriage_core::walk::SkipReason;
use rtriage_core::{Report, Severity};
use serde::{Deserialize, Serialize};

/// A file that could not be analyzed at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Failure {
    /// Path as given on the command line (lossy UTF-8).
    pub path: String,
    /// What kind of failure.
    pub kind: FailureKind,
    /// Human-readable reason.
    pub error: String,
}

/// Why a file has no report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    /// Missing, unreadable, not a regular file, or a directory that cannot be read.
    Io,
    /// Over `--max-size`.
    TooLarge,
    /// The worker did not answer within `--timeout` plus a grace period and was killed.
    TimedOut,
    /// The worker process died while analyzing the file.
    Crashed,
    /// The worker answered with an oversized or malformed response and was killed.
    InvalidResponse,
}

/// The JSON name of a failure kind (`timed_out`, ...).
pub fn kind_name(k: FailureKind) -> &'static str {
    match k {
        FailureKind::Io => "io",
        FailureKind::TooLarge => "too_large",
        FailureKind::TimedOut => "timed_out",
        FailureKind::Crashed => "crashed",
        FailureKind::InvalidResponse => "invalid_response",
    }
}

impl From<&rtriage_core::Error> for FailureKind {
    fn from(e: &rtriage_core::Error) -> Self {
        match e {
            rtriage_core::Error::FileTooLarge { .. } => Self::TooLarge,
            _ => Self::Io,
        }
    }
}

/// Everything produced by one invocation.
#[derive(Debug, Clone, PartialEq)]
pub struct Run {
    /// Reports for files that were analyzed.
    pub reports: Vec<Report>,
    /// Files that could not be analyzed.
    pub failures: Vec<Failure>,
    /// Paths skipped while walking directories (not failures).
    pub skipped: Vec<SkippedPath>,
}

/// A path skipped on purpose while walking directories.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SkippedPath {
    /// Path (lossy UTF-8).
    pub path: String,
    /// Why it was skipped.
    pub reason: SkipReason,
}

/// Output-level filtering, applied after scoring: string selection and the
/// `--min-severity` finding filter. `risk` (score and breakdown) is left
/// untouched, so it always reflects every finding.
pub fn prepare(report: &mut Report, all_strings: bool, min_severity: Severity) {
    if !all_strings {
        if let Some(strings) = report.facts.strings.as_mut() {
            strings.retain_classified();
        }
    }
    report.findings.retain(|f| f.severity >= min_severity);
}

//! Report renderers.

pub mod json;
pub mod text;

use rtriage_core::walk::SkipReason;
use rtriage_core::{Report, Severity};
use serde::Serialize;

/// A file that could not be analyzed at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Failure {
    /// Path as given on the command line (lossy UTF-8).
    pub path: String,
    /// Human-readable reason.
    pub error: String,
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

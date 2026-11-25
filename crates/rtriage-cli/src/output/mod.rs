//! Report renderers.

pub mod json;

use rtriage_core::Report;
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
}

/// Applies output-level filtering to a report (currently: string selection).
pub fn prepare(report: &mut Report, all_strings: bool) {
    if !all_strings {
        if let Some(strings) = report.facts.strings.as_mut() {
            strings.retain_classified();
        }
    }
}

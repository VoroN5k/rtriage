//! Error types.
//!
//! Two layers:
//! - [`Error`]: fatal problems that prevent analysing a file at all
//!   (unreadable, not a regular file, over the size limit).
//! - [`AnalysisError`]: a partial failure inside one analyzer. It is recorded
//!   in the report and the remaining analyzers keep running.

use std::path::PathBuf;

use serde::Serialize;

/// Fatal error: the file could not be analysed at all.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The file could not be opened or read.
    #[error("cannot read {path}: {source}", path = path.display())]
    Io {
        /// Path that failed.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The path exists but is not a regular file (directory, device, ...).
    #[error("{path} is not a regular file", path = path.display())]
    NotAFile {
        /// Offending path.
        path: PathBuf,
    },

    /// The file is larger than [`Limits::max_file_size`](crate::limits::Limits::max_file_size).
    #[error("file is {size} bytes, over the {limit}-byte limit")]
    FileTooLarge {
        /// Actual file size in bytes.
        size: u64,
        /// Configured limit in bytes.
        limit: u64,
    },
}

/// Non-fatal failure of a single analyzer. Serialized into the report.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum AnalysisError {
    /// A structure extends past the end of the data.
    #[error("{what} truncated at offset {offset:#x}: needs {needed} bytes, {available} available")]
    Truncated {
        /// Name of the structure, e.g. `"PE optional header"`.
        what: &'static str,
        /// File offset where the structure starts.
        offset: u64,
        /// Bytes the structure requires.
        needed: u64,
        /// Bytes actually available from `offset`.
        available: u64,
    },

    /// A file-derived count or size exceeded a configured resource limit.
    #[error("{limit} limit exceeded: {value} > {max}")]
    LimitExceeded {
        /// Name of the limit, e.g. `"max_sections"`.
        limit: &'static str,
        /// Value claimed by the file.
        value: u64,
        /// Configured maximum.
        max: u64,
    },

    /// The per-file time limit expired before this analyzer finished (or started).
    #[error("analysis time limit of {limit_ms} ms exceeded")]
    Timeout {
        /// Configured limit in milliseconds.
        limit_ms: u64,
    },

    /// The analysis was cancelled interactively (TUI) before this analyzer
    /// finished. Never produced by the CLI.
    #[error("analysis cancelled")]
    Cancelled,

    /// A bug in rtriage itself (e.g. a built-in pattern failed to compile).
    /// Never caused by the input file.
    #[error("internal error: {reason}")]
    Internal {
        /// What went wrong.
        reason: String,
    },

    /// A structure is present but internally inconsistent.
    #[error("malformed {what}: {reason}")]
    Malformed {
        /// Name of the structure.
        what: &'static str,
        /// Human-readable reason (may come from a parsing crate).
        reason: String,
    },
}

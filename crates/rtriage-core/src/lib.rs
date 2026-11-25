//! `rtriage-core`: static triage of PE and ELF binaries.
//!
//! Parses untrusted input files, runs independent analyzers over them and
//! produces an evidence-backed report without ever executing the input.
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
#![warn(missing_docs)]

// Third-party parsers are wrapped in `catch_unwind` (see `analyzers::pe::guarded`),
// which is a no-op under `panic = "abort"`. Refuse to build that way.
#[cfg(not(panic = "unwind"))]
compile_error!(
    "rtriage-core requires panic = \"unwind\": parser panics are caught with catch_unwind"
);

pub mod analyzers;
pub mod config;
pub mod deadline;
pub mod error;
pub mod input;
pub mod limits;
pub mod report;
pub mod rules;
pub mod rules_dir;
pub mod scoring;

pub use analyzers::{AnalysisContext, Analyzer, Registry};
pub use config::{Config, Thresholds};
pub use deadline::{Budget, Deadline};
pub use error::{AnalysisError, Error};
pub use input::{load, sniff_format, Input};
pub use limits::Limits;
pub use report::{
    Category, Confidence, Evidence, Facts, FileInfo, Finding, Format, Hashes, PeFacts,
    PeHeaderFacts, PeKind, Report, ReportBuilder, Risk, RiskLevel, Severity, StringsIncluded,
};

/// Crate version, as recorded in `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

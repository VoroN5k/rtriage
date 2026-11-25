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

/// Crate version, as recorded in `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

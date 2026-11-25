//! Builders for **synthetic** PE (and later ELF) binaries used in tests.
//!
//! No real malware is ever stored in this repository; every fixture is
//! assembled byte by byte here. The binaries are structurally valid enough
//! for static parsers but contain no meaningful code and are never executed.
//!
//! This crate is a dev-dependency only and never part of a shipped binary,
//! so panicking helpers are acceptable here: a panic means a broken test.
#![forbid(unsafe_code)]
#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
#![warn(missing_docs)]

pub mod elf;
pub mod pe;

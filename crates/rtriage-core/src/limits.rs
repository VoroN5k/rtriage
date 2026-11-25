//! Resource limits applied to every file-derived size and count.
//!
//! Input files are hostile: a header may claim billions of sections or a
//! string table larger than the file. Every such value is checked against
//! [`Limits`] *before* allocating or looping, and an over-limit value becomes
//! an [`AnalysisError::LimitExceeded`] instead of an allocation.

use serde::Serialize;

use std::time::Duration;

use crate::error::AnalysisError;

/// Configurable resource limits. [`Limits::default`] gives the documented defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Limits {
    /// Largest file accepted for analysis, in bytes. Default: 512 MiB.
    pub max_file_size: u64,
    /// Max PE sections / ELF section headers processed. Default: 4096.
    /// (The Windows loader caps PE at 96; ELF files may legitimately have more.)
    pub max_sections: usize,
    /// Max ELF program headers processed. Default: 4096.
    pub max_segments: usize,
    /// Max imported symbols processed across all libraries. Default: 65 536.
    pub max_imports: usize,
    /// Max imported libraries (import descriptors) processed. Default: 4096.
    pub max_import_libraries: usize,
    /// Max TLS callbacks read. Default: 256.
    pub max_tls_callbacks: usize,
    /// Max debug directory entries read. Default: 64.
    pub max_debug_entries: usize,
    /// Max resource leaves read. Default: 4096.
    pub max_resources: usize,
    /// Max `WIN_CERTIFICATE` entries read. Default: 16.
    pub max_certificates: usize,
    /// Max ELF `PT_DYNAMIC` entries read. Default: 4096.
    pub max_dynamic_entries: usize,
    /// Max ELF symbols read per symbol table. Default: 200 000.
    pub max_symbols: usize,
    /// Max exported symbols processed. Default: 65 536.
    pub max_exports: usize,
    /// Max strings kept by the string extractor. Default: 200 000.
    pub max_strings: usize,
    /// Strings longer than this are truncated, in characters. Default: 4096.
    pub max_string_len: usize,
    /// Hard wall-clock limit for analysing one file. Default: 30 s.
    /// Enforced cooperatively (see [`crate::deadline`]).
    pub max_analysis_time: Duration,
    /// Max loop steps per format parser over attacker-controlled structures
    /// (import thunks, TLS callbacks, ...). Default: 10 000 000.
    pub max_parser_steps: u64,
}

impl Limits {
    /// Default for [`Limits::max_file_size`]: 512 MiB.
    pub const DEFAULT_MAX_FILE_SIZE: u64 = 512 * 1024 * 1024;
    /// Default for [`Limits::max_analysis_time`]: 30 s.
    pub const DEFAULT_MAX_ANALYSIS_TIME: Duration = Duration::from_secs(30);

    /// Returns `Ok(())` if `value <= max`, otherwise a [`AnalysisError::LimitExceeded`]
    /// naming `limit`.
    pub fn ensure(limit: &'static str, value: u64, max: u64) -> Result<(), AnalysisError> {
        if value <= max {
            Ok(())
        } else {
            Err(AnalysisError::LimitExceeded { limit, value, max })
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_file_size: Self::DEFAULT_MAX_FILE_SIZE,
            max_sections: 4096,
            max_segments: 4096,
            max_imports: 65_536,
            max_import_libraries: 4096,
            max_tls_callbacks: 256,
            max_debug_entries: 64,
            max_resources: 4096,
            max_certificates: 16,
            max_dynamic_entries: 4096,
            max_symbols: 200_000,
            max_exports: 65_536,
            max_strings: 200_000,
            max_string_len: 4096,
            max_analysis_time: Self::DEFAULT_MAX_ANALYSIS_TIME,
            max_parser_steps: 10_000_000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_file_size_is_512_mib() {
        assert_eq!(Limits::default().max_file_size, 536_870_912);
    }

    #[test]
    fn ensure_accepts_value_at_limit() {
        assert_eq!(Limits::ensure("max_sections", 4096, 4096), Ok(()));
    }

    #[test]
    fn ensure_rejects_value_over_limit() {
        assert_eq!(
            Limits::ensure("max_sections", u64::from(u32::MAX), 4096),
            Err(AnalysisError::LimitExceeded {
                limit: "max_sections",
                value: u64::from(u32::MAX),
                max: 4096,
            })
        );
    }
}

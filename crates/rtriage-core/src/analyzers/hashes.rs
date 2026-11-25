//! Whole-file MD5, SHA-1 and SHA-256.
//!
//! MD5 and SHA-1 are cryptographically broken but remain the lingua franca of
//! threat-intel feeds, so they are reported alongside SHA-256.

use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};

use super::{AnalysisContext, Analyzer};
use crate::deadline::Deadline;
use crate::error::AnalysisError;
use crate::report::{Format, Hashes, ReportBuilder};

/// Bytes hashed between deadline checks.
const DEADLINE_CHUNK: usize = 1 << 20;

/// Computes [`Hashes`] for every input, regardless of format.
#[derive(Debug, Clone, Copy, Default)]
pub struct HashesAnalyzer;

impl Analyzer for HashesAnalyzer {
    fn name(&self) -> &'static str {
        "hashes"
    }

    fn applies_to(&self, _format: Format) -> bool {
        true
    }

    fn run(&self, ctx: &AnalysisContext<'_>, out: &mut ReportBuilder) -> Result<(), AnalysisError> {
        out.set_hashes(compute_bounded(&ctx.input.data, &ctx.deadline)?);
        Ok(())
    }
}

/// Hashes `data` with MD5, SHA-1 and SHA-256.
pub fn compute(data: &[u8]) -> Hashes {
    Hashes {
        md5: to_hex(&Md5::digest(data)),
        sha1: to_hex(&Sha1::digest(data)),
        sha256: to_hex(&Sha256::digest(data)),
    }
}

/// [`compute`] in one chunked pass, checking `deadline` every MiB.
///
/// # Errors
/// [`AnalysisError::Timeout`] if the deadline passes.
pub fn compute_bounded(data: &[u8], deadline: &Deadline) -> Result<Hashes, AnalysisError> {
    let (mut md5, mut sha1, mut sha256) = (Md5::new(), Sha1::new(), Sha256::new());
    for chunk in data.chunks(DEADLINE_CHUNK) {
        deadline.check()?;
        md5.update(chunk);
        sha1.update(chunk);
        sha256.update(chunk);
    }
    Ok(Hashes {
        md5: to_hex(&md5.finalize()),
        sha1: to_hex(&sha1.finalize()),
        sha256: to_hex(&sha256.finalize()),
    })
}

/// Lowercase hex encoding.
fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            // Writing to a String cannot fail.
            let _ = write!(s, "{b:02x}");
            s
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::input::Input;
    use crate::Registry;

    #[test]
    fn empty_input_known_vectors() {
        let h = compute(b"");
        assert_eq!(h.md5, "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(h.sha1, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            h.sha256,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn abc_known_vectors() {
        let h = compute(b"abc");
        assert_eq!(h.md5, "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(h.sha1, "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            h.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn chunked_matches_one_shot() {
        let data: Vec<u8> = (0..(2 * DEADLINE_CHUNK + 123)).map(|i| i as u8).collect();
        assert_eq!(
            compute_bounded(&data, &Deadline::never()).unwrap(),
            compute(&data)
        );
    }

    #[test]
    fn expired_deadline_stops_hashing() {
        assert!(matches!(
            compute_bounded(b"abc", &Deadline::expired()),
            Err(AnalysisError::Timeout { .. })
        ));
    }

    #[test]
    fn analyzer_fills_file_info() {
        let input = Input::from_bytes("abc.bin", b"abc".to_vec());
        let report = Registry::default().analyze(&input, &Config::default());
        let hashes = report.file.hashes.unwrap();
        assert_eq!(hashes.md5, "900150983cd24fb0d6963f7d28e17f72");
    }
}

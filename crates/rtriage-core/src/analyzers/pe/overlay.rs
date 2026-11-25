//! Overlay: data appended after the end of the PE image.
//!
//! The image ends at the furthest of `SizeOfHeaders` and every section's
//! `PointerToRawData + SizeOfRawData`. An Authenticode certificate table that
//! starts at or after that point is expected trailing data and is skipped;
//! anything after it (not covered by the signature) is overlay.
//!
//! Findings (see `docs/heuristics.md`):
//! - `PE-OVERLAY`: overlay present (context).
//! - `PE-OVERLAY-HIGH-ENTROPY`: overlay looks compressed/encrypted and is not
//!   a recognised archive/installer format.
//! - `PE-OVERLAY-EMBEDDED-PE`: overlay starts with another PE file.

use super::PeImage;
use crate::analyzers::entropy::shannon_bounded;
use crate::analyzers::{AnalysisContext, Analyzer};
use crate::error::AnalysisError;
use crate::input::sniff_format;
use crate::report::{
    Category, Confidence, Evidence, Finding, Format, PeFacts, PeOverlayFacts, ReportBuilder,
    Severity,
};

/// Data directory index of the certificate table (holds a *file offset*).
const DIRECTORY_SECURITY: usize = 4;

/// Formats whose own compression explains high entropy.
pub const COMPRESSED_KINDS: &[&str] = &[
    "zip", "7z", "rar", "cab", "gzip", "nsis", "png", "jpeg", "gif",
];

/// Reports the overlay and judges its contents.
#[derive(Debug, Clone, Copy, Default)]
pub struct PeOverlayAnalyzer;

impl Analyzer for PeOverlayAnalyzer {
    fn name(&self) -> &'static str {
        "pe-overlay"
    }

    fn applies_to(&self, format: Format) -> bool {
        format == Format::Pe
    }

    fn run(&self, ctx: &AnalysisContext<'_>, out: &mut ReportBuilder) -> Result<(), AnalysisError> {
        let Some(pe) = super::pe_or_skip(ctx) else {
            return Ok(());
        };
        let data = &ctx.input.data;
        let Some(start) = overlay_start(pe, data.len()) else {
            return Ok(());
        };
        let Some(bytes) = data.get(start..).filter(|b| !b.is_empty()) else {
            return Ok(());
        };
        let t = &ctx.config.thresholds;
        let entropy = if bytes.len() >= t.section_entropy_min_size {
            Some(shannon_bounded(bytes, &ctx.deadline)?)
        } else {
            None
        };
        let facts = PeOverlayFacts {
            offset: to_u64(start),
            size: to_u64(bytes.len()),
            entropy,
            kind: content_kind(bytes),
        };

        let range = Evidence::Range {
            offset: facts.offset,
            len: facts.size,
        };
        let kind_ev = Evidence::Field {
            name: "kind",
            value: facts.kind.unwrap_or("unknown").to_owned(),
        };
        out.push_finding(
            Finding::new(
                "PE-OVERLAY",
                Severity::Info,
                Category::Anomaly,
                "Data appended after the image",
            )
            .confidence(Confidence::High)
            .detail(
                "Bytes after the last section are not loaded by Windows. Installers and \
                 self-extracting archives keep their payload there; so do droppers.",
            )
            .evidence(range.clone())
            .evidence(kind_ev.clone()),
        );
        if facts.kind == Some("pe") {
            out.push_finding(
                Finding::new(
                    "PE-OVERLAY-EMBEDDED-PE",
                    Severity::Medium,
                    Category::Anomaly,
                    "Another executable is appended to this one",
                )
                .detail(
                    "The overlay starts with a complete PE header: a second program \
                     carried as payload, typical of droppers and binders.",
                )
                .evidence(range.clone()),
            );
        }
        let archive = facts.kind.is_some_and(|k| COMPRESSED_KINDS.contains(&k));
        if let Some(e) = entropy.filter(|&e| e >= t.entropy_high && !archive) {
            out.push_finding(
                Finding::new(
                    "PE-OVERLAY-HIGH-ENTROPY",
                    Severity::Low,
                    Category::Packing,
                    "Appended data looks compressed or encrypted",
                )
                .detail(
                    "The overlay has near-random content and is not a recognised \
                     archive or installer format: often an encrypted payload.",
                )
                .evidence(range)
                .evidence(Evidence::Metric {
                    name: "entropy",
                    value: e,
                }),
            );
        }

        out.facts.pe.get_or_insert_with(PeFacts::default).overlay = Some(facts);
        Ok(())
    }
}

/// File offset where the overlay starts, or `None` if the image covers the file.
pub fn overlay_start(pe: &PeImage, file_len: usize) -> Option<usize> {
    let mut end = u64::from(pe.size_of_headers);
    for s in pe.sections.iter().filter(|s| s.raw_size > 0) {
        end = end.max(u64::from(s.raw_offset).saturating_add(u64::from(s.raw_size)));
    }
    // A certificate table at/after the image end is not overlay; data after it is.
    if let Some(cert) = pe
        .data_directories
        .get(DIRECTORY_SECURITY)
        .copied()
        .flatten()
    {
        let (c_start, c_end) = (
            u64::from(cert.rva),
            u64::from(cert.rva).saturating_add(u64::from(cert.size)),
        );
        if cert.size > 0 && c_start >= end && c_end <= to_u64(file_len) {
            end = c_end;
        }
    }
    let end = usize::try_from(end).ok()?;
    (end < file_len).then_some(end)
}

/// Recognises a few container/media formats by magic bytes (shared with resources).
pub fn content_kind(bytes: &[u8]) -> Option<&'static str> {
    const MAGICS: &[(&[u8], &str)] = &[
        (b"PK\x03\x04", "zip"),
        (b"7z\xbc\xaf\x27\x1c", "7z"),
        (b"Rar!\x1a\x07", "rar"),
        (b"MSCF", "cab"),
        (b"\x1f\x8b", "gzip"),
        (b"%PDF", "pdf"),
        (b"\x89PNG\r\n\x1a\n", "png"),
        (b"\xff\xd8\xff", "jpeg"),
        (b"GIF8", "gif"),
    ];
    if sniff_format(bytes) == Format::Pe {
        return Some("pe");
    }
    // NSIS "firstheader": 4 flag bytes, then the signature.
    if bytes.get(4..20) == Some(b"\xef\xbe\xad\xdeNullsoftInst") {
        return Some("nsis");
    }
    MAGICS
        .iter()
        .find(|(magic, _)| bytes.starts_with(magic))
        .map(|&(_, name)| name)
}

/// `usize` -> `u64`; lossless on all supported (<= 64-bit) targets.
fn to_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::input::Input;
    use crate::report::Report;
    use crate::Registry;
    use rtriage_fixtures::pe::{Arch, PeBuilder};

    fn analyze(bytes: Vec<u8>) -> Report {
        let r = Registry::default().analyze(&Input::from_bytes("t.exe", bytes), &Config::default());
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        r
    }

    fn overlay(r: &Report) -> Option<&PeOverlayFacts> {
        r.facts.pe.as_ref().unwrap().overlay.as_ref()
    }

    fn ids(r: &Report) -> Vec<&'static str> {
        r.findings
            .iter()
            .map(|f| f.id)
            .filter(|id| id.starts_with("PE-OVERLAY"))
            .collect()
    }

    fn uniform(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 256) as u8).collect()
    }

    #[test]
    fn no_overlay() {
        let r = analyze(PeBuilder::minimal(Arch::X64).build().bytes);
        assert!(overlay(&r).is_none());
        assert!(ids(&r).is_empty());
    }

    #[test]
    fn plain_overlay_is_info() {
        let built = PeBuilder::minimal(Arch::X64)
            .overlay(b"config=1\n".repeat(10))
            .build();
        let r = analyze(built.bytes);
        let o = overlay(&r).unwrap();
        assert_eq!(o.offset as usize, built.layout.image_end);
        assert_eq!(o.size, 90);
        assert_eq!(o.kind, None);
        assert_eq!(ids(&r), ["PE-OVERLAY"]);
    }

    #[test]
    fn encrypted_overlay_is_high_entropy() {
        let r = analyze(
            PeBuilder::minimal(Arch::X64)
                .overlay(uniform(8192))
                .build()
                .bytes,
        );
        assert_eq!(ids(&r), ["PE-OVERLAY-HIGH-ENTROPY", "PE-OVERLAY"]);
    }

    #[test]
    fn zip_overlay_is_not_judged_by_entropy() {
        let mut zip = b"PK\x03\x04".to_vec();
        zip.extend(uniform(8192));
        let r = analyze(PeBuilder::minimal(Arch::X64).overlay(zip).build().bytes);
        assert_eq!(overlay(&r).unwrap().kind, Some("zip"));
        assert_eq!(ids(&r), ["PE-OVERLAY"]);
    }

    #[test]
    fn nsis_installer_is_recognised() {
        let mut nsis = vec![0, 0, 0, 0];
        nsis.extend_from_slice(b"\xef\xbe\xad\xdeNullsoftInst");
        nsis.extend(uniform(8192));
        let r = analyze(PeBuilder::minimal(Arch::X86).overlay(nsis).build().bytes);
        assert_eq!(overlay(&r).unwrap().kind, Some("nsis"));
        assert_eq!(ids(&r), ["PE-OVERLAY"]);
    }

    #[test]
    fn appended_pe_is_flagged() {
        let inner = PeBuilder::minimal(Arch::X86).build().bytes;
        let r = analyze(PeBuilder::minimal(Arch::X64).overlay(inner).build().bytes);
        assert_eq!(overlay(&r).unwrap().kind, Some("pe"));
        assert!(ids(&r).contains(&"PE-OVERLAY-EMBEDDED-PE"));
    }

    #[test]
    fn mz_without_pe_header_is_not_embedded_pe() {
        let r = analyze(
            PeBuilder::minimal(Arch::X64)
                .overlay(b"MZ-but-nothing-else".to_vec())
                .build()
                .bytes,
        );
        assert!(!ids(&r).contains(&"PE-OVERLAY-EMBEDDED-PE"));
    }

    #[test]
    fn signature_is_not_overlay() {
        let built = PeBuilder::minimal(Arch::X64)
            .certificate(uniform(1500))
            .build();
        let r = analyze(built.bytes);
        assert!(overlay(&r).is_none(), "{:?}", overlay(&r));
        assert!(ids(&r).is_empty());
    }

    #[test]
    fn data_after_signature_is_overlay() {
        let built = PeBuilder::minimal(Arch::X64)
            .certificate(uniform(1500))
            .overlay(b"appended after signing".to_vec())
            .build();
        let cert = built.layout.certificate_offset.unwrap();
        let r = analyze(built.bytes);
        let o = overlay(&r).unwrap();
        assert!(o.offset as usize > cert);
        assert_eq!(o.size, 22);
    }

    #[test]
    fn bogus_certificate_directory_does_not_hide_overlay() {
        // Certificate entry claiming to run far past EOF: ignored.
        let mut built = PeBuilder::minimal(Arch::X64).overlay(vec![1; 100]).build();
        let dd = built.layout.data_directory_offset(4);
        rtriage_fixtures::pe::put_u32(&mut built.bytes, dd, built.layout.image_end as u32);
        rtriage_fixtures::pe::put_u32(&mut built.bytes, dd + 4, u32::MAX);
        let r = analyze(built.bytes);
        assert_eq!(overlay(&r).unwrap().size, 100);
    }
}

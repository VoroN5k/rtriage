//! Authenticode certificate table: presence and structure only.
//!
//! The SECURITY data directory holds a **file offset** (not an RVA) to a list
//! of 8-byte aligned `WIN_CERTIFICATE` entries. This module checks that the
//! table lies inside the file, that entries are well-formed, and that the
//! blob looks like a DER PKCS#7 SignedData. The signature itself is **not**
//! verified: status is at best "signed (unverified)".
//!
//! Findings: `PE-SIGNED` (Info, never lowers the risk), `PE-SIGNATURE-MALFORMED`.

use super::{read_u16, read_u32, PeImage};
use crate::analyzers::{AnalysisContext, Analyzer};
use crate::error::AnalysisError;
use crate::limits::Limits;
use crate::report::{
    Category, Confidence, Evidence, Finding, Format, PeCertificate, PeFacts, PeSignatureFacts,
    ReportBuilder, Severity, SignatureStatus,
};

/// Data directory index of the certificate table.
const DIRECTORY_SECURITY: usize = 4;
/// DER encoding of OID 1.2.840.113549.1.7.2 (PKCS#7 signedData).
const OID_SIGNED_DATA: &[u8] = &[
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02,
];
/// The OID must appear this early in the blob.
const OID_WINDOW: usize = 32;

/// Checks the certificate table structure.
#[derive(Debug, Clone, Copy, Default)]
pub struct PeSignatureAnalyzer;

impl Analyzer for PeSignatureAnalyzer {
    fn name(&self) -> &'static str {
        "pe-signature"
    }

    fn applies_to(&self, format: Format) -> bool {
        format == Format::Pe
    }

    fn run(&self, ctx: &AnalysisContext<'_>, out: &mut ReportBuilder) -> Result<(), AnalysisError> {
        let Some(pe) = super::pe_or_skip(ctx) else {
            return Ok(());
        };
        if let Some(sig) = parse(pe, &ctx.input.data, &ctx.config.limits) {
            out.push_finding(signature_finding(&sig));
            out.facts.pe.get_or_insert_with(PeFacts::default).signature = Some(sig);
        }
        Ok(())
    }
}

/// Structural check of the certificate table; `None` if there is none.
pub fn parse(pe: &PeImage, data: &[u8], limits: &Limits) -> Option<PeSignatureFacts> {
    let dir = pe
        .data_directories
        .get(DIRECTORY_SECURITY)
        .copied()
        .flatten()?;
    if dir.rva == 0 || dir.size == 0 {
        return None;
    }
    let (start, size) = (u64::from(dir.rva), u64::from(dir.size));
    let mut facts = PeSignatureFacts {
        offset: start,
        size,
        status: SignatureStatus::Malformed,
        certificates: Vec::new(),
        problems: Vec::new(),
    };
    let len = data.len() as u64;
    let end = start.saturating_add(size);
    if end > len {
        facts
            .problems
            .push(format!("table runs past end of file ({end} > {len})"));
    }
    let image_end = pe
        .sections
        .iter()
        .map(|s| u64::from(s.raw_offset).saturating_add(u64::from(s.raw_size)))
        .max()
        .unwrap_or(0);
    if start < image_end {
        facts
            .problems
            .push("table overlaps section data (it should follow the image)".into());
    }

    let end = end.min(len);
    let mut at = start;
    while at.saturating_add(8) <= end {
        if facts.certificates.len() >= limits.max_certificates {
            facts.problems.push("too many certificate entries".into());
            break;
        }
        let Ok(off) = usize::try_from(at) else {
            break;
        };
        let (Ok(length), Ok(revision), Ok(cert_type)) = (
            read_u32(data, off, "WIN_CERTIFICATE"),
            read_u16(data, off.saturating_add(4), "WIN_CERTIFICATE"),
            read_u16(data, off.saturating_add(6), "WIN_CERTIFICATE"),
        ) else {
            break;
        };
        if length < 8 || at.saturating_add(u64::from(length)) > end {
            facts
                .problems
                .push(format!("entry at 0x{at:x} has invalid length {length}"));
            break;
        }
        if !matches!(revision, 0x0100 | 0x0200) {
            facts.problems.push(format!(
                "entry at 0x{at:x} has unknown revision 0x{revision:04x}"
            ));
        }
        let kind = match cert_type {
            1 => "x509",
            2 => "pkcs_signed_data",
            3 => "reserved",
            4 => "ts_stack_signed",
            _ => "unknown",
        };
        let blob_start = off.saturating_add(8);
        let blob_end = off.saturating_add(usize::try_from(length).unwrap_or(0));
        let blob = data.get(blob_start..blob_end).unwrap_or_default();
        let pkcs7 = looks_like_signed_data(blob);
        if cert_type == 2 && !pkcs7 {
            facts
                .problems
                .push(format!("entry at 0x{at:x} is not a PKCS#7 SignedData blob"));
        }
        facts.certificates.push(PeCertificate {
            offset: at,
            length,
            revision,
            kind,
            pkcs7_signed_data: pkcs7,
        });
        // Entries are 8-byte aligned.
        at = at.saturating_add(u64::from(length).div_ceil(8) * 8);
    }

    let has_signed_data = facts.certificates.iter().any(|c| c.pkcs7_signed_data);
    if facts.problems.is_empty() && has_signed_data {
        facts.status = SignatureStatus::SignedUnverified;
    } else if facts.problems.is_empty() {
        facts.problems.push("no PKCS#7 SignedData entry".into());
    }
    Some(facts)
}

/// `PE-SIGNED` (context only: an unverified signature never lowers the risk)
/// or `PE-SIGNATURE-MALFORMED`.
fn signature_finding(sig: &PeSignatureFacts) -> Finding {
    let location = Evidence::Range {
        offset: sig.offset,
        len: sig.size,
    };
    match sig.status {
        SignatureStatus::SignedUnverified => Finding::new(
            "PE-SIGNED",
            Severity::Info,
            Category::Metadata,
            "Signed (signature not verified)",
        )
        .confidence(Confidence::High)
        .detail(
            "An Authenticode certificate table with a PKCS#7 SignedData blob is present. \
             rtriage does not verify signatures: the file may be unsigned in practice, \
             re-signed or signed with a stolen certificate. This does not lower the risk.",
        )
        .evidence(location)
        .evidence(Evidence::Field {
            name: "certificate entries",
            value: sig.certificates.len().to_string(),
        }),
        _ => {
            let mut f = Finding::new(
                "PE-SIGNATURE-MALFORMED",
                Severity::Low,
                Category::Anomaly,
                "Certificate table is malformed",
            )
            .detail(
                "The file carries a certificate table that cannot be a valid Authenticode \
                 signature: a fake or damaged signature, or data hidden behind the \
                 SECURITY directory.",
            )
            .evidence(location);
            for p in &sig.problems {
                f = f.evidence(Evidence::Field {
                    name: "problem",
                    value: p.clone(),
                });
            }
            f
        }
    }
}

/// DER SEQUENCE whose first bytes carry the signedData OID.
fn looks_like_signed_data(blob: &[u8]) -> bool {
    blob.first() == Some(&0x30)
        && blob.get(..OID_WINDOW.min(blob.len())).is_some_and(|head| {
            head.windows(OID_SIGNED_DATA.len())
                .any(|w| w == OID_SIGNED_DATA)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::input::Input;
    use crate::report::Report;
    use crate::Registry;
    use rtriage_fixtures::pe::{put_u32, Arch, PeBuilder};

    /// Start of a DER PKCS#7 SignedData (structure only; no real certificate).
    fn pkcs7_blob() -> Vec<u8> {
        let mut b = vec![0x30, 0x82, 0x05, 0x00];
        b.extend_from_slice(OID_SIGNED_DATA);
        b.extend_from_slice(&[0xA0, 0x82, 0x04, 0xF0]);
        b.resize(1300, 0x41);
        b
    }

    fn analyze(bytes: Vec<u8>) -> Report {
        let r = Registry::default().analyze(&Input::from_bytes("t.exe", bytes), &Config::default());
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        r
    }

    fn sig(r: &Report) -> Option<&PeSignatureFacts> {
        r.facts.pe.as_ref().unwrap().signature.as_ref()
    }

    #[test]
    fn well_formed_signature_is_signed_unverified() {
        let built = PeBuilder::minimal(Arch::X64)
            .certificate(pkcs7_blob())
            .build();
        let r = analyze(built.bytes);
        let s = sig(&r).unwrap();
        assert_eq!(
            s.status,
            SignatureStatus::SignedUnverified,
            "{:?}",
            s.problems
        );
        assert_eq!(s.certificates.len(), 1);
        assert_eq!(s.certificates[0].kind, "pkcs_signed_data");
        assert_eq!(s.offset as usize, built.layout.certificate_offset.unwrap());
    }

    fn ids(r: &Report) -> Vec<&'static str> {
        r.findings
            .iter()
            .map(|f| f.id)
            .filter(|id| id.starts_with("PE-SIGN"))
            .collect()
    }

    #[test]
    fn signed_is_info_and_scores_nothing() {
        let r = analyze(
            PeBuilder::minimal(Arch::X64)
                .certificate(pkcs7_blob())
                .build()
                .bytes,
        );
        assert_eq!(ids(&r), ["PE-SIGNED"]);
        let e = r
            .risk
            .breakdown
            .iter()
            .find(|e| e.id == "PE-SIGNED")
            .unwrap();
        assert_eq!(e.points, 0);
    }

    #[test]
    fn signing_does_not_lower_the_score() {
        let inject = [
            "OpenProcess",
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
        ];
        let plain = analyze(
            PeBuilder::minimal(Arch::X64)
                .import("KERNEL32.dll", &inject)
                .build()
                .bytes,
        );
        let signed = analyze(
            PeBuilder::minimal(Arch::X64)
                .import("KERNEL32.dll", &inject)
                .certificate(pkcs7_blob())
                .build()
                .bytes,
        );
        assert_eq!(plain.risk.score, signed.risk.score);
    }

    #[test]
    fn malformed_table_is_flagged() {
        let r = analyze(
            PeBuilder::minimal(Arch::X64)
                .certificate(vec![0xAA; 200])
                .build()
                .bytes,
        );
        assert_eq!(ids(&r), ["PE-SIGNATURE-MALFORMED"]);
        let f = r
            .findings
            .iter()
            .find(|f| f.id == "PE-SIGNATURE-MALFORMED")
            .unwrap();
        assert_eq!(
            (f.severity, f.confidence),
            (Severity::Low, Confidence::Medium)
        );
        assert!(f.evidence.iter().any(|e| matches!(
            e,
            Evidence::Field {
                name: "problem",
                ..
            }
        )));
    }

    #[test]
    fn unsigned_file_has_no_signature_facts() {
        let r = analyze(PeBuilder::minimal(Arch::X64).build().bytes);
        assert!(sig(&r).is_none());
    }

    #[test]
    fn garbage_blob_is_malformed() {
        let r = analyze(
            PeBuilder::minimal(Arch::X64)
                .certificate(vec![0xAA; 200])
                .build()
                .bytes,
        );
        let s = sig(&r).unwrap();
        assert_eq!(s.status, SignatureStatus::Malformed);
        assert!(s.problems.iter().any(|p| p.contains("PKCS#7")));
    }

    #[test]
    fn table_past_eof_is_malformed() {
        let mut built = PeBuilder::minimal(Arch::X64)
            .certificate(pkcs7_blob())
            .build();
        put_u32(
            &mut built.bytes,
            built.layout.data_directory_offset(4) + 4,
            0x7FFF_FFFF,
        );
        let s = sig(&analyze(built.bytes)).unwrap().clone();
        assert_eq!(s.status, SignatureStatus::Malformed);
        assert!(s.problems.iter().any(|p| p.contains("past end of file")));
    }

    #[test]
    fn table_inside_image_is_malformed() {
        let mut built = PeBuilder::minimal(Arch::X64).build();
        let text = built.layout.sections[0].raw_ptr;
        put_u32(
            &mut built.bytes,
            built.layout.data_directory_offset(4),
            text,
        );
        put_u32(
            &mut built.bytes,
            built.layout.data_directory_offset(4) + 4,
            64,
        );
        let s = sig(&analyze(built.bytes)).unwrap().clone();
        assert_eq!(s.status, SignatureStatus::Malformed);
    }

    #[test]
    fn zero_length_entry_does_not_loop() {
        let mut built = PeBuilder::minimal(Arch::X64)
            .certificate(pkcs7_blob())
            .build();
        let off = built.layout.certificate_offset.unwrap();
        put_u32(&mut built.bytes, off, 0);
        let s = sig(&analyze(built.bytes)).unwrap().clone();
        assert_eq!(s.status, SignatureStatus::Malformed);
        assert!(s.certificates.is_empty());
    }
}

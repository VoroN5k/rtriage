//! Packer and protector hints.
//!
//! Findings (see `docs/heuristics.md`):
//! - `PE-PACKER-KNOWN`: section names or a signature of a known packer.
//! - `PE-PACKED-LIKELY`: no known packer, but high-entropy code and a tiny
//!   import table together.
//!
//! This is name/signature matching only; no unpacking or emulation.

use super::{PeImage, SectionHeader};
use crate::analyzers::entropy::shannon_bounded;
use crate::analyzers::{AnalysisContext, Analyzer};
use crate::error::AnalysisError;
use crate::report::{
    Category, Confidence, Evidence, Finding, Format, PeFacts, ReportBuilder, Severity,
};

/// How a packer leaves its mark.
struct Packer {
    name: &'static str,
    /// Exact section names (case-sensitive).
    sections: &'static [&'static str],
    /// Section name prefixes.
    section_prefixes: &'static [&'static str],
    /// Byte signature searched in the PE headers.
    header_signature: Option<&'static [u8]>,
}

/// Known packers/protectors. Section names are the defaults each tool writes.
const PACKERS: &[Packer] = &[
    Packer {
        name: "UPX",
        sections: &["UPX0", "UPX1", "UPX2", "UPX3"],
        section_prefixes: &[],
        header_signature: Some(b"UPX!"),
    },
    Packer {
        name: "ASPack",
        sections: &[".aspack", ".adata"],
        section_prefixes: &[],
        header_signature: None,
    },
    Packer {
        name: "Themida/WinLicense",
        sections: &[".themida", ".winlice"],
        section_prefixes: &[],
        header_signature: None,
    },
    Packer {
        name: "VMProtect",
        sections: &[".vmp0", ".vmp1", ".vmp2"],
        section_prefixes: &[],
        header_signature: None,
    },
    Packer {
        name: "MPRESS",
        sections: &[".MPRESS1", ".MPRESS2"],
        section_prefixes: &[],
        header_signature: None,
    },
    Packer {
        name: "PECompact",
        sections: &["pec1", "pec2", "pec3"],
        section_prefixes: &["PEC2"],
        header_signature: None,
    },
    Packer {
        name: "Petite",
        sections: &[".petite"],
        section_prefixes: &[],
        header_signature: None,
    },
    Packer {
        name: "NsPack",
        sections: &[".nsp0", ".nsp1", ".nsp2", "nsp0", "nsp1", "nsp2"],
        section_prefixes: &[],
        header_signature: None,
    },
    Packer {
        name: "Enigma Protector",
        sections: &[".enigma1", ".enigma2"],
        section_prefixes: &[],
        header_signature: None,
    },
    Packer {
        name: "kkrunchy",
        sections: &["kkrunchy"],
        section_prefixes: &[],
        header_signature: None,
    },
];

/// Detects packers and packing without a known signature.
#[derive(Debug, Clone, Copy, Default)]
pub struct PePackersAnalyzer;

impl Analyzer for PePackersAnalyzer {
    fn name(&self) -> &'static str {
        "pe-packers"
    }

    fn applies_to(&self, format: Format) -> bool {
        format == Format::Pe
    }

    fn run(&self, ctx: &AnalysisContext<'_>, out: &mut ReportBuilder) -> Result<(), AnalysisError> {
        let Some(pe) = super::pe_or_skip(ctx) else {
            return Ok(());
        };
        let data = &ctx.input.data;
        let mut names = Vec::new();
        for packer in PACKERS {
            if let Some(evidence) = match_packer(packer, pe, data) {
                names.push(packer.name);
                let mut f = Finding::new(
                    "PE-PACKER-KNOWN",
                    Severity::Medium,
                    Category::Packing,
                    format!("Packed with {}", packer.name),
                )
                .confidence(Confidence::High)
                .detail(format!(
                    "Section names or signatures written by {}. The code on disk is \
                     compressed or protected; static analysis of the original program \
                     needs unpacking first. Packers are also used by legitimate software.",
                    packer.name
                ))
                .evidence(Evidence::Field {
                    name: "packer",
                    value: packer.name.to_owned(),
                });
                for e in evidence {
                    f = f.evidence(e);
                }
                out.push_finding(f);
            }
        }

        if names.is_empty() && !pe.is_managed_dotnet() {
            packed_likely(ctx, pe, out)?;
        }
        out.facts.pe.get_or_insert_with(PeFacts::default).packers = Some(names);
        Ok(())
    }
}

/// Evidence if `packer` left section names or its header signature.
fn match_packer(packer: &Packer, pe: &PeImage, data: &[u8]) -> Option<Vec<Evidence>> {
    let mut ev: Vec<Evidence> = pe
        .sections
        .iter()
        .filter(|s| {
            packer.sections.contains(&s.name.as_str())
                || packer
                    .section_prefixes
                    .iter()
                    .any(|p| s.name.starts_with(p))
        })
        .map(section_ev)
        .collect();
    if let Some(sig) = packer.header_signature {
        let headers_end = usize::try_from(pe.size_of_headers)
            .unwrap_or(0)
            .min(data.len())
            .min(0x1000);
        let headers = data.get(..headers_end).unwrap_or_default();
        if let Some(pos) = headers.windows(sig.len()).position(|w| w == sig) {
            ev.push(Evidence::Range {
                offset: pos as u64,
                len: sig.len() as u64,
            });
            ev.push(Evidence::Field {
                name: "signature",
                value: String::from_utf8_lossy(sig).into_owned(),
            });
        }
    }
    (!ev.is_empty()).then_some(ev)
}

/// High-entropy executable code plus a tiny import table.
fn packed_likely(
    ctx: &AnalysisContext<'_>,
    pe: &PeImage,
    out: &mut ReportBuilder,
) -> Result<(), AnalysisError> {
    let t = &ctx.config.thresholds;
    let Some(imports) = ctx.pe_imports() else {
        return Ok(());
    };
    let total = imports.total_functions();
    if imports.limit_reached || total > t.imports_few_max {
        return Ok(());
    }
    let data = &ctx.input.data;
    let mut hot = None;
    for s in pe.sections.iter().filter(|s| s.is_executable()) {
        let start = usize::try_from(s.raw_offset).unwrap_or(usize::MAX);
        let end = start.saturating_add(usize::try_from(s.raw_size).unwrap_or(0));
        let Some(bytes) = data.get(start..end.min(data.len())) else {
            continue;
        };
        if bytes.len() < t.section_entropy_min_size {
            continue;
        }
        let e = shannon_bounded(bytes, &ctx.deadline)?;
        if e >= t.entropy_high {
            hot = Some((s, e));
            break;
        }
    }
    let Some((section, entropy)) = hot else {
        return Ok(());
    };
    out.push_finding(
        Finding::new(
            "PE-PACKED-LIKELY",
            Severity::Medium,
            Category::Packing,
            "Looks packed (no known packer signature)",
        )
        .confidence(Confidence::Low)
        .detail(
            "Executable code is near-random and the import table is tiny: the usual \
             shape of a custom or modified packer. Without a known signature this is \
             a weaker signal.",
        )
        .evidence(section_ev(section))
        .evidence(Evidence::Metric {
            name: "entropy",
            value: entropy,
        })
        .evidence(Evidence::Field {
            name: "imported functions",
            value: total.to_string(),
        }),
    );
    Ok(())
}

fn section_ev(s: &SectionHeader) -> Evidence {
    Evidence::Section {
        index: s.index,
        name: s.name.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::input::Input;
    use crate::report::Report;
    use crate::Registry;
    use rtriage_fixtures::pe::{profiles, Arch, PeBuilder, Section};

    fn analyze(bytes: Vec<u8>) -> Report {
        let r = Registry::default().analyze(&Input::from_bytes("t.exe", bytes), &Config::default());
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        r
    }

    fn ids(r: &Report) -> Vec<&'static str> {
        r.findings
            .iter()
            .map(|f| f.id)
            .filter(|id| id.starts_with("PE-PACK"))
            .collect()
    }

    fn packers(r: &Report) -> &[&'static str] {
        r.facts.pe.as_ref().unwrap().packers.as_deref().unwrap()
    }

    fn uniform(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 256) as u8).collect()
    }

    #[test]
    fn upx_profile_is_known_packer() {
        for arch in [Arch::X86, Arch::X64] {
            let r = analyze(profiles::upx_like(arch).build().bytes);
            assert_eq!(packers(&r), ["UPX"]);
            assert_eq!(ids(&r), ["PE-PACKER-KNOWN"]);
            let f = r
                .findings
                .iter()
                .find(|f| f.id == "PE-PACKER-KNOWN")
                .unwrap();
            assert_eq!(
                (f.severity, f.confidence),
                (Severity::Medium, Confidence::High)
            );
            assert!(f.evidence.contains(&Evidence::Field {
                name: "signature",
                value: "UPX!".into()
            }));
        }
    }

    #[test]
    fn renamed_upx_sections_still_match_signature() {
        let b = PeBuilder::minimal(Arch::X64).header_extra(b"\0UPX!\x0d\x09".to_vec());
        let r = analyze(b.build().bytes);
        assert_eq!(packers(&r), ["UPX"]);
    }

    #[test]
    fn section_name_alone_matches() {
        for (name, packer) in [
            (".aspack", "ASPack"),
            (".vmp1", "VMProtect"),
            (".themida", "Themida/WinLicense"),
            ("PEC2TO", "PECompact"),
            (".MPRESS1", "MPRESS"),
        ] {
            let r = analyze(
                PeBuilder::minimal(Arch::X86)
                    .section(Section::rdata(name, vec![0; 16]))
                    .build()
                    .bytes,
            );
            assert_eq!(packers(&r), [packer], "{name}");
        }
    }

    #[test]
    fn similar_names_do_not_match() {
        for name in [".upx", "upx0", ".vmp", "VMP0", ".text"] {
            let r = analyze(
                PeBuilder::minimal(Arch::X64)
                    .section(Section::rdata(name, vec![0; 16]))
                    .build()
                    .bytes,
            );
            assert!(packers(&r).is_empty(), "{name}");
        }
    }

    #[test]
    fn high_entropy_code_with_tiny_imports_is_packed_likely() {
        let r = analyze(
            PeBuilder::new(Arch::X64)
                .section(Section::code(".text", uniform(8192)))
                .import("KERNEL32.dll", &["LoadLibraryA", "GetProcAddress"])
                .build()
                .bytes,
        );
        assert_eq!(ids(&r), ["PE-PACKED-LIKELY"]);
        let f = r
            .findings
            .iter()
            .find(|f| f.id == "PE-PACKED-LIKELY")
            .unwrap();
        assert_eq!(
            (f.severity, f.confidence),
            (Severity::Medium, Confidence::Low)
        );
    }

    #[test]
    fn high_entropy_code_with_normal_imports_is_not_packed_likely() {
        let names: Vec<String> = (0..30).map(|i| format!("Func{i}")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let r = analyze(
            PeBuilder::new(Arch::X64)
                .section(Section::code(".text", uniform(8192)))
                .import("KERNEL32.dll", &refs)
                .build()
                .bytes,
        );
        assert!(ids(&r).is_empty(), "{:?}", ids(&r));
    }

    #[test]
    fn known_packer_suppresses_packed_likely() {
        let r = analyze(profiles::upx_like(Arch::X64).build().bytes);
        assert!(!ids(&r).contains(&"PE-PACKED-LIKELY"));
    }

    #[test]
    fn profiles_are_not_packed() {
        for b in [
            profiles::dotnet_like(Arch::X86),
            profiles::go_like(Arch::X64),
        ] {
            let r = analyze(b.build().bytes);
            assert!(ids(&r).is_empty(), "{:?}", ids(&r));
            assert!(packers(&r).is_empty());
        }
    }
}

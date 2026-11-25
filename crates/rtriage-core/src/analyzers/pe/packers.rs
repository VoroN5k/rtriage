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
    Category, Confidence, Evidence, Finding, Format, PeFacts, PePackerFacts, ReportBuilder,
    Severity,
};

/// Name-independent layout check; returns evidence when the layout matches.
type StubCheck = fn(&PeImage) -> Option<Vec<Evidence>>;

/// How a packer leaves its mark.
struct Packer {
    name: &'static str,
    /// Exact section names (case-sensitive).
    sections: &'static [&'static str],
    /// Section name prefixes.
    section_prefixes: &'static [&'static str],
    /// Byte signature searched in the PE headers.
    header_signature: Option<&'static [u8]>,
    /// Name-independent layout check.
    stub_structure: Option<StubCheck>,
}

/// Known packers/protectors. Section names are the defaults each tool writes.
const PACKERS: &[Packer] = &[
    Packer {
        name: "UPX",
        sections: &["UPX0", "UPX1", "UPX2", "UPX3"],
        section_prefixes: &[],
        header_signature: Some(b"UPX!"),
        stub_structure: Some(upx_stub),
    },
    Packer {
        name: "ASPack",
        sections: &[".aspack", ".adata"],
        section_prefixes: &[],
        header_signature: None,
        stub_structure: None,
    },
    Packer {
        name: "Themida/WinLicense",
        sections: &[".themida", ".winlice"],
        section_prefixes: &[],
        header_signature: None,
        stub_structure: None,
    },
    Packer {
        name: "VMProtect",
        sections: &[".vmp0", ".vmp1", ".vmp2"],
        section_prefixes: &[],
        header_signature: None,
        stub_structure: None,
    },
    Packer {
        name: "MPRESS",
        sections: &[".MPRESS1", ".MPRESS2"],
        section_prefixes: &[],
        header_signature: None,
        stub_structure: None,
    },
    Packer {
        name: "PECompact",
        sections: &["pec1", "pec2", "pec3"],
        section_prefixes: &["PEC2"],
        header_signature: None,
        stub_structure: None,
    },
    Packer {
        name: "Petite",
        sections: &[".petite"],
        section_prefixes: &[],
        header_signature: None,
        stub_structure: None,
    },
    Packer {
        name: "NsPack",
        sections: &[".nsp0", ".nsp1", ".nsp2", "nsp0", "nsp1", "nsp2"],
        section_prefixes: &[],
        header_signature: None,
        stub_structure: None,
    },
    Packer {
        name: "Enigma Protector",
        sections: &[".enigma1", ".enigma2"],
        section_prefixes: &[],
        header_signature: None,
        stub_structure: None,
    },
    Packer {
        name: "kkrunchy",
        sections: &["kkrunchy"],
        section_prefixes: &[],
        header_signature: None,
        stub_structure: None,
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
        let mut detected = Vec::new();
        for packer in PACKERS {
            if let Some((indicators, evidence)) = match_packer(packer, pe, data) {
                detected.push(PePackerFacts {
                    name: packer.name,
                    indicators: indicators.clone(),
                });
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
                })
                .evidence(Evidence::Field {
                    name: "indicators",
                    value: indicators.join(", "),
                });
                for e in evidence {
                    f = f.evidence(e);
                }
                out.push_finding(f);
            }
        }

        if detected.is_empty() && !pe.is_managed_dotnet() {
            packed_likely(ctx, pe, out)?;
        }
        out.facts.pe.get_or_insert_with(PeFacts::default).packers = Some(detected);
        Ok(())
    }
}

/// Indicator names, in the fixed order they are reported.
pub const INDICATOR_SECTION_NAMES: &str = "section_names";
/// See [`INDICATOR_SECTION_NAMES`].
pub const INDICATOR_HEADER_SIGNATURE: &str = "header_signature";
/// See [`INDICATOR_SECTION_NAMES`].
pub const INDICATOR_STUB_STRUCTURE: &str = "stub_structure";

/// Packer names and the indicators rtriage can check for each, for rule validation.
pub fn known_packers() -> impl Iterator<Item = (&'static str, Vec<&'static str>)> {
    PACKERS.iter().map(|p| {
        let mut ind = vec![INDICATOR_SECTION_NAMES];
        if p.header_signature.is_some() {
            ind.push(INDICATOR_HEADER_SIGNATURE);
        }
        if p.stub_structure.is_some() {
            ind.push(INDICATOR_STUB_STRUCTURE);
        }
        (p.name, ind)
    })
}

/// Independent indicators found for `packer`, plus their evidence; `None`
/// if neither its section names nor its signature are present (the stub
/// structure alone never names a packer).
fn match_packer(
    packer: &Packer,
    pe: &PeImage,
    data: &[u8],
) -> Option<(Vec<&'static str>, Vec<Evidence>)> {
    let mut indicators = Vec::new();
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
    if !ev.is_empty() {
        indicators.push(INDICATOR_SECTION_NAMES);
    }
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
            indicators.push(INDICATOR_HEADER_SIGNATURE);
        }
    }
    if indicators.is_empty() {
        return None;
    }
    if let Some(check) = packer.stub_structure {
        if let Some(stub_ev) = check(pe) {
            indicators.push(INDICATOR_STUB_STRUCTURE);
            ev.extend(stub_ev);
        }
    }
    Some((indicators, ev))
}

/// UPX layout, independent of section names: an executable section with no
/// raw data and at least one page of virtual size (decompression target),
/// immediately followed by an executable section with raw data that starts
/// at or after the first one's end and contains the entry point (the
/// decompressor stub plus compressed data).
fn upx_stub(pe: &PeImage) -> Option<Vec<Evidence>> {
    pe.sections.windows(2).find_map(|pair| {
        let [target, stub] = pair else {
            return None;
        };
        let target_end = u64::from(target.virtual_address) + u64::from(target.virtual_size);
        let ok = target.is_executable()
            && target.raw_size == 0
            && target.virtual_size >= 0x1000
            && stub.is_executable()
            && stub.raw_size > 0
            && u64::from(stub.virtual_address) >= target_end
            && stub.contains_rva(pe.entry_rva);
        ok.then(|| {
            vec![Evidence::Field {
                name: "stub structure",
                value: format!(
                    "#{} virtual-only target, entry point in #{} directly after it",
                    target.index, stub.index
                ),
            }]
        })
    })
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

    fn packers(r: &Report) -> Vec<&'static str> {
        r.facts
            .pe
            .as_ref()
            .unwrap()
            .packers
            .as_deref()
            .unwrap()
            .iter()
            .map(|p| p.name)
            .collect()
    }

    fn indicators(r: &Report, name: &str) -> Vec<&'static str> {
        r.facts
            .pe
            .as_ref()
            .unwrap()
            .packers
            .as_deref()
            .unwrap()
            .iter()
            .find(|p| p.name == name)
            .map(|p| p.indicators.clone())
            .unwrap_or_default()
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
    fn upx_profile_has_all_three_independent_indicators() {
        let r = analyze(profiles::upx_like(Arch::X86).build().bytes);
        assert_eq!(
            indicators(&r, "UPX"),
            ["section_names", "header_signature", "stub_structure"]
        );
    }

    #[test]
    fn spoofed_section_names_are_one_indicator() {
        // Names only: ordinary code/data sections called UPX0/UPX1.
        let r = analyze(
            PeBuilder::new(Arch::X64)
                .section(Section::code("UPX0", vec![0xC3; 64]))
                .section(Section::data("UPX1", vec![0; 64]))
                .build()
                .bytes,
        );
        assert_eq!(indicators(&r, "UPX"), ["section_names"]);
    }

    #[test]
    fn names_and_signature_without_stub_layout() {
        let r = analyze(
            PeBuilder::new(Arch::X64)
                .header_extra(b"UPX!".to_vec())
                .section(Section::code("UPX0", vec![0xC3; 64]))
                .section(Section::data("UPX1", vec![0; 64]))
                .build()
                .bytes,
        );
        assert_eq!(indicators(&r, "UPX"), ["section_names", "header_signature"]);
    }

    #[test]
    fn stub_layout_alone_does_not_name_a_packer() {
        // UPX-shaped layout under neutral names, no signature.
        let r = analyze(
            PeBuilder::new(Arch::X64)
                .section(
                    Section::rwx(".a", Vec::new())
                        .raw_size(0)
                        .virtual_size(0x2_0000),
                )
                .section(Section::rwx(".b", uniform(4096)))
                .entry(rtriage_fixtures::pe::Entry::Section {
                    index: 1,
                    offset: 0,
                })
                .build()
                .bytes,
        );
        assert!(packers(&r).is_empty());
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

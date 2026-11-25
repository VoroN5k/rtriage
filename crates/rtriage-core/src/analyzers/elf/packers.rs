//! ELF packer hints (name/signature/layout matching only; nothing is unpacked).
//!
//! Findings (see `docs/heuristics.md`):
//! - `ELF-PACKER-KNOWN`: UPX's `UPX!` signature or `$Info` banner.
//! - `ELF-PACKED-LIKELY`: high-entropy executable segment plus almost no
//!   imports. Evaluated even when a packer is known, so a confirmed packer can
//!   explain it (it then shows up suppressed).

use super::{ElfImage, PT_LOAD};
use crate::analyzers::entropy::shannon_bounded;
use crate::analyzers::{AnalysisContext, Analyzer};
use crate::deadline::Deadline;
use crate::error::AnalysisError;
use crate::report::{
    Category, Confidence, ElfFacts, Evidence, Finding, Format, PePackerFacts, ReportBuilder,
    Severity,
};

/// `UPX!` magic of `l_info` / `p_info` / the pack header.
const UPX_MAGIC: &[u8] = b"UPX!";
/// UPX's banner, embedded in every stub.
const UPX_BANNER: &[u8] = b"$Info: This file is packed with the UPX";
/// Bytes searched for the magic at each end of the file.
const MAGIC_WINDOW: usize = 4096;
/// Bytes searched for the banner at each end of the file.
const BANNER_WINDOW: usize = 64 * 1024;

/// Indicator: `UPX!` near the start or end of the file.
pub const INDICATOR_HEADER_SIGNATURE: &str = "header_signature";
/// Indicator: the `$Info: ... UPX` banner.
pub const INDICATOR_INFO_BANNER: &str = "info_banner";
/// Indicator: no section headers, few loads, entry in an executable load.
pub const INDICATOR_STUB_STRUCTURE: &str = "stub_structure";

/// Packer names and the indicators rtriage can check for each (rule validation).
pub fn known_packers() -> impl Iterator<Item = (&'static str, Vec<&'static str>)> {
    std::iter::once((
        "UPX",
        vec![
            INDICATOR_HEADER_SIGNATURE,
            INDICATOR_INFO_BANNER,
            INDICATOR_STUB_STRUCTURE,
        ],
    ))
}

/// Detects known packers and packing without a signature.
#[derive(Debug, Clone, Copy, Default)]
pub struct ElfPackersAnalyzer;

impl Analyzer for ElfPackersAnalyzer {
    fn name(&self) -> &'static str {
        "elf-packers"
    }

    fn applies_to(&self, format: Format) -> bool {
        format == Format::Elf
    }

    fn run(&self, ctx: &AnalysisContext<'_>, out: &mut ReportBuilder) -> Result<(), AnalysisError> {
        let Some(elf) = super::elf_or_skip(ctx) else {
            return Ok(());
        };
        let data = &ctx.input.data;
        let mut detected = Vec::new();
        if let Some((indicators, evidence)) = upx(elf, data) {
            let mut f = Finding::new(
                "ELF-PACKER-KNOWN",
                Severity::Medium,
                Category::Packing,
                "Packed with UPX",
            )
            .confidence(Confidence::High)
            .detail(
                "UPX's signature or banner is present: the program on disk is \
                 compressed and unpacks itself at run time. Static analysis of the \
                 original needs `upx -d` first. Also used for legitimate size reduction.",
            )
            .evidence(Evidence::Field {
                name: "packer",
                value: "UPX".into(),
            })
            .evidence(Evidence::Field {
                name: "indicators",
                value: indicators.join(", "),
            });
            for e in evidence {
                f = f.evidence(e);
            }
            out.push_finding(f);
            detected.push(PePackerFacts {
                name: "UPX",
                indicators,
            });
        }
        packed_likely(ctx, elf, &ctx.deadline, out)?;
        out.facts.elf.get_or_insert_with(ElfFacts::default).packers = Some(detected);
        Ok(())
    }
}

/// UPX indicators and evidence; `None` unless the magic or banner is present
/// (the layout alone never names a packer).
fn upx(elf: &ElfImage, data: &[u8]) -> Option<(Vec<&'static str>, Vec<Evidence>)> {
    let mut indicators = Vec::new();
    let mut ev = Vec::new();
    if let Some(at) = find_at_ends(data, UPX_MAGIC, MAGIC_WINDOW) {
        indicators.push(INDICATOR_HEADER_SIGNATURE);
        ev.push(Evidence::Range {
            offset: at as u64,
            len: UPX_MAGIC.len() as u64,
        });
    }
    if let Some(at) = find_at_ends(data, UPX_BANNER, BANNER_WINDOW) {
        indicators.push(INDICATOR_INFO_BANNER);
        ev.push(Evidence::Field {
            name: "banner",
            value: format!("at 0x{at:x}"),
        });
    }
    if indicators.is_empty() {
        return None;
    }
    let loads: Vec<_> = elf.segments.iter().filter(|s| s.kind == PT_LOAD).collect();
    let entry_exec = elf
        .load_for_vaddr(elf.entry)
        .is_some_and(|s| s.is_exec_load());
    if elf.sections.is_empty() && (1..=3).contains(&loads.len()) && entry_exec {
        indicators.push(INDICATOR_STUB_STRUCTURE);
        ev.push(Evidence::Field {
            name: "stub structure",
            value: format!(
                "no section headers, {} PT_LOAD, entry in an executable load",
                loads.len()
            ),
        });
    }
    Some((indicators, ev))
}

/// Offset of `needle` within the first or last `window` bytes.
fn find_at_ends(data: &[u8], needle: &[u8], window: usize) -> Option<usize> {
    let head = data.get(..window.min(data.len())).unwrap_or_default();
    if let Some(i) = head.windows(needle.len()).position(|w| w == needle) {
        return Some(i);
    }
    let start = data.len().saturating_sub(window);
    let tail = data.get(start..).unwrap_or_default();
    tail.windows(needle.len())
        .position(|w| w == needle)
        .map(|i| start + i)
}

fn packed_likely(
    ctx: &AnalysisContext<'_>,
    elf: &ElfImage,
    deadline: &Deadline,
    out: &mut ReportBuilder,
) -> Result<(), AnalysisError> {
    let t = &ctx.config.thresholds;
    let imports = match ctx.elf_dynamic() {
        Some(Ok(d)) => {
            if d.symbols_limit_reached {
                return Ok(());
            }
            d.imports().count() as u64
        }
        _ => 0,
    };
    if imports > t.imports_few_max {
        return Ok(());
    }
    let data = &ctx.input.data;
    for s in elf.segments.iter().filter(|s| s.is_exec_load()) {
        let start = usize::try_from(s.offset).unwrap_or(usize::MAX);
        let end = start.saturating_add(usize::try_from(s.filesz).unwrap_or(0));
        let Some(bytes) = data.get(start..end.min(data.len())) else {
            continue;
        };
        if bytes.len() < t.section_entropy_min_size {
            continue;
        }
        let e = shannon_bounded(bytes, deadline)?;
        if e >= t.entropy_high {
            out.push_finding(
                Finding::new(
                    "ELF-PACKED-LIKELY",
                    Severity::Medium,
                    Category::Packing,
                    "Looks packed",
                )
                .confidence(Confidence::Low)
                .detail(
                    "An executable segment is near-random and the file imports almost \
                     nothing: the usual shape of a packed or encrypted program.",
                )
                .evidence(Evidence::Field {
                    name: "segment",
                    value: format!("#{} offset 0x{:x} size 0x{:x}", s.index, s.offset, s.filesz),
                })
                .evidence(Evidence::Metric {
                    name: "entropy",
                    value: e,
                })
                .evidence(Evidence::Field {
                    name: "imported symbols",
                    value: imports.to_string(),
                }),
            );
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::input::Input;
    use crate::report::Report;
    use crate::Registry;
    use rtriage_fixtures::elf::{pf, profiles, ElfBuilder};

    fn analyze(bytes: Vec<u8>) -> Report {
        let r = Registry::default().analyze(&Input::from_bytes("t", bytes), &Config::default());
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        r
    }

    fn indicators(r: &Report) -> Vec<&'static str> {
        r.facts
            .elf
            .as_ref()
            .unwrap()
            .packers
            .as_ref()
            .unwrap()
            .iter()
            .find(|p| p.name == "UPX")
            .map(|p| p.indicators.clone())
            .unwrap_or_default()
    }

    fn uniform(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 256) as u8).collect()
    }

    #[test]
    fn upx_profile_has_three_indicators() {
        let r = analyze(profiles::upx_elf().build().bytes);
        assert_eq!(
            indicators(&r),
            ["header_signature", "info_banner", "stub_structure"]
        );
        assert!(r.findings.iter().any(|f| f.id == "ELF-PACKER-KNOWN"));
    }

    #[test]
    fn magic_only_with_sections_is_one_indicator() {
        let r = analyze(
            ElfBuilder::x86_64()
                .after_phdrs(b"\0\0\0\0UPX!".to_vec())
                .build()
                .bytes,
        );
        assert_eq!(indicators(&r), ["header_signature"]);
    }

    #[test]
    fn layout_alone_names_no_packer() {
        let r = analyze(
            ElfBuilder::x86_64()
                .section_headers(false)
                .text_flags(pf::R | pf::W | pf::X)
                .text(uniform(8192))
                .build()
                .bytes,
        );
        assert!(indicators(&r).is_empty());
        assert!(!r.findings.iter().any(|f| f.id == "ELF-PACKER-KNOWN"));
    }

    #[test]
    fn packed_likely_without_signature() {
        let r = analyze(ElfBuilder::x86_64().text(uniform(8192)).build().bytes);
        let f = r
            .findings
            .iter()
            .find(|f| f.id == "ELF-PACKED-LIKELY")
            .unwrap();
        assert_eq!(
            (f.severity, f.confidence),
            (Severity::Medium, Confidence::Low)
        );
    }

    #[test]
    fn packed_likely_is_evaluated_even_with_a_packer() {
        let r = analyze(profiles::upx_elf().build().bytes);
        assert!(r.findings.iter().any(|f| f.id == "ELF-PACKED-LIKELY"));
    }

    #[test]
    fn high_entropy_with_many_imports_is_not_packed_likely() {
        let names: Vec<String> = (0..30).map(|i| format!("f{i}")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let r = analyze(
            ElfBuilder::x86_64()
                .needed("libc.so.6")
                .imports(&refs)
                .text(uniform(8192))
                .build()
                .bytes,
        );
        assert!(!r.findings.iter().any(|f| f.id == "ELF-PACKED-LIKELY"));
    }

    #[test]
    fn benign_profiles_are_not_packed() {
        for b in [
            profiles::glibc_pie(),
            profiles::go_static(),
            profiles::rust_pie(),
            profiles::busybox_static(),
        ] {
            let r = analyze(b.build().bytes);
            assert!(
                !r.findings.iter().any(|f| f.id.starts_with("ELF-PACK")),
                "{:?}",
                r.findings.iter().map(|f| f.id).collect::<Vec<_>>()
            );
        }
    }
}

//! PE section table facts plus section and entry-point findings.
//!
//! Findings (see `docs/heuristics.md`):
//! - `PE-SECTION-RWX`: a section is both writable and executable.
//! - `PE-SECTION-NAME-UNUSUAL`: a section name no common toolchain produces.
//! - `PE-SECTION-VIRTUAL-ONLY`: executable section with no raw data but a
//!   large virtual size (unpacking target).
//! - `PE-SECTION-HIGH-ENTROPY`: section data looks compressed or encrypted.
//! - `PE-ENTRYPOINT-UNUSUAL`: entry point outside the expected code section.
//!
//! Managed .NET images skip the entry-point heuristic: their native entry is
//! a loader stub (or 0 for PE32+) by design.

use super::{scn, PeImage, SectionHeader};
use crate::analyzers::entropy::shannon_bounded;
use crate::analyzers::{AnalysisContext, Analyzer};
use crate::config::Thresholds;
use crate::deadline::Deadline;
use crate::error::AnalysisError;
use crate::report::{
    Category, Confidence, Evidence, Finding, Format, PeFacts, PeSectionFacts, ReportBuilder,
    Severity,
};

/// `IMAGE_FILE_DLL`.
const FILE_DLL: u16 = 0x2000;

/// Section names produced by common toolchains. Exact, case-sensitive match.
const KNOWN_NAMES: &[&str] = &[
    // Microsoft linker (MSVC, Clang/LLVM, Rust MSVC target)
    ".text",
    ".textbss",
    ".data",
    ".rdata",
    ".idata",
    ".edata",
    ".pdata",
    ".xdata",
    ".rsrc",
    ".reloc",
    ".tls",
    ".bss",
    ".CRT",
    ".debug",
    ".gfids",
    ".giats",
    ".gljmp",
    ".gehcont",
    ".00cfg",
    ".didat",
    ".sxdata",
    ".orpc",
    ".retplne",
    ".voltbl",
    "_RDATA",
    ".fptable",
    ".msvcjmc",
    ".detourc",
    ".detourd",
    "fothk",
    ".mrdata",
    ".a64xrm",
    ".hexpthk",
    ".cormeta",
    ".nep",
    ".wpp_sf",
    ".rtc",
    // Kernel-mode drivers
    "INIT",
    "INITDATA",
    "INITKDBG",
    "GFIDS",
    "POOLCODE",
    "POOLMI",
    "NONPAGE",
    // Borland / Delphi / C++Builder
    "CODE",
    "DATA",
    "BSS",
    ".itext",
    ".didata",
    // MinGW / GCC
    ".eh_frame",
    ".rodata",
    ".ctors",
    ".dtors",
    ".gnu_debuglink",
    ".buildid",
    // Go
    ".symtab",
];

/// Prefixes of known name families (`PAGE*` driver sections, DWARF debug
/// sections, COFF long names such as `/4` that refer to the string table).
const KNOWN_PREFIXES: &[&str] = &["PAGE", ".debug_", ".zdebug_"];

/// Fills section facts and emits section / entry-point findings.
#[derive(Debug, Clone, Copy, Default)]
pub struct PeSectionsAnalyzer;

impl Analyzer for PeSectionsAnalyzer {
    fn name(&self) -> &'static str {
        "pe-sections"
    }

    fn applies_to(&self, format: Format) -> bool {
        format == Format::Pe
    }

    fn run(&self, ctx: &AnalysisContext<'_>, out: &mut ReportBuilder) -> Result<(), AnalysisError> {
        let Some(pe) = super::pe_or_skip(ctx) else {
            return Ok(());
        };
        let t = &ctx.config.thresholds;
        let mut facts = Vec::with_capacity(pe.sections.len());
        for s in &pe.sections {
            ctx.deadline.check()?;
            facts.push(section_facts(s, &ctx.input.data, t, &ctx.deadline)?);
        }

        rwx_finding(pe, out);
        unusual_name_finding(pe, out);
        virtual_only_finding(pe, t, out);
        high_entropy_finding(pe, &facts, t, out);
        if !pe.is_managed_dotnet() {
            entry_point_finding(pe, out);
        }

        out.facts.pe.get_or_insert_with(PeFacts::default).sections = Some(facts);
        Ok(())
    }
}

fn section_facts(
    s: &SectionHeader,
    data: &[u8],
    t: &Thresholds,
    deadline: &Deadline,
) -> Result<PeSectionFacts, AnalysisError> {
    let len = data.len() as u64;
    let start = u64::from(s.raw_offset);
    let claimed_end = start.saturating_add(u64::from(s.raw_size));
    let raw_truncated = s.raw_size > 0 && claimed_end > len;
    let available = usize::try_from(start)
        .ok()
        .zip(usize::try_from(claimed_end.min(len)).ok())
        .and_then(|(a, b)| data.get(a..b))
        .unwrap_or_default();
    let entropy = if available.len() >= t.section_entropy_min_size {
        Some(shannon_bounded(available, deadline)?)
    } else {
        None
    };
    Ok(PeSectionFacts {
        index: s.index,
        name: s.name.clone(),
        virtual_address: s.virtual_address,
        virtual_size: s.virtual_size,
        raw_offset: s.raw_offset,
        raw_size: s.raw_size,
        characteristics_raw: s.characteristics,
        permissions: permissions(s.characteristics),
        flags: flag_names(s.characteristics),
        entropy,
        raw_truncated,
    })
}

fn rwx_finding(pe: &PeImage, out: &mut ReportBuilder) {
    let hits: Vec<_> = pe
        .sections
        .iter()
        .filter(|s| s.is_executable() && s.is_writable())
        .collect();
    if hits.is_empty() {
        return;
    }
    let mut f = Finding::new(
        "PE-SECTION-RWX",
        Severity::Medium,
        Category::Anomaly,
        "Writable and executable section",
    )
    .detail(
        "A section that is both writable and executable lets code modify itself \
         in place, typical of packers, self-decrypting loaders and shellcode stubs. \
         Normal compilers keep code read-only.",
    );
    for s in hits {
        f = f.evidence(section_ev(s)).evidence(Evidence::Field {
            name: "Characteristics",
            value: format!(
                "0x{:08x} ({})",
                s.characteristics,
                permissions(s.characteristics)
            ),
        });
    }
    out.push_finding(f);
}

fn unusual_name_finding(pe: &PeImage, out: &mut ReportBuilder) {
    let hits: Vec<_> = pe
        .sections
        .iter()
        .filter(|s| is_unusual_name(&s.name))
        .collect();
    if hits.is_empty() {
        return;
    }
    let mut f = Finding::new(
        "PE-SECTION-NAME-UNUSUAL",
        Severity::Info,
        Category::Anomaly,
        "Unusual section name",
    )
    .confidence(Confidence::Low)
    .detail(
        "Section names not produced by common toolchains (MSVC, Clang, GCC/MinGW, \
         Delphi, Go, drivers). Often set by packers and protectors; also by \
         custom linkers.",
    );
    for s in hits {
        f = f.evidence(section_ev(s));
    }
    out.push_finding(f);
}

/// `true` if the name is empty, non-printable, or from no known toolchain.
fn is_unusual_name(name: &str) -> bool {
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_graphic()) {
        return true;
    }
    let long_name_ref = name
        .strip_prefix('/')
        .is_some_and(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()));
    !(long_name_ref
        || KNOWN_NAMES.contains(&name)
        || KNOWN_PREFIXES.iter().any(|p| name.starts_with(p)))
}

fn virtual_only_finding(pe: &PeImage, t: &Thresholds, out: &mut ReportBuilder) {
    let hits: Vec<_> = pe
        .sections
        .iter()
        .filter(|s| {
            s.is_executable() && s.raw_size == 0 && s.virtual_size >= t.virtual_only_min_size
        })
        .collect();
    if hits.is_empty() {
        return;
    }
    let mut f = Finding::new(
        "PE-SECTION-VIRTUAL-ONLY",
        Severity::Medium,
        Category::Packing,
        "Executable section with no data on disk",
    )
    .detail(
        "An executable section occupies memory but has no bytes in the file: it is \
         filled at run time, the classic layout of packers (e.g. UPX0) that \
         decompress code into it. Uninitialized-data sections (.bss) are not \
         executable and are not reported.",
    );
    for s in hits {
        f = f.evidence(section_ev(s)).evidence(Evidence::Field {
            name: "VirtualSize",
            value: format!("0x{:x} (SizeOfRawData 0)", s.virtual_size),
        });
    }
    out.push_finding(f);
}

fn high_entropy_finding(
    pe: &PeImage,
    facts: &[PeSectionFacts],
    t: &Thresholds,
    out: &mut ReportBuilder,
) {
    let hits: Vec<_> = pe
        .sections
        .iter()
        .zip(facts)
        .filter_map(|(s, f)| f.entropy.filter(|&e| e >= t.entropy_high).map(|e| (s, e)))
        .collect();
    if hits.is_empty() {
        return;
    }
    let any_exec = hits.iter().any(|(s, _)| s.is_executable());
    let (severity, confidence) = if any_exec {
        (Severity::Medium, Confidence::Medium)
    } else {
        (Severity::Low, Confidence::Low)
    };
    let mut f = Finding::new(
        "PE-SECTION-HIGH-ENTROPY",
        severity,
        Category::Packing,
        if any_exec {
            "Executable section looks compressed or encrypted"
        } else {
            "Data section looks compressed or encrypted"
        },
    )
    .confidence(confidence)
    .detail(format!(
        "Section data has entropy >= {:.2} bits/byte. In code this means packed \
         or encrypted instructions; in data sections it is often just compressed \
         resources (images, archives), hence lower severity there.",
        t.entropy_high
    ));
    for (s, e) in hits {
        f = f.evidence(section_ev(s)).evidence(Evidence::Metric {
            name: "entropy",
            value: e,
        });
    }
    out.push_finding(f);
}

/// Why an entry point is unusual, most severe first.
fn entry_point_finding(pe: &PeImage, out: &mut ReportBuilder) {
    let ep = pe.entry_rva;
    let is_dll = pe.characteristics & FILE_DLL != 0;
    if ep == 0 && is_dll {
        return; // resource-only DLL / no DllMain: normal
    }
    let first_exec = pe.sections.iter().find(|s| s.is_executable());
    let last = pe.sections.last();
    let section = pe.section_for_rva(ep);

    let (severity, confidence, reason) = match section {
        None if ep < pe.size_of_headers => (
            Severity::Medium,
            Confidence::High,
            "entry point lies inside the PE headers",
        ),
        None => (
            Severity::Medium,
            Confidence::High,
            "entry point lies outside every section",
        ),
        Some(s) if !s.is_executable() => (
            Severity::Medium,
            Confidence::Medium,
            "entry point is in a non-executable section",
        ),
        Some(s) if Some(s.index) == last.map(|l| l.index)
            && Some(s.index) != first_exec.map(|f| f.index) =>
        {
            (
                Severity::Medium,
                Confidence::Medium,
                "entry point is in the last section, not the first code section (typical packer stub)",
            )
        }
        Some(s) if Some(s.index) != first_exec.map(|f| f.index) => (
            Severity::Low,
            Confidence::Low,
            "entry point is in an executable section other than the first one",
        ),
        Some(_) => return,
    };

    let mut f = Finding::new(
        "PE-ENTRYPOINT-UNUSUAL",
        severity,
        Category::Anomaly,
        "Unusual entry point location",
    )
    .confidence(confidence)
    .detail(format!(
        "The {reason}. Compilers put the entry point in the first code section; \
         packers and protectors move it to their own stub."
    ))
    .evidence(Evidence::Field {
        name: "AddressOfEntryPoint",
        value: format!("0x{ep:08x}"),
    });
    if let Some(s) = section {
        f = f.evidence(section_ev(s));
    }
    if let Some(fe) = first_exec.filter(|fe| Some(fe.index) != section.map(|s| s.index)) {
        f = f.evidence(Evidence::Field {
            name: "first executable section",
            value: format!("#{} {}", fe.index, fe.name),
        });
    }
    out.push_finding(f);
}

fn section_ev(s: &SectionHeader) -> Evidence {
    Evidence::Section {
        index: s.index,
        name: s.name.clone(),
    }
}

/// `rwx` string, `-` for unset bits.
fn permissions(c: u32) -> String {
    [
        (scn::MEM_READ, 'r'),
        (scn::MEM_WRITE, 'w'),
        (scn::MEM_EXECUTE, 'x'),
    ]
    .iter()
    .map(|&(bit, ch)| if c & bit != 0 { ch } else { '-' })
    .collect()
}

fn flag_names(c: u32) -> Vec<&'static str> {
    [
        (scn::CNT_CODE, "code"),
        (scn::CNT_INITIALIZED_DATA, "initialized_data"),
        (scn::CNT_UNINITIALIZED_DATA, "uninitialized_data"),
        (scn::MEM_DISCARDABLE, "discardable"),
        (scn::MEM_SHARED, "shared"),
    ]
    .iter()
    .filter(|(bit, _)| c & bit != 0)
    .map(|&(_, name)| name)
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::input::Input;
    use crate::report::Report;
    use crate::Registry;
    use rtriage_fixtures::pe::{profiles, put_u32, Arch, Entry, PeBuilder, Section};

    fn analyze(bytes: Vec<u8>) -> Report {
        let input = Input::from_bytes("t.exe", bytes);
        assert_eq!(input.format, Format::Pe);
        let r = Registry::default().analyze(&input, &Config::default());
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        r
    }

    fn finding<'a>(r: &'a Report, id: &str) -> Option<&'a Finding> {
        r.findings.iter().find(|f| f.id == id)
    }

    fn ids(r: &Report) -> Vec<&'static str> {
        r.findings.iter().map(|f| f.id).collect()
    }

    fn sections(r: &Report) -> &[PeSectionFacts] {
        r.facts.pe.as_ref().unwrap().sections.as_deref().unwrap()
    }

    /// 8.0-entropy payload.
    fn uniform(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 256) as u8).collect()
    }

    // ---- facts

    #[test]
    fn section_facts_basic() {
        let r = analyze(PeBuilder::minimal(Arch::X64).build().bytes);
        let s = sections(&r);
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].name, ".text");
        assert_eq!(s[0].permissions, "r-x");
        assert_eq!(s[0].flags, ["code"]);
        assert_eq!(s[1].permissions, "rw-");
        assert!(!s[0].raw_truncated);
        // 64 bytes of data padded to 512 raw: entropy is computed (>= 512 bytes).
        assert!(s[0].entropy.is_some());
    }

    #[test]
    fn raw_data_past_eof_is_flagged_not_panic() {
        let mut built = PeBuilder::minimal(Arch::X64).build();
        let raw_size_field = built.layout.section_table_offset + 16;
        put_u32(&mut built.bytes, raw_size_field, 0x7FFF_FFFF);
        let r = analyze(built.bytes);
        assert!(sections(&r)[0].raw_truncated);
    }

    #[test]
    fn huge_raw_offset_has_no_entropy() {
        let mut built = PeBuilder::minimal(Arch::X64).build();
        let raw_ptr_field = built.layout.section_table_offset + 20;
        put_u32(&mut built.bytes, raw_ptr_field, u32::MAX);
        let r = analyze(built.bytes);
        assert!(sections(&r)[0].entropy.is_none());
        assert!(sections(&r)[0].raw_truncated);
    }

    // ---- RWX

    #[test]
    fn rwx_section_is_flagged() {
        let r = analyze(
            PeBuilder::minimal(Arch::X64)
                .section(Section::rwx(".stub", vec![0x90; 32]))
                .build()
                .bytes,
        );
        let f = finding(&r, "PE-SECTION-RWX").unwrap();
        assert_eq!(
            (f.severity, f.confidence),
            (Severity::Medium, Confidence::Medium)
        );
        assert!(f.evidence.contains(&Evidence::Section {
            index: 2,
            name: ".stub".into()
        }));
    }

    #[test]
    fn rx_code_and_rw_data_are_not_rwx() {
        let r = analyze(PeBuilder::minimal(Arch::X86).build().bytes);
        assert!(finding(&r, "PE-SECTION-RWX").is_none());
    }

    // ---- names

    #[test]
    fn packer_like_name_is_unusual() {
        let r = analyze(
            PeBuilder::minimal(Arch::X64)
                .section(Section::rdata("UPX1", vec![0; 16]))
                .build()
                .bytes,
        );
        let f = finding(&r, "PE-SECTION-NAME-UNUSUAL").unwrap();
        assert_eq!(f.severity, Severity::Info);
    }

    #[test]
    fn toolchain_names_are_not_unusual() {
        for name in [
            ".text",
            "CODE",
            "BSS",
            ".itext",
            "PAGE",
            "PAGELK",
            "INIT",
            ".symtab",
            ".eh_frame",
            "/4",
            "/19",
            ".debug_info",
            "_RDATA",
            ".00cfg",
        ] {
            assert!(!is_unusual_name(name), "{name}");
        }
        for name in ["", "UPX0", ".aspack", "/", "/x", ".te\u{7}t", ".TEXT"] {
            assert!(is_unusual_name(name), "{name:?}");
        }
    }

    // ---- virtual-only

    #[test]
    fn executable_virtual_only_section_is_flagged() {
        let r = analyze(
            PeBuilder::minimal(Arch::X86)
                .section(
                    Section::rwx("UPX0", Vec::new())
                        .raw_size(0)
                        .virtual_size(0x10_0000),
                )
                .build()
                .bytes,
        );
        let f = finding(&r, "PE-SECTION-VIRTUAL-ONLY").unwrap();
        assert_eq!(f.category, Category::Packing);
    }

    #[test]
    fn bss_and_small_virtual_sections_are_not_flagged() {
        let bss = Section::new(
            ".bss",
            scn::CNT_UNINITIALIZED_DATA | scn::MEM_READ | scn::MEM_WRITE,
            Vec::new(),
        )
        .raw_size(0)
        .virtual_size(0x10_0000);
        let tiny_exec = Section::code(".stub", Vec::new())
            .raw_size(0)
            .virtual_size(0x200);
        let r = analyze(
            PeBuilder::minimal(Arch::X64)
                .section(bss)
                .section(tiny_exec)
                .build()
                .bytes,
        );
        assert!(finding(&r, "PE-SECTION-VIRTUAL-ONLY").is_none());
    }

    // ---- entropy

    #[test]
    fn high_entropy_code_is_medium() {
        let r = analyze(
            PeBuilder::new(Arch::X64)
                .section(Section::code(".text", uniform(4096)))
                .build()
                .bytes,
        );
        let f = finding(&r, "PE-SECTION-HIGH-ENTROPY").unwrap();
        assert_eq!(
            (f.severity, f.confidence),
            (Severity::Medium, Confidence::Medium)
        );
        assert!(f
            .evidence
            .iter()
            .any(|e| matches!(e, Evidence::Metric { name: "entropy", value } if *value > 7.9)));
    }

    #[test]
    fn high_entropy_resources_are_low() {
        let r = analyze(
            PeBuilder::minimal(Arch::X64)
                .section(Section::rdata(".rsrc", uniform(4096)))
                .build()
                .bytes,
        );
        let f = finding(&r, "PE-SECTION-HIGH-ENTROPY").unwrap();
        assert_eq!((f.severity, f.confidence), (Severity::Low, Confidence::Low));
    }

    #[test]
    fn small_sections_get_no_entropy_verdict() {
        // 256 random-looking bytes, but raw size is file-aligned to 512 with
        // zero padding, so entropy drops well below the threshold.
        let r = analyze(
            PeBuilder::new(Arch::X64)
                .section(Section::code(".text", uniform(256)))
                .build()
                .bytes,
        );
        assert!(finding(&r, "PE-SECTION-HIGH-ENTROPY").is_none());
    }

    // ---- entry point

    fn ep_finding(b: PeBuilder) -> Option<(Severity, Confidence)> {
        let r = analyze(b.build().bytes);
        finding(&r, "PE-ENTRYPOINT-UNUSUAL").map(|f| (f.severity, f.confidence))
    }

    #[test]
    fn entry_in_first_code_section_is_normal() {
        assert_eq!(ep_finding(PeBuilder::minimal(Arch::X64)), None);
    }

    #[test]
    fn entry_outside_sections() {
        assert_eq!(
            ep_finding(PeBuilder::minimal(Arch::X64).entry(Entry::Rva(0xdead_0000))),
            Some((Severity::Medium, Confidence::High))
        );
    }

    #[test]
    fn entry_in_headers() {
        assert_eq!(
            ep_finding(PeBuilder::minimal(Arch::X64).entry(Entry::Rva(0x10))),
            Some((Severity::Medium, Confidence::High))
        );
    }

    #[test]
    fn exe_with_zero_entry_is_in_headers() {
        assert_eq!(
            ep_finding(PeBuilder::minimal(Arch::X64).entry(Entry::Rva(0))),
            Some((Severity::Medium, Confidence::High))
        );
    }

    #[test]
    fn dll_with_zero_entry_is_normal() {
        assert_eq!(
            ep_finding(PeBuilder::minimal(Arch::X64).dll(true).entry(Entry::Rva(0))),
            None
        );
    }

    #[test]
    fn entry_in_data_section() {
        assert_eq!(
            ep_finding(PeBuilder::minimal(Arch::X86).entry(Entry::Section {
                index: 1,
                offset: 0
            })),
            Some((Severity::Medium, Confidence::Medium))
        );
    }

    #[test]
    fn entry_in_last_code_section() {
        let b = PeBuilder::minimal(Arch::X86)
            .section(Section::rwx(".stub", vec![0x90; 16]))
            .entry(Entry::Section {
                index: 2,
                offset: 0,
            });
        assert_eq!(ep_finding(b), Some((Severity::Medium, Confidence::Medium)));
    }

    #[test]
    fn entry_in_second_code_section_not_last() {
        let b = PeBuilder::new(Arch::X64)
            .section(Section::code(".text", vec![0xC3; 16]))
            .section(Section::code(".text2", vec![0xC3; 16]))
            .section(Section::data(".data", vec![0; 16]))
            .entry(Entry::Section {
                index: 1,
                offset: 0,
            });
        assert_eq!(ep_finding(b), Some((Severity::Low, Confidence::Low)));
    }

    #[test]
    fn single_section_image_is_normal() {
        let b = PeBuilder::new(Arch::X64).section(Section::code(".text", vec![0xC3; 16]));
        assert_eq!(ep_finding(b), None);
    }

    // ---- negative profiles

    #[test]
    fn dotnet_profile_has_no_section_findings() {
        for arch in [Arch::X86, Arch::X64] {
            let r = analyze(profiles::dotnet_like(arch).build().bytes);
            assert!(r.findings.is_empty(), "{:?}", ids(&r));
            // PE32+ IL-only assemblies have EntryPoint 0: still no finding.
            let r = analyze(
                profiles::dotnet_like(arch)
                    .entry(Entry::Rva(0))
                    .build()
                    .bytes,
            );
            assert!(r.findings.is_empty(), "{:?}", ids(&r));
        }
    }

    #[test]
    fn go_profile_has_no_section_findings() {
        for arch in [Arch::X86, Arch::X64] {
            let r = analyze(profiles::go_like(arch).build().bytes);
            assert_eq!(ids(&r), ["PE-TIMESTAMP-ZERO"]);
        }
    }

    #[test]
    fn delphi_like_layout_is_clean() {
        let b = PeBuilder::new(Arch::X86)
            .section(Section::code("CODE", vec![0xC3; 64]))
            .section(Section::data("DATA", vec![0; 64]))
            .section(
                Section::new(
                    "BSS",
                    scn::CNT_UNINITIALIZED_DATA | scn::MEM_READ | scn::MEM_WRITE,
                    Vec::new(),
                )
                .raw_size(0)
                .virtual_size(0x2000),
            )
            .section(Section::rdata(".idata", vec![0; 64]));
        let r = analyze(b.build().bytes);
        assert!(r.findings.is_empty(), "{:?}", ids(&r));
    }
}

//! ELF segment and section facts plus layout findings.
//!
//! Findings (see `docs/heuristics.md`):
//! - `ELF-SEGMENT-RWX`: a `PT_LOAD` that is writable and executable
//!   (lower on MIPS / PPC32 / ARM32, whose legacy toolchains emit RWX layouts).
//! - `ELF-SEGMENT-HIGH-ENTROPY`: a `PT_LOAD` whose file bytes look compressed.
//! - `ELF-SECTIONS-MISSING`: an executable or shared object without section headers.
//! - `ELF-SECTIONS-INCONSISTENT`: unusable or contradictory section headers.

use super::{ElfImage, ElfSection, Segment, PF_R, PF_W, PF_X, PT_LOAD};
use crate::analyzers::entropy::shannon_bounded;
use crate::analyzers::{AnalysisContext, Analyzer};
use crate::config::Thresholds;
use crate::deadline::Deadline;
use crate::error::AnalysisError;
use crate::report::{
    Category, Confidence, ElfFacts, ElfSectionFacts, ElfSegmentFacts, Evidence, Finding, Format,
    ReportBuilder, Severity,
};

const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
/// `SHT_NOBITS`: occupies no file space.
const SHT_NOBITS: u32 = 8;
/// `SHF_ALLOC`.
const SHF_ALLOC: u64 = 2;
/// Architectures whose legacy toolchains produce RWX segments by default
/// (MIPS, 32-bit PowerPC with BSS-PLT, ARM32).
const LEGACY_RWX_MACHINES: &[u16] = &[8, 20, 40];
/// Evidence entries per finding.
const MAX_EVIDENCE: usize = 8;

/// Fills segment/section facts and emits layout findings.
#[derive(Debug, Clone, Copy, Default)]
pub struct ElfSegmentsAnalyzer;

impl Analyzer for ElfSegmentsAnalyzer {
    fn name(&self) -> &'static str {
        "elf-segments"
    }

    fn applies_to(&self, format: Format) -> bool {
        format == Format::Elf
    }

    fn run(&self, ctx: &AnalysisContext<'_>, out: &mut ReportBuilder) -> Result<(), AnalysisError> {
        let Some(elf) = super::elf_or_skip(ctx) else {
            return Ok(());
        };
        let data = &ctx.input.data;
        let t = &ctx.config.thresholds;
        let mut segments = Vec::with_capacity(elf.segments.len());
        for s in &elf.segments {
            ctx.deadline.check()?;
            segments.push(segment_facts(s, data, t, &ctx.deadline)?);
        }
        let mut problems = elf.section_problems.clone();
        problems.extend(layout_problems(elf, data.len()));

        rwx_finding(elf, out);
        high_entropy_finding(elf, &segments, t, out);
        sections_finding(elf, &problems, out);

        let facts = out.facts.elf.get_or_insert_with(ElfFacts::default);
        facts.segments = Some(segments);
        facts.sections = Some(elf.sections.iter().map(section_facts).collect());
        facts.section_problems = Some(problems);
        Ok(())
    }
}

fn segment_facts(
    s: &Segment,
    data: &[u8],
    t: &Thresholds,
    deadline: &Deadline,
) -> Result<ElfSegmentFacts, AnalysisError> {
    let len = data.len() as u64;
    let end = s.offset.saturating_add(s.filesz);
    let bytes = usize::try_from(s.offset)
        .ok()
        .zip(usize::try_from(end.min(len)).ok())
        .and_then(|(a, b)| data.get(a..b))
        .unwrap_or_default();
    let entropy = if s.kind == PT_LOAD && bytes.len() >= t.section_entropy_min_size {
        Some(shannon_bounded(bytes, deadline)?)
    } else {
        None
    };
    Ok(ElfSegmentFacts {
        index: s.index,
        kind: segment_type_name(s.kind),
        kind_raw: s.kind,
        permissions: perms(s.flags),
        offset: s.offset,
        vaddr: s.vaddr,
        filesz: s.filesz,
        memsz: s.memsz,
        entropy,
        truncated: s.filesz > 0 && end > len,
    })
}

fn section_facts(s: &ElfSection) -> ElfSectionFacts {
    ElfSectionFacts {
        index: s.index,
        name: s.name.clone(),
        kind: section_type_name(s.kind),
        flags: section_flag_names(s.flags),
        addr: s.addr,
        offset: s.offset,
        size: s.size,
    }
}

/// Contradictions between usable section headers, the file and the segments.
fn layout_problems(elf: &ElfImage, file_len: usize) -> Vec<String> {
    let len = file_len as u64;
    let has_loads = elf.segments.iter().any(|s| s.kind == PT_LOAD);
    let mut problems = Vec::new();
    for s in elf.sections.iter().skip(1) {
        if s.kind != SHT_NOBITS && s.size > 0 && s.offset.saturating_add(s.size) > len {
            problems.push(format!(
                "section #{} {:?} runs past end of file",
                s.index, s.name
            ));
        }
        if has_loads
            && s.flags & SHF_ALLOC != 0
            && s.size > 0
            && elf.load_for_vaddr(s.addr).is_none()
        {
            problems.push(format!(
                "allocated section #{} {:?} at 0x{:x} is outside every PT_LOAD",
                s.index, s.name, s.addr
            ));
        }
    }
    problems
}

fn rwx_finding(elf: &ElfImage, out: &mut ReportBuilder) {
    let hits: Vec<&Segment> = elf
        .segments
        .iter()
        .filter(|s| s.kind == PT_LOAD && s.flags & PF_W != 0 && s.flags & PF_X != 0)
        .collect();
    if hits.is_empty() {
        return;
    }
    let legacy = LEGACY_RWX_MACHINES.contains(&elf.machine);
    let (severity, confidence) = if legacy {
        (Severity::Low, Confidence::Low)
    } else {
        (Severity::Medium, Confidence::Medium)
    };
    let mut f = Finding::new(
        "ELF-SEGMENT-RWX",
        severity,
        Category::Anomaly,
        "Writable and executable segment",
    )
    .confidence(confidence)
    .detail(if legacy {
        "A loadable segment is both writable and executable. Common on this \
         architecture with older toolchains (e.g. BSS-PLT on PPC32, MIPS, ARM32), \
         hence low severity; on modern toolchains it indicates packing or shellcode."
    } else {
        "A loadable segment is both writable and executable: code can rewrite \
         itself in place. Modern linkers never emit this; packers, self-decrypting \
         loaders and hand-made binaries do."
    });
    for s in hits.into_iter().take(MAX_EVIDENCE) {
        f = f.evidence(seg_ev(s));
    }
    out.push_finding(f);
}

fn high_entropy_finding(
    elf: &ElfImage,
    facts: &[ElfSegmentFacts],
    t: &Thresholds,
    out: &mut ReportBuilder,
) {
    let hits: Vec<(&Segment, f64)> = elf
        .segments
        .iter()
        .zip(facts)
        .filter_map(|(s, f)| f.entropy.filter(|&e| e >= t.entropy_high).map(|e| (s, e)))
        .collect();
    if hits.is_empty() {
        return;
    }
    let exec = hits.iter().any(|(s, _)| s.flags & PF_X != 0);
    let (severity, confidence) = if exec {
        (Severity::Medium, Confidence::Medium)
    } else {
        (Severity::Low, Confidence::Low)
    };
    let mut f = Finding::new(
        "ELF-SEGMENT-HIGH-ENTROPY",
        severity,
        Category::Packing,
        if exec {
            "Executable segment looks compressed or encrypted"
        } else {
            "Data segment looks compressed or encrypted"
        },
    )
    .confidence(confidence)
    .detail(format!(
        "Segment file data has entropy >= {:.2} bits/byte: packed or encrypted \
         code in an executable segment; often embedded compressed data otherwise.",
        t.entropy_high
    ));
    for (s, e) in hits.into_iter().take(MAX_EVIDENCE) {
        f = f.evidence(seg_ev(s)).evidence(Evidence::Metric {
            name: "entropy",
            value: e,
        });
    }
    out.push_finding(f);
}

fn sections_finding(elf: &ElfImage, problems: &[String], out: &mut ReportBuilder) {
    if !matches!(elf.elf_type, ET_EXEC | ET_DYN) {
        return;
    }
    if !problems.is_empty() {
        let mut f = Finding::new(
            "ELF-SECTIONS-INCONSISTENT",
            Severity::Low,
            Category::Anomaly,
            "Section headers are inconsistent",
        )
        .confidence(Confidence::Low)
        .detail(
            "The section header table is unusable or contradicts the file or the \
             segments. Loaders ignore sections, so this only affects tools: typical \
             of hand-crafted or anti-analysis binaries, and of truncated files.",
        );
        for p in problems.iter().take(MAX_EVIDENCE) {
            f = f.evidence(Evidence::Field {
                name: "problem",
                value: p.clone(),
            });
        }
        out.push_finding(f);
    } else if elf.sections.is_empty() {
        out.push_finding(
            Finding::new(
                "ELF-SECTIONS-MISSING",
                Severity::Low,
                Category::Anomaly,
                "No section headers",
            )
            .detail(
                "The file has no section header table. Plain `strip` keeps it; it is \
                 removed by sstrip-style tools, packers and hand-made binaries to hinder \
                 disassemblers and debuggers.",
            )
            .evidence(Evidence::Field {
                name: "e_shoff",
                value: "0".into(),
            }),
        );
    }
}

fn seg_ev(s: &Segment) -> Evidence {
    Evidence::Field {
        name: "segment",
        value: format!(
            "#{} {} {} offset 0x{:x} vaddr 0x{:x} size 0x{:x}",
            s.index,
            segment_type_name(s.kind),
            perms(s.flags),
            s.offset,
            s.vaddr,
            s.filesz
        ),
    }
}

/// `rwx` string, `-` for unset bits.
pub fn perms(flags: u32) -> String {
    [(PF_R, 'r'), (PF_W, 'w'), (PF_X, 'x')]
        .iter()
        .map(|&(bit, c)| if flags & bit != 0 { c } else { '-' })
        .collect()
}

/// Program header type name.
pub fn segment_type_name(kind: u32) -> String {
    let name = match kind {
        0 => "NULL",
        1 => "LOAD",
        2 => "DYNAMIC",
        3 => "INTERP",
        4 => "NOTE",
        5 => "SHLIB",
        6 => "PHDR",
        7 => "TLS",
        0x6474_e550 => "GNU_EH_FRAME",
        0x6474_e551 => "GNU_STACK",
        0x6474_e552 => "GNU_RELRO",
        0x6474_e553 => "GNU_PROPERTY",
        _ => return format!("0x{kind:x}"),
    };
    name.to_owned()
}

fn section_type_name(kind: u32) -> String {
    let name = match kind {
        0 => "NULL",
        1 => "PROGBITS",
        2 => "SYMTAB",
        3 => "STRTAB",
        4 => "RELA",
        5 => "HASH",
        6 => "DYNAMIC",
        7 => "NOTE",
        8 => "NOBITS",
        9 => "REL",
        11 => "DYNSYM",
        14 => "INIT_ARRAY",
        15 => "FINI_ARRAY",
        16 => "PREINIT_ARRAY",
        17 => "GROUP",
        18 => "SYMTAB_SHNDX",
        0x6fff_fff6 => "GNU_HASH",
        0x6fff_fffd => "GNU_VERDEF",
        0x6fff_fffe => "GNU_VERNEED",
        0x6fff_ffff => "GNU_VERSYM",
        _ => return format!("0x{kind:x}"),
    };
    name.to_owned()
}

fn section_flag_names(flags: u64) -> Vec<&'static str> {
    [
        (0x1, "write"),
        (0x2, "alloc"),
        (0x4, "exec"),
        (0x10, "merge"),
        (0x20, "strings"),
        (0x40, "info_link"),
        (0x200, "group"),
        (0x400, "tls"),
        (0x800, "compressed"),
    ]
    .iter()
    .filter(|(bit, _)| flags & bit != 0)
    .map(|&(_, n)| n)
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::input::Input;
    use crate::report::Report;
    use crate::Registry;
    use rtriage_fixtures::elf::{et, machine, pf, profiles, Class, ElfBuilder, Endian};

    fn analyze(bytes: Vec<u8>) -> Report {
        let r = Registry::default().analyze(&Input::from_bytes("t", bytes), &Config::default());
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        r
    }

    fn ids(r: &Report) -> Vec<&'static str> {
        r.findings
            .iter()
            .map(|f| f.id)
            .filter(|id| id.starts_with("ELF-SEGMENT") || id.starts_with("ELF-SECTIONS"))
            .collect()
    }

    fn finding<'a>(r: &'a Report, id: &str) -> &'a Finding {
        r.findings.iter().find(|f| f.id == id).unwrap()
    }

    fn elf_facts(r: &Report) -> &ElfFacts {
        r.facts.elf.as_ref().unwrap()
    }

    fn uniform(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 256) as u8).collect()
    }

    fn put16(b: &mut [u8], at: usize, v: u16) {
        b[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }

    #[test]
    fn segment_and_section_facts() {
        let r = analyze(profiles::glibc_pie().build().bytes);
        let f = elf_facts(&r);
        let segs = f.segments.as_ref().unwrap();
        assert!(segs
            .iter()
            .any(|s| s.kind == "LOAD" && s.permissions == "r-x"));
        assert!(segs.iter().any(|s| s.kind == "GNU_RELRO"));
        assert!(segs
            .iter()
            .any(|s| s.kind == "GNU_STACK" && s.permissions == "rw-"));
        let secs = f.sections.as_ref().unwrap();
        let text = secs.iter().find(|s| s.name == ".text").unwrap();
        assert_eq!(text.kind, "PROGBITS");
        assert_eq!(text.flags, ["alloc", "exec"]);
        assert!(secs.iter().any(|s| s.kind == "DYNSYM"));
        assert!(f.section_problems.as_ref().unwrap().is_empty());
    }

    #[test]
    fn benign_profiles_have_no_layout_findings() {
        for b in [
            profiles::glibc_pie(),
            profiles::go_static(),
            profiles::rust_pie(),
            profiles::busybox_static(),
        ] {
            let r = analyze(b.build().bytes);
            assert!(ids(&r).is_empty(), "{:?}", ids(&r));
        }
    }

    // ---- RWX

    #[test]
    fn rwx_on_x86_64_is_medium() {
        let r = analyze(
            ElfBuilder::x86_64()
                .text_flags(pf::R | pf::W | pf::X)
                .build()
                .bytes,
        );
        let f = finding(&r, "ELF-SEGMENT-RWX");
        assert_eq!(
            (f.severity, f.confidence),
            (Severity::Medium, Confidence::Medium)
        );
    }

    #[test]
    fn rwx_on_legacy_architectures_is_low() {
        for (class, endian, m) in [
            (Class::Elf32, Endian::Big, machine::MIPS),
            (Class::Elf32, Endian::Big, machine::PPC),
            (Class::Elf32, Endian::Little, machine::ARM),
        ] {
            let r = analyze(
                ElfBuilder::new(class, endian, m)
                    .text_flags(pf::R | pf::W | pf::X)
                    .build()
                    .bytes,
            );
            let f = finding(&r, "ELF-SEGMENT-RWX");
            assert_eq!(
                (f.severity, f.confidence),
                (Severity::Low, Confidence::Low),
                "machine {m}"
            );
        }
        // AArch64 is modern: full severity.
        let r = analyze(
            ElfBuilder::new(Class::Elf64, Endian::Little, machine::AARCH64)
                .text_flags(pf::R | pf::W | pf::X)
                .build()
                .bytes,
        );
        assert_eq!(finding(&r, "ELF-SEGMENT-RWX").severity, Severity::Medium);
    }

    #[test]
    fn rx_and_rw_segments_are_not_rwx() {
        assert!(!ids(&analyze(ElfBuilder::x86_64().build().bytes)).contains(&"ELF-SEGMENT-RWX"));
    }

    // ---- entropy

    #[test]
    fn high_entropy_code_segment() {
        let r = analyze(ElfBuilder::x86_64().text(uniform(8192)).build().bytes);
        let f = finding(&r, "ELF-SEGMENT-HIGH-ENTROPY");
        assert_eq!(
            (f.severity, f.confidence),
            (Severity::Medium, Confidence::Medium)
        );
        assert_eq!(f.category, Category::Packing);
    }

    #[test]
    fn high_entropy_data_segment_is_low() {
        let r = analyze(ElfBuilder::x86_64().data(uniform(8192)).build().bytes);
        let f = finding(&r, "ELF-SEGMENT-HIGH-ENTROPY");
        assert_eq!((f.severity, f.confidence), (Severity::Low, Confidence::Low));
    }

    #[test]
    fn small_or_plain_segments_have_no_entropy_verdict() {
        let r = analyze(ElfBuilder::x86_64().text(uniform(200)).build().bytes);
        assert!(!ids(&r).contains(&"ELF-SEGMENT-HIGH-ENTROPY"));
    }

    // ---- sections

    #[test]
    fn missing_section_headers() {
        let r = analyze(ElfBuilder::x86_64().section_headers(false).build().bytes);
        assert_eq!(ids(&r), ["ELF-SECTIONS-MISSING"]);
        assert_eq!(
            finding(&r, "ELF-SECTIONS-MISSING").confidence,
            Confidence::Medium
        );
    }

    #[test]
    fn relocatable_without_sections_is_not_judged() {
        let r = analyze(
            ElfBuilder::x86_64()
                .elf_type(et::REL)
                .section_headers(false)
                .build()
                .bytes,
        );
        assert!(ids(&r).is_empty());
    }

    #[test]
    fn wrong_shentsize_is_inconsistent_not_missing() {
        let mut built = ElfBuilder::x86_64().build();
        put16(&mut built.bytes, built.layout.shentsize_offset, 48);
        let r = analyze(built.bytes);
        assert_eq!(ids(&r), ["ELF-SECTIONS-INCONSISTENT"]);
        let f = finding(&r, "ELF-SECTIONS-INCONSISTENT");
        assert_eq!((f.severity, f.confidence), (Severity::Low, Confidence::Low));
        assert!(f
            .evidence
            .iter()
            .any(|e| matches!(e, Evidence::Field { value, .. } if value.contains("e_shentsize"))));
    }

    #[test]
    fn section_outside_every_load_is_inconsistent() {
        // Point .text's sh_addr far away from every PT_LOAD.
        let mut built = ElfBuilder::x86_64().build();
        let elf =
            crate::analyzers::elf::parse(&built.bytes, &crate::limits::Limits::default()).unwrap();
        let text = elf.sections.iter().find(|s| s.name == ".text").unwrap();
        let addr_field = built.layout.shoff + text.index * 64 + 16;
        built.bytes[addr_field..addr_field + 8].copy_from_slice(&0xdead_0000_0000u64.to_le_bytes());
        let r = analyze(built.bytes);
        assert_eq!(ids(&r), ["ELF-SECTIONS-INCONSISTENT"]);
    }

    #[test]
    fn truncated_segment_is_flagged_in_facts() {
        let mut built = ElfBuilder::x86_64().build();
        let text_seg = built
            .layout
            .segments
            .iter()
            .find(|s| s.kind == 1 && s.flags == (pf::R | pf::X))
            .unwrap();
        let filesz = text_seg.header_offset + 32;
        built.bytes[filesz..filesz + 8].copy_from_slice(&0x7fff_ffffu64.to_le_bytes());
        let r = analyze(built.bytes);
        let segs = elf_facts(&r).segments.as_ref().unwrap();
        assert!(segs.iter().any(|s| s.truncated));
    }

    #[test]
    fn upx_profile_layout_findings() {
        let r = analyze(profiles::upx_elf().build().bytes);
        let mut got = ids(&r);
        got.sort_unstable();
        assert_eq!(
            got,
            [
                "ELF-SECTIONS-MISSING",
                "ELF-SEGMENT-HIGH-ENTROPY",
                "ELF-SEGMENT-RWX"
            ]
        );
    }
}

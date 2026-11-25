//! Bounded PE export table parser.
//!
//! `NumberOfFunctions` / `NumberOfNames` are attacker-controlled: both are
//! capped at `max_exports`, every array must map contiguously into one
//! section's raw data, and every element costs a budget step.
//!
//! Findings: `PE-EXPORTS-REFLECTIVE-LOADER`, `PE-EXPORTS-ALL-FORWARDED`,
//! `PE-EXPORTS-NAME-MISMATCH` (see `docs/heuristics.md`).

use super::{read_u16, read_u32, PeImage};
use crate::analyzers::{AnalysisContext, Analyzer};
use crate::deadline::Deadline;
use crate::error::AnalysisError;
use crate::limits::Limits;
use std::path::Path;

use crate::report::{
    Category, Confidence, Evidence, Finding, Format, PeExport, PeExportsFacts, PeFacts,
    ReportBuilder, Severity,
};

/// Data directory index of the export table.
const DIRECTORY_EXPORT: usize = 0;
/// Longest export / forwarder name read, in bytes.
const MAX_NAME_LEN: usize = 256;

/// Reads the export table.
#[derive(Debug, Clone, Copy, Default)]
pub struct PeExportsAnalyzer;

impl Analyzer for PeExportsAnalyzer {
    fn name(&self) -> &'static str {
        "pe-exports"
    }

    fn applies_to(&self, format: Format) -> bool {
        format == Format::Pe
    }

    fn run(&self, ctx: &AnalysisContext<'_>, out: &mut ReportBuilder) -> Result<(), AnalysisError> {
        let Some(pe) = super::pe_or_skip(ctx) else {
            return Ok(());
        };
        if let Some(facts) = parse(pe, &ctx.input.data, &ctx.config.limits, &ctx.deadline)? {
            reflective_loader_finding(&facts, out);
            if pe.characteristics & FILE_DLL != 0 {
                all_forwarded_finding(&facts, out);
            }
            name_mismatch_finding(&facts, &ctx.input.path, out);
            out.facts.pe.get_or_insert_with(PeFacts::default).exports = Some(facts);
        }
        Ok(())
    }
}

/// `IMAGE_FILE_DLL`.
const FILE_DLL: u16 = 0x2000;
/// Exact export names of Stephen Fewer's reflective DLL loader (x64
/// undecorated, x86 `__stdcall` decorations). No substring matching.
const REFLECTIVE_LOADER_NAMES: &[&str] = &[
    "ReflectiveLoader",
    "_ReflectiveLoader@0",
    "_ReflectiveLoader@4",
];
/// A proxy DLL forwards everything; fewer exports than this is not judged.
const ALL_FORWARDED_MIN: usize = 5;

fn reflective_loader_finding(facts: &PeExportsFacts, out: &mut ReportBuilder) {
    let Some(e) = facts.exports.iter().find(|e| {
        e.name
            .as_deref()
            .is_some_and(|n| REFLECTIVE_LOADER_NAMES.contains(&n))
    }) else {
        return;
    };
    out.push_finding(
        Finding::new(
            "PE-EXPORTS-REFLECTIVE-LOADER",
            Severity::High,
            Category::Injection,
            "Exports a reflective DLL loader",
        )
        .confidence(Confidence::High)
        .detail(
            "The DLL exports ReflectiveLoader, the entry point that maps the DLL into \
             memory by itself so it can be injected without LoadLibrary. Characteristic \
             of offensive frameworks (Metasploit, Cobalt Strike and their derivatives).",
        )
        .evidence(Evidence::Field {
            name: "export",
            value: format!("#{} {}", e.ordinal, e.name.as_deref().unwrap_or_default()),
        })
        .attack("T1620"),
    );
}

fn all_forwarded_finding(facts: &PeExportsFacts, out: &mut ReportBuilder) {
    let n = facts.exports.len();
    if n < ALL_FORWARDED_MIN
        || facts.limit_reached
        || facts.exports.iter().any(|e| e.forwarder.is_none())
    {
        return;
    }
    let mut f = Finding::new(
        "PE-EXPORTS-ALL-FORWARDED",
        Severity::Low,
        Category::Anomaly,
        "Every export is forwarded to another DLL",
    )
    .confidence(Confidence::Low)
    .detail(
        "A DLL that only forwards calls elsewhere is a proxy: placed under a trusted \
         DLL's name it gets loaded instead of the original (DLL side-loading) while \
         passing calls through. Compatibility shims and game mods do the same.",
    )
    .evidence(Evidence::Field {
        name: "forwarded exports",
        value: n.to_string(),
    })
    .attack("T1574.002");
    for e in facts.exports.iter().take(5) {
        f = f.evidence(Evidence::Field {
            name: "forwarder",
            value: format!(
                "{} -> {}",
                e.name.as_deref().unwrap_or("(ordinal)"),
                e.forwarder.as_deref().unwrap_or_default()
            ),
        });
    }
    out.push_finding(f);
}

fn name_mismatch_finding(facts: &PeExportsFacts, path: &Path, out: &mut ReportBuilder) {
    let (Some(internal), Some(file)) = (
        facts.dll_name.as_deref(),
        path.file_name().map(|n| n.to_string_lossy()),
    ) else {
        return;
    };
    if internal.eq_ignore_ascii_case(&file) || looks_like_hash_name(&file) {
        return;
    }
    out.push_finding(
        Finding::new(
            "PE-EXPORTS-NAME-MISMATCH",
            Severity::Info,
            Category::Anomaly,
            "File name differs from the DLL's internal name",
        )
        .detail(
            "The export directory records the name the DLL was built as. A different \
             file name means it was renamed afterwards, e.g. to pose as another DLL.",
        )
        .evidence(Evidence::Field {
            name: "internal name",
            value: internal.to_owned(),
        })
        .evidence(Evidence::Field {
            name: "file name",
            value: file.into_owned(),
        }),
    );
}

/// Sample stores name files by MD5 / SHA-1 / SHA-256: a mismatch there says
/// nothing about the sample.
fn looks_like_hash_name(file: &str) -> bool {
    let stem = file.split('.').next().unwrap_or(file);
    matches!(stem.len(), 32 | 40 | 64) && stem.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Parses the export directory; `Ok(None)` without one.
///
/// # Errors
/// Unmapped or non-contiguous arrays, truncation, budget, deadline.
pub fn parse(
    pe: &PeImage,
    data: &[u8],
    limits: &Limits,
    deadline: &Deadline,
) -> Result<Option<PeExportsFacts>, AnalysisError> {
    let Some(dir) = pe.directory(DIRECTORY_EXPORT) else {
        return Ok(None);
    };
    let off = pe
        .rva_to_offset(dir.rva, data.len())
        .ok_or_else(|| unmapped("PE export directory", dir.rva))?;
    let field = |at: usize| read_u32(data, off.saturating_add(at), "PE export directory");
    let timestamp = field(4)?;
    let name_rva = field(12)?;
    let base = field(16)?;
    let n_funcs = usize::try_from(field(20)?).unwrap_or(usize::MAX);
    let n_names = usize::try_from(field(24)?).unwrap_or(usize::MAX);
    let funcs_rva = field(28)?;
    let names_rva = field(32)?;
    let ords_rva = field(36)?;

    let limit_reached = n_funcs > limits.max_exports || n_names > limits.max_exports;
    let n_funcs = n_funcs.min(limits.max_exports);
    let n_names = n_names.min(limits.max_exports);
    let mut budget = deadline.budget(limits.max_parser_steps);

    let funcs = array(pe, data, funcs_rva, n_funcs, 4, "export address table")?;
    let dir_end = u64::from(dir.rva) + u64::from(dir.size);
    let mut exports: Vec<Option<PeExport>> = Vec::with_capacity(n_funcs);
    for i in 0..n_funcs {
        budget.step()?;
        let rva = read_u32(funcs, i * 4, "export address table")?;
        if rva == 0 {
            exports.push(None); // unused ordinal slot
            continue;
        }
        let forwarder = (u64::from(rva) >= u64::from(dir.rva) && u64::from(rva) < dir_end)
            .then(|| read_name(pe, data, rva))
            .flatten();
        exports.push(Some(PeExport {
            ordinal: base.saturating_add(u32::try_from(i).unwrap_or(u32::MAX)),
            name: None,
            rva,
            forwarder,
        }));
    }

    if n_names > 0 {
        let names = array(pe, data, names_rva, n_names, 4, "export name table")?;
        let ords = array(pe, data, ords_rva, n_names, 2, "export ordinal table")?;
        for j in 0..n_names {
            budget.step()?;
            let index = usize::from(read_u16(ords, j * 2, "export ordinal table")?);
            let name_rva = read_u32(names, j * 4, "export name table")?;
            if let Some(Some(e)) = exports.get_mut(index) {
                if e.name.is_none() {
                    e.name = read_name(pe, data, name_rva);
                }
            }
        }
    }

    Ok(Some(PeExportsFacts {
        dll_name: read_name(pe, data, name_rva),
        timestamp,
        ordinal_base: base,
        exports: exports.into_iter().flatten().collect(),
        limit_reached,
    }))
}

/// `count` elements of `size` bytes at `rva`, mapped contiguously.
fn array<'a>(
    pe: &PeImage,
    data: &'a [u8],
    rva: u32,
    count: usize,
    size: usize,
    what: &'static str,
) -> Result<&'a [u8], AnalysisError> {
    if count == 0 {
        return Ok(&[]);
    }
    let len = count.checked_mul(size).ok_or_else(|| unmapped(what, rva))?;
    let start = pe
        .rva_to_offset(rva, data.len())
        .ok_or_else(|| unmapped(what, rva))?;
    let last_rva = u32::try_from(len - size)
        .ok()
        .and_then(|d| rva.checked_add(d))
        .ok_or_else(|| unmapped(what, rva))?;
    // The last element must map to the expected offset: same section, no gap.
    if pe.rva_to_offset(last_rva, data.len()) != Some(start + len - size) {
        return Err(AnalysisError::Malformed {
            what,
            reason: format!(
                "array at RVA 0x{rva:08x} ({count} entries) is not contiguous in the file"
            ),
        });
    }
    data.get(start..start + len)
        .ok_or_else(|| unmapped(what, rva))
}

fn read_name(pe: &PeImage, data: &[u8], rva: u32) -> Option<String> {
    let start = pe.rva_to_offset(rva, data.len())?;
    let window = data.get(start..start.saturating_add(MAX_NAME_LEN).min(data.len()))?;
    let end = window.iter().position(|&b| b == 0).unwrap_or(window.len());
    let name = String::from_utf8_lossy(window.get(..end)?).into_owned();
    (!name.is_empty()).then_some(name)
}

fn unmapped(what: &'static str, rva: u32) -> AnalysisError {
    AnalysisError::Malformed {
        what,
        reason: format!("RVA 0x{rva:08x} is not backed by file data"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::input::Input;
    use crate::report::Report;
    use crate::Registry;
    use rtriage_fixtures::pe::{put_u32, Arch, ExportSpec, PeBuilder};

    fn analyze_with(bytes: Vec<u8>, config: &Config) -> Report {
        Registry::default().analyze(&Input::from_bytes("t.dll", bytes), config)
    }

    fn exports(r: &Report) -> Option<&PeExportsFacts> {
        r.facts.pe.as_ref().unwrap().exports.as_ref()
    }

    fn dll(entries: Vec<ExportSpec>) -> PeBuilder {
        PeBuilder::minimal(Arch::X64)
            .dll(true)
            .exports("helper.dll", entries)
    }

    #[test]
    fn named_ordinal_and_forwarded_exports() {
        for arch in [Arch::X86, Arch::X64] {
            let bytes = PeBuilder::minimal(arch)
                .dll(true)
                .exports(
                    "helper.dll",
                    vec![
                        ExportSpec::named("Zeta"),
                        ExportSpec::named("Alpha"),
                        ExportSpec::ordinal_only(),
                        ExportSpec::forward("OpenFile", "KERNEL32.CreateFileW"),
                    ],
                )
                .build()
                .bytes;
            let r = analyze_with(bytes, &Config::default());
            assert!(r.errors.is_empty(), "{:?}", r.errors);
            let e = exports(&r).unwrap();
            assert_eq!(e.dll_name.as_deref(), Some("helper.dll"));
            let got: Vec<_> = e
                .exports
                .iter()
                .map(|x| (x.ordinal, x.name.as_deref(), x.forwarder.as_deref()))
                .collect();
            assert_eq!(
                got,
                [
                    (1, Some("Zeta"), None),
                    (2, Some("Alpha"), None),
                    (3, None, None),
                    (4, Some("OpenFile"), Some("KERNEL32.CreateFileW")),
                ]
            );
        }
    }

    fn analyze_named(path: &str, bytes: Vec<u8>) -> Report {
        Registry::default().analyze(&Input::from_bytes(path, bytes), &Config::default())
    }

    fn ids(r: &Report) -> Vec<&'static str> {
        r.findings
            .iter()
            .map(|f| f.id)
            .filter(|id| id.starts_with("PE-EXPORTS"))
            .collect()
    }

    #[test]
    fn reflective_loader_exact_names() {
        for name in [
            "ReflectiveLoader",
            "_ReflectiveLoader@4",
            "_ReflectiveLoader@0",
        ] {
            let r = analyze_named(
                "helper.dll",
                dll(vec![ExportSpec::named(name)]).build().bytes,
            );
            assert_eq!(ids(&r), ["PE-EXPORTS-REFLECTIVE-LOADER"], "{name}");
            let f = &r
                .findings
                .iter()
                .find(|f| f.id == "PE-EXPORTS-REFLECTIVE-LOADER")
                .unwrap();
            assert_eq!(
                (f.severity, f.confidence),
                (Severity::High, Confidence::High)
            );
            assert_eq!(f.attack, ["T1620"]);
        }
    }

    #[test]
    fn reflective_loader_lookalikes_do_not_match() {
        for name in [
            "ReflectiveLoaderHelper",
            "reflectiveloader",
            "MyReflectiveLoader",
            "Loader",
        ] {
            let r = analyze_named(
                "helper.dll",
                dll(vec![ExportSpec::named(name)]).build().bytes,
            );
            assert!(ids(&r).is_empty(), "{name}: {:?}", ids(&r));
        }
    }

    #[test]
    fn proxy_dll_all_forwarded() {
        let specs = (0..6)
            .map(|i| ExportSpec::forward(&format!("F{i}"), &format!("orig.F{i}")))
            .collect();
        let r = analyze_named("helper.dll", dll(specs).build().bytes);
        assert_eq!(ids(&r), ["PE-EXPORTS-ALL-FORWARDED"]);
    }

    #[test]
    fn partly_forwarded_or_tiny_dll_is_not_proxy() {
        let mut specs: Vec<_> = (0..6)
            .map(|i| ExportSpec::forward(&format!("F{i}"), &format!("orig.F{i}")))
            .collect();
        specs.push(ExportSpec::named("Own"));
        let r = analyze_named("helper.dll", dll(specs).build().bytes);
        assert!(ids(&r).is_empty());
        let few = (0..3)
            .map(|i| ExportSpec::forward(&format!("F{i}"), "orig.F"))
            .collect();
        assert!(ids(&analyze_named("helper.dll", dll(few).build().bytes)).is_empty());
    }

    #[test]
    fn renamed_dll_is_name_mismatch() {
        let r = analyze_named(
            r"C:\Windows\System32\version.dll",
            dll(vec![ExportSpec::named("A")]).build().bytes,
        );
        assert_eq!(ids(&r), ["PE-EXPORTS-NAME-MISMATCH"]);
    }

    #[test]
    fn same_name_any_case_or_hash_named_sample_is_fine() {
        for path in [
            "HELPER.DLL",
            "helper.dll",
            "d41d8cd98f00b204e9800998ecf8427e.bin",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ] {
            let r = analyze_named(path, dll(vec![ExportSpec::named("A")]).build().bytes);
            assert!(ids(&r).is_empty(), "{path}");
        }
    }

    #[test]
    fn no_export_table() {
        let r = analyze_with(
            PeBuilder::minimal(Arch::X64).build().bytes,
            &Config::default(),
        );
        assert!(exports(&r).is_none());
    }

    #[test]
    fn export_count_is_capped() {
        let specs: Vec<_> = (0..50)
            .map(|i| ExportSpec::named(&format!("F{i:02}")))
            .collect();
        let mut config = Config::default();
        config.limits.max_exports = 10;
        let r = analyze_with(dll(specs).build().bytes, &config);
        let e = exports(&r).unwrap();
        assert!(e.limit_reached);
        assert_eq!(e.exports.len(), 10);
    }

    #[test]
    fn huge_function_count_is_capped_not_allocated() {
        let mut built = dll(vec![ExportSpec::named("A")]).build();
        let dd = built.layout.data_directory_offset(0);
        let dir_rva = u32::from_le_bytes(built.bytes[dd..dd + 4].try_into().unwrap());
        let auto = *built.layout.sections.last().unwrap();
        let dir_off = (auto.raw_ptr + (dir_rva - auto.rva)) as usize;
        put_u32(&mut built.bytes, dir_off + 20, u32::MAX); // NumberOfFunctions
        let r = analyze_with(built.bytes, &Config::default());
        // Capped to max_exports, then the array no longer fits the section.
        assert!(r.errors.iter().any(|e| e.analyzer == "pe-exports"));
    }

    #[test]
    fn out_of_range_name_ordinal_is_ignored() {
        let mut built = dll(vec![ExportSpec::named("A")]).build();
        let dd = built.layout.data_directory_offset(0);
        let dir_rva = u32::from_le_bytes(built.bytes[dd..dd + 4].try_into().unwrap());
        let auto = *built.layout.sections.last().unwrap();
        let dir_off = (auto.raw_ptr + (dir_rva - auto.rva)) as usize;
        let ords_rva =
            u32::from_le_bytes(built.bytes[dir_off + 36..dir_off + 40].try_into().unwrap());
        let ords_off = (auto.raw_ptr + (ords_rva - auto.rva)) as usize;
        built.bytes[ords_off..ords_off + 2].copy_from_slice(&0xFFFFu16.to_le_bytes());
        let r = analyze_with(built.bytes, &Config::default());
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        assert_eq!(exports(&r).unwrap().exports[0].name, None);
    }
}

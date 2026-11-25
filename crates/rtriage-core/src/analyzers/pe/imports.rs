//! Bounded PE import directory parser, pefile-compatible imphash, and
//! import-table findings.
//!
//! goblin's full PE parse cannot skip imports, and import descriptors are
//! fully attacker-controlled (thousands of descriptors can point at one huge
//! thunk array), so imports are parsed here with hard bounds:
//! - at most `max_import_libraries` descriptors and `max_imports` thunks in
//!   total per file (not per library), so shared arrays cannot multiply work;
//! - every loop iteration consumes one [`Budget`] step;
//! - names are read up to 256 bytes; every RVA is mapped with bounds checks.
//!
//! Parsing is best-effort: on a malformed entry the libraries read so far are
//! kept and the first error is reported alongside them.
//!
//! Findings (see `docs/heuristics.md`):
//! - `PE-IMPORTS-DYNAMIC-RESOLUTION`: `LoadLibrary*` + `GetProcAddress` and a tiny table.
//! - `PE-IMPORTS-FEW`: very few imports (suppressed when the above fires).
//! - `PE-IMPORTS-ORDINAL-ONLY`: a library imported only by ordinal.

use md5::{Digest, Md5};

use super::{ordinals, PeImage};
use crate::analyzers::{AnalysisContext, Analyzer};
use crate::config::Thresholds;
use crate::deadline::{Budget, Deadline};
use crate::error::AnalysisError;
use crate::limits::Limits;
use crate::report::{
    Category, Confidence, Evidence, Finding, Format, PeFacts, PeImportLibrary, PeImportedFunction,
    PeImportsFacts, ReportBuilder, Severity,
};

/// Data directory index of the import table.
const DIRECTORY_IMPORT: usize = 1;
/// Size of `IMAGE_IMPORT_DESCRIPTOR`.
const DESCRIPTOR_SIZE: usize = 20;
/// Longest DLL or function name read, in bytes.
const MAX_NAME_LEN: usize = 256;
/// `IMAGE_FILE_DLL`.
const FILE_DLL: u16 = 0x2000;

/// Library loaders that, together with a resolver, enable runtime API lookup.
const LOADERS: &[&str] = &[
    "LoadLibraryA",
    "LoadLibraryW",
    "LoadLibraryExA",
    "LoadLibraryExW",
    "LdrLoadDll",
];
/// Function address resolvers.
const RESOLVERS: &[&str] = &["GetProcAddress", "LdrGetProcedureAddress"];

/// Libraries commonly imported purely by ordinal by legitimate toolchains.
const ORDINAL_ONLY_OK: &[&str] = &[
    "ws2_32.dll",
    "wsock32.dll",
    "oleaut32.dll",
    "comctl32.dll",
    "shlwapi.dll",
    "shell32.dll",
    "msvbvm50.dll",
    "msvbvm60.dll",
];

/// Parses imports, computes the imphash, and emits import findings.
#[derive(Debug, Clone, Copy, Default)]
pub struct PeImportsAnalyzer;

impl Analyzer for PeImportsAnalyzer {
    fn name(&self) -> &'static str {
        "pe-imports"
    }

    fn applies_to(&self, format: Format) -> bool {
        format == Format::Pe
    }

    fn run(&self, ctx: &AnalysisContext<'_>, out: &mut ReportBuilder) -> Result<(), AnalysisError> {
        let Some(pe) = super::pe_or_skip(ctx) else {
            return Ok(());
        };
        let parsed = parse(pe, &ctx.input.data, &ctx.config.limits, &ctx.deadline);
        let facts = PeImportsFacts {
            total_functions: parsed
                .libraries
                .iter()
                .map(|l| l.functions.len() as u64)
                .sum(),
            imphash: imphash(&parsed.libraries),
            limit_reached: parsed.limit_reached,
            libraries: parsed.libraries,
        };

        if !pe.is_managed_dotnet() && !parsed.limit_reached {
            let t = &ctx.config.thresholds;
            let dynamic = dynamic_resolution_finding(&facts, t, out);
            if !dynamic && !is_resource_only_dll(pe) {
                few_imports_finding(&facts, t, out);
            }
        }
        ordinal_only_finding(&facts, out);

        out.facts.pe.get_or_insert_with(PeFacts::default).imports = Some(facts);
        parsed.error.map_or(Ok(()), Err)
    }
}

/// Result of a best-effort parse.
#[derive(Debug, Default)]
struct Parsed {
    libraries: Vec<PeImportLibrary>,
    limit_reached: bool,
    /// First error hit; parsing stops or skips past it.
    error: Option<AnalysisError>,
}

/// Walks the import directory within `limits` and `deadline`.
fn parse(pe: &PeImage, data: &[u8], limits: &Limits, deadline: &Deadline) -> Parsed {
    let mut p = Parsed::default();
    let Some(dir) = pe.directory(DIRECTORY_IMPORT) else {
        return p;
    };
    let mut budget = deadline.budget(limits.max_parser_steps);
    let mut total: usize = 0;
    let Some(mut desc_off) = pe.rva_to_offset(dir.rva, data.len()) else {
        p.error = Some(malformed(
            "PE import directory",
            format!("RVA 0x{:08x} is not backed by file data", dir.rva),
        ));
        return p;
    };

    loop {
        if let Err(e) = budget.step() {
            p.error = Some(e);
            break;
        }
        let Some(desc) = desc_off
            .checked_add(DESCRIPTOR_SIZE)
            .and_then(|end| data.get(desc_off..end))
        else {
            p.error = Some(AnalysisError::Truncated {
                what: "PE import descriptor",
                offset: to_u64(desc_off),
                needed: to_u64(DESCRIPTOR_SIZE),
                available: to_u64(data.len().saturating_sub(desc_off)),
            });
            break;
        };
        let original_first_thunk = le_u32(desc, 0);
        let name_rva = le_u32(desc, 12);
        let first_thunk = le_u32(desc, 16);
        if original_first_thunk == 0 && name_rva == 0 && first_thunk == 0 {
            break; // null terminator
        }
        if p.libraries.len() >= limits.max_import_libraries {
            p.limit_reached = true;
            p.error = Some(limit("max_import_libraries", limits.max_import_libraries));
            break;
        }
        desc_off = desc_off.saturating_add(DESCRIPTOR_SIZE);

        let Some(name) = read_name(pe, data, name_rva) else {
            keep_first(&mut p.error, || {
                malformed(
                    "PE import descriptor",
                    format!("DLL name RVA 0x{name_rva:08x} is not readable"),
                )
            });
            continue;
        };
        let thunks_rva = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };
        let walk = walk_thunks(
            pe,
            data,
            thunks_rva,
            &mut budget,
            &mut total,
            limits.max_imports,
        );
        p.libraries.push(PeImportLibrary {
            name,
            functions: walk.functions,
        });
        if let Some(e) = walk.error {
            let fatal = matches!(
                e,
                AnalysisError::LimitExceeded { .. } | AnalysisError::Timeout { .. }
            );
            if matches!(
                e,
                AnalysisError::LimitExceeded {
                    limit: "max_imports",
                    ..
                }
            ) {
                p.limit_reached = true;
            }
            keep_first(&mut p.error, || e);
            if fatal {
                break;
            }
        }
    }
    p
}

struct Walk {
    functions: Vec<PeImportedFunction>,
    error: Option<AnalysisError>,
}

/// Reads one null-terminated thunk array.
fn walk_thunks(
    pe: &PeImage,
    data: &[u8],
    rva: u32,
    budget: &mut Budget,
    total: &mut usize,
    max_total: usize,
) -> Walk {
    let mut w = Walk {
        functions: Vec::new(),
        error: None,
    };
    let thunk_size: usize = if pe.is64 { 8 } else { 4 };
    let ordinal_flag: u64 = if pe.is64 { 1 << 63 } else { 1 << 31 };
    let Some(mut off) = pe.rva_to_offset(rva, data.len()) else {
        w.error = Some(malformed(
            "PE import thunks",
            format!("RVA 0x{rva:08x} is not backed by file data"),
        ));
        return w;
    };
    loop {
        if let Err(e) = budget.step() {
            w.error = Some(e);
            break;
        }
        let Some(raw) = off
            .checked_add(thunk_size)
            .and_then(|end| data.get(off..end))
        else {
            w.error = Some(AnalysisError::Truncated {
                what: "PE import thunk array",
                offset: to_u64(off),
                needed: to_u64(thunk_size),
                available: to_u64(data.len().saturating_sub(off)),
            });
            break;
        };
        let value = if pe.is64 {
            le_u64(raw)
        } else {
            u64::from(le_u32(raw, 0))
        };
        if value == 0 {
            break;
        }
        if *total >= max_total {
            w.error = Some(limit("max_imports", max_total));
            break;
        }
        *total += 1;
        off = off.saturating_add(thunk_size);

        if value & ordinal_flag != 0 {
            w.functions.push(PeImportedFunction {
                name: None,
                ordinal: Some((value & 0xffff) as u16),
            });
            continue;
        }
        // Hint/name RVA: bits 0..31 only; higher bits must be clear.
        let name = u32::try_from(value)
            .ok()
            .and_then(|hint_rva| hint_rva.checked_add(2))
            .and_then(|name_rva| read_name(pe, data, name_rva));
        match name {
            Some(name) => w.functions.push(PeImportedFunction {
                name: Some(name),
                ordinal: None,
            }),
            None => keep_first(&mut w.error, || {
                malformed(
                    "PE import thunk",
                    format!("hint/name entry 0x{value:x} is not readable"),
                )
            }),
        }
    }
    w
}

/// Reads a NUL-terminated name at `rva`, at most [`MAX_NAME_LEN`] bytes
/// (longer names are cut). Lossy UTF-8; `None` if the RVA is unmapped.
fn read_name(pe: &PeImage, data: &[u8], rva: u32) -> Option<String> {
    let start = pe.rva_to_offset(rva, data.len())?;
    let window = data.get(start..start.saturating_add(MAX_NAME_LEN).min(data.len()))?;
    let end = window.iter().position(|&b| b == 0).unwrap_or(window.len());
    Some(String::from_utf8_lossy(window.get(..end).unwrap_or_default()).into_owned())
}

/// pefile-compatible imphash: MD5 over `lib.func` pairs joined by `,`,
/// lowercase, with `.dll` / `.ocx` / `.sys` stripped from the library name and
/// ordinal-only imports resolved via the frozen pefile tables (else `ordN`).
pub fn imphash(libraries: &[PeImportLibrary]) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    for lib in libraries {
        let full = lib.name.to_lowercase();
        let short = match full.rsplit_once('.') {
            Some((stem, "dll" | "ocx" | "sys")) => stem,
            _ => full.as_str(),
        };
        for f in &lib.functions {
            let func = match (&f.name, f.ordinal) {
                (Some(n), _) if !n.is_empty() => n.to_lowercase(),
                (_, Some(o)) => ordinals::lookup(&full, o)
                    .map_or_else(|| format!("ord{o}"), str::to_owned)
                    .to_lowercase(),
                _ => continue,
            };
            parts.push(format!("{short}.{func}"));
        }
    }
    if parts.is_empty() {
        return None;
    }
    let digest = Md5::digest(parts.join(",").as_bytes());
    Some(digest.iter().map(|b| format!("{b:02x}")).collect())
}

fn dynamic_resolution_finding(
    facts: &PeImportsFacts,
    t: &Thresholds,
    out: &mut ReportBuilder,
) -> bool {
    if facts.total_functions > t.dynamic_resolution_max_imports {
        return false;
    }
    let find = |names: &[&str]| {
        facts.libraries.iter().find_map(|lib| {
            lib.functions
                .iter()
                .filter_map(|f| f.name.as_deref())
                .find(|n| names.contains(n))
                .map(|n| (lib.name.clone(), n.to_owned()))
        })
    };
    let (Some(loader), Some(resolver)) = (find(LOADERS), find(RESOLVERS)) else {
        return false;
    };
    out.push_finding(
        Finding::new(
            "PE-IMPORTS-DYNAMIC-RESOLUTION",
            Severity::Medium,
            Category::Obfuscation,
            "APIs resolved at run time",
        )
        .detail(format!(
            "The import table is tiny ({} functions) but includes a library loader and \
             GetProcAddress: the real API set is resolved at run time and hidden from \
             static import analysis. Typical of packers and shellcode-style loaders.",
            facts.total_functions
        ))
        .evidence(Evidence::Import {
            library: Some(loader.0),
            symbol: loader.1,
        })
        .evidence(Evidence::Import {
            library: Some(resolver.0),
            symbol: resolver.1,
        })
        .evidence(Evidence::Field {
            name: "imported functions",
            value: facts.total_functions.to_string(),
        })
        .attack("T1027.007"),
    );
    true
}

fn few_imports_finding(facts: &PeImportsFacts, t: &Thresholds, out: &mut ReportBuilder) {
    if facts.total_functions > t.imports_few_max {
        return;
    }
    let mut f = Finding::new(
        "PE-IMPORTS-FEW",
        Severity::Low,
        Category::Anomaly,
        if facts.total_functions == 0 {
            "No imports"
        } else {
            "Very few imports"
        },
    )
    .confidence(Confidence::Low)
    .detail(
        "Normal programs import dozens of functions through their C runtime. A \
         near-empty import table suggests packing or position-independent code \
         that finds APIs itself.",
    )
    .evidence(Evidence::Field {
        name: "imported functions",
        value: facts.total_functions.to_string(),
    });
    for lib in &facts.libraries {
        for func in &lib.functions {
            f = f.evidence(import_ev(&lib.name, func));
        }
    }
    out.push_finding(f);
}

fn ordinal_only_finding(facts: &PeImportsFacts, out: &mut ReportBuilder) {
    let hits: Vec<_> = facts
        .libraries
        .iter()
        .filter(|lib| {
            let lower = lib.name.to_lowercase();
            !lib.functions.is_empty()
                && lib.functions.iter().all(|f| f.name.is_none())
                && !ORDINAL_ONLY_OK.contains(&lower.as_str())
                && !lower.starts_with("mfc")
        })
        .collect();
    if hits.is_empty() {
        return;
    }
    let mut f = Finding::new(
        "PE-IMPORTS-ORDINAL-ONLY",
        Severity::Low,
        Category::Obfuscation,
        "Library imported only by ordinal",
    )
    .confidence(Confidence::Low)
    .detail(
        "Every function from these libraries is imported by number, so the import \
         table does not reveal which APIs are used. Common only for a few system \
         DLLs (ws2_32, oleaut32, MFC), which are not reported.",
    );
    for lib in hits {
        for func in lib.functions.iter().take(5) {
            f = f.evidence(import_ev(&lib.name, func));
        }
        if lib.functions.len() > 5 {
            f = f.evidence(Evidence::Field {
                name: "more ordinals",
                value: format!("{}: +{}", lib.name, lib.functions.len() - 5),
            });
        }
    }
    out.push_finding(f);
}

/// DLL whose entry point is 0: resource-only, nothing to import.
fn is_resource_only_dll(pe: &PeImage) -> bool {
    pe.characteristics & FILE_DLL != 0 && pe.entry_rva == 0
}

fn import_ev(library: &str, f: &PeImportedFunction) -> Evidence {
    Evidence::Import {
        library: Some(library.to_owned()),
        symbol: match (&f.name, f.ordinal) {
            (Some(n), _) => n.clone(),
            (None, Some(o)) => format!("#{o}"),
            (None, None) => "?".to_owned(),
        },
    }
}

fn keep_first(slot: &mut Option<AnalysisError>, e: impl FnOnce() -> AnalysisError) {
    if slot.is_none() {
        *slot = Some(e());
    }
}

fn malformed(what: &'static str, reason: String) -> AnalysisError {
    AnalysisError::Malformed { what, reason }
}

fn limit(name: &'static str, max: usize) -> AnalysisError {
    AnalysisError::LimitExceeded {
        limit: name,
        value: to_u64(max).saturating_add(1),
        max: to_u64(max),
    }
}

fn le_u32(b: &[u8], at: usize) -> u32 {
    let mut a = [0u8; 4];
    if let Some(s) = at.checked_add(4).and_then(|end| b.get(at..end)) {
        a.copy_from_slice(s);
    }
    u32::from_le_bytes(a)
}

fn le_u64(b: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    if let Some(s) = b.get(..8) {
        a.copy_from_slice(s);
    }
    u64::from_le_bytes(a)
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
    use rtriage_fixtures::pe::{
        imphash_vectors, profiles, put_u32, Arch, Entry, ImportEntry, PeBuilder,
    };

    fn analyze_with(bytes: Vec<u8>, config: &Config) -> Report {
        let input = Input::from_bytes("t.exe", bytes);
        assert_eq!(input.format, Format::Pe);
        Registry::default().analyze(&input, config)
    }

    fn analyze(bytes: Vec<u8>) -> Report {
        analyze_with(bytes, &Config::default())
    }

    fn imports(r: &Report) -> &PeImportsFacts {
        r.facts.pe.as_ref().unwrap().imports.as_ref().unwrap()
    }

    /// IDs of import findings only.
    fn ids(r: &Report) -> Vec<&'static str> {
        r.findings
            .iter()
            .map(|f| f.id)
            .filter(|id| id.starts_with("PE-IMPORTS"))
            .collect()
    }

    fn md5_hex(s: &str) -> String {
        Md5::digest(s.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// A realistic CRT-sized import table (no findings expected).
    const CRT: &[&str] = &[
        "ExitProcess",
        "GetModuleHandleW",
        "GetCommandLineW",
        "GetProcessHeap",
        "HeapAlloc",
        "HeapFree",
        "GetStdHandle",
        "WriteFile",
        "CloseHandle",
        "GetLastError",
        "SetLastError",
        "QueryPerformanceCounter",
        "GetCurrentProcessId",
        "GetSystemTimeAsFileTime",
    ];

    // ---- parsing

    #[test]
    fn parses_names_and_ordinals_on_both_arches() {
        for arch in [Arch::X86, Arch::X64] {
            let r = analyze(
                PeBuilder::minimal(arch)
                    .import("KERNEL32.dll", &["LoadLibraryA", "GetProcAddress"])
                    .import_ordinals("WS2_32.dll", &[23, 115])
                    .build()
                    .bytes,
            );
            assert!(r.errors.is_empty(), "{:?}", r.errors);
            let i = imports(&r);
            assert_eq!(i.total_functions, 4);
            assert_eq!(i.libraries[0].name, "KERNEL32.dll");
            assert_eq!(
                i.libraries[0].functions[1].name.as_deref(),
                Some("GetProcAddress")
            );
            assert_eq!(i.libraries[1].functions[0].ordinal, Some(23));
            assert_eq!(i.libraries[1].functions[0].name, None);
            assert!(!i.limit_reached);
        }
    }

    #[test]
    fn no_import_directory_means_empty_table() {
        let r = analyze(PeBuilder::minimal(Arch::X64).build().bytes);
        let i = imports(&r);
        assert!(i.libraries.is_empty());
        assert_eq!(i.imphash, None);
    }

    #[test]
    fn max_imports_is_enforced_across_libraries() {
        let names: Vec<String> = (0..50).map(|i| format!("Func{i}")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let bytes = PeBuilder::minimal(Arch::X64)
            .import("a.dll", &refs)
            .import("b.dll", &refs)
            .build()
            .bytes;
        let mut config = Config::default();
        config.limits.max_imports = 60;
        let r = analyze_with(bytes, &config);
        let i = imports(&r);
        assert_eq!(i.total_functions, 60);
        assert!(i.limit_reached);
        assert!(r.errors.iter().any(|e| matches!(
            e.error,
            AnalysisError::LimitExceeded {
                limit: "max_imports",
                ..
            }
        )));
        // A capped table must not be judged as "few imports".
        assert!(ids(&r).is_empty());
    }

    #[test]
    fn shared_thunk_arrays_cannot_multiply_work() {
        // 300 descriptors all pointing at the same 40-entry thunk array: the
        // total-thunk limit, not the descriptor count, bounds the work.
        let mut built = PeBuilder::minimal(Arch::X64)
            .import("kernel32.dll", profiles::GO_KERNEL32_IMPORTS)
            .build();
        let dir_rva_off = built.layout.data_directory_offset(1);
        let dir_rva = u32::from_le_bytes(
            built.bytes[dir_rva_off..dir_rva_off + 4]
                .try_into()
                .unwrap(),
        );
        let auto = *built.layout.sections.last().unwrap();
        let desc = (auto.raw_ptr + (dir_rva - auto.rva)) as usize;
        let first: Vec<u8> = built.bytes[desc..desc + 20].to_vec();
        let mut table = first.repeat(300);
        table.extend_from_slice(&[0u8; 20]);

        // The auto section is the last one in the file and nothing follows it,
        // so grow it and append the new descriptor table at its old end.
        let table_off = (auto.raw_ptr + auto.raw_size) as usize;
        let table_rva = auto.rva + auto.raw_size;
        let grown = auto.raw_size + (table.len() as u32).div_ceil(0x200) * 0x200;
        let hdr = built.layout.section_table_offset + 40 * (built.layout.sections.len() - 1);
        put_u32(&mut built.bytes, hdr + 8, grown); // VirtualSize
        put_u32(&mut built.bytes, hdr + 16, grown); // SizeOfRawData
        built.bytes.resize((auto.raw_ptr + grown) as usize, 0);
        built.bytes[table_off..table_off + table.len()].copy_from_slice(&table);
        put_u32(&mut built.bytes, dir_rva_off, table_rva);

        let mut config = Config::default();
        config.limits.max_imports = 1000;
        let r = analyze_with(built.bytes, &config);
        let i = imports(&r);
        assert_eq!(i.total_functions, 1000);
        assert!(i.limit_reached);
        assert!(i.libraries.len() <= 26);
    }

    #[test]
    fn unmapped_directory_rva_is_an_error_not_a_panic() {
        let mut built = PeBuilder::minimal(Arch::X86)
            .import("k.dll", &["A"])
            .build();
        put_u32(
            &mut built.bytes,
            built.layout.data_directory_offset(1),
            0xdead_0000,
        );
        let r = analyze(built.bytes);
        assert!(r.errors.iter().any(|e| e.analyzer == "pe-imports"));
        assert!(imports(&r).libraries.is_empty());
    }

    #[test]
    fn missing_terminator_stops_at_end_of_data() {
        // Directory pointing near the end of the auto section: descriptors run
        // off the file instead of hitting a terminator.
        let mut built = PeBuilder::minimal(Arch::X64)
            .import("k.dll", &["A"])
            .build();
        let auto = *built.layout.sections.last().unwrap();
        let near_end = auto.rva + auto.raw_size - 10;
        put_u32(
            &mut built.bytes,
            built.layout.data_directory_offset(1),
            near_end,
        );
        let r = analyze(built.bytes);
        assert!(r.errors.iter().any(|e| e.analyzer == "pe-imports"));
    }

    // ---- imphash

    #[test]
    fn imphash_follows_pefile_rules() {
        let r = analyze(
            imphash_vectors::cases()
                .into_iter()
                .find(|(n, _)| *n == "named_x86")
                .unwrap()
                .1
                .build()
                .bytes,
        );
        let expected = md5_hex(
            "kernel32.loadlibrarya,kernel32.getprocaddress,kernel32.exitprocess,user32.messageboxa",
        );
        assert_eq!(imports(&r).imphash.as_deref(), Some(expected.as_str()));
    }

    #[test]
    fn imphash_ordinals_and_extensions() {
        let r = analyze(
            imphash_vectors::cases()
                .into_iter()
                .find(|(n, _)| *n == "ordinals_x64")
                .unwrap()
                .1
                .build()
                .bytes,
        );
        // ws2_32 1/4/115 resolve via the frozen table, 9999 -> ord9999;
        // oleaut32 2 resolves; .ocx is stripped, .drv is kept.
        let o9 = ordinals::lookup("oleaut32.dll", 9)
            .map_or_else(|| "ord9".to_owned(), str::to_lowercase);
        let expected = md5_hex(&format!(
            "ws2_32.accept,ws2_32.connect,ws2_32.wsastartup,ws2_32.ord9999,\
             oleaut32.sysallocstring,oleaut32.{o9},custom.ord7,odd.drv.foo"
        ));
        assert_eq!(imports(&r).imphash.as_deref(), Some(expected.as_str()));
    }

    #[test]
    fn imphash_is_case_insensitive_and_wsock32_uses_ws2_32_table() {
        let r = analyze(
            PeBuilder::minimal(Arch::X64)
                .import_entries(
                    "Kernel32.DLL",
                    vec![
                        ImportEntry::Name("CreateFileW".into()),
                        ImportEntry::Ordinal(42),
                    ],
                )
                .import_ordinals("wsock32.dll", &[3])
                .build()
                .bytes,
        );
        let expected = md5_hex("kernel32.createfilew,kernel32.ord42,wsock32.closesocket");
        assert_eq!(imports(&r).imphash.as_deref(), Some(expected.as_str()));
    }

    // ---- findings

    #[test]
    fn crt_sized_table_is_clean() {
        let r = analyze(
            PeBuilder::minimal(Arch::X64)
                .import("KERNEL32.dll", CRT)
                .build()
                .bytes,
        );
        assert!(ids(&r).is_empty(), "{:?}", ids(&r));
    }

    #[test]
    fn loadlibrary_getprocaddress_tiny_table_is_dynamic_resolution() {
        let r = analyze(
            PeBuilder::minimal(Arch::X86)
                .import(
                    "KERNEL32.dll",
                    &["LoadLibraryA", "GetProcAddress", "VirtualAlloc"],
                )
                .build()
                .bytes,
        );
        // FEW is suppressed: dynamic resolution already explains the tiny table.
        assert_eq!(ids(&r), ["PE-IMPORTS-DYNAMIC-RESOLUTION"]);
        let f = r
            .findings
            .iter()
            .find(|f| f.id == "PE-IMPORTS-DYNAMIC-RESOLUTION")
            .unwrap();
        assert_eq!(f.attack, ["T1027.007"]);
        assert_eq!(f.category, Category::Obfuscation);
    }

    #[test]
    fn loader_without_resolver_is_only_few() {
        let r = analyze(
            PeBuilder::minimal(Arch::X64)
                .import("KERNEL32.dll", &["LoadLibraryW", "ExitProcess"])
                .build()
                .bytes,
        );
        assert_eq!(ids(&r), ["PE-IMPORTS-FEW"]);
    }

    #[test]
    fn go_runtime_imports_are_not_dynamic_resolution() {
        // 40 imports including LoadLibraryW + GetProcAddress: above the limit.
        for arch in [Arch::X86, Arch::X64] {
            let r = analyze(profiles::go_like(arch).build().bytes);
            assert!(ids(&r).is_empty(), "{:?}", ids(&r));
        }
    }

    #[test]
    fn no_imports_is_few() {
        let r = analyze(PeBuilder::minimal(Arch::X64).build().bytes);
        assert_eq!(ids(&r), ["PE-IMPORTS-FEW"]);
        let f = r
            .findings
            .iter()
            .find(|f| f.id == "PE-IMPORTS-FEW")
            .unwrap();
        assert_eq!((f.severity, f.confidence), (Severity::Low, Confidence::Low));
    }

    #[test]
    fn dotnet_and_resource_only_dll_are_not_few() {
        let r = analyze(profiles::dotnet_like(Arch::X86).build().bytes);
        assert!(ids(&r).is_empty(), "{:?}", ids(&r));
        let r = analyze(
            PeBuilder::minimal(Arch::X64)
                .dll(true)
                .entry(Entry::Rva(0))
                .build()
                .bytes,
        );
        assert!(ids(&r).is_empty(), "{:?}", ids(&r));
    }

    #[test]
    fn custom_library_by_ordinal_only_is_flagged() {
        let r = analyze(
            PeBuilder::minimal(Arch::X64)
                .import("KERNEL32.dll", CRT)
                .import_ordinals("helper.dll", &[1, 2, 3, 4, 5, 6, 7])
                .build()
                .bytes,
        );
        assert_eq!(ids(&r), ["PE-IMPORTS-ORDINAL-ONLY"]);
        let f = r
            .findings
            .iter()
            .find(|f| f.id == "PE-IMPORTS-ORDINAL-ONLY")
            .unwrap();
        assert!(f.evidence.contains(&Evidence::Import {
            library: Some("helper.dll".into()),
            symbol: "#1".into()
        }));
        assert!(f.evidence.iter().any(|e| matches!(
            e,
            Evidence::Field { name: "more ordinals", value } if value == "helper.dll: +2"
        )));
    }

    #[test]
    fn system_ordinal_dlls_are_not_flagged() {
        let r = analyze(
            PeBuilder::minimal(Arch::X64)
                .import("KERNEL32.dll", CRT)
                .import_ordinals("WS2_32.dll", &[1, 4])
                .import_ordinals("OLEAUT32.dll", &[2])
                .import_ordinals("MFC140U.dll", &[1001, 2002])
                .build()
                .bytes,
        );
        assert!(ids(&r).is_empty(), "{:?}", ids(&r));
    }

    #[test]
    fn mixed_name_and_ordinal_library_is_not_ordinal_only() {
        let r = analyze(
            PeBuilder::minimal(Arch::X64)
                .import("KERNEL32.dll", CRT)
                .import_entries(
                    "helper.dll",
                    vec![ImportEntry::Ordinal(1), ImportEntry::Name("Init".into())],
                )
                .build()
                .bytes,
        );
        assert!(ids(&r).is_empty(), "{:?}", ids(&r));
    }
}

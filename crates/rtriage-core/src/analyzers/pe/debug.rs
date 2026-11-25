//! CodeView debug record: PDB path, GUID and age.
//!
//! Only the debug directory entries and the first CodeView record are read,
//! bounded by `max_debug_entries` and a 1 KiB record size.
//!
//! Finding: `PE-PDB-PATH` (see `docs/heuristics.md`).

use super::{read_u32, PeImage};
use crate::analyzers::{AnalysisContext, Analyzer};
use crate::deadline::Deadline;
use crate::error::AnalysisError;
use crate::limits::Limits;
use crate::report::{
    Category, Confidence, Evidence, Finding, Format, PeDebugFacts, PeFacts, ReportBuilder, Severity,
};

/// Data directory index of the debug directory.
const DIRECTORY_DEBUG: usize = 6;
/// Size of `IMAGE_DEBUG_DIRECTORY`.
const ENTRY_SIZE: usize = 28;
/// `IMAGE_DEBUG_TYPE_CODEVIEW`.
const TYPE_CODEVIEW: u32 = 2;
/// Largest CodeView record read.
const MAX_RECORD: usize = 1024;

/// Extracts the PDB path.
#[derive(Debug, Clone, Copy, Default)]
pub struct PeDebugAnalyzer;

impl Analyzer for PeDebugAnalyzer {
    fn name(&self) -> &'static str {
        "pe-debug"
    }

    fn applies_to(&self, format: Format) -> bool {
        format == Format::Pe
    }

    fn run(&self, ctx: &AnalysisContext<'_>, out: &mut ReportBuilder) -> Result<(), AnalysisError> {
        let Some(pe) = super::pe_or_skip(ctx) else {
            return Ok(());
        };
        let Some(facts) = parse(pe, &ctx.input.data, &ctx.config.limits, &ctx.deadline)? else {
            return Ok(());
        };
        let mut f = Finding::new(
            "PE-PDB-PATH",
            Severity::Info,
            Category::Metadata,
            "Debug symbols path embedded",
        )
        .confidence(Confidence::High)
        .detail(
            "The linker recorded where the PDB was written. Build paths often reveal \
             user names, project names and directory layouts useful for attribution \
             and for clustering samples from the same build environment.",
        )
        .evidence(Evidence::Field {
            name: "PdbPath",
            value: facts.pdb_path.clone(),
        });
        if let Some(user) = user_from_path(&facts.pdb_path) {
            f = f.evidence(Evidence::Field {
                name: "user",
                value: user.to_owned(),
            });
        }
        out.push_finding(f);
        out.facts.pe.get_or_insert_with(PeFacts::default).debug = Some(facts);
        Ok(())
    }
}

/// First CodeView record, or `Ok(None)` without a debug directory / record.
///
/// # Errors
/// Unmapped directory, budget exhaustion, deadline.
pub fn parse(
    pe: &PeImage,
    data: &[u8],
    limits: &Limits,
    deadline: &Deadline,
) -> Result<Option<PeDebugFacts>, AnalysisError> {
    let Some(dir) = pe.directory(DIRECTORY_DEBUG) else {
        return Ok(None);
    };
    let base = pe
        .rva_to_offset(dir.rva, data.len())
        .ok_or_else(|| AnalysisError::Malformed {
            what: "PE debug directory",
            reason: format!("RVA 0x{:08x} is not backed by file data", dir.rva),
        })?;
    let count = (usize::try_from(dir.size).unwrap_or(0) / ENTRY_SIZE).min(limits.max_debug_entries);
    let mut budget = deadline.budget(limits.max_parser_steps);
    for i in 0..count {
        budget.step()?;
        let entry = base.saturating_add(i * ENTRY_SIZE);
        if read_u32(data, entry.saturating_add(12), "PE debug entry")? != TYPE_CODEVIEW {
            continue;
        }
        let size = usize::try_from(read_u32(data, entry.saturating_add(16), "PE debug entry")?)
            .unwrap_or(0)
            .min(MAX_RECORD);
        let raw_ptr = read_u32(data, entry.saturating_add(24), "PE debug entry")?;
        let start = if raw_ptr != 0 {
            usize::try_from(raw_ptr).ok()
        } else {
            let rva = read_u32(data, entry.saturating_add(20), "PE debug entry")?;
            pe.rva_to_offset(rva, data.len())
        };
        let record = start.and_then(|s| data.get(s..s.saturating_add(size).min(data.len())));
        if let Some(facts) = record.and_then(parse_codeview) {
            return Ok(Some(facts));
        }
    }
    Ok(None)
}

/// Parses an `RSDS` (PDB 7.0) or `NB10` (PDB 2.0) record.
fn parse_codeview(rec: &[u8]) -> Option<PeDebugFacts> {
    let u32_at = |at: usize| {
        rec.get(at..at + 4)
            .and_then(|b| <[u8; 4]>::try_from(b).ok())
            .map(u32::from_le_bytes)
    };
    let (codeview, guid, age, path_at) = match rec.get(..4)? {
        b"RSDS" => ("RSDS", Some(format_guid(rec.get(4..20)?)?), u32_at(20)?, 24),
        b"NB10" => ("NB10", None, u32_at(12)?, 16),
        _ => return None,
    };
    let tail = rec.get(path_at..)?;
    let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
    let path = String::from_utf8_lossy(tail.get(..end)?).into_owned();
    (!path.is_empty()).then_some(PeDebugFacts {
        codeview,
        pdb_path: path,
        pdb_guid: guid,
        pdb_age: age,
    })
}

/// `{Data1}-{Data2}-{Data3}-{Data4[0..2]}-{Data4[2..8]}` with the first three
/// fields little-endian, as Windows prints GUIDs.
fn format_guid(b: &[u8]) -> Option<String> {
    let g: [u8; 16] = b.try_into().ok()?;
    let d1 = u32::from_le_bytes([g[0], g[1], g[2], g[3]]);
    let d2 = u16::from_le_bytes([g[4], g[5]]);
    let d3 = u16::from_le_bytes([g[6], g[7]]);
    let tail: String = g[8..].iter().map(|x| format!("{x:02X}")).collect();
    Some(format!(
        "{d1:08X}-{d2:04X}-{d3:04X}-{}-{}",
        tail.get(..4)?,
        tail.get(4..)?
    ))
}

/// User name from `...\Users\<name>\...`, `...\Documents and Settings\<name>\...`
/// or `/home/<name>/...` (case-insensitive), if present.
pub fn user_from_path(path: &str) -> Option<&str> {
    let lower = path.to_ascii_lowercase();
    for marker in [
        "\\users\\",
        "\\documents and settings\\",
        "/home/",
        "/users/",
    ] {
        if let Some(i) = lower.find(marker) {
            let rest = path.get(i + marker.len()..)?;
            let name = rest.split(['\\', '/']).next()?;
            if !name.is_empty() && !name.eq_ignore_ascii_case("public") {
                return Some(name);
            }
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
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

    fn debug(r: &Report) -> Option<&PeDebugFacts> {
        r.facts.pe.as_ref().unwrap().debug.as_ref()
    }

    #[test]
    fn rsds_path_guid_and_age() {
        let path = r"C:\Users\alice\source\repos\Tool\x64\Release\Tool.pdb";
        let r = analyze(PeBuilder::minimal(Arch::X64).pdb_path(path).build().bytes);
        let d = debug(&r).unwrap();
        assert_eq!(d.codeview, "RSDS");
        assert_eq!(d.pdb_path, path);
        assert_eq!(d.pdb_age, 1);
        assert_eq!(
            d.pdb_guid.as_deref(),
            Some("11111111-1111-1111-1111-111111111111")
        );
        let f = r.findings.iter().find(|f| f.id == "PE-PDB-PATH").unwrap();
        assert_eq!(f.severity, Severity::Info);
        assert!(f.evidence.contains(&Evidence::Field {
            name: "user",
            value: "alice".into()
        }));
    }

    #[test]
    fn path_without_user_has_no_user_evidence() {
        let r = analyze(
            PeBuilder::minimal(Arch::X86)
                .pdb_path(r"D:\build\agent\_work\1\s\out\app.pdb")
                .build()
                .bytes,
        );
        let f = r.findings.iter().find(|f| f.id == "PE-PDB-PATH").unwrap();
        assert!(f
            .evidence
            .iter()
            .all(|e| !matches!(e, Evidence::Field { name: "user", .. })));
    }

    #[test]
    fn no_debug_directory() {
        let r = analyze(PeBuilder::minimal(Arch::X64).build().bytes);
        assert!(debug(&r).is_none());
        assert!(r.findings.iter().all(|f| f.id != "PE-PDB-PATH"));
    }

    #[test]
    fn nb10_record() {
        let mut rec = b"NB10".to_vec();
        rec.extend_from_slice(&[0; 8]);
        rec.extend_from_slice(&3u32.to_le_bytes());
        rec.extend_from_slice(b"old.pdb\0");
        let d = parse_codeview(&rec).unwrap();
        assert_eq!(
            (d.codeview, d.pdb_path.as_str(), d.pdb_age, d.pdb_guid),
            ("NB10", "old.pdb", 3, None)
        );
    }

    #[test]
    fn malformed_records_are_ignored() {
        assert!(parse_codeview(b"RSDS").is_none());
        assert!(parse_codeview(b"XXXX0000000000000000000000000").is_none());
        let mut empty_path = b"RSDS".to_vec();
        empty_path.extend_from_slice(&[0; 21]);
        assert!(parse_codeview(&empty_path).is_none());
    }

    #[test]
    fn guid_format() {
        let mut g = [0u8; 16];
        g[..4].copy_from_slice(&0x0011_2233u32.to_le_bytes());
        g[4..6].copy_from_slice(&0x4455u16.to_le_bytes());
        g[6..8].copy_from_slice(&0x6677u16.to_le_bytes());
        g[8..].copy_from_slice(&[0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert_eq!(
            format_guid(&g).unwrap(),
            "00112233-4455-6677-8899-AABBCCDDEEFF"
        );
    }

    #[test]
    fn user_extraction() {
        assert_eq!(user_from_path(r"C:\Users\Bob\x.pdb"), Some("Bob"));
        assert_eq!(
            user_from_path(r"c:\documents and settings\eve\x.pdb"),
            Some("eve")
        );
        assert_eq!(user_from_path("/home/mallory/src/x.pdb"), Some("mallory"));
        assert_eq!(user_from_path(r"C:\Users\Public\x.pdb"), None);
        assert_eq!(user_from_path(r"D:\src\x.pdb"), None);
    }
}

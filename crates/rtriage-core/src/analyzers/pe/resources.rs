//! Bounded PE resource directory walker.
//!
//! The tree is type / name / language. Entries are attacker-controlled
//! offsets, so the walk is bounded: fixed depth 3, a visited set that breaks
//! cycles and shared subdirectories, at most `max_resources` leaves, and a
//! budget step per entry.
//!
//! Findings: `PE-RESOURCE-EMBEDDED-PE`, `PE-RESOURCE-HIGH-ENTROPY` (see `docs/heuristics.md`).

use std::collections::BTreeSet;

use super::overlay::{content_kind, COMPRESSED_KINDS};
use super::{read_u16, read_u32, PeImage};
use crate::analyzers::entropy::shannon_bounded;
use crate::analyzers::{AnalysisContext, Analyzer};
use crate::config::Thresholds;
use crate::deadline::{Budget, Deadline};
use crate::error::AnalysisError;
use crate::limits::Limits;
use crate::report::{
    Category, Confidence, Evidence, Finding, Format, PeFacts, PeResource, PeResourcesFacts,
    ReportBuilder, Severity,
};

/// Data directory index of the resource table.
const DIRECTORY_RESOURCE: usize = 2;
/// High bit of an entry's offset: points at a subdirectory / named entry.
const HIGH_BIT: u32 = 0x8000_0000;
/// Longest resource name read, in UTF-16 units.
const MAX_NAME_UNITS: usize = 256;

/// Walks the resource tree.
#[derive(Debug, Clone, Copy, Default)]
pub struct PeResourcesAnalyzer;

impl Analyzer for PeResourcesAnalyzer {
    fn name(&self) -> &'static str {
        "pe-resources"
    }

    fn applies_to(&self, format: Format) -> bool {
        format == Format::Pe
    }

    fn run(&self, ctx: &AnalysisContext<'_>, out: &mut ReportBuilder) -> Result<(), AnalysisError> {
        let Some(pe) = super::pe_or_skip(ctx) else {
            return Ok(());
        };
        let t = &ctx.config.thresholds;
        if let Some(facts) = parse(
            pe,
            &ctx.input.data,
            &ctx.config.limits,
            &ctx.deadline,
            t.section_entropy_min_size,
        )? {
            embedded_pe_finding(&facts, out);
            high_entropy_finding(&facts, t, out);
            out.facts.pe.get_or_insert_with(PeFacts::default).resources = Some(facts);
        }
        Ok(())
    }
}

/// Image-like resource types: compressed pixel data is expected there.
const IMAGE_TYPES: &[&str] = &[
    "RT_CURSOR",
    "RT_BITMAP",
    "RT_ICON",
    "RT_GROUP_CURSOR",
    "RT_GROUP_ICON",
    "RT_ANICURSOR",
    "RT_ANIICON",
];

fn resource_ev(r: &PeResource) -> Evidence {
    Evidence::Field {
        name: "resource",
        value: format!(
            "{} / {} / {} ({} bytes at RVA 0x{:x})",
            r.type_name, r.name, r.lang, r.size, r.rva
        ),
    }
}

fn embedded_pe_finding(facts: &PeResourcesFacts, out: &mut ReportBuilder) {
    let hits: Vec<_> = facts
        .entries
        .iter()
        .filter(|r| r.kind == Some("pe"))
        .collect();
    if hits.is_empty() {
        return;
    }
    let mut f = Finding::new(
        "PE-RESOURCE-EMBEDDED-PE",
        Severity::Medium,
        Category::Anomaly,
        "Another executable is stored as a resource",
    )
    .confidence(Confidence::Low)
    .detail(
        "A resource holds a complete PE file: a second program carried as payload, \
         typical of droppers. Installers and driver packages do this legitimately.",
    );
    for r in hits {
        f = f.evidence(resource_ev(r));
    }
    out.push_finding(f);
}

fn high_entropy_finding(facts: &PeResourcesFacts, t: &Thresholds, out: &mut ReportBuilder) {
    let hits: Vec<_> = facts
        .entries
        .iter()
        .filter(|r| {
            r.size as usize >= t.resource_entropy_min_size
                && r.entropy.is_some_and(|e| e >= t.entropy_high)
                && !IMAGE_TYPES.contains(&r.type_name.as_str())
                && !r.kind.is_some_and(|k| COMPRESSED_KINDS.contains(&k))
        })
        .collect();
    if hits.is_empty() {
        return;
    }
    let mut f = Finding::new(
        "PE-RESOURCE-HIGH-ENTROPY",
        Severity::Low,
        Category::Packing,
        "Resource data looks encrypted",
    )
    .confidence(Confidence::Low)
    .detail(
        "A large resource has near-random content and is neither an image nor a \
         recognised compressed format: often an encrypted payload or configuration.",
    );
    for r in hits {
        f = f.evidence(resource_ev(r)).evidence(Evidence::Metric {
            name: "entropy",
            value: r.entropy.unwrap_or_default(),
        });
    }
    out.push_finding(f);
}

struct Walk<'a> {
    pe: &'a PeImage,
    data: &'a [u8],
    root: usize,
    limits: &'a Limits,
    deadline: &'a Deadline,
    budget: Budget,
    visited: BTreeSet<u32>,
    min_entropy_size: usize,
    out: PeResourcesFacts,
}

/// Walks the resource directory; `Ok(None)` without one.
///
/// # Errors
/// Unmapped root, budget exhaustion, deadline.
pub fn parse(
    pe: &PeImage,
    data: &[u8],
    limits: &Limits,
    deadline: &Deadline,
    min_entropy_size: usize,
) -> Result<Option<PeResourcesFacts>, AnalysisError> {
    let Some(dir) = pe.directory(DIRECTORY_RESOURCE) else {
        return Ok(None);
    };
    let root = pe
        .rva_to_offset(dir.rva, data.len())
        .ok_or_else(|| AnalysisError::Malformed {
            what: "PE resource directory",
            reason: format!("RVA 0x{:08x} is not backed by file data", dir.rva),
        })?;
    let mut w = Walk {
        pe,
        data,
        root,
        limits,
        deadline,
        budget: deadline.budget(limits.max_parser_steps),
        visited: BTreeSet::new(),
        min_entropy_size,
        out: PeResourcesFacts {
            entries: Vec::new(),
            limit_reached: false,
        },
    };
    w.directory(0, &[])?;
    Ok(Some(w.out))
}

impl Walk<'_> {
    /// Visits the directory at `rel` (offset from the root); `path` holds the
    /// type and name labels of the levels above.
    fn directory(&mut self, rel: u32, path: &[(String, u32)]) -> Result<(), AnalysisError> {
        if !self.visited.insert(rel) {
            return Ok(()); // cycle or shared subdirectory: visit once
        }
        let at = self.root.saturating_add(rel as usize);
        let named = usize::from(read_u16(
            self.data,
            at.saturating_add(12),
            "resource directory",
        )?);
        let ids = usize::from(read_u16(
            self.data,
            at.saturating_add(14),
            "resource directory",
        )?);
        for i in 0..named + ids {
            self.budget.step()?;
            if self.out.limit_reached {
                return Ok(());
            }
            let entry = at.saturating_add(16 + 8 * i);
            let name_field = read_u32(self.data, entry, "resource directory entry")?;
            let target = read_u32(
                self.data,
                entry.saturating_add(4),
                "resource directory entry",
            )?;
            let label = self.label(name_field, path.len());
            let mut child = path.to_vec();
            child.push((label, name_field));
            match (target & HIGH_BIT != 0, path.len()) {
                (true, 0 | 1) => self.directory(target & !HIGH_BIT, &child)?,
                (false, 2) => self.leaf(target, &child)?,
                _ => {} // wrong shape for this depth: ignore
            }
        }
        Ok(())
    }

    fn leaf(&mut self, rel: u32, path: &[(String, u32)]) -> Result<(), AnalysisError> {
        if self.out.entries.len() >= self.limits.max_resources {
            self.out.limit_reached = true;
            return Ok(());
        }
        let at = self.root.saturating_add(rel as usize);
        let rva = read_u32(self.data, at, "resource data entry")?;
        let size = read_u32(self.data, at.saturating_add(4), "resource data entry")?;
        let bytes = self
            .pe
            .rva_to_offset(rva, self.data.len())
            .and_then(|start| {
                let end = start.saturating_add(size as usize).min(self.data.len());
                self.data.get(start..end)
            })
            .unwrap_or_default();
        let entropy = if bytes.len() >= self.min_entropy_size {
            Some(shannon_bounded(bytes, self.deadline)?)
        } else {
            None
        };
        let label = |i: usize| path.get(i).map(|(l, _)| l.clone()).unwrap_or_default();
        self.out.entries.push(PeResource {
            type_name: label(0),
            name: label(1),
            lang: path.get(2).map_or(0, |(_, raw)| *raw),
            rva,
            size,
            entropy,
            kind: content_kind(bytes),
        });
        Ok(())
    }

    /// Human label for an entry: type names for level 0 IDs, `#id`, or the
    /// UTF-16 string a named entry points at.
    fn label(&self, name_field: u32, depth: usize) -> String {
        if name_field & HIGH_BIT == 0 {
            return match (depth, rt_name(name_field)) {
                (0, Some(rt)) => rt.to_owned(),
                _ => format!("#{name_field}"),
            };
        }
        let at = self.root.saturating_add((name_field & !HIGH_BIT) as usize);
        let Ok(len) = read_u16(self.data, at, "resource name") else {
            return "?".to_owned();
        };
        let units: Vec<u16> = (0..usize::from(len).min(MAX_NAME_UNITS))
            .map_while(|k| read_u16(self.data, at.saturating_add(2 + 2 * k), "resource name").ok())
            .collect();
        String::from_utf16_lossy(&units)
    }
}

/// Standard resource type names.
fn rt_name(id: u32) -> Option<&'static str> {
    Some(match id {
        1 => "RT_CURSOR",
        2 => "RT_BITMAP",
        3 => "RT_ICON",
        4 => "RT_MENU",
        5 => "RT_DIALOG",
        6 => "RT_STRING",
        7 => "RT_FONTDIR",
        8 => "RT_FONT",
        9 => "RT_ACCELERATOR",
        10 => "RT_RCDATA",
        11 => "RT_MESSAGETABLE",
        12 => "RT_GROUP_CURSOR",
        14 => "RT_GROUP_ICON",
        16 => "RT_VERSION",
        17 => "RT_DLGINCLUDE",
        19 => "RT_PLUGPLAY",
        20 => "RT_VXD",
        21 => "RT_ANICURSOR",
        22 => "RT_ANIICON",
        23 => "RT_HTML",
        24 => "RT_MANIFEST",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::input::Input;
    use crate::report::Report;
    use crate::Registry;
    use rtriage_fixtures::pe::{put_u32, Arch, PeBuilder, ResId, ResourceSpec};

    fn analyze_with(bytes: Vec<u8>, config: &Config) -> Report {
        Registry::default().analyze(&Input::from_bytes("t.exe", bytes), config)
    }

    fn analyze(bytes: Vec<u8>) -> Report {
        let r = analyze_with(bytes, &Config::default());
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        r
    }

    fn res(r: &Report) -> Option<&PeResourcesFacts> {
        r.facts.pe.as_ref().unwrap().resources.as_ref()
    }

    fn uniform(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 256) as u8).collect()
    }

    #[test]
    fn walks_types_names_languages() {
        let r = analyze(
            PeBuilder::minimal(Arch::X64)
                .resource(ResourceSpec::new(24, 1, b"<assembly/>".to_vec()))
                .resource(ResourceSpec::new(10, 101, uniform(4096)))
                .resource(ResourceSpec {
                    type_id: ResId::Name("CONFIG".into()),
                    name: ResId::Name("main".into()),
                    lang: 1049,
                    data: b"k=v".to_vec(),
                })
                .build()
                .bytes,
        );
        let got: Vec<_> = res(&r)
            .unwrap()
            .entries
            .iter()
            .map(|e| (e.type_name.as_str(), e.name.as_str(), e.lang, e.size))
            .collect();
        assert_eq!(
            got,
            [
                ("CONFIG", "main", 1049, 3),
                ("RT_RCDATA", "#101", 1033, 4096),
                ("RT_MANIFEST", "#1", 1033, 11),
            ]
        );
        let rcdata = &res(&r).unwrap().entries[1];
        assert!(rcdata.entropy.unwrap() > 7.9);
    }

    #[test]
    fn embedded_pe_and_png_are_recognised() {
        let inner = PeBuilder::minimal(Arch::X86).build().bytes;
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        png.extend(uniform(600));
        let r = analyze(
            PeBuilder::minimal(Arch::X64)
                .resource(ResourceSpec::new(10, 1, inner))
                .resource(ResourceSpec::new(3, 1, png))
                .build()
                .bytes,
        );
        let kinds: Vec<_> = res(&r).unwrap().entries.iter().map(|e| e.kind).collect();
        assert_eq!(kinds, [Some("png"), Some("pe")]);
    }

    fn ids(r: &Report) -> Vec<&'static str> {
        r.findings
            .iter()
            .map(|f| f.id)
            .filter(|id| id.starts_with("PE-RESOURCE"))
            .collect()
    }

    #[test]
    fn embedded_pe_resource_is_medium_low() {
        let inner = PeBuilder::minimal(Arch::X86).build().bytes;
        let r = analyze(
            PeBuilder::minimal(Arch::X64)
                .resource(ResourceSpec::new(10, 1, inner))
                .build()
                .bytes,
        );
        assert_eq!(ids(&r), ["PE-RESOURCE-EMBEDDED-PE"]);
        let f = r
            .findings
            .iter()
            .find(|f| f.id == "PE-RESOURCE-EMBEDDED-PE")
            .unwrap();
        assert_eq!(
            (f.severity, f.confidence),
            (
                crate::report::Severity::Medium,
                crate::report::Confidence::Low
            )
        );
    }

    #[test]
    fn mz_without_pe_header_is_not_embedded_pe() {
        let r = analyze(
            PeBuilder::minimal(Arch::X64)
                .resource(ResourceSpec::new(10, 1, b"MZ just two letters".to_vec()))
                .build()
                .bytes,
        );
        assert!(ids(&r).is_empty());
    }

    #[test]
    fn encrypted_rcdata_is_high_entropy() {
        let r = analyze(
            PeBuilder::minimal(Arch::X64)
                .resource(ResourceSpec::new(10, 7, uniform(8192)))
                .build()
                .bytes,
        );
        assert_eq!(ids(&r), ["PE-RESOURCE-HIGH-ENTROPY"]);
    }

    #[test]
    fn icons_compressed_formats_and_small_blobs_are_not_high_entropy() {
        let mut zip = b"PK\x03\x04".to_vec();
        zip.extend(uniform(8192));
        let r = analyze(
            PeBuilder::minimal(Arch::X64)
                .resource(ResourceSpec::new(3, 1, uniform(8192))) // RT_ICON
                .resource(ResourceSpec::new(10, 2, zip)) // zip in RCDATA
                .resource(ResourceSpec::new(10, 3, uniform(2048))) // under 4 KiB
                .build()
                .bytes,
        );
        assert!(ids(&r).is_empty(), "{:?}", ids(&r));
    }

    #[test]
    fn no_resources() {
        assert!(res(&analyze(PeBuilder::minimal(Arch::X64).build().bytes)).is_none());
    }

    #[test]
    fn leaf_limit() {
        let mut b = PeBuilder::minimal(Arch::X64);
        for i in 0..20 {
            b = b.resource(ResourceSpec::new(10, i, vec![1, 2, 3]));
        }
        let mut config = Config::default();
        config.limits.max_resources = 5;
        let r = analyze_with(b.build().bytes, &config);
        let f = res(&r).unwrap();
        assert_eq!(f.entries.len(), 5);
        assert!(f.limit_reached);
    }

    #[test]
    fn self_referencing_directory_terminates() {
        // Point the root's first entry back at the root itself.
        let mut built = PeBuilder::minimal(Arch::X64)
            .resource(ResourceSpec::new(10, 1, vec![1]))
            .build();
        let dd = built.layout.data_directory_offset(2);
        let rva = u32::from_le_bytes(built.bytes[dd..dd + 4].try_into().unwrap());
        let auto = *built.layout.sections.last().unwrap();
        let root = (auto.raw_ptr + (rva - auto.rva)) as usize;
        put_u32(&mut built.bytes, root + 16 + 4, HIGH_BIT); // -> offset 0 (root)
        let r = analyze_with(built.bytes, &Config::default());
        assert!(res(&r).unwrap().entries.is_empty());
    }

    #[test]
    fn huge_entry_counts_hit_the_budget_or_eof() {
        let mut built = PeBuilder::minimal(Arch::X64)
            .resource(ResourceSpec::new(10, 1, vec![1]))
            .build();
        let dd = built.layout.data_directory_offset(2);
        let rva = u32::from_le_bytes(built.bytes[dd..dd + 4].try_into().unwrap());
        let auto = *built.layout.sections.last().unwrap();
        let root = (auto.raw_ptr + (rva - auto.rva)) as usize;
        built.bytes[root + 14..root + 16].copy_from_slice(&0xFFFFu16.to_le_bytes());
        let r = analyze_with(built.bytes, &Config::default());
        // Entries past EOF are a truncation error, not a hang or panic.
        assert!(r.errors.iter().any(|e| e.analyzer == "pe-resources"));
    }
}

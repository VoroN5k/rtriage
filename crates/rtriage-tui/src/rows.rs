//! Display text of every list row, sanitized. Views draw these cells and
//! search matches against them, so the user finds exactly what they see.

use rtriage_core::{Report, Severity};
use rtriage_sanitize::single_line;

use crate::app::{App, Tab};
use crate::model;
use crate::view::snake;

/// Column titles of the PE section table.
pub const PE_SECTION_COLUMNS: [&str; 8] = [
    "#", "Name", "VirtAddr", "VirtSize", "RawOff", "RawSize", "Perm", "Entropy",
];
/// Column titles of the ELF section-header table.
pub const ELF_SECTION_COLUMNS: [&str; 7] = ["#", "Name", "Type", "Flags", "Addr", "Offset", "Size"];
/// Column titles of the ELF program-header table.
pub const ELF_SEGMENT_COLUMNS: [&str; 8] = [
    "#", "Type", "Perm", "Offset", "VAddr", "FileSz", "MemSz", "Entropy",
];
/// Column titles of the import table.
pub const IMPORT_COLUMNS: [&str; 2] = ["Library", "Symbol"];

/// Short severity label used in lists.
pub fn severity_name(s: Severity) -> &'static str {
    match s {
        Severity::High => "HIGH",
        Severity::Medium => "MED",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    }
}

fn entropy(e: Option<f64>) -> String {
    e.map_or_else(|| "-".to_owned(), |e| format!("{e:.2}"))
}

/// Text of findings row `row`.
pub fn finding(report: &Report, row: usize) -> Option<String> {
    let f = report.findings.get(row)?;
    // `~` marks findings that are explained away and score 0.
    let mark = if f.suppressed.is_some() { '~' } else { ' ' };
    Some(format!(
        "{:<4} {mark}{} {}",
        severity_name(f.severity),
        f.id,
        single_line(&f.title)
    ))
}

/// Cells of Sections row `row` (PE sections or ELF section headers).
pub fn section(report: &Report, row: usize) -> Option<Vec<String>> {
    if let Some(s) = report.facts.pe.as_ref().and_then(|p| p.sections.as_ref()) {
        let s = s.get(row)?;
        let truncated = if s.raw_truncated { " (truncated)" } else { "" };
        return Some(vec![
            s.index.to_string(),
            single_line(&s.name).into_owned(),
            format!("0x{:08x}", s.virtual_address),
            format!("0x{:x}", s.virtual_size),
            format!("0x{:08x}", s.raw_offset),
            format!("0x{:x}{truncated}", s.raw_size),
            s.permissions.clone(),
            entropy(s.entropy),
        ]);
    }
    let s = report.facts.elf.as_ref()?.sections.as_ref()?.get(row)?;
    Some(vec![
        s.index.to_string(),
        single_line(&s.name).into_owned(),
        single_line(&s.kind).into_owned(),
        s.flags.join(","),
        format!("0x{:x}", s.addr),
        format!("0x{:08x}", s.offset),
        format!("0x{:x}", s.size),
    ])
}

/// Number of ELF program headers.
pub fn segment_count(report: &Report) -> usize {
    report
        .facts
        .elf
        .as_ref()
        .and_then(|e| e.segments.as_ref())
        .map_or(0, Vec::len)
}

/// Cells of ELF segment row `row`.
pub fn segment(report: &Report, row: usize) -> Option<Vec<String>> {
    let s = report.facts.elf.as_ref()?.segments.as_ref()?.get(row)?;
    let truncated = if s.truncated { " (truncated)" } else { "" };
    Some(vec![
        s.index.to_string(),
        single_line(&s.kind).into_owned(),
        s.permissions.clone(),
        format!("0x{:08x}", s.offset),
        format!("0x{:x}", s.vaddr),
        format!("0x{:x}{truncated}", s.filesz),
        format!("0x{:x}", s.memsz),
        entropy(s.entropy),
    ])
}

/// Cells of every import row; the library is named on the first row of
/// its group only, so groups read as blocks.
pub fn imports(report: &Report) -> Vec<[String; 2]> {
    let mut previous: Option<&str> = None;
    model::import_rows(report)
        .into_iter()
        .map(|r| {
            let lib = match r.library {
                Some(l) if previous != Some(l) => single_line(l).into_owned(),
                _ => String::new(),
            };
            previous = r.library;
            [lib, single_line(&r.symbol).into_owned()]
        })
        .collect()
}

/// Searchable text of string item `row`: offset and value.
pub fn string(report: &Report, row: usize) -> Option<String> {
    let s = report.facts.strings.as_ref()?.items.get(row)?;
    Some(format!("0x{:08x} {}", s.offset, single_line(&s.value)))
}

/// Searchable text of every row of the current tab's main list, produced
/// lazily (`None` for tabs without one).
pub fn searchable<'a>(
    app: &'a App,
    report: &'a Report,
) -> Option<Box<dyn Fn(usize) -> Option<String> + 'a>> {
    Some(match app.tab {
        Tab::Findings => Box::new(move |r| finding(report, r)),
        Tab::Sections if app.panes.show_segments => {
            Box::new(move |r| segment(report, r).map(|c| c.join(" ")))
        }
        Tab::Sections => Box::new(move |r| section(report, r).map(|c| c.join(" "))),
        Tab::Imports => {
            // Search the full library name on every row, not the grouped cell.
            let rows = model::import_rows(report);
            Box::new(move |r| {
                rows.get(r).map(|row| {
                    format!(
                        "{} {}",
                        single_line(row.library.unwrap_or("")),
                        single_line(&row.symbol)
                    )
                })
            })
        }
        Tab::Strings => {
            let visible = &app.panes.string_rows;
            Box::new(move |r| {
                let item = usize::try_from(*visible.get(r)?).ok()?;
                string(report, item)
            })
        }
        Tab::Iocs => {
            let raw = app.panes.raw_iocs;
            Box::new(move |r| ioc(report, r, raw).map(|c| c.join(" ")))
        }
        Tab::Explain => return None,
    })
}

/// One row of the IOCs tab.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IocRow<'a> {
    /// A file hash: algorithm and lowercase hex (computed by rtriage).
    Hash(&'static str, &'a str),
    /// An indicator extracted from the file's strings.
    Ioc(&'a rtriage_core::report::Ioc),
}

/// Column titles of the IOCs table.
pub const IOC_COLUMNS: [&str; 5] = ["Kind", "Value", "Notes", "Count", "First at"];

fn hashes(report: &Report) -> Vec<IocRow<'_>> {
    report.file.hashes.as_ref().map_or_else(Vec::new, |h| {
        vec![
            IocRow::Hash("md5", h.md5.as_str()),
            IocRow::Hash("sha1", h.sha1.as_str()),
            IocRow::Hash("sha256", h.sha256.as_str()),
        ]
    })
}

/// Rows of the IOCs tab.
pub fn ioc_count(report: &Report) -> usize {
    let iocs = report.facts.iocs.as_ref().map_or(0, |i| i.items.len());
    hashes(report).len().saturating_add(iocs)
}

/// IOCs row `row`: hashes first, then indicators.
pub fn ioc_row(report: &Report, row: usize) -> Option<IocRow<'_>> {
    let h = hashes(report);
    match h.get(row) {
        Some(r) => Some(*r),
        None => report
            .facts
            .iocs
            .as_ref()?
            .items
            .get(row.checked_sub(h.len())?)
            .map(IocRow::Ioc),
    }
}

/// Cells of IOCs row `row`, defanged unless `raw`.
pub fn ioc(report: &Report, row: usize, raw: bool) -> Option<Vec<String>> {
    Some(match ioc_row(report, row)? {
        IocRow::Hash(alg, hex) => vec![
            alg.to_owned(),
            hex.to_owned(),
            "file hash".to_owned(),
            String::new(),
            String::new(),
        ],
        IocRow::Ioc(i) => {
            let value = if raw { &i.value } else { &i.value_defanged };
            let mut notes: Vec<String> = i.scope.iter().map(snake).collect();
            if i.allowlisted {
                notes.push("allowlisted".to_owned());
            }
            vec![
                snake(&i.kind),
                single_line(value).into_owned(),
                notes.join(", "),
                i.count.to_string(),
                i.offsets
                    .first()
                    .map(|o| format!("0x{o:08x}"))
                    .unwrap_or_default(),
            ]
        }
    })
}

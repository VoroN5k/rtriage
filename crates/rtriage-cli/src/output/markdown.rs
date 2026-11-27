//! Markdown renderer: the same sections, in the same order, as the text
//! report, with every file-derived value in a code span (see [`super::md`]).
//!
//! Raw text is only our own static labels, enum names and numbers we format.
//! Our own text also avoids `#<digit>` and `@<word>` (GitHub would link them)
//! and `|`. Every table ends with a blank line: GFM would otherwise take the
//! next line as one more row.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::io::{self, Write};

use rtriage_core::analyzers::iocs::defang_text;
use rtriage_core::report::{
    AnalysisLimit, ElfFacts, ElfHeaderFacts, EntropyFacts, ExtractedString, Ioc, IocFacts, IocKind,
    PeExportsFacts, PeImportsFacts, PeResourcesFacts, PeSectionFacts, Reduction, SignatureStatus,
    StringEncoding, StringKind, StringsFacts, YaraFacts,
};
use rtriage_core::{Evidence, Finding, PeFacts, PeHeaderFacts, Report, Risk, RiskLevel, Severity};

use super::common::{
    enum_name, explainer_label, format_name, group_digits, human_size, short_size,
};
use super::md::{cell, code, code_limited, Budget, DETAIL_LIMIT, TAIL_RESERVE, VALUE_LIMIT};
use super::{Failure, Run, SkippedPath};
use crate::worker::Summary;

/// Classified strings and IOCs shown per kind before "+N more" (as text).
const PER_KIND: usize = 20;
/// Functions listed per library before "+N more" (as text).
const IMPORTS_PER_LIBRARY: usize = 8;
/// Exports listed before "+N more" (as text).
const EXPORTS_SHOWN: usize = 20;
/// Resources listed before "+N more" (as text).
const RESOURCES_SHOWN: usize = 30;
/// ELF dynamic imports listed before "+N more" (as text).
const ELF_IMPORTS_SHOWN: usize = 12;
/// ELF sections listed before "+N more" (as text).
const ELF_SECTIONS_SHOWN: usize = 40;

/// Rendering options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MdOptions {
    /// Print the score breakdown.
    pub explain: bool,
    /// List every string instead of capping classified ones per kind.
    pub all_strings: bool,
    /// Defang URLs, domains, IPs and emails in IOCs, evidence and strings.
    pub defang: bool,
}

/// Skipped paths listed before "+N more" (as text).
const SKIPPED_SHOWN: usize = 20;

/// Writes `run` as one Markdown document within `limit` characters
/// (`None` = no limit).
///
/// # Errors
/// Errors of `out`.
pub fn render(
    run: &Run,
    out: &mut dyn Write,
    opts: MdOptions,
    limit: Option<usize>,
) -> io::Result<()> {
    let mut doc = Document::new(out, limit)?;
    for r in &run.reports {
        doc.report(&render_report(r, opts))?;
    }
    doc.finish(&run.failures, &run.skipped)?;
    Ok(())
}

/// A Markdown document written as reports arrive: the title, an optional
/// scan table, report bodies separated by rules, then the tail (failed and
/// skipped files), all under one [`Budget`] that keeps room for the tail.
pub struct Document<W: Write> {
    budget: Budget<W>,
    /// Parts written so far (scan table and bodies).
    parts: usize,
}

/// The rule written between two parts.
const SEPARATOR: &str = "---

";

impl<W: Write> Document<W> {
    /// Starts the document (writes the title).
    ///
    /// # Errors
    /// Errors of `inner`.
    pub fn new(inner: W, limit: Option<usize>) -> io::Result<Self> {
        let mut budget = Budget::new(inner, limit, TAIL_RESERVE);
        budget.write_all(
            b"# rtriage report

",
        )?;
        Ok(Document { budget, parts: 0 })
    }

    /// Adds one body from [`render_report`].
    ///
    /// # Errors
    /// Errors of the inner writer.
    pub fn report(&mut self, body: &str) -> io::Result<()> {
        if self.parts > 0 {
            self.budget.write_all(SEPARATOR.as_bytes())?;
        }
        self.parts += 1;
        self.budget.write_all(body.as_bytes())
    }

    /// Adds the scan table ([`render_scan_table`]).
    ///
    /// # Errors
    /// Errors of the inner writer.
    pub fn scan_table(&mut self, rows: &[Summary], failed: usize) -> io::Result<()> {
        self.report(&render_scan_table(rows, failed))
    }

    /// Adds the bodies of `held`, then counts the ones it dropped.
    ///
    /// # Errors
    /// Errors of the inner writer.
    pub fn held(&mut self, held: HeldBodies) -> io::Result<()> {
        for body in &held.bodies {
            self.report(body)?;
        }
        self.budget.skip(held.dropped_lines, held.dropped_chars);
        Ok(())
    }

    /// Writes the tail and the truncation notes; returns the inner writer.
    ///
    /// # Errors
    /// Errors of the inner writer.
    pub fn finish(mut self, failures: &[Failure], skipped: &[SkippedPath]) -> io::Result<W> {
        if self.parts == 0 && failures.is_empty() {
            self.budget.write_all(
                b"_No files analyzed._

",
            )?;
        }
        self.budget.begin_tail()?;
        self.budget
            .write_all(render_tail(failures, skipped).as_bytes())?;
        self.budget.finish()
    }
}

/// Report bodies kept for `scan --full -f md`, whose table comes first:
/// only as many as the document can show. Once the body allowance is used
/// (the body that crosses it is still kept, so the budget is sure to cut),
/// later bodies are only counted for the truncation note.
#[derive(Debug, Default)]
pub struct HeldBodies {
    cap: Option<usize>,
    used: usize,
    full: bool,
    bodies: Vec<String>,
    dropped_lines: u64,
    dropped_chars: u64,
}

impl HeldBodies {
    /// Holds bodies for a document limited to `limit` characters.
    pub fn new(limit: Option<usize>) -> Self {
        HeldBodies {
            cap: limit.map(|l| l.saturating_sub(TAIL_RESERVE)),
            ..HeldBodies::default()
        }
    }

    /// Keeps or counts one body.
    pub fn push(&mut self, body: String) {
        let chars = body.chars().count().saturating_add(SEPARATOR.len());
        if self.full {
            let lines = body.matches('\n').count().saturating_add(2);
            self.dropped_lines = self
                .dropped_lines
                .saturating_add(u64::try_from(lines).unwrap_or(u64::MAX));
            self.dropped_chars = self
                .dropped_chars
                .saturating_add(u64::try_from(chars).unwrap_or(u64::MAX));
            return;
        }
        self.used = self.used.saturating_add(chars);
        self.full = self.cap.is_some_and(|cap| self.used > cap);
        self.bodies.push(body);
    }
}

/// The `scan` table: counts, then one row per file in the caller's order
/// (sorted by risk).
pub fn render_scan_table(rows: &[Summary], failed: usize) -> String {
    let mut d = Doc {
        out: String::new(),
        defang: false,
    };
    d.para("## Scan");
    let c = super::json::Counts::of(rows);
    d.para(&format!(
        "{} file(s): {} high, {} medium, {} low, {} clean-looking{}.",
        group_digits(rows.len() as u64),
        c.high,
        c.medium,
        c.low,
        c.clean_looking,
        if failed == 0 {
            String::new()
        } else {
            format!("; {failed} failed")
        }
    ));
    if rows.is_empty() {
        d.para("_No files analyzed._");
        return d.out;
    }
    let table: Vec<Vec<String>> = rows
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let size = if r.size < 1024 {
                format!("{} B", r.size)
            } else {
                short_size(r.size)
            };
            let top = r.top_finding.as_ref().map_or_else(
                || "-".to_owned(),
                |t| format!("{} {}", cell(&t.id), cell(&t.title)),
            );
            let flags: Vec<&str> = [(r.packed, "packed"), (r.partial, "partial")]
                .iter()
                .filter_map(|(on, n)| on.then_some(*n))
                .collect();
            vec![
                (i + 1).to_string(),
                risk_text(r.level).to_owned(),
                r.score.to_string(),
                format_name(r.format).to_owned(),
                size,
                cell(&r.path),
                top,
                flags.join(", "),
            ]
        })
        .collect();
    d.table(
        &[
            "Rank",
            "Risk",
            "Score",
            "Type",
            "Size",
            "File",
            "Top finding",
            "Flags",
        ],
        &table,
    );
    d.out
}

/// Failed and skipped files.
fn render_tail(failures: &[Failure], skipped: &[SkippedPath]) -> String {
    let mut d = Doc {
        out: String::new(),
        defang: false,
    };
    if !failures.is_empty() {
        d.para("## Failed");
        let items: Vec<String> = failures
            .iter()
            .map(|f| {
                format!(
                    "{}: {} ({})",
                    code(&f.path),
                    code(&f.error),
                    enum_name(&f.kind)
                )
            })
            .collect();
        d.list(&items);
    }
    if !skipped.is_empty() {
        d.para("## Skipped");
        d.para(&format!(
            "{} (not analyzed, not failures).",
            group_digits(skipped.len() as u64)
        ));
        let mut items: Vec<String> = skipped
            .iter()
            .take(SKIPPED_SHOWN)
            .map(|s| format!("{} {}", enum_name(&s.reason), code(&s.path)))
            .collect();
        if skipped.len() > SKIPPED_SHOWN {
            items.push(format!(
                "+{} more (see JSON)",
                skipped.len() - SKIPPED_SHOWN
            ));
        }
        d.list(&items);
    }
    d.out
}

/// One report as a Markdown section headed `## `file``; the caller writes
/// the document title (`# rtriage report`) and separators.
pub fn render_report(report: &Report, opts: MdOptions) -> String {
    let mut d = Doc {
        out: String::new(),
        defang: opts.defang,
    };
    d.report(report, opts);
    d.out
}

/// The document being written.
struct Doc {
    out: String,
    defang: bool,
}

impl Doc {
    fn line(&mut self, s: &str) {
        self.out.push_str(s);
        self.out.push('\n');
    }

    fn blank(&mut self) {
        self.out.push('\n');
    }

    fn heading(&mut self, text: &str) {
        self.line(&format!("### {text}"));
        self.blank();
    }

    /// A paragraph followed by a blank line.
    fn para(&mut self, text: &str) {
        self.line(text);
        self.blank();
    }

    /// A GFM table: header, rows, blank line. Each row must have `cols.len()`
    /// cells; cells are either our own text or [`cell`] output.
    fn table(&mut self, cols: &[&str], rows: &[Vec<String>]) {
        self.line(&format!("| {} |", cols.join(" | ")));
        let rule: Vec<&str> = cols.iter().map(|_| "---").collect();
        self.line(&format!("| {} |", rule.join(" | ")));
        for r in rows {
            self.line(&format!("| {} |", r.join(" | ")));
        }
        self.blank();
    }

    /// A bullet list followed by a blank line.
    fn list(&mut self, items: &[String]) {
        if items.is_empty() {
            return;
        }
        for i in items {
            self.line(&format!("- {i}"));
        }
        self.blank();
    }

    /// File-derived text that may hold IOCs: defanged if requested.
    fn untrusted<'a>(&self, s: &'a str) -> Cow<'a, str> {
        if self.defang {
            defang_text(s)
        } else {
            Cow::Borrowed(s)
        }
    }

    fn report(&mut self, r: &Report, opts: MdOptions) {
        self.header(r);
        self.findings(&r.findings);
        if opts.explain {
            self.explain(&r.risk);
        }
        if let Some(pe) = &r.facts.pe {
            self.pe_block(pe);
        }
        if let Some(elf) = &r.facts.elf {
            self.elf_block(elf);
        }
        if let Some(s) = r.facts.pe.as_ref().and_then(|pe| pe.sections.as_deref()) {
            self.pe_sections(s);
        }
        if let Some(i) = r.facts.pe.as_ref().and_then(|pe| pe.imports.as_ref()) {
            self.pe_imports(i);
        }
        if let Some(e) = r.facts.pe.as_ref().and_then(|pe| pe.exports.as_ref()) {
            self.pe_exports(e);
        }
        if let Some(res) = r.facts.pe.as_ref().and_then(|pe| pe.resources.as_ref()) {
            self.pe_resources(res);
        }
        if let Some(e) = &r.facts.entropy {
            self.entropy(e);
        }
        if let Some(y) = &r.facts.yara {
            self.yara(y);
        }
        if let Some(i) = &r.facts.iocs {
            self.iocs(i);
        }
        if let Some(s) = &r.facts.strings {
            self.strings(s, opts.all_strings);
        }
        if !r.errors.is_empty() {
            self.heading("Analyzer errors");
            let items: Vec<String> = r
                .errors
                .iter()
                .map(|e| format!("{}: {}", e.analyzer, code(&e.error.to_string())))
                .collect();
            self.list(&items);
        }
    }

    fn header(&mut self, r: &Report) {
        let f = &r.file;
        self.para(&format!("## {}", code(&f.path)));
        let mut risk = format!(
            "**Risk: {}** · score {}",
            risk_text(r.risk.level),
            r.risk.score
        );
        if let Some(fl) = &r.risk.floor {
            risk.push_str(&format!(
                " · level raised to {} by {}",
                enum_name(&fl.level),
                code(&fl.title)
            ));
        }
        if r.analysis_limited.contains(&AnalysisLimit::Packed) {
            risk.push_str(" · **PACKED: analysis limited**");
        }
        self.para(&risk);
        let mut rows = vec![
            vec!["Type".to_owned(), format_name(f.format).to_owned()],
            vec!["Size".to_owned(), human_size(f.size)],
        ];
        if let Some(h) = &f.hashes {
            rows.push(vec!["MD5".to_owned(), cell(&h.md5)]);
            rows.push(vec!["SHA-1".to_owned(), cell(&h.sha1)]);
            rows.push(vec!["SHA-256".to_owned(), cell(&h.sha256)]);
        }
        self.table(&["Field", "Value"], &rows);
    }

    fn findings(&mut self, findings: &[Finding]) {
        self.heading("Findings");
        if findings.is_empty() {
            self.para("_none_");
            return;
        }
        for f in findings {
            self.para(&format!(
                "#### {} · {} · {}",
                severity_text(f.severity),
                code(f.id),
                code(&f.title)
            ));
            self.para(&format!(
                "Confidence {}, category {}.",
                enum_name(&f.confidence),
                enum_name(&f.category)
            ));
            if !f.detail.is_empty() {
                self.para(&code_limited(&f.detail, DETAIL_LIMIT));
            }
            let ev: Vec<String> = f.evidence.iter().map(|e| self.evidence(e)).collect();
            self.list(&ev);
            if !f.attack.is_empty() {
                let ids: Vec<String> = f.attack.iter().map(|a| code(a)).collect();
                self.para(&format!("ATT&CK: {}", ids.join(", ")));
            }
            if let Some(s) = &f.suppressed {
                self.para(&format!(
                    "_Explained by {}: not scored._",
                    explainer_label(s.kind, s.name, s.by)
                ));
            }
        }
    }

    fn evidence(&self, e: &Evidence) -> String {
        match e {
            Evidence::Range { offset, len } => format!("range 0x{offset:08x} (+{len} bytes)"),
            Evidence::Section { index, name } => format!("section {index} {}", code(name)),
            Evidence::Import { library, symbol } => match library {
                Some(lib) => format!("import {}", code(&format!("{lib}!{symbol}"))),
                None => format!("import {}", code(symbol)),
            },
            Evidence::String {
                offset,
                encoding,
                value,
            } => format!(
                "string 0x{offset:08x} {} {}",
                enum_name(encoding),
                code(&self.untrusted(value))
            ),
            Evidence::Metric { name, value } => format!("{} = {value:.3}", code(name)),
            Evidence::Field { name, value } => {
                format!("{} = {}", code(name), code(&self.untrusted(value)))
            }
            _ => "(unsupported evidence type)".to_owned(),
        }
    }

    fn explain(&mut self, risk: &Risk) {
        self.heading("Score breakdown");
        self.para(&format!(
            "Score {} = sum of points below; level {}.",
            risk.score,
            enum_name(&risk.level)
        ));
        if let Some(f) = &risk.floor {
            self.para(&format!(
                "Level raised from {} to {} by {} ({}); the score is unchanged.",
                enum_name(&rtriage_core::scoring::level_for(risk.score)),
                enum_name(&f.level),
                code(f.finding),
                code(&f.title)
            ));
        }
        if risk.breakdown.is_empty() {
            self.para("_no findings_");
            return;
        }
        let rows: Vec<Vec<String>> = risk
            .breakdown
            .iter()
            .map(|e| {
                let note = match &e.reduced_by {
                    None if e.table_points == 0 => "informational".to_owned(),
                    None => String::new(),
                    Some(Reduction::Suppressed {
                        explainer,
                        name,
                        by,
                    }) => format!(
                        "explained by {}, not scored",
                        explainer_label(*explainer, name, *by)
                    ),
                    Some(Reduction::Duplicate) => "duplicate ID, counted once".to_owned(),
                    Some(Reduction::CategoryCap { cap }) => format!(
                        "of {}; {} cap {cap} reached",
                        e.table_points,
                        enum_name(&e.category)
                    ),
                    Some(Reduction::LowSeverityCap { cap }) => {
                        format!("of {}; low-severity cap {cap} reached", e.table_points)
                    }
                    Some(_) => "reduced".to_owned(),
                };
                vec![
                    format!("+{}", e.points),
                    cell(e.id),
                    enum_name(&e.category),
                    note,
                ]
            })
            .collect();
        self.table(&["Points", "Finding", "Category", "Note"], &rows);
    }

    /// PE header lines plus packer, overlay, TLS, PDB, Rich and signature.
    fn pe_block(&mut self, pe: &PeFacts) {
        let mut items = Vec::new();
        if let Some(h) = &pe.headers {
            pe_header_items(h, &mut items);
        }
        pe_extra_items(pe, &mut items);
        if items.is_empty() {
            return;
        }
        self.heading("PE");
        self.list(&items);
    }

    fn elf_block(&mut self, elf: &ElfFacts) {
        let mut items = Vec::new();
        if let Some(h) = &elf.headers {
            elf_header_items(h, &mut items);
        }
        elf_dynamic_items(elf, &mut items);
        if !items.is_empty() {
            self.heading("ELF");
            self.list(&items);
        }
        self.elf_layout(elf);
    }

    fn elf_layout(&mut self, elf: &ElfFacts) {
        if let Some(segs) = &elf.segments {
            self.heading("Segments");
            let rows: Vec<Vec<String>> = segs
                .iter()
                .map(|s| {
                    vec![
                        s.index.to_string(),
                        cell(&s.kind),
                        cell(&s.permissions),
                        format!("0x{:x}", s.offset),
                        format!("0x{:x}", s.vaddr),
                        format!("0x{:x}", s.filesz),
                        format!("0x{:x}", s.memsz),
                        entropy_text(s.entropy),
                        if s.truncated { "past EOF" } else { "" }.to_owned(),
                    ]
                })
                .collect();
            self.table(
                &[
                    "Index", "Type", "Perm", "Offset", "VirtAddr", "FileSize", "MemSize",
                    "Entropy", "Note",
                ],
                &rows,
            );
        }
        if let Some(secs) = &elf.sections {
            self.heading("Sections");
            if secs.is_empty() {
                self.para("_none_");
            } else {
                self.para(&format!("{} entries.", secs.len()));
                let rows: Vec<Vec<String>> = secs
                    .iter()
                    .skip(1)
                    .take(ELF_SECTIONS_SHOWN)
                    .map(|s| {
                        vec![
                            s.index.to_string(),
                            cell(&s.name),
                            cell(&s.kind),
                            format!("0x{:x}", s.addr),
                            format!("0x{:x}", s.size),
                            static_cell(&s.flags.join(",")),
                        ]
                    })
                    .collect();
                self.table(&["Index", "Name", "Type", "Addr", "Size", "Flags"], &rows);
                if secs.len() > ELF_SECTIONS_SHOWN + 1 {
                    self.para(&format!("+{} more", secs.len() - ELF_SECTIONS_SHOWN - 1));
                }
            }
        }
        let problems: Vec<String> = elf
            .section_problems
            .iter()
            .flatten()
            .map(|p| format!("Problem: {}", code(p)))
            .collect();
        self.list(&problems);
    }

    fn pe_sections(&mut self, sections: &[PeSectionFacts]) {
        self.heading("Sections");
        if sections.is_empty() {
            self.para("_none_");
            return;
        }
        let rows: Vec<Vec<String>> = sections
            .iter()
            .map(|s| {
                vec![
                    s.index.to_string(),
                    cell(&s.name),
                    format!("0x{:x}", s.virtual_address),
                    format!("0x{:x}", s.virtual_size),
                    format!("0x{:x}", s.raw_size),
                    cell(&s.permissions),
                    entropy_text(s.entropy),
                    if s.raw_truncated {
                        "raw data past EOF"
                    } else {
                        ""
                    }
                    .to_owned(),
                ]
            })
            .collect();
        self.table(
            &[
                "Index", "Name", "VirtAddr", "VirtSize", "RawSize", "Perm", "Entropy", "Note",
            ],
            &rows,
        );
    }

    fn pe_imports(&mut self, i: &PeImportsFacts) {
        self.heading("Imports");
        let mut summary = format!(
            "{} functions from {} libraries",
            group_digits(i.total_functions),
            i.libraries.len()
        );
        if let Some(h) = &i.imphash {
            summary.push_str(&format!(", imphash {}", code(h)));
        }
        if i.limit_reached {
            summary.push_str(" (limit reached, table truncated)");
        }
        summary.push('.');
        self.para(&summary);
        if i.libraries.is_empty() {
            self.para("_no import table_");
            return;
        }
        let rows: Vec<Vec<String>> = i
            .libraries
            .iter()
            .map(|lib| {
                let mut shown: Vec<String> = lib
                    .functions
                    .iter()
                    .take(IMPORTS_PER_LIBRARY)
                    .map(|f| match (&f.name, f.ordinal) {
                        (Some(n), _) => cell(n),
                        (None, Some(o)) => cell(&format!("#{o}")),
                        (None, None) => "?".to_owned(),
                    })
                    .collect();
                let more = lib.functions.len().saturating_sub(IMPORTS_PER_LIBRARY);
                if more > 0 {
                    shown.push(format!("+{more} more"));
                }
                vec![
                    cell(&lib.name),
                    lib.functions.len().to_string(),
                    shown.join(", "),
                ]
            })
            .collect();
        self.table(&["Library", "Count", "Functions"], &rows);
    }

    fn pe_exports(&mut self, e: &PeExportsFacts) {
        self.heading("Exports");
        let forwarded = e.exports.iter().filter(|x| x.forwarder.is_some()).count();
        self.para(&format!(
            "{}, {} exports ({} forwarded){}.",
            e.dll_name
                .as_deref()
                .map_or_else(|| "_no name_".into(), code),
            e.exports.len(),
            forwarded,
            if e.limit_reached {
                ", limit reached"
            } else {
                ""
            }
        ));
        if e.exports.is_empty() {
            return;
        }
        let rows: Vec<Vec<String>> = e
            .exports
            .iter()
            .take(EXPORTS_SHOWN)
            .map(|x| {
                vec![
                    x.ordinal.to_string(),
                    x.name
                        .as_deref()
                        .map_or_else(|| "_ordinal only_".into(), cell),
                    x.forwarder.as_deref().map_or_else(String::new, cell),
                ]
            })
            .collect();
        self.table(&["Ordinal", "Name", "Forwarder"], &rows);
        if e.exports.len() > EXPORTS_SHOWN {
            self.para(&format!("+{} more", e.exports.len() - EXPORTS_SHOWN));
        }
    }

    fn pe_resources(&mut self, r: &PeResourcesFacts) {
        self.heading("Resources");
        self.para(&format!(
            "{} entries{}.",
            r.entries.len(),
            if r.limit_reached {
                ", limit reached"
            } else {
                ""
            }
        ));
        if r.entries.is_empty() {
            return;
        }
        let rows: Vec<Vec<String>> = r
            .entries
            .iter()
            .take(RESOURCES_SHOWN)
            .map(|e| {
                vec![
                    cell(&e.type_name),
                    cell(&e.name),
                    e.lang.to_string(),
                    short_size(u64::from(e.size)),
                    entropy_text(e.entropy),
                    e.kind.map_or_else(String::new, static_cell),
                ]
            })
            .collect();
        self.table(&["Type", "Name", "Lang", "Size", "Entropy", "Kind"], &rows);
        if r.entries.len() > RESOURCES_SHOWN {
            self.para(&format!("+{} more", r.entries.len() - RESOURCES_SHOWN));
        }
    }

    fn entropy(&mut self, e: &EntropyFacts) {
        self.heading("Entropy");
        self.para(&format!("Whole file {:.3} bits/byte.", e.whole_file));
        if e.high_regions.is_empty() {
            self.para(&format!(
                "No high-entropy regions (>= {:.2}, window {}).",
                e.high_threshold, e.window
            ));
            return;
        }
        self.para(&format!(
            "High-entropy regions (>= {:.2}, window {}):",
            e.high_threshold, e.window
        ));
        let rows: Vec<Vec<String>> = e
            .high_regions
            .iter()
            .map(|r| {
                vec![
                    format!("0x{:08x}", r.offset),
                    format!("0x{:08x}", r.offset.saturating_add(r.len)),
                    short_size(r.len),
                    format!("{:.3}", r.entropy),
                ]
            })
            .collect();
        self.table(&["Start", "End", "Size", "Entropy"], &rows);
    }

    fn yara(&mut self, y: &YaraFacts) {
        self.heading("YARA");
        self.para(&format!(
            "{} rule(s) loaded, {} matched{}.",
            group_digits(y.rules_loaded as u64),
            y.matches.len(),
            if y.limit_reached {
                " (limit reached)"
            } else {
                ""
            }
        ));
        if y.matches.is_empty() {
            return;
        }
        let rows: Vec<Vec<String>> = y
            .matches
            .iter()
            .map(|m| {
                let tags: Vec<String> = m.tags.iter().map(|t| cell(t)).collect();
                vec![
                    cell(&format!("{}:{}", m.namespace, m.rule)),
                    tags.join(", "),
                    m.strings.len().to_string(),
                ]
            })
            .collect();
        self.table(&["Rule", "Tags", "String matches"], &rows);
    }

    fn iocs(&mut self, iocs: &IocFacts) {
        self.heading("IOCs");
        let mut notes = Vec::new();
        if iocs.allowlisted > 0 {
            notes.push(format!(
                "{} allowlisted, hidden (see JSON)",
                iocs.allowlisted
            ));
        }
        if iocs.limit_reached {
            notes.push("limit reached".to_owned());
        }
        self.para(&format!(
            "{} found{}.",
            group_digits(iocs.items.len() as u64),
            if notes.is_empty() {
                String::new()
            } else {
                format!(" ({})", notes.join(", "))
            }
        ));
        let mut groups: BTreeMap<IocKind, Vec<&Ioc>> = BTreeMap::new();
        for i in iocs.items.iter().filter(|i| !i.allowlisted) {
            groups.entry(i.kind).or_default().push(i);
        }
        if groups.is_empty() {
            self.para("_none_");
            return;
        }
        let mut rows = Vec::new();
        for (kind, items) in &groups {
            let name = enum_name(kind);
            for i in items.iter().take(PER_KIND) {
                let value = if self.defang {
                    &i.value_defanged
                } else {
                    &i.value
                };
                rows.push(vec![
                    name.clone(),
                    cell(value),
                    i.scope.map(|s| enum_name(&s)).unwrap_or_default(),
                    i.count.to_string(),
                    i.offsets
                        .first()
                        .map(|o| format!("0x{o:08x}"))
                        .unwrap_or_default(),
                ]);
            }
            if items.len() > PER_KIND {
                rows.push(more_row(&name, items.len() - PER_KIND, 5));
            }
        }
        self.table(&["Kind", "Value", "Scope", "Count", "First offset"], &rows);
    }

    fn strings(&mut self, s: &StringsFacts, all: bool) {
        self.heading("Strings");
        let classified = s.items.iter().filter(|i| !i.kinds.is_empty()).count();
        self.para(&format!(
            "{} found (ASCII + UTF-16LE, min {}), {} classified{}.",
            group_digits(s.total),
            s.min_len,
            group_digits(classified as u64),
            if s.limit_reached {
                format!(
                    ", limit reached: only the first {} kept",
                    group_digits(s.items.len() as u64)
                )
            } else {
                String::new()
            }
        ));
        let mut rows = Vec::new();
        if all {
            for item in &s.items {
                let kinds: Vec<String> = item.kinds.iter().map(enum_name).collect();
                let kinds = if kinds.is_empty() {
                    "-".to_owned()
                } else {
                    kinds.join(", ")
                };
                rows.push(self.string_row(kinds, item));
            }
        } else {
            // Group by primary (first) kind; each string is listed once.
            let mut groups: BTreeMap<StringKind, Vec<&ExtractedString>> = BTreeMap::new();
            for item in &s.items {
                if let Some(&k) = item.kinds.first() {
                    groups.entry(k).or_default().push(item);
                }
            }
            if groups.is_empty() {
                self.para("_No classified strings; use --all-strings to list all._");
                return;
            }
            for (kind, items) in &groups {
                let name = enum_name(kind);
                for item in items.iter().take(PER_KIND) {
                    rows.push(self.string_row(name.clone(), item));
                }
                if items.len() > PER_KIND {
                    rows.push(more_row(&name, items.len() - PER_KIND, 4));
                }
            }
        }
        if !rows.is_empty() {
            self.table(&["Kind", "Offset", "Enc", "Value"], &rows);
        }
    }

    fn string_row(&self, kind: String, s: &ExtractedString) -> Vec<String> {
        let enc = match s.encoding {
            StringEncoding::Ascii => "A",
            StringEncoding::Utf16Le => "W",
        };
        vec![
            kind,
            format!("0x{:08x}", s.offset),
            enc.to_owned(),
            self.long_cell(&s.value, s.len),
        ]
    }

    /// A string value whose full length (`full_len`) may exceed what was
    /// kept: cut to [`VALUE_LIMIT`] here, so the note gives the real total.
    fn long_cell(&self, value: &str, full_len: u64) -> String {
        let value = self.untrusted(value);
        let shown: String = value.chars().take(VALUE_LIMIT).collect();
        let shown_len = shown.chars().count() as u64;
        let mut out = cell(&shown);
        if full_len > shown_len {
            out.push_str(&format!(" … [{} chars total]", group_digits(full_len)));
        }
        out
    }
}

fn pe_header_items(h: &PeHeaderFacts, items: &mut Vec<String>) {
    items.push(format!(
        "Machine: {} ({}-bit), {}, {}",
        code(&h.machine),
        h.bits,
        enum_name(&h.kind),
        code(&h.subsystem)
    ));
    if h.managed_dotnet {
        items.push("Managed: .NET assembly (CLR header present)".to_owned());
    }
    items.push(match &h.entry_point {
        Some(ep) => match &ep.section {
            Some(s) => format!(
                "Entry point: 0x{:08x} in section {} {}",
                ep.rva,
                s.index,
                code(&s.name)
            ),
            None => format!("Entry point: 0x{:08x} (outside all sections)", ep.rva),
        },
        None => "Entry point: none (AddressOfEntryPoint = 0)".to_owned(),
    });
    items.push(format!("Image base: 0x{:x}", h.image_base));
    items.push(match &h.timestamp.utc {
        Some(utc) => format!("Timestamp: 0x{:08x} ({})", h.timestamp.raw, code(utc)),
        None => "Timestamp: 0 (cleared)".to_owned(),
    });
    let c = &h.checksum;
    let state = if c.stored == 0 {
        "not set"
    } else if c.stored == c.computed {
        "valid"
    } else {
        "MISMATCH"
    };
    items.push(format!(
        "Checksum: 0x{:08x} ({state}; computed 0x{:08x})",
        c.stored, c.computed
    ));
    if !h.dll_characteristics.is_empty() {
        items.push(format!(
            "DLL flags: {}",
            code(&h.dll_characteristics.join(", "))
        ));
    }
}

fn pe_extra_items(pe: &PeFacts, items: &mut Vec<String>) {
    for packer in pe.packers.iter().flatten() {
        items.push(format!(
            "Packer: {} ({})",
            code(packer.name),
            code(&packer.indicators.join(", "))
        ));
    }
    if let Some(o) = &pe.overlay {
        let entropy = o
            .entropy
            .map_or_else(String::new, |e| format!(", entropy {e:.3}"));
        items.push(format!(
            "Overlay: 0x{:x}, {}, {}{entropy}",
            o.offset,
            short_size(o.size),
            o.kind.map_or_else(|| "unknown format".to_owned(), code)
        ));
    }
    if let Some(t) = pe.tls.as_ref().filter(|t| !t.callbacks.is_empty()) {
        let list: Vec<String> = t
            .callbacks
            .iter()
            .map(|c| format!("0x{:x}", c.va))
            .collect();
        items.push(format!(
            "TLS: {} callback(s): {}{}",
            t.callbacks.len(),
            list.join(", "),
            if t.limit_reached { " (truncated)" } else { "" }
        ));
    }
    if let Some(d) = &pe.debug {
        items.push(format!("PDB: {}", code(&d.pdb_path)));
    }
    if let Some(r) = &pe.rich {
        items.push(format!(
            "Rich: {} records, checksum {}",
            r.entries.len(),
            if r.checksum_valid {
                "valid".to_owned()
            } else {
                format!(
                    "INVALID (stored 0x{:08x}, computed 0x{:08x})",
                    r.key, r.computed_checksum
                )
            }
        ));
    }
    if let Some(s) = &pe.signature {
        items.push(match s.status {
            SignatureStatus::SignedUnverified => format!(
                "Signature: signed (unverified), {} certificate entr{}",
                s.certificates.len(),
                if s.certificates.len() == 1 {
                    "y"
                } else {
                    "ies"
                }
            ),
            _ => format!("Signature: MALFORMED: {}", code(&s.problems.join("; "))),
        });
    }
}

fn elf_header_items(h: &ElfHeaderFacts, items: &mut Vec<String>) {
    items.push(format!(
        "Machine: {} ({}-bit, {}-endian), {}, OS/ABI {}",
        code(&h.machine),
        h.bits,
        h.endianness,
        h.kind,
        code(&h.os_abi)
    ));
    items.push(match &h.entry_point {
        Some(e) => match e.segment {
            Some(i) => format!("Entry point: 0x{:x} in segment {i}", e.vaddr),
            None => format!("Entry point: 0x{:x} (outside all PT_LOAD)", e.vaddr),
        },
        None => "Entry point: none (e_entry = 0)".to_owned(),
    });
    items.push(match &h.interpreter {
        Some(i) => format!("Interpreter: {}", code(i)),
        None => "Interpreter: none (static or library)".to_owned(),
    });
    items.push(format!(
        "Headers: {} segments, {} sections",
        h.number_of_segments, h.number_of_sections
    ));
}

fn elf_dynamic_items(elf: &ElfFacts, items: &mut Vec<String>) {
    let yes_no = |b: bool| if b { "yes" } else { "no" };
    let opt = |b: Option<bool>| b.map_or("n/a", |v| if v { "yes" } else { "no" });
    if let Some(c) = &elf.checksec {
        items.push(format!(
            "Hardening: PIE {} · NX {}{} · RELRO {} · BIND_NOW {} · canary {} · FORTIFY {} · stripped {}",
            opt(c.pie),
            yes_no(c.nx),
            if c.nx_source == "architecture_default" {
                " (no PT_GNU_STACK)"
            } else {
                ""
            },
            c.relro,
            yes_no(c.bind_now),
            opt(c.canary),
            opt(c.fortify),
            yes_no(c.stripped)
        ));
    }
    let Some(d) = &elf.dynamic else {
        return;
    };
    if !d.needed.is_empty() {
        let needed: Vec<String> = d.needed.iter().map(|n| code(n)).collect();
        items.push(format!("Needed: {}", needed.join(", ")));
    }
    for (label, value) in [("RPATH", &d.rpath), ("RUNPATH", &d.runpath)] {
        if let Some(v) = value {
            items.push(format!("{label}: {}", code(v)));
        }
    }
    let mut shown: Vec<String> = d
        .imports
        .iter()
        .take(ELF_IMPORTS_SHOWN)
        .map(|n| code(n))
        .collect();
    let more = d.imports.len().saturating_sub(ELF_IMPORTS_SHOWN);
    if more > 0 {
        shown.push(format!("+{more} more"));
    }
    items.push(format!(
        "Imports: {} via {}{}: {}",
        d.imports.len(),
        d.symbol_count_source,
        if d.symbols_limit_reached {
            ", limit reached"
        } else {
            ""
        },
        shown.join(", ")
    ));
}

/// A row saying how many more items of `kind` were left out.
fn more_row(kind: &str, more: usize, cols: usize) -> Vec<String> {
    let mut row = vec![kind.to_owned(), format!("+{more} more")];
    row.resize(cols, String::new());
    row
}

/// Our own static text in a table cell: empty stays empty.
fn static_cell(s: &str) -> String {
    if s.is_empty() {
        String::new()
    } else {
        cell(s)
    }
}

fn entropy_text(e: Option<f64>) -> String {
    e.map_or_else(|| "-".to_owned(), |e| format!("{e:.3}"))
}

fn risk_text(level: RiskLevel) -> &'static str {
    match level {
        RiskLevel::CleanLooking => "CLEAN-LOOKING",
        RiskLevel::Low => "LOW",
        RiskLevel::Medium => "MEDIUM",
        RiskLevel::High => "HIGH",
    }
}

fn severity_text(s: Severity) -> &'static str {
    match s {
        Severity::Info => "INFO",
        Severity::Low => "LOW",
        Severity::Medium => "MEDIUM",
        Severity::High => "HIGH",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use pulldown_cmark::{Event, Options, Parser, Tag, TagEnd};
    use rtriage_core::report::{
        PeSignatureFacts, RiskFloor, SignatureStatus, YaraFacts, YaraMatch, YaraStringMatch,
    };
    use rtriage_core::{
        Category, Confidence, Config, Evidence, Finding, Input, Registry, RiskLevel, Severity,
    };

    use super::*;
    use crate::output::prepare;

    const OPTS: MdOptions = MdOptions {
        explain: false,
        all_strings: false,
        defang: true,
    };

    /// Unique tokens: none of them may reach the page outside a code span.
    const TOKENS: [&str; 14] = [
        "octocat",
        "4242",
        "e.ru",
        "lnk7",
        "img7",
        "details7",
        "javascript",
        "alert7",
        "lt;",
        "bold7",
        "ital7",
        "end7",
        "auto7",
        "pipe7",
    ];
    const HOSTILE: &str = "@octocat #4242 [lnk7](http://e.ru/) ![img7](http://e.ru/p.png) \
        <img src=x> <details7> <http://auto7.e.ru> javascript:alert7(1) &lt; *bold7* _ital7_ \
        ` pipe7|x \n end7";

    fn options() -> Options {
        Options::ENABLE_TABLES
            | Options::ENABLE_STRIKETHROUGH
            | Options::ENABLE_FOOTNOTES
            | Options::ENABLE_TASKLISTS
    }

    fn analyze(name: &str, bytes: Vec<u8>) -> Report {
        let input = Input::from_bytes(name, bytes);
        let mut report = Registry::default().analyze(&input, &Config::default());
        prepare(&mut report, false, Severity::Info);
        report
    }

    fn pe_report() -> Report {
        use rtriage_fixtures::pe::{Arch, Checksum, PeBuilder};
        let built = PeBuilder::minimal(Arch::X64)
            .timestamp(0)
            .checksum(Checksum::Value(0x1234))
            .import("KERNEL32.dll", &["LoadLibraryA", "GetProcAddress"])
            .import_ordinals("WS2_32.dll", &[23])
            .build();
        analyze("sample.exe", built.bytes)
    }

    fn elf_report() -> Report {
        use rtriage_fixtures::elf::ElfBuilder;
        let built = ElfBuilder::x86_64()
            .interp("/tmp/.x/ld-linux-x86-64.so.2")
            .needed("libc.so.6")
            .imports(&["puts"])
            .build();
        analyze("implant", built.bytes)
    }

    fn upx_report() -> Report {
        use rtriage_fixtures::pe::{profiles, Arch};
        let built = profiles::upx_like(Arch::X86)
            .tls_callbacks(1)
            .pdb_path(r"C:\Users\dev\proj\Release\tool.pdb")
            .overlay(b"PK\x03\x04 appended archive".to_vec())
            .build();
        analyze("packed.exe", built.bytes)
    }

    fn signed_dll_report() -> Report {
        use rtriage_fixtures::pe::{Arch, ExportSpec, PeBuilder, ResourceSpec};
        let built = PeBuilder::minimal(Arch::X64)
            .dll(true)
            .rich_header(&[(0x0104, 30_795, 12)])
            .import("KERNEL32.dll", &["ExitProcess"])
            .exports(
                "helper.dll",
                vec![
                    ExportSpec::named("Init"),
                    ExportSpec::forward("OpenFile", "KERNEL32.CreateFileW"),
                ],
            )
            .resource(ResourceSpec::new(24, 2, b"<assembly/>".to_vec()))
            .tls_callbacks(1)
            .pdb_path(r"C:\x\y.pdb")
            .overlay(b"PK\x03\x04 tail".to_vec())
            .build();
        analyze("helper.dll", built.bytes)
    }

    fn text_report() -> Report {
        let mut data = b"\x00\x00http://c2.example.ru/gate.php\x00".to_vec();
        data.extend(b"\x00Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00");
        data.extend((0..8192).map(|i| (i % 256) as u8));
        data.extend(vec![0u8; 4096]);
        data.extend(b"\x00just some text\x00");
        let mut report = analyze("sample.bin", data);
        report.findings.push(
            Finding::new(
                "TEST-FINDING",
                Severity::High,
                Category::Injection,
                "Example finding",
            )
            .confidence(Confidence::High)
            .detail("Shown to check the layout.")
            .evidence(Evidence::Section {
                index: 1,
                name: ".text".into(),
            })
            .evidence(Evidence::Metric {
                name: "entropy",
                value: 7.91234,
            })
            .attack("T1055"),
        );
        report
    }

    fn hostile_finding() -> Finding {
        Finding::new("TEST-HOSTILE", Severity::High, Category::Anomaly, HOSTILE)
            .detail(HOSTILE)
            .evidence(Evidence::Section {
                index: 1,
                name: HOSTILE.into(),
            })
            .evidence(Evidence::Import {
                library: Some(HOSTILE.into()),
                symbol: HOSTILE.into(),
            })
            .evidence(Evidence::Import {
                library: None,
                symbol: HOSTILE.into(),
            })
            .evidence(Evidence::String {
                offset: 0x40,
                encoding: rtriage_core::report::StringEncoding::Ascii,
                value: HOSTILE.into(),
            })
            .evidence(Evidence::Field {
                name: "pdb",
                value: HOSTILE.into(),
            })
    }

    fn hostile_yara() -> YaraFacts {
        YaraFacts {
            rules_loaded: 1,
            matches: vec![YaraMatch {
                rule: HOSTILE.into(),
                namespace: HOSTILE.into(),
                tags: vec![HOSTILE.into(), HOSTILE.into()],
                meta: vec![(HOSTILE.into(), HOSTILE.into())],
                strings: vec![YaraStringMatch {
                    id: HOSTILE.into(),
                    offset: 0,
                    len: 1,
                }],
            }],
            limit_reached: false,
        }
    }

    /// Every file-derived string of a PE report replaced by [`HOSTILE`].
    fn hostile_pe() -> Report {
        let mut r = signed_dll_report();
        r.file.path = HOSTILE.into();
        r.findings.push(hostile_finding());
        r.risk.floor = Some(RiskFloor {
            level: RiskLevel::High,
            finding: "TEST-HOSTILE",
            title: HOSTILE.into(),
        });
        r.facts.yara = Some(hostile_yara());
        let pe = r.facts.pe.as_mut().unwrap();
        let h = pe.headers.as_mut().unwrap();
        h.machine = HOSTILE.into();
        h.subsystem = HOSTILE.into();
        h.timestamp.utc = Some(HOSTILE.into());
        if let Some(s) = h.entry_point.as_mut().and_then(|e| e.section.as_mut()) {
            s.name = HOSTILE.into();
        }
        for s in pe.sections.iter_mut().flatten() {
            s.name = HOSTILE.into();
            s.permissions = HOSTILE.into();
        }
        for lib in &mut pe.imports.as_mut().unwrap().libraries {
            lib.name = HOSTILE.into();
            for f in &mut lib.functions {
                f.name = Some(HOSTILE.into());
            }
        }
        pe.imports.as_mut().unwrap().imphash = Some(HOSTILE.into());
        let ex = pe.exports.as_mut().unwrap();
        ex.dll_name = Some(HOSTILE.into());
        for x in &mut ex.exports {
            x.name = Some(HOSTILE.into());
            x.forwarder = Some(HOSTILE.into());
        }
        for e in &mut pe.resources.as_mut().unwrap().entries {
            e.type_name = HOSTILE.into();
            e.name = HOSTILE.into();
        }
        pe.debug.as_mut().unwrap().pdb_path = HOSTILE.into();
        pe.signature = Some(PeSignatureFacts {
            offset: 0,
            size: 0,
            status: SignatureStatus::Malformed,
            certificates: vec![],
            problems: vec![HOSTILE.into()],
        });
        hostile_strings_and_iocs(&mut r);
        r
    }

    fn hostile_strings_and_iocs(r: &mut Report) {
        let data = format!("\x00{HOSTILE} http://e.ru/x\x00");
        let other = analyze("x", data.into_bytes());
        r.facts.strings = other.facts.strings.clone();
        if let Some(s) = r.facts.strings.as_mut() {
            for item in &mut s.items {
                item.value = HOSTILE.into();
            }
        }
        r.facts.iocs = other.facts.iocs.clone();
        if let Some(i) = r.facts.iocs.as_mut() {
            assert!(!i.items.is_empty());
            for item in &mut i.items {
                item.value = HOSTILE.into();
                item.value_defanged = HOSTILE.into();
            }
        }
    }

    /// Every file-derived string of an ELF report replaced by [`HOSTILE`].
    fn hostile_elf() -> Report {
        let mut r = elf_report();
        r.file.path = HOSTILE.into();
        r.findings.push(hostile_finding());
        let elf = r.facts.elf.as_mut().unwrap();
        let h = elf.headers.as_mut().unwrap();
        h.machine = HOSTILE.into();
        h.os_abi = HOSTILE.into();
        h.interpreter = Some(HOSTILE.into());
        for s in elf.segments.iter_mut().flatten() {
            s.kind = HOSTILE.into();
            s.permissions = HOSTILE.into();
        }
        for s in elf.sections.iter_mut().flatten() {
            s.name = HOSTILE.into();
            s.kind = HOSTILE.into();
        }
        elf.section_problems = Some(vec![HOSTILE.into()]);
        let d = elf.dynamic.as_mut().unwrap();
        d.needed = vec![HOSTILE.into()];
        d.rpath = Some(HOSTILE.into());
        d.runpath = Some(HOSTILE.into());
        d.imports = vec![HOSTILE.into()];
        hostile_strings_and_iocs(&mut r);
        r
    }

    /// Text and code events, failing on anything that is not plain structure.
    fn check_safe(md: &str) {
        let mut code = String::new();
        for ev in Parser::new_ext(md, options()) {
            match &ev {
                Event::Start(Tag::Link { .. } | Tag::Image { .. } | Tag::HtmlBlock)
                | Event::Html(_)
                | Event::InlineHtml(_)
                | Event::FootnoteReference(_)
                | Event::TaskListMarker(_) => panic!("unsafe event {ev:?} in\n{md}"),
                Event::Text(t) => {
                    for tok in TOKENS {
                        assert!(!t.contains(tok), "{tok:?} outside code: {t:?}\n{md}");
                    }
                    assert!(!t.contains('`') && !t.contains('|'), "{t:?}\n{md}");
                    assert_no_reference(t);
                }
                Event::Code(c) => code.push_str(c),
                _ => {}
            }
        }
        for tok in TOKENS {
            assert!(code.contains(tok), "{tok:?} missing from code spans\n{md}");
        }
    }

    /// No `@name` mention or `#123` reference in text GitHub would link.
    fn assert_no_reference(t: &str) {
        let chars: Vec<char> = t.chars().collect();
        for w in chars.windows(2) {
            let bad =
                (w[0] == '@' && w[1].is_alphanumeric()) || (w[0] == '#' && w[1].is_ascii_digit());
            assert!(!bad, "reference-like text {t:?}");
        }
    }

    /// Every table row has as many cells as the header.
    fn check_tables(md: &str) -> usize {
        let mut tables = 0;
        let mut header = None;
        let mut cells = 0;
        for ev in Parser::new_ext(md, options()) {
            match ev {
                Event::Start(Tag::Table(_)) => {
                    tables += 1;
                    header = None;
                }
                Event::Start(Tag::TableHead | Tag::TableRow) => cells = 0,
                Event::Start(Tag::TableCell) => cells += 1,
                Event::End(TagEnd::TableHead) => header = Some(cells),
                Event::End(TagEnd::TableRow) => {
                    assert_eq!(Some(cells), header, "row width differs\n{md}");
                }
                _ => {}
            }
        }
        tables
    }

    #[test]
    fn md_pe() {
        insta::assert_snapshot!(render_report(&pe_report(), OPTS));
    }

    #[test]
    fn md_elf() {
        insta::assert_snapshot!(render_report(&elf_report(), OPTS));
    }

    #[test]
    fn md_explain() {
        let opts = MdOptions {
            explain: true,
            ..OPTS
        };
        insta::assert_snapshot!(render_report(&upx_report(), opts));
    }

    #[test]
    fn md_plain_text_file() {
        insta::assert_snapshot!(render_report(&text_report(), OPTS));
    }

    #[test]
    fn md_signed_dll() {
        insta::assert_snapshot!(render_report(&signed_dll_report(), OPTS));
    }

    #[test]
    fn defang_is_on_by_default_and_off_with_no_defang() {
        let r = text_report();
        let on = render_report(&r, OPTS);
        assert!(on.contains("hxxp://c2[.]example[.]ru/gate.php"), "{on}");
        assert!(!on.contains("http://c2.example.ru"), "{on}");
        let off = render_report(
            &r,
            MdOptions {
                defang: false,
                ..OPTS
            },
        );
        assert!(off.contains("`http://c2.example.ru/gate.php`"), "{off}");
        check_safe_structure(&off);
    }

    /// Like [`check_safe`] without the token checks (for ordinary input).
    fn check_safe_structure(md: &str) {
        for ev in Parser::new_ext(md, options()) {
            match &ev {
                Event::Start(Tag::Link { .. } | Tag::Image { .. } | Tag::HtmlBlock)
                | Event::Html(_)
                | Event::InlineHtml(_)
                | Event::FootnoteReference(_)
                | Event::TaskListMarker(_) => panic!("unsafe event {ev:?} in\n{md}"),
                Event::Text(t) => assert_no_reference(t),
                _ => {}
            }
        }
    }

    #[test]
    fn hostile_fields_only_in_code_events() {
        for r in [hostile_pe(), hostile_elf()] {
            for (explain, all_strings, defang) in [(true, false, true), (true, true, false)] {
                let md = render_report(
                    &r,
                    MdOptions {
                        explain,
                        all_strings,
                        defang,
                    },
                );
                check_safe(&md);
            }
        }
    }

    #[test]
    fn ordinary_reports_are_safe() {
        for r in [
            pe_report(),
            elf_report(),
            upx_report(),
            signed_dll_report(),
            text_report(),
        ] {
            let md = render_report(
                &r,
                MdOptions {
                    explain: true,
                    ..OPTS
                },
            );
            check_safe_structure(&md);
        }
    }

    #[test]
    fn tables_keep_their_columns() {
        for r in [
            hostile_pe(),
            hostile_elf(),
            signed_dll_report(),
            upx_report(),
        ] {
            let md = render_report(
                &r,
                MdOptions {
                    explain: true,
                    all_strings: true,
                    defang: true,
                },
            );
            assert!(check_tables(&md) >= 3, "{md}");
        }
    }

    fn row(path: &str, level: RiskLevel, score: u32) -> crate::worker::Summary {
        crate::worker::Summary {
            path: path.into(),
            format: rtriage_core::Format::Pe,
            size: 48_128,
            score,
            level,
            top_finding: Some(crate::worker::TopFinding {
                id: "PE-SECTION-RWX".into(),
                title: "Writable and executable section".into(),
                severity: Severity::Medium,
            }),
            packed: false,
            partial: false,
            errors: 0,
        }
    }

    fn scan_rows() -> Vec<crate::worker::Summary> {
        let mut packed = row("dir/packed.exe", RiskLevel::Medium, 40);
        packed.packed = true;
        packed.partial = true;
        let mut clean = row("dir/clean.bin", RiskLevel::CleanLooking, 0);
        clean.top_finding = None;
        clean.format = rtriage_core::Format::Unknown;
        clean.size = 12;
        vec![row("dir/a.exe", RiskLevel::High, 66), packed, clean]
    }

    #[test]
    fn md_scan() {
        insta::assert_snapshot!(render_scan_table(&scan_rows(), 1));
    }

    #[test]
    fn scan_md_table_keeps_caller_order_with_ranks() {
        let md = render_scan_table(&scan_rows(), 0);
        let a = md.find("| 1 | HIGH | 66 |").unwrap();
        let p = md.find("| 2 | MEDIUM | 40 |").unwrap();
        let c = md.find("| 3 | CLEAN-LOOKING | 0 |").unwrap();
        assert!(a < p && p < c, "{md}");
        assert!(
            md.contains("3 file(s): 1 high, 1 medium, 0 low, 1 clean-looking."),
            "{md}"
        );
        assert!(render_scan_table(&[], 0).contains("_No files analyzed._"));
    }

    #[test]
    fn scan_md_hostile_file_names_keep_rows() {
        let mut rows = scan_rows();
        for r in &mut rows {
            r.path = HOSTILE.into();
            if let Some(t) = r.top_finding.as_mut() {
                t.title = HOSTILE.into();
            }
        }
        let md = render_scan_table(&rows, 2);
        check_safe(&md);
        assert_eq!(check_tables(&md), 1, "{md}");
    }

    #[test]
    fn finding_detail_is_kept_up_to_detail_limit() {
        let mut r = pe_report();
        let long = "d".repeat(600);
        let huge = "h".repeat(DETAIL_LIMIT + 50);
        for detail in [&long, &huge] {
            r.findings.push(
                Finding::new("TEST-LONG", Severity::Low, Category::Anomaly, "t").detail(detail),
            );
        }
        let md = render_report(&r, OPTS);
        assert!(md.contains(&format!("`{long}`\n")), "{md}");
        assert!(md.contains(&format!(
            "`{}` … [{} chars total]",
            "h".repeat(DETAIL_LIMIT),
            DETAIL_LIMIT + 50
        )));
    }

    #[test]
    fn file_name_with_pipe_and_backticks_in_heading() {
        let mut r = pe_report();
        r.file.path = "a|b``c`.exe".into();
        let md = render_report(&r, OPTS);
        assert!(md.starts_with("## "), "{md}");
        let mut in_heading = false;
        let mut seen = Vec::new();
        for ev in Parser::new_ext(&md, options()) {
            match ev {
                Event::Start(Tag::Heading { level, .. }) => {
                    in_heading = level == pulldown_cmark::HeadingLevel::H2
                }
                Event::End(TagEnd::Heading(_)) if in_heading => break,
                e if in_heading => seen.push(e),
                _ => {}
            }
        }
        assert_eq!(seen, vec![Event::Code("a|b``c`.exe".into())], "{md}");
    }
}

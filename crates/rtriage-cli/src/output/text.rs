//! Human-readable terminal renderer.
//!
//! Every value that comes from the input file (path, strings, section names,
//! evidence) goes through [`sanitize`]. Color is decorative only: risk and
//! severity are always spelled out as text too.

use std::collections::BTreeMap;
use std::io::{self, Write};

use anstyle::{AnsiColor, Style};
use rtriage_core::report::{
    AnalysisLimit, ElfFacts, ElfHeaderFacts, PeExportsFacts, PeResourcesFacts, Reduction,
    SignatureStatus,
};
use rtriage_core::report::{
    EntropyFacts, ExtractedString, PeImportsFacts, PeSectionFacts, StringEncoding, StringKind,
    StringsFacts,
};
use rtriage_core::{
    Evidence, Finding, Format, PeFacts, PeHeaderFacts, Report, Risk, RiskLevel, Severity,
};
use serde::Serialize;

use super::{Failure, Run};
use crate::sanitize::sanitize;

/// Classified strings shown per kind before collapsing into "+N more".
const STRINGS_PER_KIND: usize = 20;
/// Characters of a string value shown before it is shortened.
const MAX_VALUE_CHARS: usize = 120;
const RULE: &str = "------------------------------------------------------------------------";

/// Rendering options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TextOptions {
    /// Emit ANSI styles (the caller strips them for non-terminals).
    pub color: bool,
    /// List every string instead of capping classified ones per kind.
    pub all_strings: bool,
    /// Print the score breakdown.
    pub explain: bool,
}

/// Writes `run` as text.
pub fn render(run: &Run, out: &mut dyn Write, opts: TextOptions) -> io::Result<()> {
    let p = Painter { color: opts.color };
    for (i, report) in run.reports.iter().enumerate() {
        if i > 0 {
            writeln!(out, "\n{RULE}\n")?;
        }
        render_report(report, out, &p, opts)?;
    }
    render_failures(&run.failures, out, &p, !run.reports.is_empty())
}

fn render_report(
    r: &Report,
    out: &mut dyn Write,
    p: &Painter,
    opts: TextOptions,
) -> io::Result<()> {
    render_header(r, out, p)?;
    render_findings(&r.findings, out, p)?;
    if opts.explain {
        render_explain(&r.risk, out, p)?;
    }
    if let Some(h) = r.facts.pe.as_ref().and_then(|pe| pe.headers.as_ref()) {
        render_pe_headers(h, out, p)?;
    }
    if let Some(pe) = &r.facts.pe {
        render_pe_extras(pe, out)?;
    }
    if let Some(h) = r.facts.elf.as_ref().and_then(|e| e.headers.as_ref()) {
        render_elf_headers(h, out, p)?;
    }
    if let Some(elf) = &r.facts.elf {
        render_elf_layout(elf, out, p)?;
    }
    if let Some(s) = r.facts.pe.as_ref().and_then(|pe| pe.sections.as_deref()) {
        render_pe_sections(s, out, p)?;
    }
    if let Some(i) = r.facts.pe.as_ref().and_then(|pe| pe.imports.as_ref()) {
        render_pe_imports(i, out, p)?;
    }
    if let Some(e) = r.facts.pe.as_ref().and_then(|pe| pe.exports.as_ref()) {
        render_pe_exports(e, out, p)?;
    }
    if let Some(res) = r.facts.pe.as_ref().and_then(|pe| pe.resources.as_ref()) {
        render_pe_resources(res, out, p)?;
    }
    if let Some(e) = &r.facts.entropy {
        render_entropy(e, out, p)?;
    }
    if let Some(s) = &r.facts.strings {
        render_strings(s, out, p, opts.all_strings)?;
    }
    if !r.errors.is_empty() {
        writeln!(out, "\n{}", p.heading("Analyzer errors"))?;
        for e in &r.errors {
            writeln!(out, "  {}: {}", e.analyzer, sanitize(&e.error.to_string()))?;
        }
    }
    Ok(())
}

fn render_header(r: &Report, out: &mut dyn Write, p: &Painter) -> io::Result<()> {
    let f = &r.file;
    writeln!(out, "{}", p.paint(Style::new().bold(), &sanitize(&f.path)))?;
    writeln!(
        out,
        "  {}  {:<26} {}  {}",
        p.label("Type   "),
        format_name(f.format),
        p.label("Size"),
        human_size(f.size)
    )?;
    if let Some(h) = &f.hashes {
        writeln!(out, "  {}  {}", p.label("MD5    "), h.md5)?;
        writeln!(out, "  {}  {}", p.label("SHA-1  "), h.sha1)?;
        writeln!(out, "  {}  {}", p.label("SHA-256"), h.sha256)?;
    }
    let (text, color) = risk_badge(r.risk.level);
    let limited = if r.analysis_limited.contains(&AnalysisLimit::Packed) {
        format!(
            "  {}",
            p.paint(
                Style::new()
                    .bold()
                    .fg_color(Some(AnsiColor::Magenta.into())),
                "[PACKED: analysis limited]"
            )
        )
    } else {
        String::new()
    };
    writeln!(
        out,
        "  {}  {} score {}{limited}",
        p.label("Risk   "),
        p.paint(
            Style::new().bold().fg_color(Some(color.into())),
            &format!("[{text}]")
        ),
        r.risk.score
    )
}

fn render_explain(risk: &Risk, out: &mut dyn Write, p: &Painter) -> io::Result<()> {
    writeln!(
        out,
        "\n{}  score {} = sum of points below; level {}",
        p.heading("Score breakdown"),
        risk.score,
        enum_name(&risk.level)
    )?;
    if risk.breakdown.is_empty() {
        return writeln!(out, "  (no findings)");
    }
    writeln!(
        out,
        "  {:>6}  {:<32} {:<18} note",
        "points", "finding", "category"
    )?;
    for e in &risk.breakdown {
        let note = match &e.reduced_by {
            None if e.table_points == 0 => "informational".to_owned(),
            None => String::new(),
            Some(Reduction::Suppressed { by, packer }) => {
                format!("explained by {packer} ({by}), not scored")
            }
            Some(Reduction::Duplicate) => "duplicate ID, counted once".to_owned(),
            Some(Reduction::CategoryCap { cap }) => {
                format!(
                    "of {}; {} cap {cap} reached",
                    e.table_points,
                    enum_name(&e.category)
                )
            }
            Some(Reduction::LowSeverityCap { cap }) => {
                format!("of {}; low-severity cap {cap} reached", e.table_points)
            }
            Some(_) => "reduced".to_owned(),
        };
        writeln!(
            out,
            "  {:>6}  {:<32} {:<18} {note}",
            format!("+{}", e.points),
            e.id,
            enum_name(&e.category)
        )?;
    }
    Ok(())
}

fn render_findings(findings: &[Finding], out: &mut dyn Write, p: &Painter) -> io::Result<()> {
    writeln!(out, "\n{}", p.heading("Findings"))?;
    if findings.is_empty() {
        return writeln!(out, "  (none)");
    }
    for f in findings {
        let (text, color) = severity_badge(f.severity);
        writeln!(
            out,
            "  {} {}  {}  (confidence: {}, {})",
            p.paint(
                Style::new().bold().fg_color(Some(color.into())),
                &format!("[{text}]")
            ),
            f.id,
            sanitize(&f.title),
            enum_name(&f.confidence),
            enum_name(&f.category),
        )?;
        if !f.detail.is_empty() {
            writeln!(out, "      {}", sanitize(&f.detail))?;
        }
        for e in &f.evidence {
            writeln!(out, "      - {}", evidence(e))?;
        }
        if !f.attack.is_empty() {
            writeln!(out, "      ATT&CK: {}", f.attack.join(", "))?;
        }
        if let Some(s) = &f.suppressed {
            writeln!(
                out,
                "      {}",
                p.label(&format!(
                    "(explained by {} via {}: not scored)",
                    s.packer, s.by
                ))
            )?;
        }
    }
    Ok(())
}

fn render_entropy(e: &EntropyFacts, out: &mut dyn Write, p: &Painter) -> io::Result<()> {
    writeln!(out, "\n{}", p.heading("Entropy"))?;
    writeln!(out, "  Whole file  {:.3} bits/byte", e.whole_file)?;
    if e.high_regions.is_empty() {
        return writeln!(
            out,
            "  No high-entropy regions (>= {:.2}, window {})",
            e.high_threshold, e.window
        );
    }
    writeln!(
        out,
        "  High-entropy regions (>= {:.2}, window {}):",
        e.high_threshold, e.window
    )?;
    for r in &e.high_regions {
        writeln!(
            out,
            "    0x{:08x}..0x{:08x}  {:>10}  {:.3}",
            r.offset,
            r.offset.saturating_add(r.len),
            short_size(r.len),
            r.entropy
        )?;
    }
    Ok(())
}

fn render_strings(s: &StringsFacts, out: &mut dyn Write, p: &Painter, all: bool) -> io::Result<()> {
    let classified = s.items.iter().filter(|i| !i.kinds.is_empty()).count();
    writeln!(
        out,
        "\n{}  {} found (ASCII + UTF-16LE, min {}), {} classified{}",
        p.heading("Strings"),
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
    )?;

    if all {
        for item in &s.items {
            let kinds = item
                .kinds
                .iter()
                .map(enum_name)
                .collect::<Vec<_>>()
                .join(",");
            string_line(out, if kinds.is_empty() { "-" } else { &kinds }, item)?;
        }
        return Ok(());
    }

    // Group by primary (first) kind; each string is listed once.
    let mut groups: BTreeMap<StringKind, Vec<&ExtractedString>> = BTreeMap::new();
    for item in &s.items {
        if let Some(&k) = item.kinds.first() {
            groups.entry(k).or_default().push(item);
        }
    }
    if groups.is_empty() {
        return writeln!(
            out,
            "  (no classified strings; use --all-strings to list all)"
        );
    }
    for (kind, items) in &groups {
        let name = enum_name(kind);
        for item in items.iter().take(STRINGS_PER_KIND) {
            string_line(out, &name, item)?;
        }
        if items.len() > STRINGS_PER_KIND {
            writeln!(
                out,
                "  {:<18} +{} more",
                name,
                items.len() - STRINGS_PER_KIND
            )?;
        }
    }
    Ok(())
}

fn string_line(out: &mut dyn Write, kind: &str, s: &ExtractedString) -> io::Result<()> {
    let enc = match s.encoding {
        StringEncoding::Ascii => 'A',
        StringEncoding::Utf16Le => 'W',
    };
    writeln!(
        out,
        "  {:<18} 0x{:08x}  {}  {}",
        kind,
        s.offset,
        enc,
        shorten(&s.value, s.len)
    )
}

fn render_failures(
    failures: &[Failure],
    out: &mut dyn Write,
    p: &Painter,
    after_reports: bool,
) -> io::Result<()> {
    if failures.is_empty() {
        return Ok(());
    }
    if after_reports {
        writeln!(out, "\n{RULE}")?;
    }
    writeln!(out, "\n{}", p.heading("Failed"))?;
    for f in failures {
        writeln!(out, "  {}: {}", sanitize(&f.path), sanitize(&f.error))?;
    }
    Ok(())
}

// ---------------------------------------------------------------- helpers

/// Applies styles only when color is enabled.
struct Painter {
    color: bool,
}

impl Painter {
    fn paint(&self, style: Style, text: &str) -> String {
        if self.color {
            format!("{}{text}{}", style.render(), style.render_reset())
        } else {
            text.to_owned()
        }
    }

    fn heading(&self, text: &str) -> String {
        self.paint(Style::new().bold().underline(), text)
    }

    fn label(&self, text: &str) -> String {
        self.paint(Style::new().dimmed(), text)
    }
}

fn risk_badge(level: RiskLevel) -> (&'static str, AnsiColor) {
    match level {
        RiskLevel::CleanLooking => ("CLEAN-LOOKING", AnsiColor::Green),
        RiskLevel::Low => ("LOW", AnsiColor::Cyan),
        RiskLevel::Medium => ("MEDIUM", AnsiColor::Yellow),
        RiskLevel::High => ("HIGH", AnsiColor::Red),
    }
}

fn severity_badge(s: Severity) -> (&'static str, AnsiColor) {
    match s {
        Severity::Info => ("INFO", AnsiColor::Blue),
        Severity::Low => ("LOW", AnsiColor::Cyan),
        Severity::Medium => ("MEDIUM", AnsiColor::Yellow),
        Severity::High => ("HIGH", AnsiColor::Red),
    }
}

fn render_pe_headers(h: &PeHeaderFacts, out: &mut dyn Write, p: &Painter) -> io::Result<()> {
    writeln!(out, "\n{}", p.heading("PE"))?;
    writeln!(
        out,
        "  Machine      {} ({}-bit), {}, {}",
        h.machine,
        h.bits,
        enum_name(&h.kind),
        h.subsystem
    )?;
    if h.managed_dotnet {
        writeln!(out, "  Managed      .NET assembly (CLR header present)")?;
    }
    match &h.entry_point {
        Some(ep) => match &ep.section {
            Some(s) => writeln!(
                out,
                "  Entry point  0x{:08x} in #{} \"{}\"",
                ep.rva,
                s.index,
                sanitize(&s.name)
            )?,
            None => writeln!(
                out,
                "  Entry point  0x{:08x} (outside all sections)",
                ep.rva
            )?,
        },
        None => writeln!(out, "  Entry point  none (AddressOfEntryPoint = 0)")?,
    }
    writeln!(out, "  Image base   0x{:x}", h.image_base)?;
    match &h.timestamp.utc {
        Some(utc) => writeln!(out, "  Timestamp    0x{:08x} ({utc})", h.timestamp.raw)?,
        None => writeln!(out, "  Timestamp    0 (cleared)")?,
    }
    let c = &h.checksum;
    let state = if c.stored == 0 {
        "not set"
    } else if c.stored == c.computed {
        "valid"
    } else {
        "MISMATCH"
    };
    writeln!(
        out,
        "  Checksum     0x{:08x} ({state}; computed 0x{:08x})",
        c.stored, c.computed
    )?;
    if !h.dll_characteristics.is_empty() {
        writeln!(out, "  DLL flags    {}", h.dll_characteristics.join(", "))?;
    }
    Ok(())
}

fn render_pe_sections(
    sections: &[PeSectionFacts],
    out: &mut dyn Write,
    p: &Painter,
) -> io::Result<()> {
    writeln!(out, "\n{}", p.heading("Sections"))?;
    if sections.is_empty() {
        return writeln!(out, "  (none)");
    }
    writeln!(
        out,
        "  {:>3}  {:<10} {:>10} {:>10} {:>10}  {:<4} {:>7}",
        "#", "Name", "VirtAddr", "VirtSize", "RawSize", "Perm", "Entropy"
    )?;
    for s in sections {
        let entropy = s
            .entropy
            .map_or_else(|| "-".to_owned(), |e| format!("{e:.3}"));
        let note = if s.raw_truncated {
            "  (raw data past EOF)"
        } else {
            ""
        };
        writeln!(
            out,
            "  {:>3}  {:<10} {:>10} {:>10} {:>10}  {:<4} {:>7}{note}",
            s.index,
            sanitize(&s.name),
            format!("0x{:x}", s.virtual_address),
            format!("0x{:x}", s.virtual_size),
            format!("0x{:x}", s.raw_size),
            s.permissions,
            entropy,
        )?;
    }
    Ok(())
}

/// Packer, overlay, TLS and PDB lines, appended to the PE block.
fn render_pe_extras(pe: &PeFacts, out: &mut dyn Write) -> io::Result<()> {
    for packer in pe.packers.iter().flatten() {
        writeln!(
            out,
            "  Packer       {} ({})",
            packer.name,
            packer.indicators.join(", ")
        )?;
    }
    if let Some(o) = &pe.overlay {
        let entropy = o
            .entropy
            .map_or_else(String::new, |e| format!(", entropy {e:.3}"));
        writeln!(
            out,
            "  Overlay      0x{:x}, {}, {}{entropy}",
            o.offset,
            short_size(o.size),
            o.kind.unwrap_or("unknown format")
        )?;
    }
    if let Some(t) = pe.tls.as_ref().filter(|t| !t.callbacks.is_empty()) {
        let list: Vec<String> = t
            .callbacks
            .iter()
            .map(|c| format!("0x{:x}", c.va))
            .collect();
        writeln!(
            out,
            "  TLS          {} callback(s): {}{}",
            t.callbacks.len(),
            list.join(", "),
            if t.limit_reached { " (truncated)" } else { "" }
        )?;
    }
    if let Some(d) = &pe.debug {
        writeln!(out, "  PDB          {}", sanitize(&d.pdb_path))?;
    }
    if let Some(r) = &pe.rich {
        writeln!(
            out,
            "  Rich         {} records, checksum {}",
            r.entries.len(),
            if r.checksum_valid {
                "valid".to_owned()
            } else {
                format!(
                    "INVALID (stored 0x{:08x}, computed 0x{:08x})",
                    r.key, r.computed_checksum
                )
            }
        )?;
    }
    if let Some(s) = &pe.signature {
        match s.status {
            SignatureStatus::SignedUnverified => writeln!(
                out,
                "  Signature    signed (unverified), {} certificate entr{}",
                s.certificates.len(),
                if s.certificates.len() == 1 {
                    "y"
                } else {
                    "ies"
                }
            )?,
            _ => writeln!(
                out,
                "  Signature    MALFORMED: {}",
                sanitize(&s.problems.join("; "))
            )?,
        }
    }
    Ok(())
}

fn render_elf_headers(h: &ElfHeaderFacts, out: &mut dyn Write, p: &Painter) -> io::Result<()> {
    writeln!(out, "\n{}", p.heading("ELF"))?;
    writeln!(
        out,
        "  Machine      {} ({}-bit, {}-endian), {}, OS/ABI {}",
        h.machine, h.bits, h.endianness, h.kind, h.os_abi
    )?;
    match &h.entry_point {
        Some(e) => match e.segment {
            Some(i) => writeln!(out, "  Entry point  0x{:x} in segment #{i}", e.vaddr)?,
            None => writeln!(out, "  Entry point  0x{:x} (outside all PT_LOAD)", e.vaddr)?,
        },
        None => writeln!(out, "  Entry point  none (e_entry = 0)")?,
    }
    match &h.interpreter {
        Some(i) => writeln!(out, "  Interpreter  {}", sanitize(i))?,
        None => writeln!(out, "  Interpreter  none (static or library)")?,
    }
    writeln!(
        out,
        "  Headers      {} segments, {} sections",
        h.number_of_segments, h.number_of_sections
    )
}

/// ELF sections listed before "+N more".
const ELF_SECTIONS_SHOWN: usize = 40;

fn render_elf_layout(elf: &ElfFacts, out: &mut dyn Write, p: &Painter) -> io::Result<()> {
    if let Some(segs) = &elf.segments {
        writeln!(out, "\n{}", p.heading("Segments"))?;
        writeln!(
            out,
            "  {:>3}  {:<13} {:<4} {:>10} {:>18} {:>10} {:>10} {:>7}",
            "#", "Type", "Perm", "Offset", "VirtAddr", "FileSize", "MemSize", "Entropy"
        )?;
        for s in segs {
            let entropy = s
                .entropy
                .map_or_else(|| "-".to_owned(), |e| format!("{e:.3}"));
            let note = if s.truncated { "  (past EOF)" } else { "" };
            writeln!(
                out,
                "  {:>3}  {:<13} {:<4} {:>10} {:>18} {:>10} {:>10} {:>7}{note}",
                s.index,
                s.kind,
                s.permissions,
                format!("0x{:x}", s.offset),
                format!("0x{:x}", s.vaddr),
                format!("0x{:x}", s.filesz),
                format!("0x{:x}", s.memsz),
                entropy
            )?;
        }
    }
    if let Some(secs) = &elf.sections {
        if secs.is_empty() {
            writeln!(out, "\n{}  (none)", p.heading("Sections"))?;
        } else {
            writeln!(out, "\n{}  {} entries", p.heading("Sections"), secs.len())?;
            for s in secs.iter().skip(1).take(ELF_SECTIONS_SHOWN) {
                let line = format!(
                    "  {:>3}  {:<20} {:<12} {:>18} {:>10}  {}",
                    s.index,
                    sanitize(&s.name),
                    s.kind,
                    format!("0x{:x}", s.addr),
                    format!("0x{:x}", s.size),
                    s.flags.join(",")
                );
                writeln!(out, "{}", line.trim_end())?;
            }
            if secs.len() > ELF_SECTIONS_SHOWN + 1 {
                writeln!(out, "  +{} more", secs.len() - ELF_SECTIONS_SHOWN - 1)?;
            }
        }
    }
    for problem in elf.section_problems.iter().flatten() {
        writeln!(out, "  ! {}", sanitize(problem))?;
    }
    Ok(())
}

/// Exports listed before "+N more".
const EXPORTS_SHOWN: usize = 20;
/// Resources listed before "+N more".
const RESOURCES_SHOWN: usize = 30;

fn render_pe_exports(e: &PeExportsFacts, out: &mut dyn Write, p: &Painter) -> io::Result<()> {
    let forwarded = e.exports.iter().filter(|x| x.forwarder.is_some()).count();
    writeln!(
        out,
        "\n{}  {}, {} exports ({} forwarded){}",
        p.heading("Exports"),
        e.dll_name
            .as_deref()
            .map_or_else(|| "(no name)".into(), sanitize),
        e.exports.len(),
        forwarded,
        if e.limit_reached {
            ", limit reached"
        } else {
            ""
        }
    )?;
    for x in e.exports.iter().take(EXPORTS_SHOWN) {
        let name = x
            .name
            .as_deref()
            .map_or_else(|| "(ordinal only)".into(), sanitize);
        match &x.forwarder {
            Some(f) => writeln!(out, "  #{:<5} {name} -> {}", x.ordinal, sanitize(f))?,
            None => writeln!(out, "  #{:<5} {name}", x.ordinal)?,
        }
    }
    if e.exports.len() > EXPORTS_SHOWN {
        writeln!(out, "  +{} more", e.exports.len() - EXPORTS_SHOWN)?;
    }
    Ok(())
}

fn render_pe_resources(r: &PeResourcesFacts, out: &mut dyn Write, p: &Painter) -> io::Result<()> {
    writeln!(
        out,
        "\n{}  {} entries{}",
        p.heading("Resources"),
        r.entries.len(),
        if r.limit_reached {
            ", limit reached"
        } else {
            ""
        }
    )?;
    for e in r.entries.iter().take(RESOURCES_SHOWN) {
        let entropy = e
            .entropy
            .map_or_else(|| "      -".to_owned(), |v| format!("{v:>7.3}"));
        let line = format!(
            "  {:<16} {:<10} {:>5} {:>10} {entropy}  {}",
            sanitize(&e.type_name),
            sanitize(&e.name),
            e.lang,
            short_size(u64::from(e.size)),
            e.kind.unwrap_or("")
        );
        writeln!(out, "{}", line.trim_end())?;
    }
    if r.entries.len() > RESOURCES_SHOWN {
        writeln!(out, "  +{} more", r.entries.len() - RESOURCES_SHOWN)?;
    }
    Ok(())
}

/// Functions listed per library before "+N more".
const IMPORTS_PER_LIBRARY: usize = 8;

fn render_pe_imports(i: &PeImportsFacts, out: &mut dyn Write, p: &Painter) -> io::Result<()> {
    write!(
        out,
        "\n{}  {} functions from {} libraries",
        p.heading("Imports"),
        group_digits(i.total_functions),
        i.libraries.len()
    )?;
    if let Some(h) = &i.imphash {
        write!(out, ", imphash {h}")?;
    }
    if i.limit_reached {
        write!(out, " (limit reached, table truncated)")?;
    }
    writeln!(out)?;
    if i.libraries.is_empty() {
        return writeln!(out, "  (no import table)");
    }
    for lib in &i.libraries {
        let shown: Vec<String> = lib
            .functions
            .iter()
            .take(IMPORTS_PER_LIBRARY)
            .map(|f| match (&f.name, f.ordinal) {
                (Some(n), _) => sanitize(n).into_owned(),
                (None, Some(o)) => format!("#{o}"),
                (None, None) => "?".to_owned(),
            })
            .collect();
        let more = lib.functions.len().saturating_sub(IMPORTS_PER_LIBRARY);
        writeln!(
            out,
            "  {:<20} {:>4}  {}{}",
            sanitize(&lib.name),
            lib.functions.len(),
            shown.join(", "),
            if more > 0 {
                format!(", +{more} more")
            } else {
                String::new()
            }
        )?;
    }
    Ok(())
}

fn format_name(f: Format) -> &'static str {
    match f {
        Format::Pe => "PE",
        Format::Elf => "ELF",
        _ => "unknown",
    }
}

fn evidence(e: &Evidence) -> String {
    match e {
        Evidence::Range { offset, len } => format!("range 0x{offset:08x} (+{len} bytes)"),
        Evidence::Section { index, name } => format!("section #{index} \"{}\"", sanitize(name)),
        Evidence::Import { library, symbol } => match library {
            Some(lib) => format!("import {}!{}", sanitize(lib), sanitize(symbol)),
            None => format!("import {}", sanitize(symbol)),
        },
        Evidence::String {
            offset,
            encoding,
            value,
        } => format!(
            "string 0x{offset:08x} {} \"{}\"",
            enum_name(encoding),
            sanitize(value)
        ),
        Evidence::Metric { name, value } => format!("{name} = {value:.3}"),
        Evidence::Field { name, value } => format!("{name} = {}", sanitize(value)),
        _ => "(unsupported evidence type)".to_owned(),
    }
}

/// Same snake_case name as in the JSON output, so text and JSON agree.
fn enum_name<T: Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "?".to_owned())
}

/// Sanitized value, cut to [`MAX_VALUE_CHARS`] with a note of the full length.
fn shorten(value: &str, full_len: u64) -> String {
    let shown: String = value.chars().take(MAX_VALUE_CHARS).collect();
    let cut = full_len > MAX_VALUE_CHARS as u64;
    let clean = sanitize(&shown).into_owned();
    if cut {
        format!("{clean} [... {} chars total]", group_digits(full_len))
    } else {
        clean
    }
}

/// `48128` -> `"48 128 bytes (47.0 KiB)"`.
fn human_size(n: u64) -> String {
    if n < 1024 {
        format!("{} bytes", group_digits(n))
    } else {
        format!("{} bytes ({})", group_digits(n), short_size(n))
    }
}

/// `16384` -> `"16.0 KiB"`.
fn short_size(n: u64) -> String {
    const UNITS: [&str; 4] = ["KiB", "MiB", "GiB", "TiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut value = n as f64 / 1024.0;
    let mut unit = "KiB";
    for next in UNITS.iter().skip(1) {
        if value < 1024.0 {
            break;
        }
        value /= 1024.0;
        unit = next;
    }
    format!("{value:.1} {unit}")
}

/// `1204` -> `"1 204"`.
fn group_digits(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(' ');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::prepare;
    use rtriage_core::{Category, Confidence, Config, Input, Registry};

    fn sample(all_strings: bool) -> Run {
        let mut data = b"\x00\x00http://c2.example.ru/gate.php\x00".to_vec();
        data.extend(b"\x00Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00");
        data.extend((0..8192).map(|i| (i % 256) as u8));
        data.extend(vec![0u8; 4096]);
        data.extend(b"\x00just some text\x00");
        let input = Input::from_bytes("sample.bin", data);
        let mut report = Registry::default().analyze(&input, &Config::default());
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
        prepare(&mut report, all_strings, rtriage_core::Severity::Info);
        Run {
            reports: vec![report],
            failures: vec![Failure {
                path: "missing.bin".into(),
                error: "cannot read missing.bin: not found".into(),
            }],
        }
    }

    fn render_string(run: &Run, opts: TextOptions) -> String {
        let mut buf = Vec::new();
        render(run, &mut buf, opts).unwrap();
        String::from_utf8(buf).unwrap()
    }

    const PLAIN: TextOptions = TextOptions {
        color: false,
        all_strings: false,
        explain: false,
    };

    #[test]
    fn snapshot_plain() {
        insta::assert_snapshot!(render_string(&sample(false), PLAIN));
    }

    #[test]
    fn snapshot_all_strings() {
        insta::assert_snapshot!(render_string(
            &sample(true),
            TextOptions {
                all_strings: true,
                ..PLAIN
            }
        ));
    }

    #[test]
    fn plain_output_has_no_escape_bytes() {
        assert!(!render_string(&sample(false), PLAIN).contains('\x1b'));
    }

    #[test]
    fn color_output_keeps_text_badges() {
        let s = render_string(
            &sample(false),
            TextOptions {
                color: true,
                ..PLAIN
            },
        );
        assert!(s.contains('\x1b'));
        assert!(s.contains("[CLEAN-LOOKING]"));
        assert!(s.contains("[HIGH]"));
    }

    #[test]
    fn hostile_path_is_sanitized() {
        let input = Input::from_bytes("evil\x1b[2J\u{202e}fdp.exe", b"abc".to_vec());
        let report = Registry::default().analyze(&input, &Config::default());
        let s = render_string(
            &Run {
                reports: vec![report],
                failures: vec![],
            },
            PLAIN,
        );
        assert!(!s.contains('\x1b'));
        assert!(!s.contains('\u{202e}'));
        assert!(s.contains("evil\\x1b[2J\\u{202e}fdp.exe"));
    }

    #[test]
    fn classified_strings_are_capped_per_kind() {
        let mut data = Vec::new();
        for i in 0..25 {
            data.extend(format!("\x00http://host{i}.example.com/\x00").bytes());
        }
        let input = Input::from_bytes("many.bin", data);
        let mut report = Registry::default().analyze(&input, &Config::default());
        prepare(&mut report, false, rtriage_core::Severity::Info);
        let s = render_string(
            &Run {
                reports: vec![report],
                failures: vec![],
            },
            PLAIN,
        );
        assert!(s.contains("+5 more"));
    }

    #[test]
    fn snapshot_pe() {
        use rtriage_fixtures::pe::{Arch, Checksum, PeBuilder};
        let built = PeBuilder::minimal(Arch::X64)
            .timestamp(0)
            .checksum(Checksum::Value(0x1234))
            .import("KERNEL32.dll", &["LoadLibraryA", "GetProcAddress"])
            .import_ordinals("WS2_32.dll", &[23])
            .build();
        let input = Input::from_bytes("sample.exe", built.bytes);
        let mut report = Registry::default().analyze(&input, &Config::default());
        prepare(&mut report, false, rtriage_core::Severity::Info);
        insta::assert_snapshot!(render_string(
            &Run {
                reports: vec![report],
                failures: vec![],
            },
            PLAIN
        ));
    }

    #[test]
    fn snapshot_upx_like() {
        use rtriage_fixtures::pe::{profiles, Arch};
        let built = profiles::upx_like(Arch::X86)
            .tls_callbacks(1)
            .pdb_path(r"C:\Users\dev\proj\Release\tool.pdb")
            .overlay(b"PK\x03\x04 appended archive".to_vec())
            .build();
        let input = Input::from_bytes("packed.exe", built.bytes);
        let mut report = Registry::default().analyze(&input, &Config::default());
        prepare(&mut report, false, rtriage_core::Severity::Info);
        insta::assert_snapshot!(render_string(
            &Run {
                reports: vec![report],
                failures: vec![],
            },
            TextOptions {
                explain: true,
                ..PLAIN
            }
        ));
    }

    #[test]
    fn snapshot_signed_dll() {
        use rtriage_fixtures::pe::{Arch, ExportSpec, PeBuilder, ResourceSpec};
        let mut pkcs7 = vec![0x30, 0x82, 0x05, 0x00, 0x06, 0x09];
        pkcs7.extend_from_slice(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02]);
        pkcs7.resize(600, 0x41);
        let built = PeBuilder::minimal(Arch::X64)
            .dll(true)
            .rich_header(&[(0x0104, 30_795, 12), (0x0105, 30_795, 3)])
            .import(
                "KERNEL32.dll",
                &[
                    "ExitProcess",
                    "GetModuleHandleW",
                    "GetProcessHeap",
                    "HeapAlloc",
                    "HeapFree",
                    "GetLastError",
                    "CloseHandle",
                    "WriteFile",
                    "GetStdHandle",
                    "SetLastError",
                    "QueryPerformanceCounter",
                ],
            )
            .exports(
                "helper.dll",
                vec![
                    ExportSpec::named("Init"),
                    ExportSpec::named("Run"),
                    ExportSpec::forward("OpenFile", "KERNEL32.CreateFileW"),
                ],
            )
            .resource(ResourceSpec::new(
                24,
                2,
                b"<assembly manifestVersion='1.0'/>".to_vec(),
            ))
            .resource(ResourceSpec::new(16, 1, vec![0u8; 92]))
            .certificate(pkcs7)
            .build();
        let input = Input::from_bytes("helper.dll", built.bytes);
        let mut report = Registry::default().analyze(&input, &Config::default());
        prepare(&mut report, false, rtriage_core::Severity::Info);
        insta::assert_snapshot!(render_string(
            &Run {
                reports: vec![report],
                failures: vec![],
            },
            PLAIN
        ));
    }

    #[test]
    fn snapshot_elf_unsafe_interp() {
        use rtriage_fixtures::elf::ElfBuilder;
        let built = ElfBuilder::x86_64()
            .interp("/tmp/.x/ld-linux-x86-64.so.2")
            .needed("libc.so.6")
            .imports(&["puts"])
            .build();
        let input = Input::from_bytes("implant", built.bytes);
        let mut report = Registry::default().analyze(&input, &Config::default());
        prepare(&mut report, false, rtriage_core::Severity::Info);
        insta::assert_snapshot!(render_string(
            &Run {
                reports: vec![report],
                failures: vec![],
            },
            PLAIN
        ));
    }

    #[test]
    fn hostile_section_name_is_sanitized() {
        use rtriage_fixtures::pe::{Arch, PeBuilder, Section};
        let built = PeBuilder::new(Arch::X64)
            .section(Section::code("\x1b[2J\x1b", vec![0xC3; 16]))
            .build();
        let input = Input::from_bytes("x.exe", built.bytes);
        let report = Registry::default().analyze(&input, &Config::default());
        let s = render_string(
            &Run {
                reports: vec![report],
                failures: vec![],
            },
            PLAIN,
        );
        assert!(!s.contains('\x1b'));
        assert!(s.contains("\\x1b[2J\\x1b"));
    }

    #[test]
    fn number_formatting() {
        assert_eq!(group_digits(0), "0");
        assert_eq!(group_digits(999), "999");
        assert_eq!(group_digits(1204), "1 204");
        assert_eq!(group_digits(1_234_567), "1 234 567");
        assert_eq!(human_size(570), "570 bytes");
        assert_eq!(human_size(48_128), "48 128 bytes (47.0 KiB)");
        assert_eq!(short_size(3 * 1024 * 1024), "3.0 MiB");
    }

    #[test]
    fn long_values_are_shortened() {
        let v = "A".repeat(300);
        let s = shorten(&v, 300);
        assert!(s.starts_with(&"A".repeat(MAX_VALUE_CHARS)));
        assert!(s.ends_with("[... 300 chars total]"));
    }
}

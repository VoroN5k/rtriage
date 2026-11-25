//! Human-readable terminal renderer.
//!
//! Every value that comes from the input file (path, strings, section names,
//! evidence) goes through [`sanitize`]. Color is decorative only: risk and
//! severity are always spelled out as text too.

use std::collections::BTreeMap;
use std::io::{self, Write};

use anstyle::{AnsiColor, Style};
use rtriage_core::report::{
    EntropyFacts, ExtractedString, StringEncoding, StringKind, StringsFacts,
};
use rtriage_core::{Evidence, Finding, Format, Report, RiskLevel, Severity};
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
    writeln!(
        out,
        "  {}  {} score {}",
        p.label("Risk   "),
        p.paint(
            Style::new().bold().fg_color(Some(color.into())),
            &format!("[{text}]")
        ),
        r.risk.score
    )
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
        prepare(&mut report, all_strings);
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
        prepare(&mut report, false);
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

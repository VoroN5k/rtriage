//! Language runtime recognition (Go, Rust) for PE and ELF.
//!
//! Recorded as a **fact** only when at least two independent indicators
//! agree. It sets analyst expectations (static, huge, unusual layout) and,
//! through `rules/packers.toml` `[[runtime]]`, may explain small hardening /
//! import findings its toolchain produces by design. It never produces a
//! finding of its own and never affects API behavior groups.

use crate::analyzers::{AnalysisContext, Analyzer};
use crate::deadline::Deadline;
use crate::error::AnalysisError;
use crate::report::{Format, ReportBuilder, RuntimeFacts, StringsFacts};
use crate::rules::MIN_CONFIRM_INDICATORS;

/// Runtimes this analyzer can recognise.
pub const KNOWN_RUNTIMES: &[&str] = &["go", "rust"];
/// Go's build info magic (`.go.buildinfo`).
const GO_BUILDINFO_MAGIC: &[u8] = b"\xff Go buildinf:";
/// Bytes searched between deadline checks.
const SEARCH_CHUNK: usize = 1 << 20;

/// Recognises Go and Rust binaries.
#[derive(Debug, Clone, Copy, Default)]
pub struct RuntimeAnalyzer;

impl Analyzer for RuntimeAnalyzer {
    fn name(&self) -> &'static str {
        "runtime"
    }

    fn applies_to(&self, format: Format) -> bool {
        matches!(format, Format::Pe | Format::Elf)
    }

    fn run(&self, ctx: &AnalysisContext<'_>, out: &mut ReportBuilder) -> Result<(), AnalysisError> {
        let strings = ctx.strings()?;
        let section_names: Vec<&str> = match ctx.input.format {
            Format::Elf => ctx
                .elf()
                .map(|e| e.sections.iter().map(|s| s.name.as_str()).collect())
                .unwrap_or_default(),
            _ => Vec::new(),
        };
        let symbols: Vec<&str> = match ctx.elf_dynamic() {
            Some(Ok(d)) => d.all_names().collect(),
            _ => Vec::new(),
        };
        let go = go(&ctx.input.data, strings, &section_names, &ctx.deadline)?;
        let rust = rust(strings, &symbols);
        let best = [go, rust]
            .into_iter()
            .filter(|r| r.indicators.len() >= MIN_CONFIRM_INDICATORS)
            .max_by_key(|r| r.indicators.len());
        out.facts.runtime = best;
        Ok(())
    }
}

fn any_contains(strings: &StringsFacts, needles: &[&str]) -> bool {
    strings
        .items
        .iter()
        .any(|s| needles.iter().any(|n| s.value.contains(n)))
}

fn go(
    data: &[u8],
    strings: &StringsFacts,
    sections: &[&str],
    deadline: &Deadline,
) -> Result<RuntimeFacts, AnalysisError> {
    let mut ind = Vec::new();
    if contains_bytes(data, GO_BUILDINFO_MAGIC, deadline)? {
        ind.push("go_buildinfo");
    }
    if any_contains(strings, &["Go build ID: \""]) || sections.contains(&".note.go.buildid") {
        ind.push("go_build_id");
    }
    if sections
        .iter()
        .any(|s| matches!(*s, ".gopclntab" | ".go.buildinfo" | ".noptrdata"))
    {
        ind.push("go_sections");
    }
    if any_contains(
        strings,
        &[
            "runtime.main",
            "runtime.goexit",
            "runtime: unexpected return pc",
        ],
    ) {
        ind.push("go_runtime_strings");
    }
    let version = strings.items.iter().find_map(|s| go_version(&s.value));
    Ok(RuntimeFacts {
        language: "go",
        version,
        indicators: ind,
    })
}

/// `go1.N` or `go1.N.M` at the start of a token.
fn go_version(s: &str) -> Option<String> {
    let at = s.find("go1.")?;
    let tail: String = s
        .get(at + 2..)?
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let tail = tail.trim_end_matches('.');
    (tail.len() >= 3 && tail.split('.').count() <= 3).then(|| format!("go{tail}"))
}

fn rust(strings: &StringsFacts, symbols: &[&str]) -> RuntimeFacts {
    let mut ind = Vec::new();
    let commit = strings.items.iter().find_map(|s| rustc_commit(&s.value));
    if commit.is_some() {
        ind.push("rustc_path");
    }
    if any_contains(
        strings,
        &[
            "called `Option::unwrap()` on a `None` value",
            "called `Result::unwrap()` on an `Err` value",
        ],
    ) {
        ind.push("panic_messages");
    }
    if symbols.iter().any(|s| is_rust_symbol(s)) {
        ind.push("mangled_symbols");
    }
    RuntimeFacts {
        language: "rust",
        version: commit.map(|c| format!("rustc {c}")),
        indicators: ind,
    }
}

/// The 40-hex commit in `/rustc/<commit>/`.
fn rustc_commit(s: &str) -> Option<String> {
    let at = s.find("/rustc/")?;
    let hash = s.get(at + 7..at + 47)?;
    (hash.bytes().all(|b| b.is_ascii_hexdigit()) && s.get(at + 47..at + 48) == Some("/"))
        .then(|| hash.to_owned())
}

/// Legacy (`_ZN...17h<16 hex>E`) or v0 (`_R...`) Rust mangling, or runtime symbols.
fn is_rust_symbol(s: &str) -> bool {
    if matches!(
        s,
        "rust_begin_unwind" | "rust_panic" | "__rust_alloc" | "__rust_probestack"
    ) {
        return true;
    }
    if let Some(body) = s.strip_prefix("_ZN").and_then(|b| b.strip_suffix('E')) {
        if let Some(i) = body.rfind("17h") {
            let h = body.get(i + 3..).unwrap_or_default();
            return h.len() == 16 && h.bytes().all(|b| b.is_ascii_hexdigit());
        }
    }
    s.starts_with("_RNv") || s.starts_with("_RINv")
}

/// Byte search over the whole file, checking the deadline per MiB.
fn contains_bytes(data: &[u8], needle: &[u8], deadline: &Deadline) -> Result<bool, AnalysisError> {
    let overlap = needle.len().saturating_sub(1);
    let mut start = 0;
    while start < data.len() {
        deadline.check()?;
        let end = start
            .saturating_add(SEARCH_CHUNK)
            .saturating_add(overlap)
            .min(data.len());
        if data
            .get(start..end)
            .is_some_and(|w| w.windows(needle.len()).any(|x| x == needle))
        {
            return Ok(true);
        }
        start = start.saturating_add(SEARCH_CHUNK);
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::input::Input;
    use crate::report::Report;
    use crate::Registry;
    use rtriage_fixtures::elf::{profiles as elf_profiles, ElfBuilder};
    use rtriage_fixtures::pe::{profiles as pe_profiles, Arch, PeBuilder, Section};

    fn analyze(bytes: Vec<u8>) -> Report {
        let r = Registry::default().analyze(&Input::from_bytes("t", bytes), &Config::default());
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        r
    }

    #[test]
    fn go_static_elf() {
        let r = analyze(elf_profiles::go_static().build().bytes);
        let rt = r.facts.runtime.unwrap();
        assert_eq!(rt.language, "go");
        assert_eq!(rt.version.as_deref(), Some("go1.22.5"));
        assert!(rt.indicators.len() >= 3, "{:?}", rt.indicators);
    }

    #[test]
    fn go_pe() {
        let r = analyze(pe_profiles::go_like(Arch::X64).build().bytes);
        let rt = r.facts.runtime.unwrap();
        assert_eq!(rt.language, "go");
        assert_eq!(rt.indicators, ["go_build_id", "go_runtime_strings"]);
    }

    #[test]
    fn rust_pie_elf() {
        let r = analyze(elf_profiles::rust_pie().build().bytes);
        let rt = r.facts.runtime.unwrap();
        assert_eq!(rt.language, "rust");
        assert_eq!(
            rt.indicators,
            ["rustc_path", "panic_messages", "mangled_symbols"]
        );
        assert_eq!(
            rt.version.as_deref(),
            Some("rustc 82e1608dfa6e0b5569232559e3d385fea5a93112")
        );
    }

    #[test]
    fn single_indicator_is_not_enough() {
        // Only a "go1.22" string (e.g. a tool that prints Go versions).
        let r = analyze(
            ElfBuilder::x86_64()
                .rodata(b"built with go1.22\0runtime.main\0".to_vec())
                .build()
                .bytes,
        );
        // runtime.main string alone = one indicator: not recognised.
        assert!(r.facts.runtime.is_none());
        let r = analyze(
            PeBuilder::minimal(Arch::X64)
                .section(Section::rdata(
                    ".r",
                    b"called `Option::unwrap()` on a `None` value\0".to_vec(),
                ))
                .build()
                .bytes,
        );
        assert!(r.facts.runtime.is_none());
    }

    #[test]
    fn c_programs_have_no_runtime() {
        for b in [
            elf_profiles::glibc_pie().build().bytes,
            elf_profiles::busybox_static().build().bytes,
        ] {
            assert!(analyze(b).facts.runtime.is_none());
        }
    }

    #[test]
    fn helpers() {
        assert_eq!(go_version("go1.22.5").as_deref(), Some("go1.22.5"));
        assert_eq!(go_version("x go1.21 y").as_deref(), Some("go1.21"));
        assert_eq!(go_version("go1."), None);
        assert!(is_rust_symbol(
            "_ZN4core9panicking5panic17h1a2b3c4d5e6f7081E"
        ));
        assert!(!is_rust_symbol("_ZN4core9panicking5panicE"));
        assert!(!is_rust_symbol("_ZNSt6vectorIiE9push_backEi"));
        assert!(is_rust_symbol("_RNvCs1234_7mycrate4main"));
        assert!(rustc_commit("/rustc/82e1608dfa6e0b5569232559e3d385fea5a93112/library").is_some());
        assert!(rustc_commit("/rustc/nothex/").is_none());
    }

    #[test]
    fn byte_search_spans_chunks_and_respects_deadline() {
        let mut data = vec![0u8; SEARCH_CHUNK - 3];
        data.extend_from_slice(GO_BUILDINFO_MAGIC);
        assert!(contains_bytes(&data, GO_BUILDINFO_MAGIC, &Deadline::never()).unwrap());
        assert!(contains_bytes(&data, GO_BUILDINFO_MAGIC, &Deadline::expired()).is_err());
    }
}

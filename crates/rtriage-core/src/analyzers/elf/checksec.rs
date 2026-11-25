//! Dynamic-section facts, checksec-style hardening summary, and hardening /
//! search-path findings.
//!
//! Findings (see `docs/heuristics.md`):
//! - `ELF-HARDENING-EXEC-STACK`: the stack is executable.
//! - `ELF-HARDENING-NO-PIE`: an executable that is not position independent.
//! - `ELF-HARDENING-NO-RELRO`: a dynamically linked file without `PT_GNU_RELRO`.
//! - `ELF-RPATH-UNSAFE`: a library search path component that an attacker
//!   may control (`$ORIGIN` is never flagged).

use super::dynamic::{ElfDynamic, DF_1_PIE, DF_TEXTREL};
use super::{ElfImage, PF_X, PT_INTERP};
use crate::analyzers::{AnalysisContext, Analyzer};
use crate::error::AnalysisError;
use crate::report::{
    Category, Confidence, ElfChecksec, ElfDynamicFacts, ElfFacts, Evidence, Finding, Format,
    ReportBuilder, Severity,
};

const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
/// `PT_GNU_STACK`.
const PT_GNU_STACK: u32 = 0x6474_e551;
/// `PT_GNU_RELRO`.
const PT_GNU_RELRO: u32 = 0x6474_e552;
/// Architectures whose kernels make the stack executable when
/// `PT_GNU_STACK` is missing (x86, x86-64, MIPS, PPC32, ARM32, SPARC).
const EXEC_STACK_BY_DEFAULT: &[u16] = &[2, 3, 8, 20, 40, 62];
/// World-writable or volatile directories.
const UNSAFE_DIRS: &[&str] = &["/tmp", "/var/tmp", "/dev/shm", "/run/user"];
/// Stack-protector symbols.
const CANARY_SYMBOLS: &[&str] = &[
    "__stack_chk_fail",
    "__stack_chk_guard",
    "__stack_chk_fail_local",
];

/// Publishes dynamic facts and the hardening summary.
#[derive(Debug, Clone, Copy, Default)]
pub struct ElfChecksecAnalyzer;

impl Analyzer for ElfChecksecAnalyzer {
    fn name(&self) -> &'static str {
        "elf-dynamic"
    }

    fn applies_to(&self, format: Format) -> bool {
        format == Format::Elf
    }

    fn run(&self, ctx: &AnalysisContext<'_>, out: &mut ReportBuilder) -> Result<(), AnalysisError> {
        let Some(elf) = super::elf_or_skip(ctx) else {
            return Ok(());
        };
        let dynamic = match ctx.elf_dynamic() {
            Some(Ok(d)) => d,
            Some(Err(e)) => return Err(e),
            None => return Ok(()),
        };
        let checksec = checksec(elf, dynamic);
        let runnable = matches!(elf.elf_type, ET_EXEC | ET_DYN);

        if runnable && !checksec.nx {
            exec_stack_finding(&checksec, out);
        }
        if checksec.pie == Some(false) {
            out.push_finding(
                Finding::new(
                    "ELF-HARDENING-NO-PIE",
                    Severity::Low,
                    Category::Hardening,
                    "Executable is not position independent",
                )
                .confidence(Confidence::Low)
                .detail(
                    "A fixed load address defeats ASLR for the main image, which helps \
                     exploitation. Common for older or statically linked builds (Go, \
                     many embedded toolchains).",
                )
                .evidence(Evidence::Field {
                    name: "e_type",
                    value: "EXEC".into(),
                }),
            );
        }
        if runnable && dynamic.present && checksec.relro == "none" {
            out.push_finding(
                Finding::new(
                    "ELF-HARDENING-NO-RELRO",
                    Severity::Low,
                    Category::Hardening,
                    "No RELRO",
                )
                .confidence(Confidence::Low)
                .detail(
                    "Dynamically linked without PT_GNU_RELRO: the GOT and other \
                     relocated data stay writable, a classic exploitation target.",
                )
                .evidence(Evidence::Field {
                    name: "PT_GNU_RELRO",
                    value: "absent".into(),
                }),
            );
        }
        rpath_finding(dynamic, out);

        let facts = out.facts.elf.get_or_insert_with(ElfFacts::default);
        if dynamic.present {
            facts.dynamic = Some(ElfDynamicFacts {
                needed: dynamic.needed.clone(),
                soname: dynamic.soname.clone(),
                rpath: dynamic.rpath.clone(),
                runpath: dynamic.runpath.clone(),
                imports: dynamic.imports().map(str::to_owned).collect(),
                exported_symbols: dynamic
                    .dynamic_symbols
                    .iter()
                    .filter(|s| s.defined && !s.name.is_empty())
                    .count(),
                symbol_count_source: dynamic.symbol_count_source,
                symbols_limit_reached: dynamic.symbols_limit_reached,
                textrel: dynamic.textrel_tag || dynamic.flags & DF_TEXTREL != 0,
            });
        }
        facts.checksec = Some(checksec);
        Ok(())
    }
}

/// Builds the hardening summary.
pub fn checksec(elf: &ElfImage, d: &ElfDynamic) -> ElfChecksec {
    let has_interp = elf.segments.iter().any(|s| s.kind == PT_INTERP);
    let pie = match elf.elf_type {
        ET_EXEC => Some(false),
        ET_DYN if has_interp || d.flags_1 & DF_1_PIE != 0 => Some(true),
        _ => None, // shared libraries, objects, cores
    };
    let (nx, nx_source) = match elf.segments.iter().find(|s| s.kind == PT_GNU_STACK) {
        Some(s) => (s.flags & PF_X == 0, "gnu_stack"),
        None => (
            !EXEC_STACK_BY_DEFAULT.contains(&elf.machine),
            "architecture_default",
        ),
    };
    let has_relro = elf.segments.iter().any(|s| s.kind == PT_GNU_RELRO);
    // Without dynamic relocations there is no lazy binding: RELRO is full.
    let relro = match (has_relro, d.bind_now() || !d.present) {
        (false, _) => "none",
        (true, false) => "partial",
        (true, true) => "full",
    };
    let have_symbols = !d.dynamic_symbols.is_empty() || !d.static_symbols.is_empty();
    let canary = have_symbols.then(|| d.all_names().any(|n| CANARY_SYMBOLS.contains(&n)));
    let fortify = have_symbols.then(|| d.all_names().any(is_fortify_symbol));
    ElfChecksec {
        pie,
        nx,
        nx_source,
        relro,
        bind_now: d.bind_now(),
        canary,
        fortify,
        stripped: !d.has_symtab,
    }
}

/// `__memcpy_chk`, `__printf_chk`, ... but not `__stack_chk_fail`.
fn is_fortify_symbol(name: &str) -> bool {
    name.starts_with("__")
        && name.ends_with("_chk")
        && !name.starts_with("__stack_chk")
        && name.len() > "___chk".len()
}

fn exec_stack_finding(c: &ElfChecksec, out: &mut ReportBuilder) {
    out.push_finding(
        Finding::new(
            "ELF-HARDENING-EXEC-STACK",
            Severity::Low,
            Category::Hardening,
            "Executable stack",
        )
        .detail(if c.nx_source == "gnu_stack" {
            "PT_GNU_STACK requests an executable stack: injected shellcode on the \
             stack can run. Modern toolchains only do this for code that needs \
             trampolines, which is rare."
        } else {
            "There is no PT_GNU_STACK header, so on this architecture the kernel \
             makes the stack executable. Typical of old or hand-made binaries."
        })
        .evidence(Evidence::Field {
            name: "PT_GNU_STACK",
            value: if c.nx_source == "gnu_stack" {
                "RWX".into()
            } else {
                "absent".into()
            },
        }),
    );
}

/// Why a search path component is unsafe, or `None` if it is fine.
pub fn unsafe_component(component: &str) -> Option<&'static str> {
    if component.starts_with("$ORIGIN") || component.starts_with("${ORIGIN}") {
        return None;
    }
    if component.is_empty() {
        return Some("empty component (means the current directory)");
    }
    if component == "." || !component.starts_with('/') {
        return Some("relative to the current directory");
    }
    if component.split('/').any(|c| c == "..") {
        return Some("contains ..");
    }
    if UNSAFE_DIRS
        .iter()
        .any(|d| component == *d || component.starts_with(&format!("{d}/")))
    {
        return Some("world-writable location");
    }
    None
}

fn rpath_finding(d: &ElfDynamic, out: &mut ReportBuilder) {
    let mut ev = Vec::new();
    for (tag, value) in [("DT_RPATH", &d.rpath), ("DT_RUNPATH", &d.runpath)] {
        let Some(path) = value else {
            continue;
        };
        for component in path.split(':') {
            if let Some(why) = unsafe_component(component) {
                ev.push(Evidence::Field {
                    name: tag,
                    value: format!("{component:?}: {why}"),
                });
            }
        }
    }
    if ev.is_empty() {
        return;
    }
    let mut f = Finding::new(
        "ELF-RPATH-UNSAFE",
        Severity::Medium,
        Category::Anomaly,
        "Library search path an attacker may control",
    )
    .confidence(Confidence::Low)
    .detail(
        "The loader searches these directories for shared libraries before the \
         system ones. A relative, empty or world-writable entry lets whoever can \
         write there plant a library that runs in this process. $ORIGIN-relative \
         entries are not reported.",
    )
    .attack("T1574.006");
    for e in ev {
        f = f.evidence(e);
    }
    out.push_finding(f);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::input::Input;
    use crate::report::Report;
    use crate::Registry;
    use rtriage_fixtures::elf::{df, et, machine, pf, profiles, Class, ElfBuilder, Endian};

    fn analyze(bytes: Vec<u8>) -> Report {
        let r = Registry::default().analyze(&Input::from_bytes("t", bytes), &Config::default());
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        r
    }

    fn cs(r: &Report) -> &ElfChecksec {
        r.facts.elf.as_ref().unwrap().checksec.as_ref().unwrap()
    }

    fn ids(r: &Report) -> Vec<&'static str> {
        r.findings
            .iter()
            .map(|f| f.id)
            .filter(|id| id.starts_with("ELF-HARDENING") || id.starts_with("ELF-RPATH"))
            .collect()
    }

    #[test]
    fn glibc_pie_is_fully_hardened() {
        let r = analyze(profiles::glibc_pie().build().bytes);
        let c = cs(&r);
        assert_eq!(c.pie, Some(true));
        assert!(c.nx);
        assert_eq!(c.relro, "full");
        assert!(c.bind_now);
        assert_eq!(c.canary, Some(true));
        assert_eq!(c.fortify, Some(true));
        assert!(ids(&r).is_empty(), "{:?}", ids(&r));
        let d = r.facts.elf.as_ref().unwrap().dynamic.as_ref().unwrap();
        assert_eq!(d.needed, ["libc.so.6"]);
        assert!(d.imports.contains(&"__printf_chk".to_owned()));
    }

    #[test]
    fn go_static_is_no_pie_only() {
        let r = analyze(profiles::go_static().build().bytes);
        let c = cs(&r);
        assert_eq!(c.pie, Some(false));
        assert_eq!(c.relro, "none");
        assert!(!c.stripped);
        // Static: RELRO is not judged, only PIE.
        assert_eq!(ids(&r), ["ELF-HARDENING-NO-PIE"]);
        assert!(r.facts.elf.as_ref().unwrap().dynamic.is_none());
    }

    #[test]
    fn rust_pie_is_clean() {
        assert!(ids(&analyze(profiles::rust_pie().build().bytes)).is_empty());
    }

    #[test]
    fn partial_relro_is_not_flagged() {
        let r = analyze(
            ElfBuilder::x86_64()
                .elf_type(et::DYN)
                .interp("/lib64/ld-linux-x86-64.so.2")
                .needed("libc.so.6")
                .relro(true)
                .build()
                .bytes,
        );
        assert_eq!(cs(&r).relro, "partial");
        assert!(ids(&r).is_empty(), "{:?}", ids(&r));
    }

    #[test]
    fn dynamic_without_relro() {
        let r = analyze(
            ElfBuilder::x86_64()
                .elf_type(et::DYN)
                .interp("/lib64/ld-linux-x86-64.so.2")
                .needed("libc.so.6")
                .build()
                .bytes,
        );
        assert_eq!(ids(&r), ["ELF-HARDENING-NO-RELRO"]);
    }

    #[test]
    fn exec_stack_from_gnu_stack() {
        let r = analyze(
            ElfBuilder::x86_64()
                .gnu_stack(Some(pf::R | pf::W | pf::X))
                .build()
                .bytes,
        );
        assert!(!cs(&r).nx);
        let f = r
            .findings
            .iter()
            .find(|f| f.id == "ELF-HARDENING-EXEC-STACK")
            .unwrap();
        assert_eq!(
            (f.severity, f.confidence),
            (Severity::Low, Confidence::Medium)
        );
    }

    #[test]
    fn missing_gnu_stack_depends_on_architecture() {
        let x86 = analyze(ElfBuilder::x86_64().gnu_stack(None).build().bytes);
        assert!(!cs(&x86).nx);
        assert_eq!(cs(&x86).nx_source, "architecture_default");
        assert!(ids(&x86).contains(&"ELF-HARDENING-EXEC-STACK"));
        let arm64 = analyze(
            ElfBuilder::new(Class::Elf64, Endian::Little, machine::AARCH64)
                .gnu_stack(None)
                .build()
                .bytes,
        );
        assert!(cs(&arm64).nx);
        assert!(!ids(&arm64).contains(&"ELF-HARDENING-EXEC-STACK"));
    }

    #[test]
    fn shared_library_pie_is_not_applicable() {
        let r = analyze(
            ElfBuilder::x86_64()
                .elf_type(et::DYN)
                .needed("libc.so.6")
                .relro(true)
                .dt_flags(df::BIND_NOW)
                .build()
                .bytes,
        );
        assert_eq!(cs(&r).pie, None);
        assert!(!ids(&r).contains(&"ELF-HARDENING-NO-PIE"));
    }

    #[test]
    fn stripped_static_has_unknown_canary() {
        let r = analyze(profiles::busybox_static().build().bytes);
        assert_eq!(cs(&r).canary, None);
        assert_eq!(cs(&r).fortify, None);
        assert!(cs(&r).stripped);
    }

    #[test]
    fn fortify_symbol_rule() {
        assert!(is_fortify_symbol("__printf_chk"));
        assert!(is_fortify_symbol("__memcpy_chk"));
        assert!(!is_fortify_symbol("__stack_chk_fail"));
        assert!(!is_fortify_symbol("printf_chk"));
        assert!(!is_fortify_symbol("___chk"));
    }

    // ---- RPATH

    #[test]
    fn rpath_components() {
        for ok in [
            "$ORIGIN",
            "$ORIGIN/../lib",
            "${ORIGIN}/lib",
            "/usr/lib",
            "/opt/app/lib",
            "/usr/$LIB",
        ] {
            assert_eq!(unsafe_component(ok), None, "{ok}");
        }
        for bad in [
            "",
            ".",
            "lib",
            "./lib",
            "/tmp",
            "/tmp/x",
            "/var/tmp/l",
            "/dev/shm",
            "/opt/../tmp",
        ] {
            assert!(unsafe_component(bad).is_some(), "{bad:?}");
        }
        assert_eq!(unsafe_component("/tmpfiles"), None);
    }

    #[test]
    fn unsafe_rpath_is_medium_low() {
        let r = analyze(
            ElfBuilder::x86_64()
                .needed("libfoo.so")
                .rpath("$ORIGIN/lib::/tmp")
                .build()
                .bytes,
        );
        let f = r
            .findings
            .iter()
            .find(|f| f.id == "ELF-RPATH-UNSAFE")
            .unwrap();
        assert_eq!(
            (f.severity, f.confidence),
            (Severity::Medium, Confidence::Low)
        );
        assert_eq!(f.attack, ["T1574.006"]);
        // Empty component and /tmp, not $ORIGIN.
        assert_eq!(f.evidence.len(), 2);
    }

    #[test]
    fn origin_only_runpath_is_clean() {
        let r = analyze(
            ElfBuilder::x86_64()
                .needed("libfoo.so")
                .runpath("$ORIGIN:$ORIGIN/../lib")
                .build()
                .bytes,
        );
        assert!(!ids(&r).contains(&"ELF-RPATH-UNSAFE"));
    }
}

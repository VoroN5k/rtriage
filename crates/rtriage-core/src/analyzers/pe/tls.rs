//! TLS callbacks: code the loader runs before the entry point.
//!
//! Bounded parser: the callback array is attacker-controlled, so at most
//! `max_tls_callbacks` entries are read, each consuming a [`Budget`](crate::deadline::Budget) step.
//!
//! Finding: `PE-TLS-CALLBACKS` (see `docs/heuristics.md`).

use super::{read_array, read_u32, PeImage};
use crate::analyzers::{AnalysisContext, Analyzer};
use crate::deadline::Deadline;
use crate::error::AnalysisError;
use crate::limits::Limits;
use crate::report::{
    Category, Evidence, Finding, Format, PeFacts, PeTlsCallback, PeTlsFacts, ReportBuilder,
    SectionRef, Severity,
};

/// Data directory index of the TLS table.
const DIRECTORY_TLS: usize = 9;
/// Callbacks listed as evidence.
const MAX_EVIDENCE: usize = 8;

/// Reads the TLS callback array.
#[derive(Debug, Clone, Copy, Default)]
pub struct PeTlsAnalyzer;

impl Analyzer for PeTlsAnalyzer {
    fn name(&self) -> &'static str {
        "pe-tls"
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
        if !facts.callbacks.is_empty() {
            let mut f = Finding::new(
                "PE-TLS-CALLBACKS",
                Severity::Low,
                Category::AntiAnalysis,
                "TLS callbacks run before the entry point",
            )
            .detail(format!(
                "{} TLS callback(s) execute before the entry point, so a debugger \
                 breaking at the entry point misses them; used for anti-debugging and \
                 early unpacking. Rust and MinGW runtimes also register TLS callbacks.",
                facts.callbacks.len()
            ));
            for cb in facts.callbacks.iter().take(MAX_EVIDENCE) {
                f = f.evidence(Evidence::Field {
                    name: "callback",
                    value: match &cb.section {
                        Some(s) => format!("0x{:x} in #{} {}", cb.va, s.index, s.name),
                        None => format!("0x{:x} (outside all sections)", cb.va),
                    },
                });
            }
            out.push_finding(f);
        }
        out.facts.pe.get_or_insert_with(PeFacts::default).tls = Some(facts);
        Ok(())
    }
}

/// Parses the TLS directory; `Ok(None)` if there is none.
///
/// # Errors
/// Truncated or unmapped structures, budget exhaustion, deadline.
pub fn parse(
    pe: &PeImage,
    data: &[u8],
    limits: &Limits,
    deadline: &Deadline,
) -> Result<Option<PeTlsFacts>, AnalysisError> {
    let Some(dir) = pe.directory(DIRECTORY_TLS) else {
        return Ok(None);
    };
    let ptr = if pe.is64 { 8 } else { 4 };
    let dir_off = pe
        .rva_to_offset(dir.rva, data.len())
        .ok_or_else(|| unmapped("PE TLS directory", dir.rva))?;
    // AddressOfCallBacks is the 4th pointer-sized field.
    let callbacks_va = read_ptr(data, dir_off.saturating_add(3 * ptr), pe.is64)?;
    let mut facts = PeTlsFacts {
        callbacks: Vec::new(),
        limit_reached: false,
    };
    if callbacks_va == 0 {
        return Ok(Some(facts));
    }
    let array_rva = va_to_rva(pe, callbacks_va).ok_or_else(|| AnalysisError::Malformed {
        what: "PE TLS directory",
        reason: format!("AddressOfCallBacks 0x{callbacks_va:x} is outside the image"),
    })?;
    let mut at = pe
        .rva_to_offset(array_rva, data.len())
        .ok_or_else(|| unmapped("PE TLS callback array", array_rva))?;
    let mut budget = deadline.budget(limits.max_parser_steps);
    loop {
        budget.step()?;
        let va = read_ptr(data, at, pe.is64)?;
        if va == 0 {
            break;
        }
        if facts.callbacks.len() >= limits.max_tls_callbacks {
            facts.limit_reached = true;
            break;
        }
        let section = va_to_rva(pe, va)
            .and_then(|rva| pe.section_for_rva(rva))
            .map(|s| SectionRef {
                index: s.index,
                name: s.name.clone(),
            });
        facts.callbacks.push(PeTlsCallback { va, section });
        at = at.saturating_add(ptr);
    }
    Ok(Some(facts))
}

fn read_ptr(data: &[u8], offset: usize, is64: bool) -> Result<u64, AnalysisError> {
    if is64 {
        read_array::<8>(data, offset, "PE TLS pointer").map(u64::from_le_bytes)
    } else {
        read_u32(data, offset, "PE TLS pointer").map(u64::from)
    }
}

fn va_to_rva(pe: &PeImage, va: u64) -> Option<u32> {
    va.checked_sub(pe.image_base)
        .and_then(|rva| u32::try_from(rva).ok())
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
    use crate::report::{Confidence, Report};
    use crate::Registry;
    use rtriage_fixtures::pe::{put_u32, Arch, PeBuilder};

    fn analyze_with(bytes: Vec<u8>, config: &Config) -> Report {
        Registry::default().analyze(&Input::from_bytes("t.exe", bytes), config)
    }

    fn analyze(bytes: Vec<u8>) -> Report {
        analyze_with(bytes, &Config::default())
    }

    fn tls(r: &Report) -> Option<&PeTlsFacts> {
        r.facts.pe.as_ref().unwrap().tls.as_ref()
    }

    #[test]
    fn callbacks_on_both_arches() {
        for arch in [Arch::X86, Arch::X64] {
            let r = analyze(PeBuilder::minimal(arch).tls_callbacks(2).build().bytes);
            assert!(r.errors.is_empty(), "{:?}", r.errors);
            let t = tls(&r).unwrap();
            assert_eq!(t.callbacks.len(), 2);
            assert_eq!(t.callbacks[0].section.as_ref().unwrap().name, ".text");
            let f = r
                .findings
                .iter()
                .find(|f| f.id == "PE-TLS-CALLBACKS")
                .unwrap();
            assert_eq!(
                (f.severity, f.confidence),
                (Severity::Low, Confidence::Medium)
            );
        }
    }

    #[test]
    fn no_tls_directory() {
        let r = analyze(PeBuilder::minimal(Arch::X64).build().bytes);
        assert!(tls(&r).is_none());
        assert!(r.findings.iter().all(|f| f.id != "PE-TLS-CALLBACKS"));
    }

    #[test]
    fn tls_without_callbacks_is_not_flagged() {
        // Zero AddressOfCallBacks: TLS data only (plain thread_local storage).
        let mut built = PeBuilder::minimal(Arch::X86).tls_callbacks(1).build();
        let dd = built.layout.data_directory_offset(9);
        let dir_rva = u32::from_le_bytes(built.bytes[dd..dd + 4].try_into().unwrap());
        let auto = *built.layout.sections.last().unwrap();
        let dir_off = (auto.raw_ptr + (dir_rva - auto.rva)) as usize;
        put_u32(&mut built.bytes, dir_off + 12, 0);
        let r = analyze(built.bytes);
        assert!(tls(&r).unwrap().callbacks.is_empty());
        assert!(r.findings.iter().all(|f| f.id != "PE-TLS-CALLBACKS"));
    }

    #[test]
    fn callback_limit_is_enforced() {
        let mut config = Config::default();
        config.limits.max_tls_callbacks = 3;
        let r = analyze_with(
            PeBuilder::minimal(Arch::X64)
                .tls_callbacks(10)
                .build()
                .bytes,
            &config,
        );
        let t = tls(&r).unwrap();
        assert_eq!(t.callbacks.len(), 3);
        assert!(t.limit_reached);
    }

    #[test]
    fn unmapped_tls_directory_is_an_error() {
        let mut built = PeBuilder::minimal(Arch::X64).tls_callbacks(1).build();
        put_u32(
            &mut built.bytes,
            built.layout.data_directory_offset(9),
            0xdead_0000,
        );
        let r = analyze(built.bytes);
        assert!(r.errors.iter().any(|e| e.analyzer == "pe-tls"));
    }
}

//! Property tests: hostile ELF input must never panic, must respect the
//! deadline and the parser budget, and must always yield a coherent report.
//!
//! Inputs are the synthetic ELF corpus (both classes and byte orders, with
//! dynamic sections, hash tables, notes, symbols and UPX-like layouts) with
//! random mutations, plus random bytes behind real ELF headers so the program
//! header, dynamic, symbol and note parsers are actually reached.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

mod common;

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use common::{
    analyze, apply, budget_errors_report_the_limit, cases, check_report, expired_deadline_report,
    mutation, noise, only_timeouts,
};
use proptest::prelude::*;
use rtriage_core::analyzers::elf;
use rtriage_core::{AnalysisError, Config, Deadline, Limits};

/// The shared synthetic corpus (see `rtriage_fixtures::elf::corpus`), built once.
fn corpus() -> &'static [Vec<u8>] {
    static CORPUS: OnceLock<Vec<Vec<u8>>> = OnceLock::new();
    CORPUS.get_or_init(|| {
        rtriage_fixtures::elf::corpus()
            .into_iter()
            .map(|(_, bytes)| bytes)
            .collect()
    })
}

/// ELF header size for the class in `bytes` (52 or 64).
fn header_len(bytes: &[u8]) -> usize {
    if bytes.get(4) == Some(&2) {
        64
    } else {
        52
    }
}

/// The lower-level parsers directly, bypassing the analyzers' skip logic.
fn parse_directly(bytes: &[u8], limits: &Limits) {
    if let Ok(image) = elf::parse(bytes, limits) {
        let _ = elf::dynamic::parse(&image, bytes, limits, &Deadline::never());
        let _ = elf::notes::parse(&image, bytes, limits, &Deadline::never());
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases()))]

    /// Mutated fixtures never panic and always yield a coherent report.
    #[test]
    fn mutated_fixtures_never_panic(
        idx in 0usize..1000,
        mutations in prop::collection::vec(mutation(), 1..12),
    ) {
        let bytes = apply(corpus()[idx % corpus().len()].clone(), &mutations);
        parse_directly(&bytes, &Limits::default());
        analyze("fuzz.elf", bytes, &Config::default());
    }

    /// A real ELF header followed by random program headers and data.
    #[test]
    fn random_bodies_behind_a_real_header_never_panic(
        idx in 0usize..1000,
        body in prop::collection::vec(any::<u8>(), 0..4096),
    ) {
        let base = &corpus()[idx % corpus().len()];
        let mut bytes = base[..header_len(base)].to_vec();
        bytes.extend_from_slice(&body);
        parse_directly(&bytes, &Limits::default());
        analyze("fuzz.elf", bytes, &Config::default());
    }

    /// Header and program headers intact, everything after them random:
    /// reaches the dynamic, symbol, hash and note parsers with garbage.
    #[test]
    fn random_data_behind_real_tables_never_panic(
        idx in 0usize..1000,
        keep in 0usize..0x400,
        tail in prop::collection::vec(any::<u8>(), 0..8192),
    ) {
        let base = &corpus()[idx % corpus().len()];
        let keep = keep.min(base.len());
        let mut bytes = base[..keep].to_vec();
        bytes.extend_from_slice(&tail);
        bytes.resize(bytes.len().max(base.len()), 0);
        parse_directly(&bytes, &Limits::default());
        analyze("fuzz.elf", bytes, &Config::default());
    }

    /// A tiny parser budget only ever produces budget errors, never a panic.
    #[test]
    fn tiny_budget_is_enforced(
        idx in 0usize..1000,
        steps in 0u64..64,
        mutations in prop::collection::vec(mutation(), 0..4),
    ) {
        let mut config = Config::default();
        config.limits.max_parser_steps = steps;
        let bytes = apply(corpus()[idx % corpus().len()].clone(), &mutations);
        let r = analyze("fuzz.elf", bytes, &config);
        prop_assert!(budget_errors_report_the_limit(&r, steps), "{:?}", r.errors);
    }

    /// With an expired deadline every analyzer is skipped quickly.
    #[test]
    fn expired_deadline_skips_everything(
        idx in 0usize..1000,
        mutations in prop::collection::vec(mutation(), 0..4),
    ) {
        let bytes = apply(corpus()[idx % corpus().len()].clone(), &mutations);
        let r = expired_deadline_report("fuzz.elf", bytes);
        prop_assert!(r.findings.is_empty());
        prop_assert!(only_timeouts(&r), "non-timeout error: {:?}", r.errors);
    }
}

/// Every fixture needs some budget: with none, the bounded parsers stop with
/// a `max_parser_steps` error instead of reading anything.
#[test]
fn zero_budget_stops_the_bounded_parsers() {
    let mut config = Config::default();
    config.limits.max_parser_steps = 0;
    let bytes = rtriage_fixtures::elf::profiles::glibc_pie().build().bytes;
    let r = analyze("t.elf", bytes, &config);
    let budget_errors: Vec<_> = r
        .errors
        .iter()
        .filter(|e| {
            matches!(&e.error, AnalysisError::LimitExceeded { limit, .. } if *limit == "max_parser_steps")
        })
        .map(|e| e.analyzer)
        .collect();
    assert!(!budget_errors.is_empty(), "{:?}", r.errors);
    check_report(&r);
}

/// Header counts far beyond the limits are clean errors, not allocations.
#[test]
fn huge_header_counts_are_rejected_cleanly() {
    let base = rtriage_fixtures::elf::profiles::glibc_pie().build().bytes;
    // ELF64 LE: e_phnum at 0x38, e_shnum at 0x3c.
    for (at, value) in [(0x38usize, 0xFFFFu16), (0x3c, 0xFFFF), (0x38, 0), (0x3c, 0)] {
        let mut bytes = base.clone();
        bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
        let start = Instant::now();
        let r = analyze("t.elf", bytes, &Config::default());
        assert!(start.elapsed() < Duration::from_secs(5));
        check_report(&r);
    }
}

/// The deadline bounds wall time even on large inputs.
#[test]
fn large_input_respects_a_short_deadline() {
    let mut bytes = rtriage_fixtures::elf::profiles::busybox_static()
        .build()
        .bytes;
    bytes.extend(noise(16 << 20));
    let mut config = Config::default();
    config.limits.max_analysis_time = Duration::from_millis(1);
    let start = Instant::now();
    let r = analyze("fuzz.elf", bytes, &config);
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "analysis took {elapsed:?} with a 1 ms deadline"
    );
    assert!(r
        .errors
        .iter()
        .any(|e| matches!(e.error, AnalysisError::Timeout { .. })));
}

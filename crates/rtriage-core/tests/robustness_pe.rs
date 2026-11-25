//! Property tests: hostile PE input must never panic, must respect the
//! deadline and the parser budget, and must always yield a coherent report.
//!
//! Inputs are synthetic fixtures (every PE feature the builder supports) with
//! random mutations biased towards header fields, plus raw random bytes behind
//! a valid `MZ`/`PE` prefix so goblin and the PE parsers are actually reached.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

mod common;

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use common::{
    analyze, apply, budget_errors_report_the_limit, cases, expired_deadline_report, mutation,
    noise, only_timeouts,
};
use proptest::prelude::*;
use rtriage_core::{AnalysisError, Config};

/// The shared synthetic corpus (see `rtriage_fixtures::pe::corpus`), built once.
fn corpus() -> &'static [Vec<u8>] {
    static CORPUS: OnceLock<Vec<Vec<u8>>> = OnceLock::new();
    CORPUS.get_or_init(|| {
        rtriage_fixtures::pe::corpus()
            .into_iter()
            .map(|(_, bytes)| bytes)
            .collect()
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases()))]

    /// Mutated fixtures never panic and always yield a coherent report.
    #[test]
    fn mutated_fixtures_never_panic(
        idx in 0usize..1000,
        mutations in prop::collection::vec(mutation(), 1..12),
    ) {
        let base = &corpus()[idx % corpus().len()];
        analyze("fuzz.exe", apply(base.clone(), &mutations), &Config::default());
    }

    /// Random bytes behind a valid MZ/PE prefix reach the PE parsers.
    #[test]
    fn random_pe_bodies_never_panic(body in prop::collection::vec(any::<u8>(), 0..4096)) {
        let mut bytes = vec![0u8; 0x40];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        bytes.extend_from_slice(b"PE\0\0");
        bytes.extend_from_slice(&body);
        analyze("fuzz.exe", bytes, &Config::default());
    }

    /// Completely arbitrary input.
    #[test]
    fn arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
        analyze("fuzz.bin", bytes, &Config::default());
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
        let base = &corpus()[idx % corpus().len()];
        let r = analyze("fuzz.exe", apply(base.clone(), &mutations), &config);
        prop_assert!(budget_errors_report_the_limit(&r, steps), "{:?}", r.errors);
    }

    /// With an expired deadline every analyzer is skipped quickly.
    #[test]
    fn expired_deadline_skips_everything(
        idx in 0usize..1000,
        mutations in prop::collection::vec(mutation(), 0..4),
    ) {
        let base = &corpus()[idx % corpus().len()];
        let r = expired_deadline_report("fuzz.exe", apply(base.clone(), &mutations));
        prop_assert!(r.findings.is_empty());
        prop_assert!(only_timeouts(&r), "non-timeout error: {:?}", r.errors);
    }
}

/// The deadline bounds wall time even on large inputs.
#[test]
fn large_input_respects_a_short_deadline() {
    // 16 MiB of deterministic pseudo-random data behind a PE prefix.
    let mut bytes = corpus()[0].clone();
    bytes.extend(noise(16 << 20));
    let mut config = Config::default();
    config.limits.max_analysis_time = Duration::from_millis(1);
    let start = Instant::now();
    let r = analyze("fuzz.exe", bytes, &config);
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

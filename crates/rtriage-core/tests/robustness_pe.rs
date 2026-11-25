//! Property tests: hostile PE input must never panic, must respect the
//! deadline and the parser budget, and must always yield a coherent report.
//!
//! Inputs are synthetic fixtures (every PE feature the builder supports) with
//! random mutations biased towards header fields, plus raw random bytes behind
//! a valid `MZ`/`PE` prefix so goblin and the PE parsers are actually reached.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use proptest::prelude::*;
use rtriage_core::{AnalysisError, Config, Deadline, Input, Registry, Report};

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

/// Cases per property: `PROPTEST_CASES` if set (for long local runs), else 300.
fn cases() -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300)
}

#[derive(Debug, Clone)]
enum Mutation {
    /// Overwrite one byte.
    Byte { pos: usize, value: u8 },
    /// Overwrite a little-endian dword with an edge value.
    Dword { pos: usize, value: u32 },
    /// Cut the file.
    Truncate { len: usize },
}

/// Positions are biased: half land in the first 1 KiB (headers, directories).
fn position() -> impl Strategy<Value = usize> {
    prop_oneof![0usize..0x400, any::<usize>()]
}

fn edge_u32() -> impl Strategy<Value = u32> {
    prop_oneof![
        Just(0u32),
        Just(1),
        Just(0x7FFF_FFFF),
        Just(0x8000_0000),
        Just(u32::MAX),
        Just(0xFFFF),
        0u32..0x2000,
        any::<u32>(),
    ]
}

fn mutation() -> impl Strategy<Value = Mutation> {
    prop_oneof![
        4 => (position(), any::<u8>()).prop_map(|(pos, value)| Mutation::Byte { pos, value }),
        4 => (position(), edge_u32()).prop_map(|(pos, value)| Mutation::Dword { pos, value }),
        1 => any::<usize>().prop_map(|len| Mutation::Truncate { len }),
    ]
}

fn apply(mut bytes: Vec<u8>, mutations: &[Mutation]) -> Vec<u8> {
    for m in mutations {
        if bytes.is_empty() {
            break;
        }
        match *m {
            Mutation::Byte { pos, value } => {
                let p = pos % bytes.len();
                bytes[p] = value;
            }
            Mutation::Dword { pos, value } => {
                let p = pos % bytes.len();
                let end = (p + 4).min(bytes.len());
                bytes[p..end].copy_from_slice(&value.to_le_bytes()[..end - p]);
            }
            Mutation::Truncate { len } => bytes.truncate(len % (bytes.len() + 1)),
        }
    }
    bytes
}

/// Invariants every report must satisfy, whatever the input.
fn check_report(r: &Report) {
    let sum: u32 = r.risk.breakdown.iter().map(|e| e.points).sum();
    assert_eq!(sum, r.risk.score, "score must equal the breakdown sum");
    assert_eq!(r.risk.breakdown.len(), r.findings.len());
    assert!(r.risk.breakdown.iter().all(|e| e.points <= e.table_points));
    // Findings stay sorted: severity desc, confidence desc, id asc.
    for w in r.findings.windows(2) {
        let key = |f: &rtriage_core::Finding| {
            (
                std::cmp::Reverse(f.severity),
                std::cmp::Reverse(f.confidence),
                f.id,
            )
        };
        assert!(key(&w[0]) <= key(&w[1]));
    }
    // A suppressed finding can never be an API group.
    assert!(r
        .findings
        .iter()
        .all(|f| f.suppressed.is_none() || !f.id.starts_with("PE-API-")));
}

fn analyze(bytes: Vec<u8>, config: &Config) -> Report {
    let report = Registry::default().analyze(&Input::from_bytes("fuzz.exe", bytes), config);
    check_report(&report);
    report
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
        analyze(apply(base.clone(), &mutations), &Config::default());
    }

    /// Random bytes behind a valid MZ/PE prefix reach the PE parsers.
    #[test]
    fn random_pe_bodies_never_panic(body in prop::collection::vec(any::<u8>(), 0..4096)) {
        let mut bytes = vec![0u8; 0x40];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        bytes.extend_from_slice(b"PE\0\0");
        bytes.extend_from_slice(&body);
        analyze(bytes, &Config::default());
    }

    /// Completely arbitrary input.
    #[test]
    fn arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
        analyze(bytes, &Config::default());
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
        let r = analyze(apply(base.clone(), &mutations), &config);
        for e in &r.errors {
            if let AnalysisError::LimitExceeded { limit, max, .. } = &e.error {
                if *limit == "max_parser_steps" {
                    prop_assert_eq!(*max, steps);
                }
            }
        }
    }

    /// With an expired deadline every analyzer is skipped quickly.
    #[test]
    fn expired_deadline_skips_everything(
        idx in 0usize..1000,
        mutations in prop::collection::vec(mutation(), 0..4),
    ) {
        let base = &corpus()[idx % corpus().len()];
        let input = Input::from_bytes("fuzz.exe", apply(base.clone(), &mutations));
        let r = Registry::default().analyze_with_deadline(&input, &Config::default(), Deadline::expired());
        check_report(&r);
        prop_assert!(r.findings.is_empty());
        let all_timeouts = r.errors.iter().all(|e| matches!(e.error, AnalysisError::Timeout { .. }));
        prop_assert!(all_timeouts, "non-timeout error: {:?}", r.errors);
    }
}

/// The deadline bounds wall time even on large inputs.
#[test]
fn large_input_respects_a_short_deadline() {
    // 16 MiB of deterministic pseudo-random data behind a PE prefix.
    let mut bytes = corpus()[0].clone();
    let mut x: u32 = 0x1234_5678;
    bytes.extend((0..16 << 20).map(|_| {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        x as u8
    }));
    let mut config = Config::default();
    config.limits.max_analysis_time = Duration::from_millis(1);
    let start = Instant::now();
    let r = analyze(bytes, &config);
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

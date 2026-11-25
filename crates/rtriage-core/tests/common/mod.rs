//! Shared helpers for the robustness property tests: mutation strategies and
//! the invariants every report must satisfy, whatever the input.
#![allow(dead_code, clippy::unwrap_used, clippy::indexing_slicing)]

use proptest::prelude::*;
use rtriage_core::{AnalysisError, Config, Deadline, Finding, Input, Registry, Report};

/// Cases per property: `PROPTEST_CASES` if set (for long local runs), else 300.
pub fn cases() -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300)
}

/// One edit to a fixture.
#[derive(Debug, Clone)]
pub enum Mutation {
    /// Overwrite one byte.
    Byte { pos: usize, value: u8 },
    /// Overwrite a dword with an edge value, in either byte order.
    Dword { pos: usize, value: u32, big: bool },
    /// Overwrite a qword with an edge value (ELF64 offsets, sizes, addresses).
    Qword { pos: usize, value: u64, big: bool },
    /// Cut the file.
    Truncate { len: usize },
}

/// Positions are biased: half land in the first 1 KiB (headers, tables).
pub fn position() -> impl Strategy<Value = usize> {
    prop_oneof![0usize..0x400, any::<usize>()]
}

/// Values that tend to break size and offset arithmetic.
pub fn edge_u32() -> impl Strategy<Value = u32> {
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

/// 64-bit edge values.
pub fn edge_u64() -> impl Strategy<Value = u64> {
    prop_oneof![
        Just(0u64),
        Just(1),
        Just(u64::MAX),
        Just(i64::MAX as u64),
        Just(u64::from(u32::MAX)),
        Just(u64::from(u32::MAX) + 1),
        0u64..0x2000,
        any::<u64>(),
    ]
}

/// Any mutation, weighted towards field overwrites.
pub fn mutation() -> impl Strategy<Value = Mutation> {
    prop_oneof![
        4 => (position(), any::<u8>()).prop_map(|(pos, value)| Mutation::Byte { pos, value }),
        4 => (position(), edge_u32(), any::<bool>())
            .prop_map(|(pos, value, big)| Mutation::Dword { pos, value, big }),
        2 => (position(), edge_u64(), any::<bool>())
            .prop_map(|(pos, value, big)| Mutation::Qword { pos, value, big }),
        1 => any::<usize>().prop_map(|len| Mutation::Truncate { len }),
    ]
}

fn write(bytes: &mut [u8], pos: usize, value: &[u8]) {
    let p = pos % bytes.len();
    let end = (p + value.len()).min(bytes.len());
    bytes[p..end].copy_from_slice(&value[..end - p]);
}

/// Applies `mutations` in order; positions wrap around the current length.
pub fn apply(mut bytes: Vec<u8>, mutations: &[Mutation]) -> Vec<u8> {
    for m in mutations {
        if bytes.is_empty() {
            break;
        }
        match *m {
            Mutation::Byte { pos, value } => write(&mut bytes, pos, &[value]),
            Mutation::Dword { pos, value, big } => {
                let b = if big {
                    value.to_be_bytes()
                } else {
                    value.to_le_bytes()
                };
                write(&mut bytes, pos, &b);
            }
            Mutation::Qword { pos, value, big } => {
                let b = if big {
                    value.to_be_bytes()
                } else {
                    value.to_le_bytes()
                };
                write(&mut bytes, pos, &b);
            }
            Mutation::Truncate { len } => bytes.truncate(len % (bytes.len() + 1)),
        }
    }
    bytes
}

/// Invariants every report must satisfy, whatever the input.
pub fn check_report(r: &Report) {
    let sum: u32 = r.risk.breakdown.iter().map(|e| e.points).sum();
    assert_eq!(sum, r.risk.score, "score must equal the breakdown sum");
    assert_eq!(r.risk.breakdown.len(), r.findings.len());
    assert!(r.risk.breakdown.iter().all(|e| e.points <= e.table_points));
    // Findings stay sorted: severity desc, confidence desc, id asc.
    for w in r.findings.windows(2) {
        let key = |f: &Finding| {
            (
                std::cmp::Reverse(f.severity),
                std::cmp::Reverse(f.confidence),
                f.id,
            )
        };
        assert!(key(&w[0]) <= key(&w[1]));
    }
    // API behavior groups are never suppressed, in either format.
    assert!(r.findings.iter().all(|f| f.suppressed.is_none()
        || !(f.id.starts_with("PE-API-") || f.id.starts_with("ELF-API-"))));
}

/// Full analysis plus [`check_report`].
pub fn analyze(name: &str, bytes: Vec<u8>, config: &Config) -> Report {
    let report = Registry::default().analyze(&Input::from_bytes(name, bytes), config);
    check_report(&report);
    report
}

/// Every `max_parser_steps` error reports the configured limit.
pub fn budget_errors_report_the_limit(r: &Report, steps: u64) -> bool {
    r.errors.iter().all(|e| match &e.error {
        AnalysisError::LimitExceeded { limit, max, .. } if *limit == "max_parser_steps" => {
            *max == steps
        }
        _ => true,
    })
}

/// Analysis under an already expired deadline: no findings, only timeouts.
pub fn expired_deadline_report(name: &str, bytes: Vec<u8>) -> Report {
    let input = Input::from_bytes(name, bytes);
    let r =
        Registry::default().analyze_with_deadline(&input, &Config::default(), Deadline::expired());
    check_report(&r);
    r
}

/// `true` if every recorded error is a timeout.
pub fn only_timeouts(r: &Report) -> bool {
    r.errors
        .iter()
        .all(|e| matches!(e.error, AnalysisError::Timeout { .. }))
}

/// Deterministic pseudo-random bytes (xorshift), for large inputs.
pub fn noise(len: usize) -> Vec<u8> {
    let mut x: u32 = 0x1234_5678;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

//! Shannon entropy of the whole file and detection of high-entropy regions.
//!
//! The file is split into non-overlapping windows of
//! [`Thresholds::entropy_window`](crate::config::Thresholds::entropy_window)
//! bytes. Consecutive windows at or above
//! [`Thresholds::entropy_high`](crate::config::Thresholds::entropy_high) are
//! merged into one [`EntropyRegion`]. A trailing partial window is ignored:
//! entropy of a short buffer is biased low and would be misleading.
//!
//! This analyzer only records facts. Judging them (packed? encrypted payload?)
//! is left to format-aware analyzers, which know where sections and resources are.

use super::{AnalysisContext, Analyzer};
use crate::deadline::Deadline;
use crate::error::AnalysisError;
use crate::report::{EntropyFacts, EntropyRegion, Format, ReportBuilder};

/// Bytes hashed into the histogram between deadline checks.
const DEADLINE_CHUNK: usize = 1 << 20;
/// Windows evaluated between deadline checks.
const WINDOWS_PER_CHECK: usize = 256;

/// Records [`EntropyFacts`] for every input, regardless of format.
#[derive(Debug, Clone, Copy, Default)]
pub struct EntropyAnalyzer;

impl Analyzer for EntropyAnalyzer {
    fn name(&self) -> &'static str {
        "entropy"
    }

    fn applies_to(&self, _format: Format) -> bool {
        true
    }

    fn run(&self, ctx: &AnalysisContext<'_>, out: &mut ReportBuilder) -> Result<(), AnalysisError> {
        let data = &ctx.input.data;
        let window = ctx.config.thresholds.entropy_window.get();
        let threshold = ctx.config.thresholds.entropy_high;
        out.facts.entropy = Some(EntropyFacts {
            whole_file: shannon_bounded(data, &ctx.deadline)?,
            window: to_u64(window),
            high_threshold: threshold,
            high_regions: high_regions(data, window, threshold, &ctx.deadline)?,
        });
        Ok(())
    }
}

/// Shannon entropy of `data` in bits per byte, in `0.0..=8.0`. Empty input is `0.0`.
///
/// Unbounded single pass: use [`shannon_bounded`] for data of file size.
pub fn shannon(data: &[u8]) -> f64 {
    let mut counts = [0u64; 256];
    count_bytes(data, &mut counts);
    entropy_of(&counts, data.len())
}

/// [`shannon`] that checks `deadline` every MiB.
///
/// # Errors
/// [`AnalysisError::Timeout`] if the deadline passes.
pub fn shannon_bounded(data: &[u8], deadline: &Deadline) -> Result<f64, AnalysisError> {
    let mut counts = [0u64; 256];
    for chunk in data.chunks(DEADLINE_CHUNK) {
        deadline.check()?;
        count_bytes(chunk, &mut counts);
    }
    Ok(entropy_of(&counts, data.len()))
}

fn count_bytes(data: &[u8], counts: &mut [u64; 256]) {
    for &b in data {
        if let Some(c) = counts.get_mut(usize::from(b)) {
            *c += 1;
        }
    }
}

fn entropy_of(counts: &[u64; 256], total: usize) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let len = total as f64;
    let h: f64 = counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum();
    // Normalise -0.0 / float noise so output is stable.
    if h <= 0.0 {
        0.0
    } else {
        h.min(8.0)
    }
}

/// Merges consecutive full windows with entropy >= `threshold` into regions.
///
/// `window` must be non-zero (guaranteed by `NonZeroUsize` in the config).
fn high_regions(
    data: &[u8],
    window: usize,
    threshold: f64,
    deadline: &Deadline,
) -> Result<Vec<EntropyRegion>, AnalysisError> {
    if window == 0 {
        return Ok(Vec::new());
    }
    let mut spans: Vec<(usize, usize)> = Vec::new();
    let mut offset = 0usize;
    for (i, chunk) in data.chunks_exact(window).enumerate() {
        if i % WINDOWS_PER_CHECK == 0 {
            deadline.check()?;
        }
        let end = offset.saturating_add(window);
        if shannon(chunk) >= threshold {
            match spans.last_mut() {
                Some((_, last_end)) if *last_end == offset => *last_end = end,
                _ => spans.push((offset, end)),
            }
        }
        offset = end;
    }
    let mut regions = Vec::with_capacity(spans.len());
    for (start, end) in spans {
        let Some(bytes) = data.get(start..end) else {
            continue;
        };
        regions.push(EntropyRegion {
            offset: to_u64(start),
            len: to_u64(end - start),
            entropy: shannon_bounded(bytes, deadline)?,
        });
    }
    Ok(regions)
}

/// `usize` -> `u64`; lossless on all supported (<= 64-bit) targets.
fn to_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::input::Input;
    use crate::Registry;

    const W: usize = 4096;
    const HIGH: f64 = 7.2;

    /// Every byte value equally often: entropy exactly 8.0.
    fn uniform(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 256) as u8).collect()
    }

    fn approx(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-9
    }

    /// Shadows the real `high_regions` for tests that don't care about deadlines.
    fn high_regions(data: &[u8], window: usize, threshold: f64) -> Vec<EntropyRegion> {
        super::high_regions(data, window, threshold, &Deadline::never()).unwrap()
    }

    #[test]
    fn bounded_matches_unbounded() {
        let data = uniform(3 * DEADLINE_CHUNK + 17);
        let b = shannon_bounded(&data, &Deadline::never()).unwrap();
        assert!(approx(b, shannon(&data)));
    }

    #[test]
    fn expired_deadline_stops_entropy() {
        assert!(matches!(
            shannon_bounded(&[1, 2, 3], &Deadline::expired()),
            Err(AnalysisError::Timeout { .. })
        ));
        assert!(super::high_regions(&uniform(W), W, HIGH, &Deadline::expired()).is_err());
    }

    #[test]
    fn shannon_edge_values() {
        assert_eq!(shannon(b""), 0.0);
        assert_eq!(shannon(&[0x41; 1000]), 0.0);
        assert!(approx(shannon(b"abababab"), 1.0));
        assert!(approx(shannon(&uniform(256)), 8.0));
    }

    #[test]
    fn shannon_never_negative_zero() {
        assert!(shannon(&[7; 10]).is_sign_positive());
    }

    #[test]
    fn finds_single_high_region_between_zeros() {
        let mut data = vec![0u8; W];
        data.extend(uniform(2 * W));
        data.extend(vec![0u8; W]);

        let regions = high_regions(&data, W, HIGH);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].offset, W as u64);
        assert_eq!(regions[0].len, 2 * W as u64);
        assert!(approx(regions[0].entropy, 8.0));
    }

    #[test]
    fn separated_regions_are_not_merged() {
        let mut data = uniform(W);
        data.extend(vec![0u8; W]);
        data.extend(uniform(W));

        let offsets: Vec<_> = high_regions(&data, W, HIGH)
            .iter()
            .map(|r| r.offset)
            .collect();
        assert_eq!(offsets, [0, 2 * W as u64]);
    }

    #[test]
    fn low_entropy_text_has_no_regions() {
        let text = b"The quick brown fox jumps over the lazy dog. ".repeat(400);
        assert!(high_regions(&text, W, HIGH).is_empty());
    }

    #[test]
    fn trailing_partial_window_is_ignored() {
        let mut data = vec![0u8; W];
        data.extend(uniform(W - 1));
        assert!(high_regions(&data, W, HIGH).is_empty());
    }

    #[test]
    fn file_smaller_than_window_has_whole_file_entropy_only() {
        let input = Input::from_bytes("small.bin", uniform(512));
        let report = Registry::default().analyze(&input, &Config::default());
        let e = report.facts.entropy.unwrap();
        assert!(approx(e.whole_file, 8.0));
        assert!(e.high_regions.is_empty());
        assert_eq!(e.window, W as u64);
    }

    #[test]
    fn empty_file_is_fine() {
        let input = Input::from_bytes("empty.bin", Vec::new());
        let report = Registry::default().analyze(&input, &Config::default());
        let e = report.facts.entropy.unwrap();
        assert_eq!(e.whole_file, 0.0);
        assert!(e.high_regions.is_empty());
        assert!(report.errors.is_empty());
    }
}

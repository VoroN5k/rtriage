//! ASCII and UTF-16LE string extraction.
//!
//! A string is a run of at least [`Config::strings_min_len`](crate::config::Config::strings_min_len)
//! printable characters (`0x20..=0x7e` plus tab):
//! - **ASCII**: one byte per character.
//! - **UTF-16LE**: a printable ASCII byte followed by `0x00`, scanned at both
//!   even and odd alignments. Non-ASCII UTF-16 is not extracted (too noisy in
//!   binary data).
//!
//! Hostile-input safety: runs are tracked as offsets, and at most
//! `max_string_len` characters of any string are ever copied, so a 512 MiB run
//! of `A` costs one bounded allocation. At most `max_strings` strings are kept;
//! the rest are only counted.

pub mod classify;

use super::{AnalysisContext, Analyzer};
use crate::config::Config;
use crate::deadline::Deadline;
use crate::error::AnalysisError;
use crate::input::Input;
use crate::report::{
    ExtractedString, Format, ReportBuilder, StringEncoding, StringsFacts, StringsIncluded,
};

/// Bytes (or UTF-16 units) scanned between deadline checks. Power of two.
const DEADLINE_CHUNK: usize = 1 << 16;
/// Strings classified between deadline checks.
const CLASSIFY_CHUNK: usize = 1024;

/// Publishes the context's shared [`StringsFacts`] into the report.
///
/// Extraction itself happens once in [`AnalysisContext::strings`], so other
/// analyzers can use the same strings without depending on this one.
#[derive(Debug, Clone, Copy, Default)]
pub struct StringsAnalyzer;

impl Analyzer for StringsAnalyzer {
    fn name(&self) -> &'static str {
        "strings"
    }

    fn applies_to(&self, _format: Format) -> bool {
        true
    }

    fn run(&self, ctx: &AnalysisContext<'_>, out: &mut ReportBuilder) -> Result<(), AnalysisError> {
        out.facts.strings = Some(ctx.strings()?.clone());
        Ok(())
    }
}

/// Extracts and classifies strings of `input` using `config`'s limits.
///
/// # Errors
/// [`AnalysisError::Timeout`] if `deadline` passes, [`AnalysisError::Internal`]
/// if a built-in classifier pattern failed to compile.
pub fn extract_classified(
    input: &Input,
    config: &Config,
    deadline: &Deadline,
) -> Result<StringsFacts, AnalysisError> {
    let opts = Options {
        min_len: config.strings_min_len.get(),
        max_len: config.limits.max_string_len,
        max_items: config.limits.max_strings,
    };
    let mut facts = extract(&input.data, opts, deadline)?;
    let classifier = classify::classifier().map_err(|e| AnalysisError::Internal {
        reason: format!("string classifier failed to build: {e}"),
    })?;
    for chunk in facts.items.chunks_mut(CLASSIFY_CHUNK) {
        deadline.check()?;
        for s in chunk {
            s.kinds = classifier.classify(&s.value);
        }
    }
    Ok(facts)
}

/// Extraction parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// Minimum run length in characters (values below 1 are treated as 1).
    pub min_len: usize,
    /// Characters copied per string; longer strings are truncated.
    pub max_len: usize,
    /// Strings kept; further strings are only counted.
    pub max_items: usize,
}

/// Extracts ASCII and UTF-16LE strings from `data`, sorted by offset.
///
/// # Errors
/// [`AnalysisError::Timeout`] if `deadline` passes during the scan.
pub fn extract(
    data: &[u8],
    opts: Options,
    deadline: &Deadline,
) -> Result<StringsFacts, AnalysisError> {
    let mut c = Collector::new(opts);
    scan_ascii(data, &mut c, deadline)?;
    scan_utf16le(data, 0, &mut c, deadline)?;
    scan_utf16le(data, 1, &mut c, deadline)?;
    Ok(c.finish())
}

/// Printable ASCII plus horizontal tab.
fn is_printable(b: u8) -> bool {
    matches!(b, 0x20..=0x7e | b'\t')
}

/// Accumulates strings while enforcing limits.
struct Collector {
    opts: Options,
    total: u64,
    items: Vec<ExtractedString>,
}

impl Collector {
    fn new(opts: Options) -> Self {
        Self {
            opts: Options {
                min_len: opts.min_len.max(1),
                ..opts
            },
            total: 0,
            items: Vec::new(),
        }
    }

    /// Records a run of `len` characters at `offset`. `chars` yields the
    /// characters lazily, so only `max_len` of them are ever materialised.
    fn push(
        &mut self,
        offset: usize,
        len: usize,
        encoding: StringEncoding,
        chars: impl Iterator<Item = char>,
    ) {
        if len < self.opts.min_len {
            return;
        }
        self.total = self.total.saturating_add(1);
        if self.items.len() >= self.opts.max_items {
            return;
        }
        let value: String = chars.take(self.opts.max_len).collect();
        self.items.push(ExtractedString {
            offset: to_u64(offset),
            encoding,
            len: to_u64(len),
            value,
            truncated: len > self.opts.max_len,
            kinds: Vec::new(),
        });
    }

    fn finish(mut self) -> StringsFacts {
        // ASCII is scanned first, so it can fill the cap before UTF-16 is seen.
        // That bias only matters once the limit is hit, which is flagged.
        self.items
            .sort_by(|a, b| a.offset.cmp(&b.offset).then(enc_rank(a).cmp(&enc_rank(b))));
        StringsFacts {
            min_len: to_u64(self.opts.min_len),
            limit_reached: self.total > to_u64(self.items.len()),
            total: self.total,
            items_included: StringsIncluded::All,
            items: self.items,
        }
    }
}

fn enc_rank(s: &ExtractedString) -> u8 {
    match s.encoding {
        StringEncoding::Ascii => 0,
        StringEncoding::Utf16Le => 1,
    }
}

fn scan_ascii(data: &[u8], c: &mut Collector, deadline: &Deadline) -> Result<(), AnalysisError> {
    let mut start: Option<usize> = None;
    for (i, &b) in data.iter().enumerate() {
        if i % DEADLINE_CHUNK == 0 {
            deadline.check()?;
        }
        match (is_printable(b), start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                emit_ascii(data, s, i, c);
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        emit_ascii(data, s, data.len(), c);
    }
    Ok(())
}

fn emit_ascii(data: &[u8], start: usize, end: usize, c: &mut Collector) {
    let bytes = data.get(start..end).unwrap_or_default();
    c.push(
        start,
        bytes.len(),
        StringEncoding::Ascii,
        bytes.iter().map(|&b| char::from(b)),
    );
}

/// Scans 2-byte units starting at byte `align` (0 or 1).
fn scan_utf16le(
    data: &[u8],
    align: usize,
    c: &mut Collector,
    deadline: &Deadline,
) -> Result<(), AnalysisError> {
    let body = data.get(align..).unwrap_or_default();
    // Start index (in units) of the current run.
    let mut start: Option<usize> = None;
    let mut units = 0usize;
    for (k, unit) in body.chunks_exact(2).enumerate() {
        if k % DEADLINE_CHUNK == 0 {
            deadline.check()?;
        }
        units = k + 1;
        let is_char = matches!(unit, [lo, 0] if is_printable(*lo));
        match (is_char, start) {
            (true, None) => start = Some(k),
            (false, Some(s)) => {
                emit_utf16(body, align, s, k, c);
                start = None;
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        emit_utf16(body, align, s, units, c);
    }
    Ok(())
}

/// Emits units `start..end` of `body` (which begins at file offset `align`).
fn emit_utf16(body: &[u8], align: usize, start: usize, end: usize, c: &mut Collector) {
    let byte_start = start.saturating_mul(2);
    let byte_end = end.saturating_mul(2);
    let bytes = body.get(byte_start..byte_end).unwrap_or_default();
    c.push(
        align.saturating_add(byte_start),
        end.saturating_sub(start),
        StringEncoding::Utf16Le,
        bytes
            .chunks_exact(2)
            .filter_map(|u| u.first())
            .map(|&b| char::from(b)),
    );
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

    /// Shadows the real `extract` for tests that don't care about deadlines.
    fn extract(data: &[u8], opts: Options) -> StringsFacts {
        super::extract(data, opts, &Deadline::never()).unwrap()
    }

    #[test]
    fn expired_deadline_stops_extraction() {
        let data = vec![b'A'; 3 * DEADLINE_CHUNK];
        assert!(matches!(
            super::extract(&data, OPTS, &Deadline::expired()),
            Err(AnalysisError::Timeout { .. })
        ));
    }

    const OPTS: Options = Options {
        min_len: 5,
        max_len: 4096,
        max_items: 1000,
    };

    fn utf16(s: &str) -> Vec<u8> {
        s.bytes().flat_map(|b| [b, 0]).collect()
    }

    fn values(f: &StringsFacts) -> Vec<(u64, StringEncoding, &str)> {
        f.items
            .iter()
            .map(|s| (s.offset, s.encoding, s.value.as_str()))
            .collect()
    }

    #[test]
    fn extracts_ascii_with_offset() {
        let f = extract(b"\x00\x01hello world\xff", OPTS);
        assert_eq!(values(&f), [(2, StringEncoding::Ascii, "hello world")]);
        assert_eq!(f.items[0].len, 11);
    }

    #[test]
    fn respects_min_len_boundary() {
        let f = extract(b"abcd\x00abcde\x00", OPTS);
        assert_eq!(values(&f), [(5, StringEncoding::Ascii, "abcde")]);
    }

    #[test]
    fn string_at_end_of_file_is_kept() {
        let f = extract(b"\x00\x00tail!", OPTS);
        assert_eq!(values(&f), [(2, StringEncoding::Ascii, "tail!")]);
    }

    #[test]
    fn tab_is_printable() {
        let f = extract(b"\x00a\tb\tc\x00", OPTS);
        assert_eq!(f.items[0].value, "a\tb\tc");
    }

    #[test]
    fn extracts_utf16le_even_alignment() {
        let mut data = vec![0xff, 0xfe];
        data.extend(utf16("C:\\Windows"));
        data.extend([0xff, 0xff]);
        let f = extract(&data, OPTS);
        assert_eq!(values(&f), [(2, StringEncoding::Utf16Le, "C:\\Windows")]);
        assert_eq!(f.items[0].len, 10);
    }

    #[test]
    fn extracts_utf16le_odd_alignment() {
        let mut data = vec![0xff];
        data.extend(utf16("kernel32"));
        data.push(0xff);
        let f = extract(&data, OPTS);
        assert_eq!(values(&f), [(1, StringEncoding::Utf16Le, "kernel32")]);
    }

    #[test]
    fn mixed_encodings_sorted_by_offset() {
        let mut data = utf16("second");
        data.extend([0xff, 0xff]);
        data.extend(b"third!");
        data.push(0xff);
        let mut all = b"first\xff".to_vec();
        all.extend(data);
        let f = extract(&all, OPTS);
        assert_eq!(
            values(&f),
            [
                (0, StringEncoding::Ascii, "first"),
                (6, StringEncoding::Utf16Le, "second"),
                (20, StringEncoding::Ascii, "third!"),
            ]
        );
    }

    #[test]
    fn long_string_is_truncated() {
        let data = vec![b'A'; 10_000];
        let f = extract(
            &data,
            Options {
                max_len: 16,
                ..OPTS
            },
        );
        assert_eq!(f.items.len(), 1);
        assert_eq!(f.items[0].value.len(), 16);
        assert_eq!(f.items[0].len, 10_000);
        assert!(f.items[0].truncated);
    }

    #[test]
    fn max_items_caps_but_counts_all() {
        let data = b"aaaaa\x00".repeat(10);
        let f = extract(
            &data,
            Options {
                max_items: 3,
                ..OPTS
            },
        );
        assert_eq!(f.items.len(), 3);
        assert_eq!(f.total, 10);
        assert!(f.limit_reached);
    }

    #[test]
    fn non_printable_noise_yields_nothing() {
        let data: Vec<u8> = (0u8..=31).cycle().take(4096).collect();
        let f = extract(&data, OPTS);
        assert!(f.items.is_empty());
        assert_eq!(f.total, 0);
        assert!(!f.limit_reached);
    }

    #[test]
    fn empty_and_odd_length_inputs() {
        assert!(extract(b"", OPTS).items.is_empty());
        assert!(extract(b"\x00", OPTS).items.is_empty());
    }

    #[test]
    fn analyzer_uses_config() {
        let input = Input::from_bytes("s.bin", b"abc\x00abcdef\x00".to_vec());
        let config = Config {
            strings_min_len: std::num::NonZeroUsize::new(3).unwrap(),
            ..Config::default()
        };
        let report = Registry::default().analyze(&input, &config);
        let s = report.facts.strings.unwrap();
        assert_eq!(s.min_len, 3);
        assert_eq!(s.total, 2);
    }

    #[test]
    fn analyzer_classifies_strings() {
        // 0xff separator: without it ('e', 0x00) would glue onto the UTF-16 run.
        let mut data = b"\x00http://c2.evil.ru/gate\xff\xff".to_vec();
        data.extend(utf16(r"Software\Microsoft\Windows\CurrentVersion\Run"));
        let input = Input::from_bytes("c.bin", data);
        let report = Registry::default().analyze(&input, &Config::default());
        assert!(report.errors.is_empty());
        let kinds: Vec<_> = report
            .facts
            .strings
            .unwrap()
            .items
            .into_iter()
            .map(|s| s.kinds)
            .collect();
        use crate::report::StringKind::*;
        assert_eq!(kinds, [vec![Url, Domain], vec![RegistryKey]]);
    }
}

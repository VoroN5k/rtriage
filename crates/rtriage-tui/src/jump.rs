//! Evidence → the pane that shows it, and the way back.

use rtriage_core::analyzers::entropy::shannon;
use rtriage_core::{Evidence, Input, Report};

use crate::app::{Focus, Tab};
use crate::model;

/// Where an evidence item points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// A section header (index in the header table).
    Section {
        /// Header-table index.
        index: usize,
    },
    /// An imported symbol.
    Import {
        /// Providing library, if known.
        library: Option<String>,
        /// Symbol or `#ordinal`.
        symbol: String,
    },
    /// An extracted string by file offset.
    String {
        /// File offset of the string.
        offset: u64,
    },
    /// A byte range of the file.
    Range {
        /// Start offset.
        offset: u64,
        /// Length in bytes.
        len: u64,
    },
}

/// The target of `evidence`; `None` for values (metrics, fields).
pub fn target(evidence: &Evidence) -> Option<Target> {
    match evidence {
        Evidence::Section { index, .. } => Some(Target::Section { index: *index }),
        Evidence::Import { library, symbol } => Some(Target::Import {
            library: library.clone(),
            symbol: symbol.clone(),
        }),
        Evidence::String { offset, .. } => Some(Target::String { offset: *offset }),
        Evidence::Range { offset, len } => Some(Target::Range {
            offset: *offset,
            len: *len,
        }),
        _ => None,
    }
}

/// Resolves a target to a tab and row, or says why it cannot.
pub fn resolve(report: &Report, target: &Target) -> Result<(Tab, usize), String> {
    match target {
        Target::Section { index } => model::section_row(report, *index)
            .map(|row| (Tab::Sections, row))
            .ok_or_else(|| format!("section #{index} is not in the section table")),
        Target::Import { library, symbol } => model::import_row(report, library.as_deref(), symbol)
            .map(|row| (Tab::Imports, row))
            .ok_or_else(|| "import is not in the import table".to_owned()),
        Target::String { offset } => model::string_row(report, *offset)
            .map(|row| (Tab::Strings, row))
            .ok_or_else(|| {
                format!("string at 0x{offset:08x} is not in the extracted list (over the limit?)")
            }),
        Target::Range { .. } => Err("byte ranges are shown below the evidence list".to_owned()),
    }
}

/// A place to come back to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Location {
    /// Tab.
    pub tab: Tab,
    /// Selected row of the tab's main list.
    pub row: Option<usize>,
    /// Selected evidence row (Findings tab).
    pub evidence: Option<usize>,
    /// Focused pane (Findings tab).
    pub focus: Focus,
}

/// Back stack of jumps, oldest dropped beyond [`History::DEPTH`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct History {
    back: Vec<Location>,
}

impl History {
    /// Maximum number of remembered locations.
    pub const DEPTH: usize = 64;

    /// Remembers `loc`.
    pub fn push(&mut self, loc: Location) {
        if self.back.len() >= Self::DEPTH {
            self.back.remove(0);
        }
        self.back.push(loc);
    }

    /// The most recent location, removed.
    pub fn pop(&mut self) -> Option<Location> {
        self.back.pop()
    }

    /// Number of remembered locations.
    pub fn len(&self) -> usize {
        self.back.len()
    }

    /// `true` if there is nowhere to go back to.
    pub fn is_empty(&self) -> bool {
        self.back.is_empty()
    }
}

/// At most this many bytes of a range are used for its entropy.
pub const RANGE_ENTROPY_CAP: u64 = 16 << 20;

/// What the Findings pane shows for a byte-range evidence item.
#[derive(Debug, Clone, PartialEq)]
pub struct RangeInfo {
    /// Start offset.
    pub offset: u64,
    /// Length claimed by the evidence.
    pub len: u64,
    /// Section whose file bytes contain the start (raw name).
    pub section: Option<String>,
    /// Shannon entropy of the bytes present in the file (bits per byte).
    pub entropy: Option<f64>,
    /// Bytes of the range beyond the end of the file.
    pub past_eof: u64,
    /// `true` if the entropy covers only the first [`RANGE_ENTROPY_CAP`] bytes.
    pub sampled: bool,
}

/// Facts about `offset..offset+len` in `input`.
pub fn range_info(input: &Input, report: &Report, offset: u64, len: u64) -> RangeInfo {
    let size = input.size();
    let end = offset.saturating_add(len);
    let present_end = end.min(size);
    let sample_end = present_end.min(offset.saturating_add(RANGE_ENTROPY_CAP));
    let bytes = usize::try_from(offset)
        .ok()
        .zip(usize::try_from(sample_end).ok())
        .and_then(|(a, b)| input.data.get(a..b))
        .filter(|b| !b.is_empty());
    RangeInfo {
        offset,
        len,
        section: model::section_containing(report, offset).map(str::to_owned),
        entropy: bytes.map(shannon),
        past_eof: end.saturating_sub(size.max(offset)),
        sampled: present_end > sample_end,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::testkit::{analyze, suspicious_pe};

    fn loc(row: usize) -> Location {
        Location {
            tab: Tab::Findings,
            row: Some(row),
            evidence: None,
            focus: Focus::List,
        }
    }

    #[test]
    fn history_is_capped_and_drops_the_oldest() {
        let mut h = History::default();
        for i in 0..100 {
            h.push(loc(i));
        }
        assert_eq!(h.len(), History::DEPTH);
        let mut last = None;
        while let Some(l) = h.pop() {
            last = l.row;
        }
        assert_eq!(last, Some(100 - History::DEPTH), "oldest kept");
    }

    #[test]
    fn range_past_eof_is_reported() {
        let input = Input::from_bytes("t", vec![0u8; 100]);
        let report = analyze(&input);
        let r = range_info(&input, &report, 90, 50);
        assert_eq!(r.past_eof, 40);
        assert!(r.entropy.is_some());
        let r = range_info(&input, &report, 500, 10);
        assert_eq!((r.past_eof, r.entropy), (10, None));
        let r = range_info(&input, &report, u64::MAX, u64::MAX);
        assert_eq!(r.entropy, None);
        let r = range_info(&input, &report, 0, 0);
        assert_eq!((r.past_eof, r.entropy), (0, None));
    }

    #[test]
    fn range_inside_a_section_names_it() {
        let input = Input::from_bytes("t.exe", suspicious_pe());
        let report = analyze(&input);
        let pe = report.facts.pe.as_ref().unwrap();
        let evil = pe
            .sections
            .as_ref()
            .unwrap()
            .iter()
            .find(|s| s.name == ".evil")
            .unwrap()
            .raw_offset;
        let r = range_info(&input, &report, u64::from(evil) + 4, 8);
        assert_eq!(r.section.as_deref(), Some(".evil"));
    }

    #[test]
    fn values_have_no_target() {
        let metric = Evidence::Metric {
            name: "entropy",
            value: 1.0,
        };
        assert_eq!(target(&metric), None);
    }
}

//! Strings filter (classes and length) and the dialog that edits it.

use std::collections::BTreeSet;

use rtriage_core::report::{ExtractedString, StringKind};

use crate::view::snake;

/// Every string class, in dialog order.
pub const ALL_KINDS: [StringKind; 11] = [
    StringKind::Url,
    StringKind::Ipv4,
    StringKind::Ipv6,
    StringKind::Domain,
    StringKind::Email,
    StringKind::FilePath,
    StringKind::RegistryKey,
    StringKind::Base64,
    StringKind::SuspiciousCommand,
    StringKind::CryptoWallet,
    StringKind::UserAgent,
];

/// Longest length bound accepted from the dialog, in digits.
pub const MAX_LEN_DIGITS: usize = 9;

/// Which strings the Strings tab shows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StringFilter {
    /// Show strings with at least one of these classes; empty = any string.
    pub kinds: BTreeSet<StringKind>,
    /// Minimum length in characters.
    pub min_len: Option<u64>,
    /// Maximum length in characters.
    pub max_len: Option<u64>,
}

impl StringFilter {
    /// `true` if the filter hides anything.
    pub fn is_active(&self) -> bool {
        *self != StringFilter::default()
    }

    /// `true` if `s` passes the filter.
    pub fn admits(&self, s: &ExtractedString) -> bool {
        (self.kinds.is_empty() || s.kinds.iter().any(|k| self.kinds.contains(k)))
            && self.min_len.is_none_or(|m| s.len >= m)
            && self.max_len.is_none_or(|m| s.len <= m)
    }

    /// Short description for titles, e.g. `url,ipv4 · len 20..`.
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if !self.kinds.is_empty() {
            let kinds: Vec<String> = self.kinds.iter().map(snake).collect();
            parts.push(kinds.join(","));
        }
        match (self.min_len, self.max_len) {
            (None, None) => {}
            (min, max) => parts.push(format!(
                "len {}..{}",
                min.map(|m| m.to_string()).unwrap_or_default(),
                max.map(|m| m.to_string()).unwrap_or_default()
            )),
        }
        parts.join(" · ")
    }
}

/// Item indices of `items` that pass `filter`, in item (offset) order.
pub fn rebuild(items: &[ExtractedString], filter: &StringFilter) -> Vec<u32> {
    items
        .iter()
        .enumerate()
        .filter(|(_, s)| filter.admits(s))
        .filter_map(|(i, _)| u32::try_from(i).ok())
        .collect()
}

/// State of the open filter dialog: a draft applied with Enter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterDialog {
    /// Classes ticked so far.
    pub kinds: BTreeSet<StringKind>,
    /// Minimum length as typed.
    pub min_text: String,
    /// Maximum length as typed.
    pub max_text: String,
    /// Selected row: one per class, then minimum, then maximum.
    pub cursor: usize,
}

impl FilterDialog {
    /// Row of the minimum-length field.
    pub const MIN_ROW: usize = ALL_KINDS.len();
    /// Row of the maximum-length field.
    pub const MAX_ROW: usize = ALL_KINDS.len() + 1;

    /// A dialog prefilled with `current`.
    pub fn new(current: &StringFilter) -> FilterDialog {
        FilterDialog {
            kinds: current.kinds.clone(),
            min_text: current.min_len.map(|m| m.to_string()).unwrap_or_default(),
            max_text: current.max_len.map(|m| m.to_string()).unwrap_or_default(),
            cursor: 0,
        }
    }

    /// Moves the cursor by `delta` rows, clamped.
    pub fn move_by(&mut self, delta: isize) {
        self.cursor = self.cursor.saturating_add_signed(delta).min(Self::MAX_ROW);
    }

    /// Space: ticks or unticks the class under the cursor.
    pub fn toggle(&mut self) {
        if let Some(kind) = ALL_KINDS.get(self.cursor) {
            if !self.kinds.remove(kind) {
                self.kinds.insert(*kind);
            }
        }
    }

    /// The length field under the cursor, if any.
    fn field(&mut self) -> Option<&mut String> {
        match self.cursor {
            Self::MIN_ROW => Some(&mut self.min_text),
            Self::MAX_ROW => Some(&mut self.max_text),
            _ => None,
        }
    }

    /// Types a digit into the length field under the cursor.
    pub fn digit(&mut self, c: char) {
        if let Some(f) = self.field() {
            if c.is_ascii_digit() && f.len() < MAX_LEN_DIGITS {
                f.push(c);
            }
        }
    }

    /// Deletes the last digit of the length field under the cursor.
    pub fn backspace(&mut self) {
        if let Some(f) = self.field() {
            f.pop();
        }
    }

    /// The filter this dialog describes, or why it is invalid.
    pub fn to_filter(&self) -> Result<StringFilter, String> {
        let parse = |t: &str| -> Option<u64> { t.parse().ok() };
        let filter = StringFilter {
            kinds: self.kinds.clone(),
            min_len: parse(&self.min_text),
            max_len: parse(&self.max_text),
        };
        match (filter.min_len, filter.max_len) {
            (Some(min), Some(max)) if min > max => Err(format!(
                "minimum length {min} is greater than maximum {max}"
            )),
            _ => Ok(filter),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use rtriage_core::report::StringEncoding;

    fn s(len: u64, kinds: &[StringKind]) -> ExtractedString {
        ExtractedString {
            offset: 0,
            encoding: StringEncoding::Ascii,
            len,
            value: "x".repeat(usize::try_from(len).unwrap()),
            truncated: false,
            kinds: kinds.to_vec(),
        }
    }

    #[test]
    fn default_admits_everything() {
        let f = StringFilter::default();
        assert!(!f.is_active());
        assert!(f.admits(&s(1, &[])));
        assert_eq!(f.describe(), "");
    }

    #[test]
    fn kinds_are_any_of_and_lengths_are_inclusive() {
        let f = StringFilter {
            kinds: [StringKind::Url, StringKind::Ipv4].into(),
            min_len: Some(5),
            max_len: Some(10),
        };
        assert!(f.admits(&s(5, &[StringKind::Url, StringKind::Domain])));
        assert!(f.admits(&s(10, &[StringKind::Ipv4])));
        assert!(!f.admits(&s(11, &[StringKind::Url])));
        assert!(!f.admits(&s(4, &[StringKind::Url])));
        assert!(!f.admits(&s(7, &[StringKind::Email])));
        assert!(!f.admits(&s(7, &[])));
        assert_eq!(f.describe(), "url,ipv4 · len 5..10");
    }

    #[test]
    fn rebuild_keeps_item_order() {
        let items = [s(3, &[]), s(30, &[]), s(4, &[]), s(40, &[])];
        let f = StringFilter {
            min_len: Some(10),
            ..StringFilter::default()
        };
        assert_eq!(rebuild(&items, &f), [1, 3]);
    }

    #[test]
    fn dialog_edits_and_validates() {
        let mut d = FilterDialog::new(&StringFilter::default());
        d.toggle();
        d.move_by(1);
        d.toggle();
        d.toggle();
        assert_eq!(d.kinds, [StringKind::Url].into());
        d.digit('7');
        assert_eq!(d.min_text, "", "digits only go into length fields");
        d.move_by(100);
        assert_eq!(d.cursor, FilterDialog::MAX_ROW);
        for c in "1x2345678901".chars() {
            d.digit(c);
        }
        assert_eq!(d.max_text, "123456789", "digits only, capped");
        d.backspace();
        d.move_by(-1);
        d.digit('9');
        d.digit('9');
        d.digit('9');
        d.digit('9');
        d.digit('9');
        d.digit('9');
        d.digit('9');
        d.digit('9');
        d.digit('9');
        assert!(d.to_filter().unwrap_err().contains("greater than"));
        d.min_text = "20".into();
        let f = d.to_filter().unwrap();
        assert_eq!((f.min_len, f.max_len), (Some(20), Some(12_345_678)));
    }
}

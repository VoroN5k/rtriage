//! Read-only hex view state: a byte cursor, the first visible row and an
//! optional highlighted range. Pure; the view reads only the visible bytes.

use crate::jump::RangeInfo;

/// Bytes per hex row.
pub const ROW_BYTES: u64 = 16;

/// Longest text accepted by the go-to prompt.
pub const MAX_GOTO_CHARS: usize = 20;

/// Cursor and scroll of the hex view.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HexState {
    /// Offset of the byte under the cursor.
    pub cursor: u64,
    /// Offset of the first visible row (a multiple of [`ROW_BYTES`]).
    pub top: u64,
    /// Highlighted `start..end` (the range an evidence item points at).
    pub highlight: Option<(u64, u64)>,
    /// Details of the highlighted range.
    pub info: Option<RangeInfo>,
}

impl HexState {
    /// Moves the cursor by `delta` bytes within a file of `size` bytes and
    /// scrolls so it stays inside `rows` visible rows.
    pub fn move_by(&mut self, delta: i64, size: u64, rows: u64) {
        let last = size.saturating_sub(1);
        self.cursor = self.cursor.saturating_add_signed(delta).min(last);
        self.follow(rows);
    }

    /// Puts the cursor on `offset` (clamped) and scrolls to it.
    pub fn go_to(&mut self, offset: u64, size: u64, rows: u64) {
        self.cursor = offset.min(size.saturating_sub(1));
        self.follow(rows);
    }

    /// Jumps to `offset` (clamped) with its row at the top of the view, so
    /// what follows it is visible, unless that would scroll past the end.
    pub fn jump_to(&mut self, offset: u64, size: u64, rows: u64) {
        self.cursor = offset.min(size.saturating_sub(1));
        let rows = rows.max(1);
        let last_row = size.saturating_sub(1) / ROW_BYTES;
        let max_top_row = last_row.saturating_add(1).saturating_sub(rows);
        let top_row = (self.cursor / ROW_BYTES).min(max_top_row);
        self.top = top_row.saturating_mul(ROW_BYTES);
    }

    /// Scrolls just enough for the cursor row to be visible.
    pub fn follow(&mut self, rows: u64) {
        let rows = rows.max(1);
        let row = self.cursor / ROW_BYTES;
        let top_row = self.top / ROW_BYTES;
        let top_row = if row < top_row {
            row
        } else if row >= top_row.saturating_add(rows) {
            row.saturating_sub(rows - 1)
        } else {
            top_row
        };
        self.top = top_row.saturating_mul(ROW_BYTES);
    }

    /// `true` if `offset` is inside the highlighted range.
    pub fn is_highlighted(&self, offset: u64) -> bool {
        self.highlight
            .is_some_and(|(start, end)| (start..end).contains(&offset))
    }
}

/// Parses go-to text: `0x1f`/`0X1F` is hex, anything else decimal.
pub fn parse_offset(text: &str) -> Result<u64, String> {
    let t = text.trim();
    let parsed = match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => t.parse(),
    };
    parsed.map_err(|_| "not an offset: use decimal or 0x-prefixed hex".to_owned())
}

/// One hex row: `offset  xx xx … xx  xx … xx  |ascii|`. Bytes outside
/// 0x20..=0x7e are shown as `.` in the ASCII column, so no byte of the file
/// can reach the terminal as a control character.
pub fn ascii(byte: u8) -> char {
    if (0x20..=0x7e).contains(&byte) {
        char::from(byte)
    } else {
        '.'
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn moves_are_clamped_and_scroll() {
        let mut h = HexState::default();
        h.move_by(-5, 100, 2);
        assert_eq!((h.cursor, h.top), (0, 0));
        h.move_by(16 * 3, 100, 2);
        assert_eq!((h.cursor, h.top), (48, 32), "row 3 visible in 2 rows");
        h.move_by(1000, 100, 2);
        assert_eq!(h.cursor, 99);
        h.move_by(-99, 100, 2);
        assert_eq!((h.cursor, h.top), (0, 0));
    }

    #[test]
    fn jumps_put_the_target_on_top() {
        let mut h = HexState::default();
        h.jump_to(0x105, 0x1000, 10);
        assert_eq!((h.cursor, h.top), (0x105, 0x100));
        // Near the end the last page is shown instead of a short one.
        h.jump_to(0xff0, 0x1000, 10);
        assert_eq!((h.cursor, h.top), (0xff0, 0xf60));
        h.jump_to(5, 8, 10);
        assert_eq!((h.cursor, h.top), (5, 0));
    }

    #[test]
    fn empty_file_is_safe() {
        let mut h = HexState::default();
        h.move_by(10, 0, 5);
        h.go_to(500, 0, 5);
        assert_eq!((h.cursor, h.top), (0, 0));
    }

    #[test]
    fn huge_offsets_do_not_overflow() {
        let mut h = HexState::default();
        h.go_to(u64::MAX, u64::MAX, 10);
        assert_eq!(h.cursor, u64::MAX - 1);
        h.move_by(i64::MAX, u64::MAX, 10);
        h.move_by(i64::MIN, u64::MAX, 10);
        assert_eq!(h.cursor, u64::MAX - 1 - (1 << 63), "saturating, no wrap");
        h.move_by(i64::MIN, u64::MAX, 10);
        assert_eq!(h.cursor, 0);
    }

    #[test]
    fn offsets_parse_as_hex_or_decimal() {
        assert_eq!(parse_offset("0x1f"), Ok(31));
        assert_eq!(parse_offset("0X1F"), Ok(31));
        assert_eq!(parse_offset(" 42 "), Ok(42));
        assert!(parse_offset("1f").is_err());
        assert!(parse_offset("0x").is_err());
        assert!(parse_offset("0xffffffffffffffffff").is_err());
        assert!(parse_offset("").is_err());
    }

    #[test]
    fn ascii_column_never_emits_control_bytes() {
        for b in 0..=255u8 {
            let c = ascii(b);
            assert!(c == '.' || (' '..='~').contains(&c), "{b:#x} -> {c:?}");
        }
        assert_eq!(ascii(b'M'), 'M');
        assert_eq!(ascii(0x1b), '.');
        assert_eq!(ascii(0x9b), '.');
    }
}

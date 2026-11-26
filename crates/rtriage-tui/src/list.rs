//! Cursor and scroll position of one list. Shared by every list pane.
//!
//! The list itself is not stored here, only its length: panes keep their
//! data in the report and map row numbers to items.

use std::ops::Range;

/// Cursor and first visible row of a list of `len` rows.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ListState {
    len: usize,
    cursor: usize,
    offset: usize,
}

impl ListState {
    /// A list of `len` rows with the cursor on the first.
    pub fn new(len: usize) -> ListState {
        ListState {
            len,
            cursor: 0,
            offset: 0,
        }
    }

    /// Number of rows.
    pub fn len(&self) -> usize {
        self.len
    }

    /// `true` if the list has no rows.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Selected row, `None` for an empty list.
    pub fn selected(&self) -> Option<usize> {
        (self.cursor < self.len).then_some(self.cursor)
    }

    /// First row of the scroll window (as last stored).
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// Moves the cursor by `delta` rows, clamped to the list.
    pub fn move_by(&mut self, delta: isize) {
        let last = self.len.saturating_sub(1);
        self.cursor = self.cursor.saturating_add_signed(delta).min(last);
    }

    /// First row.
    pub fn home(&mut self) {
        self.cursor = 0;
    }

    /// Last row.
    pub fn end(&mut self) {
        self.cursor = self.len.saturating_sub(1);
    }

    /// Selects `row`; `false` (and nothing changes) if it does not exist.
    pub fn select(&mut self, row: usize) -> bool {
        if row < self.len {
            self.cursor = row;
            true
        } else {
            false
        }
    }

    /// Scrolls just enough for the cursor to be visible in `rows` rows and
    /// remembers that position.
    pub fn follow(&mut self, rows: usize) {
        self.offset = self.offset_for(rows);
    }

    /// The scroll offset that shows the cursor in a window of `rows` rows,
    /// starting from the stored offset (so the view does not jump). Pure:
    /// views call it with their real height.
    pub fn offset_for(&self, rows: usize) -> usize {
        if rows == 0 || self.len == 0 {
            return 0;
        }
        let max_offset = self.len.saturating_sub(rows);
        let mut offset = self.offset.min(max_offset);
        if self.cursor < offset {
            offset = self.cursor;
        } else if self.cursor >= offset.saturating_add(rows) {
            offset = self.cursor.saturating_sub(rows - 1);
        }
        offset
    }

    /// Rows visible in a window of `rows` rows.
    pub fn window(&self, rows: usize) -> Range<usize> {
        let start = self.offset_for(rows);
        start..start.saturating_add(rows).min(self.len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_list_is_safe() {
        let mut l = ListState::new(0);
        l.move_by(5);
        l.move_by(-5);
        l.end();
        assert_eq!(l.selected(), None);
        assert!(!l.select(0));
        assert_eq!(l.window(10), 0..0);
    }

    #[test]
    fn moves_are_clamped() {
        let mut l = ListState::new(3);
        l.move_by(-1);
        assert_eq!(l.selected(), Some(0));
        l.move_by(10);
        assert_eq!(l.selected(), Some(2));
        l.home();
        assert_eq!(l.selected(), Some(0));
        l.end();
        assert_eq!(l.selected(), Some(2));
    }

    #[test]
    fn window_follows_the_cursor_without_jumping() {
        let mut l = ListState::new(100);
        assert_eq!(l.window(10), 0..10);
        l.select(15);
        l.follow(10);
        assert_eq!(l.window(10), 6..16);
        // Moving up inside the window does not scroll.
        l.move_by(-3);
        l.follow(10);
        assert_eq!(l.window(10), 6..16);
        l.select(2);
        assert_eq!(l.window(10), 2..12);
        l.end();
        assert_eq!(l.window(10), 90..100);
        assert_eq!(l.window(0), 0..0);
    }
}

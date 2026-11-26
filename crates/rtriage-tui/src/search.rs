//! Substring search over list rows (case-insensitive, on displayed text).

/// Longest search text accepted from the prompt, in characters.
pub const MAX_QUERY_CHARS: usize = 256;

/// `true` if `text` contains `needle_lower` ignoring case. `needle_lower`
/// must already be lowercase.
pub fn matches(text: &str, needle_lower: &str) -> bool {
    text.to_lowercase().contains(needle_lower)
}

/// Direction of a search step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// From the cursor itself, forwards (a new search).
    Here,
    /// After the cursor (`n`).
    Next,
    /// Before the cursor (`N`).
    Previous,
}

/// A match: its row, and whether the search wrapped around the list end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Found {
    /// Matching row.
    pub row: usize,
    /// The search passed the end (or start) of the list.
    pub wrapped: bool,
    /// 1-based position among all matches.
    pub nth: usize,
    /// Number of matching rows.
    pub total: usize,
}

/// Finds `query` among `len` rows starting at `cursor`, with `text(row)`
/// giving a row's displayed text. `None` if nothing matches.
pub fn find(
    len: usize,
    cursor: usize,
    dir: Direction,
    query: &str,
    text: &dyn Fn(usize) -> Option<String>,
) -> Option<Found> {
    if len == 0 || query.is_empty() {
        return None;
    }
    let needle = query.to_lowercase();
    let hits: Vec<usize> = (0..len)
        .filter(|&r| text(r).is_some_and(|t| matches(&t, &needle)))
        .collect();
    let cursor = cursor.min(len - 1);
    let (row, wrapped) = match dir {
        Direction::Here => pick(hits.iter().find(|&&r| r >= cursor), hits.first()),
        Direction::Next => pick(hits.iter().find(|&&r| r > cursor), hits.first()),
        Direction::Previous => pick(hits.iter().rev().find(|&&r| r < cursor), hits.last()),
    }?;
    let nth = hits.iter().position(|&r| r == row).map_or(1, |p| p + 1);
    Some(Found {
        row,
        wrapped,
        nth,
        total: hits.len(),
    })
}

/// The first choice, or the wrap-around one.
fn pick(direct: Option<&usize>, wrap: Option<&usize>) -> Option<(usize, bool)> {
    match (direct, wrap) {
        (Some(r), _) => Some((*r, false)),
        (None, Some(r)) => Some((*r, true)),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(r: usize) -> Option<String> {
        [
            "OpenProcess",
            "VirtualAllocEx",
            "WriteProcessMemory",
            "Sleep",
        ]
        .get(r)
        .map(|s| (*s).to_owned())
    }

    #[test]
    fn case_insensitive_substring() {
        assert!(matches("VirtualAllocEx", "virtualalloc"));
        assert!(matches("Привіт", &"ПРИВ".to_lowercase()));
        assert!(!matches("Sleep", "slept"));
    }

    #[test]
    fn here_next_previous_and_wrap() {
        let f = find(4, 0, Direction::Here, "process", &rows).unwrap();
        assert_eq!((f.row, f.wrapped, f.nth, f.total), (0, false, 1, 2));
        let f = find(4, 0, Direction::Next, "process", &rows).unwrap();
        assert_eq!((f.row, f.wrapped, f.nth), (2, false, 2));
        let f = find(4, 2, Direction::Next, "process", &rows).unwrap();
        assert_eq!((f.row, f.wrapped), (0, true));
        let f = find(4, 0, Direction::Previous, "process", &rows).unwrap();
        assert_eq!((f.row, f.wrapped), (2, true));
    }

    #[test]
    fn nothing_found_or_nothing_to_search() {
        assert_eq!(find(4, 0, Direction::Here, "zzz", &rows), None);
        assert_eq!(find(0, 0, Direction::Here, "a", &rows), None);
        assert_eq!(find(4, 0, Direction::Here, "", &rows), None);
        // A stale cursor beyond the list is clamped.
        assert_eq!(find(4, 99, Direction::Here, "sleep", &rows).unwrap().row, 3);
    }
}

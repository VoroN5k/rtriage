//! Key help overlay (`?`).

use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;

use super::centered;
use crate::app::App;

/// Key, description. Grows as later steps add keys.
const KEYS: [(&str, &str); 18] = [
    ("1-7", "switch tab"),
    ("Tab / Shift-Tab", "next / previous tab"),
    ("↑↓ j k", "move"),
    ("PgUp PgDn Home End", "move by page / to the ends"),
    ("← → h l", "findings list / evidence; Hex: byte"),
    ("Enter", "select; on evidence or a score row: jump to it"),
    ("Backspace / Alt-←", "go back"),
    (
        "/  n  N",
        "search this list (case-insensitive) · next · previous",
    ),
    ("s", "Sections tab of an ELF: section headers / segments"),
    (
        "f / x",
        "Strings: filter by class and length / clear filter",
    ),
    ("d", "IOCs: show raw / defanged values"),
    ("g", "Hex: go to an offset (decimal or 0x hex)"),
    ("y / Y", "copy sanitized+defanged / copy raw (asks first)"),
    ("?", "toggle this help"),
    (
        "Esc",
        "close help, clear the search, or cancel the analysis",
    ),
    ("q / Ctrl-C", "quit (cancels a running analysis)"),
    ("", "→ evidence opens another tab · ~ suppressed finding"),
    ("", "search box and filter dialog take keys until Enter/Esc"),
];

pub(super) fn draw(app: &App, frame: &mut Frame<'_>, area: Rect) {
    let lines: Vec<Line<'_>> = KEYS
        .iter()
        .map(|(k, d)| Line::from(format!(" {k:<18} {d}")))
        .collect();
    let rect = centered(area, 76, full_height());
    let max = max_scroll((area.width, area.height));
    let title = if max > 0 {
        " Keys · ↑↓ PgUp PgDn scroll "
    } else {
        " Keys "
    };
    frame.render_widget(Clear, rect);
    frame.render_widget(
        Paragraph::new(lines)
            .scroll((app.help_scroll.min(max), 0))
            .block(Block::new().borders(Borders::ALL).title(title)),
        rect,
    );
}

/// Height of the overlay with every line visible (lines plus borders).
fn full_height() -> u16 {
    u16::try_from(KEYS.len())
        .unwrap_or(u16::MAX)
        .saturating_add(2)
}

/// Furthest the help can scroll on a `(width, height)` screen: the lines
/// that do not fit. `update` clamps with it, `draw` too.
pub(crate) fn max_scroll(size: (u16, u16)) -> u16 {
    let shown = full_height().min(size.1).saturating_sub(2);
    full_height().saturating_sub(2).saturating_sub(shown)
}

#[cfg(test)]
mod tests {
    use ratatui::crossterm::event::KeyCode;

    use super::*;
    use crate::testkit::{key, ready_app, render, suspicious_pe};
    use crate::update::update;

    #[test]
    fn fits_without_scrolling_at_80x24() {
        assert_eq!(max_scroll((80, 24)), 0);
    }

    #[test]
    fn scrolls_to_the_last_line_at_60x16_and_clamps() {
        let mut a = ready_app("s.exe", suspicious_pe(), (60, 16));
        update(&mut a, key(KeyCode::Char('?')));
        let max = max_scroll(a.size);
        assert!(max > 0);
        let top = render(&a);
        assert!(top.contains("↑↓ PgUp PgDn scroll"), "{top}");
        assert!(top.contains("1-7"), "{top}");
        for _ in 0..100 {
            update(&mut a, key(KeyCode::Down));
        }
        assert_eq!(a.help_scroll, max, "clamped");
        let end = render(&a);
        assert!(end.contains("search box and filter dialog"), "{end}");
        assert!(!end.contains("1-7"), "{end}");
        update(&mut a, key(KeyCode::Up));
        assert_eq!(a.help_scroll, max - 1, "one press is one line");
        update(&mut a, key(KeyCode::Home));
        assert_eq!(a.help_scroll, 0);
        // Keys do not leak to the tab underneath while help is open.
        update(&mut a, key(KeyCode::Tab));
        assert_eq!(a.tab, crate::app::Tab::Findings);
    }

    #[test]
    fn reopening_starts_at_the_top() {
        let mut a = ready_app("s.exe", suspicious_pe(), (60, 16));
        update(&mut a, key(KeyCode::Char('?')));
        update(&mut a, key(KeyCode::End));
        update(&mut a, key(KeyCode::Char('?')));
        update(&mut a, key(KeyCode::Char('?')));
        assert_eq!(a.help_scroll, 0);
    }
}

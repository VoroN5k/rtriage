//! Key help overlay (`?`).

use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;

use super::centered;

/// Key, description. Grows as later steps add keys.
const KEYS: [(&str, &str); 14] = [
    ("1-6", "switch tab"),
    ("Tab / Shift-Tab", "next / previous tab"),
    ("↑↓ j k", "move"),
    ("PgUp PgDn Home End", "move by page / to the ends"),
    ("← → h l", "findings list / evidence"),
    ("Enter", "select; on evidence: jump to it"),
    ("Backspace / Alt-←", "go back"),
    (
        "/  n  N",
        "search this list (case-insensitive) · next · previous",
    ),
    ("s", "Sections tab of an ELF: section headers / segments"),
    ("?", "toggle this help"),
    (
        "Esc",
        "close help, clear the search, or cancel the analysis",
    ),
    ("q / Ctrl-C", "quit (cancels a running analysis)"),
    ("", "→ evidence opens another tab · ~ suppressed finding"),
    ("", "the search box takes every key until Enter or Esc"),
];

pub(super) fn draw(frame: &mut Frame<'_>, area: Rect) {
    let lines: Vec<Line<'_>> = KEYS
        .iter()
        .map(|(k, d)| Line::from(format!(" {k:<18} {d}")))
        .collect();
    let height = u16::try_from(lines.len())
        .unwrap_or(u16::MAX)
        .saturating_add(2);
    let rect = centered(area, 76, height);
    frame.render_widget(Clear, rect);
    frame.render_widget(
        Paragraph::new(lines).block(Block::new().borders(Borders::ALL).title(" Keys ")),
        rect,
    );
}

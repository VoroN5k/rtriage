//! Key help overlay (`?`).

use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;

use super::centered;

/// Key, description. Grows as later steps add keys.
const KEYS: [(&str, &str); 5] = [
    ("1-6", "switch tab"),
    ("Tab / Shift-Tab", "next / previous tab"),
    ("?", "toggle this help"),
    ("Esc", "close help, or cancel a running analysis"),
    ("q / Ctrl-C", "quit (cancels a running analysis)"),
];

pub(super) fn draw(frame: &mut Frame<'_>, area: Rect) {
    let lines: Vec<Line<'_>> = KEYS
        .iter()
        .map(|(k, d)| Line::from(format!(" {k:<16} {d}")))
        .collect();
    let height = u16::try_from(lines.len())
        .unwrap_or(u16::MAX)
        .saturating_add(2);
    let rect = centered(area, 62, height);
    frame.render_widget(Clear, rect);
    frame.render_widget(
        Paragraph::new(lines).block(Block::new().borders(Borders::ALL).title(" Keys ")),
        rect,
    );
}

//! A bordered table that draws only the rows in view (any length is fine).

use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Paragraph, Row, Table};
use ratatui::Frame;

use crate::list::ListState;

/// What to draw: the frame of the table and how to get a row's cells.
pub(super) struct TableSpec<'a> {
    /// Block title (already sanitized).
    pub title: String,
    /// Column titles.
    pub header: &'a [&'a str],
    /// Column widths.
    pub widths: &'a [Constraint],
    /// Mark the cursor row (off when the cursor is in another widget).
    pub highlight: bool,
    /// Shown instead of the table when it has no rows.
    pub empty: String,
}

/// Draws `spec` with the cursor and scroll of `state`; `cells(row)` gives
/// the sanitized cells of a row and is called for visible rows only.
pub(super) fn draw(
    frame: &mut Frame<'_>,
    area: Rect,
    spec: &TableSpec<'_>,
    state: &ListState,
    cells: &dyn Fn(usize) -> Option<Vec<String>>,
) {
    let block = Block::new().borders(Borders::ALL).title(spec.title.clone());
    if state.is_empty() {
        frame.render_widget(Paragraph::new(spec.empty.clone()).block(block), area);
        return;
    }
    let inner_rows = usize::from(block.inner(area).height.saturating_sub(1));
    let rows: Vec<Row<'_>> = state
        .window(inner_rows)
        .filter_map(|i| cells(i).map(|c| (i, c)))
        .map(|(i, c)| {
            let row = Row::new(c);
            if spec.highlight && Some(i) == state.selected() {
                row.style(Style::new().add_modifier(Modifier::REVERSED))
            } else {
                row
            }
        })
        .collect();
    let header = Row::new(spec.header.iter().copied())
        .style(Style::new().add_modifier(Modifier::BOLD | Modifier::UNDERLINED));
    frame.render_widget(
        Table::new(rows, spec.widths.iter().copied())
            .header(header)
            .block(block)
            .column_spacing(1),
        area,
    );
}

/// A full-pane note (e.g. "not applicable").
pub(super) fn note(frame: &mut Frame<'_>, area: Rect, title: &str, lines: Vec<Line<'_>>) {
    frame.render_widget(
        Paragraph::new(lines).block(
            Block::new()
                .borders(Borders::ALL)
                .title(format!(" {title} ")),
        ),
        area,
    );
}

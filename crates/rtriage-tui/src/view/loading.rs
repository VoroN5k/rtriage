//! Screen shown while the analysis runs.

use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use super::{centered, file_name, format_name, human_size};
use crate::app::App;

const SPINNER: [char; 4] = ['|', '/', '-', '\\'];

pub(super) fn draw(app: &App, cancel_sent: bool, frame: &mut Frame<'_>, area: Rect) {
    let spin_at = usize::try_from(app.ticks % 4).unwrap_or(0);
    let spinner = SPINNER.get(spin_at).copied().unwrap_or('|');
    let (status, hint) = if cancel_sent {
        (
            "Cancelling... the report will be partial".to_owned(),
            "q quit",
        )
    } else {
        (format!("{spinner} Analyzing"), "Esc cancel · q quit")
    };
    let text = vec![
        Line::styled(status, Style::new().add_modifier(Modifier::BOLD)),
        Line::from(""),
        Line::from(file_name(app)),
        Line::from(format!(
            "{} · {}",
            format_name(app.input.format),
            human_size(app.input.size())
        )),
        Line::from(""),
        Line::styled(hint, Style::new().add_modifier(Modifier::DIM)),
    ];
    let block = Block::new().borders(Borders::ALL).title(" rtriage ");
    frame.render_widget(Paragraph::new(text).block(block), centered(area, 64, 8));
}

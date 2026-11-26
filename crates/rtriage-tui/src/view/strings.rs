//! Strings tab: a virtualized table of the (filtered) extracted strings,
//! and the filter dialog.

use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;
use rtriage_core::report::{ExtractedString, StringsIncluded};
use rtriage_core::Report;
use rtriage_sanitize::single_line;

use super::table::{self, TableSpec};
use super::{centered, snake};
use crate::app::App;
use crate::filter::{FilterDialog, ALL_KINDS};

/// Column titles of the strings table.
const COLUMNS: [&str; 5] = ["Offset", "Enc", "Len", "Kinds", "Value"];

#[cfg(test)]
thread_local! {
    /// Rows formatted by [`cells`], to prove rendering is proportional to
    /// the viewport, not to the number of strings.
    pub(crate) static ROWS_FORMATTED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

pub(super) fn draw(app: &App, report: &Report, frame: &mut Frame<'_>, area: Rect) {
    let Some(strings) = report.facts.strings.as_ref() else {
        table::note(
            frame,
            area,
            "Strings",
            vec![Line::from("No strings: the strings analyzer did not run.")],
        );
        return;
    };
    let p = &app.panes;
    let mut title = format!(
        " Strings ({} of {}",
        p.string_rows.len(),
        strings.items.len()
    );
    if p.string_filter.is_active() {
        title.push_str(&format!(" · filter {}", p.string_filter.describe()));
    }
    title.push(')');
    if strings.limit_reached {
        title.push_str(&format!(
            " · first {} of {} found",
            strings.items.len(),
            strings.total
        ));
    }
    if strings.items_included == StringsIncluded::Classified {
        title.push_str(" · classified only");
    }
    title.push_str(" · f filter · x clear ");
    let empty = if strings.items.is_empty() {
        "No strings found.".to_owned()
    } else {
        "No strings match the filter (x clears it).".to_owned()
    };
    let widths = [
        Constraint::Length(10),
        Constraint::Length(5),
        Constraint::Length(6),
        Constraint::Length(16),
        Constraint::Fill(1),
    ];
    let spec = TableSpec {
        title,
        header: &COLUMNS,
        widths: &widths,
        highlight: true,
        empty,
    };
    table::draw(frame, area, &spec, &p.strings, &|row| {
        let item = usize::try_from(*p.string_rows.get(row)?).ok()?;
        strings.items.get(item).map(cells)
    });
}

/// Cells of one string (sanitized).
fn cells(s: &ExtractedString) -> Vec<String> {
    #[cfg(test)]
    ROWS_FORMATTED.with(|c| c.set(c.get() + 1));
    let enc = match s.encoding {
        rtriage_core::report::StringEncoding::Ascii => "ascii",
        _ => "utf16",
    };
    let kinds: Vec<String> = s.kinds.iter().map(snake).collect();
    let more = if s.truncated { " …" } else { "" };
    vec![
        format!("0x{:08x}", s.offset),
        enc.to_owned(),
        s.len.to_string(),
        kinds.join(","),
        format!("{}{more}", single_line(&s.value)),
    ]
}

/// The filter dialog, over whatever is below.
pub(super) fn dialog(d: &FilterDialog, frame: &mut Frame<'_>, area: Rect) {
    let mark = |row: usize| if d.cursor == row { '›' } else { ' ' };
    let mut lines: Vec<Line<'_>> = ALL_KINDS
        .iter()
        .enumerate()
        .map(|(i, k)| {
            let tick = if d.kinds.contains(k) { 'x' } else { ' ' };
            Line::from(format!("{} [{tick}] {}", mark(i), snake(k)))
        })
        .collect();
    let field = |row: usize, name: &str, text: &str| {
        let caret = if d.cursor == row { "▏" } else { "" };
        Line::from(format!("{} {name}: {text}{caret}", mark(row)))
    };
    lines.push(field(FilterDialog::MIN_ROW, "min length", &d.min_text));
    lines.push(field(FilterDialog::MAX_ROW, "max length", &d.max_text));
    lines.push(Line::styled(
        "Space tick · digits · Enter apply · Esc cancel",
        Style::new().add_modifier(Modifier::DIM),
    ));
    lines.push(Line::styled(
        "no class ticked = any string",
        Style::new().add_modifier(Modifier::DIM),
    ));
    let height = u16::try_from(lines.len())
        .unwrap_or(u16::MAX)
        .saturating_add(2);
    let rect = centered(area, 50, height);
    frame.render_widget(Clear, rect);
    frame.render_widget(
        Paragraph::new(lines).block(Block::new().borders(Borders::ALL).title(" Filter strings ")),
        rect,
    );
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use ratatui::crossterm::event::KeyCode;
    use rtriage_core::report::StringKind;

    use super::*;
    use crate::testkit::{key, mixed_strings, render, string, strings_app};
    use crate::update::update;

    fn app(size: (u16, u16)) -> App {
        let mut a = strings_app(mixed_strings(), size);
        update(&mut a, key(KeyCode::Char('4')));
        a
    }

    #[test]
    fn strings_80x24() {
        insta::assert_snapshot!(render(&app((80, 24))));
    }

    #[test]
    fn strings_120x40() {
        insta::assert_snapshot!(render(&app((120, 40))));
    }

    #[test]
    fn filter_dialog_80x24() {
        let mut a = app((80, 24));
        update(&mut a, key(KeyCode::Char('f')));
        update(&mut a, key(KeyCode::Char(' ')));
        update(&mut a, key(KeyCode::Down));
        insta::assert_snapshot!(render(&a));
    }

    #[test]
    fn filtered_and_empty_80x24() {
        let mut a = app((80, 24));
        update(&mut a, key(KeyCode::Char('f')));
        update(&mut a, key(KeyCode::Char(' ')));
        update(&mut a, key(KeyCode::Enter));
        let screen = render(&a);
        assert!(screen.contains("Strings (2 of 6 · filter url)"), "{screen}");
        insta::assert_snapshot!(screen);
        a.panes.string_filter.min_len = Some(1000);
        update(&mut a, key(KeyCode::Char('f')));
        update(&mut a, key(KeyCode::Enter));
        let screen = render(&a);
        assert!(screen.contains("No strings match the filter"), "{screen}");
    }

    #[test]
    fn hostile_strings_are_escaped() {
        let items = vec![string(
            0,
            "a\x1b]52;c;aGk=\x07b\u{202e}c\u{200b}d\u{9b}2J",
            &[StringKind::Base64],
        )];
        let mut a = strings_app(items, (100, 20));
        update(&mut a, key(KeyCode::Char('4')));
        let screen = render(&a);
        assert!(
            screen.contains(r"a\x1b]52;c;aGk=\x07b\u{202e}c\u{200b}d\x9b2J"),
            "{screen}"
        );
    }

    #[test]
    fn render_formats_only_visible_rows() {
        let items: Vec<_> = (0..200_000u64)
            .map(|i| string(i * 16, &format!("string number {i}"), &[]))
            .collect();
        let mut a = strings_app(items, (80, 24));
        update(&mut a, key(KeyCode::Char('4')));
        update(&mut a, key(KeyCode::End));
        ROWS_FORMATTED.with(|c| c.set(0));
        let screen = render(&a);
        let formatted = ROWS_FORMATTED.with(std::cell::Cell::get);
        assert!(
            formatted > 0 && formatted <= 24,
            "{formatted} rows formatted"
        );
        assert!(screen.contains("string number 199999"), "{screen}");
    }
}

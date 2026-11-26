//! IOCs tab: file hashes (full width, so a SHA-256 is never cut), then the
//! indicators (defanged unless toggled). One cursor runs over both: rows
//! 0..3 are the hashes.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;
use rtriage_core::Report;

use super::table::{self, TableSpec};
use crate::app::App;
use crate::list::ListState;
use crate::rows::{self, IocRow};

pub(super) fn draw(app: &App, report: &Report, frame: &mut Frame<'_>, area: Rect) {
    let hashes: Vec<(&str, &str)> = (0..3)
        .map_while(|r| match rows::ioc_row(report, r) {
            Some(IocRow::Hash(alg, hex)) => Some((alg, hex)),
            _ => None,
        })
        .collect();
    let selected = app.panes.iocs.selected();
    let hash_h = if hashes.is_empty() {
        0
    } else {
        u16::try_from(hashes.len()).unwrap_or(3).saturating_add(2)
    };
    let [top, bottom] =
        Layout::vertical([Constraint::Length(hash_h), Constraint::Min(3)]).areas(area);
    if !hashes.is_empty() {
        let lines: Vec<Line<'_>> = hashes
            .iter()
            .enumerate()
            .map(|(i, (alg, hex))| {
                let line = Line::from(format!("{alg:<7} {hex}"));
                if selected == Some(i) {
                    line.style(Style::new().add_modifier(Modifier::REVERSED))
                } else {
                    line
                }
            })
            .collect();
        frame.render_widget(
            Paragraph::new(lines).block(
                Block::new()
                    .borders(Borders::ALL)
                    .title(" File hashes · y copy "),
            ),
            top,
        );
    }
    // The indicator table gets its own cursor, shifted past the hashes.
    let first = hashes.len();
    let count = app.panes.iocs.len().saturating_sub(first);
    let mut state = ListState::new(count);
    let in_table = selected.and_then(|s| s.checked_sub(first));
    if let Some(row) = in_table {
        state.select(row);
    }
    indicators(
        app,
        report,
        &state,
        in_table.is_some(),
        first,
        frame,
        bottom,
    );
}

fn indicators(
    app: &App,
    report: &Report,
    state: &ListState,
    highlight: bool,
    first: usize,
    frame: &mut Frame<'_>,
    area: Rect,
) {
    let raw = app.panes.raw_iocs;
    let mut title = match &report.facts.iocs {
        Some(i) => {
            let mut t = format!(" IOCs ({}", i.items.len());
            if i.allowlisted > 0 {
                t.push_str(&format!(", {} allowlisted", i.allowlisted));
            }
            if i.limit_reached {
                t.push_str(", limit reached");
            }
            t.push(')');
            t
        }
        None => " IOCs (the IOC analyzer did not run)".to_owned(),
    };
    title.push_str(if raw {
        " · RAW · d defang"
    } else {
        " · defanged · d raw"
    });
    title.push_str(" · y copy · Y copy raw ");
    let widths = [
        Constraint::Length(13),
        Constraint::Fill(1),
        Constraint::Length(16),
        Constraint::Length(5),
        Constraint::Length(10),
    ];
    let spec = TableSpec {
        title,
        header: &rows::IOC_COLUMNS,
        widths: &widths,
        highlight,
        empty: "No IOCs found.".into(),
    };
    table::draw(frame, area, &spec, state, &|r| {
        rows::ioc(report, r.checked_add(first)?, raw)
    });
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use ratatui::crossterm::event::KeyCode;

    use crate::app::Phase;
    use crate::testkit::{key, ready_app, render, suspicious_pe};
    use crate::update::update;

    fn app() -> crate::app::App {
        let mut a = ready_app("s.exe", suspicious_pe(), (100, 24));
        update(&mut a, key(KeyCode::Char('5')));
        a
    }

    #[test]
    fn iocs_defanged_by_default_100x24() {
        let screen = render(&app());
        assert!(
            screen.contains("hxxp://c2[.]evil-example[.]ru/gate.php"),
            "{screen}"
        );
        assert!(!screen.contains("http://c2.evil"), "{screen}");
        insta::assert_snapshot!(screen);
    }

    #[test]
    fn iocs_raw_after_d_100x24() {
        let mut a = app();
        update(&mut a, key(KeyCode::Char('d')));
        let screen = render(&a);
        assert!(
            screen.contains("http://c2.evil-example.ru/gate.php"),
            "{screen}"
        );
        assert!(screen.contains("RAW"), "{screen}");
        insta::assert_snapshot!(screen);
    }

    #[test]
    fn raw_copy_question_80x24() {
        let mut a = app();
        a.size = (80, 24);
        let row = a.panes.iocs.len() - 1;
        a.panes.iocs.select(row);
        update(&mut a, key(KeyCode::Char('Y')));
        let screen = render(&a);
        assert!(screen.contains("copy RAW"), "{screen}");
    }

    #[test]
    fn hostile_ioc_values_are_escaped_even_raw() {
        let mut a = app();
        if let Phase::Ready(r) = &mut a.phase {
            let i = &mut r.facts.iocs.as_mut().unwrap().items[0];
            i.value = "http://e\x1b[2J\u{202e}vil.ru/".into();
            i.value_defanged = "hxxp://e\x1b[2J\u{202e}vil[.]ru/".into();
        }
        for raw in [false, true] {
            a.panes.raw_iocs = raw;
            let screen = render(&a);
            assert!(screen.contains(r"e\x1b[2J\u{202e}vil"), "{screen}");
            assert!(!screen.contains(['\x1b', '\u{202e}']));
        }
    }
}

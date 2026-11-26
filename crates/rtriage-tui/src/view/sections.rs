//! Sections tab: PE sections, or ELF section headers / program headers.

use ratatui::layout::{Constraint, Rect};
use ratatui::text::Line;
use ratatui::Frame;
use rtriage_core::{Format, Report};

use super::format_name;
use super::table::{self, TableSpec};
use crate::app::App;
use crate::rows;

pub(super) fn draw(app: &App, report: &Report, frame: &mut Frame<'_>, area: Rect) {
    match report.file.format {
        Format::Pe => pe(app, report, frame, area),
        Format::Elf if app.panes.show_segments => segments(app, report, frame, area),
        Format::Elf => elf(app, report, frame, area),
        other => table::note(
            frame,
            area,
            "Sections",
            vec![Line::from(format!(
                "Not applicable for {}: only PE and ELF files have sections.",
                format_name(other)
            ))],
        ),
    }
}

fn pe(app: &App, report: &Report, frame: &mut Frame<'_>, area: Rect) {
    let widths = [
        Constraint::Length(3),
        Constraint::Min(8),
        Constraint::Length(10),
        Constraint::Length(9),
        Constraint::Length(10),
        Constraint::Length(9),
        Constraint::Length(4),
        Constraint::Length(7),
    ];
    let spec = TableSpec {
        title: format!(" Sections ({}) ", app.panes.sections.len()),
        header: &rows::PE_SECTION_COLUMNS,
        widths: &widths,
        empty: "No section table (it could not be parsed; see the report's errors).".into(),
    };
    table::draw(frame, area, &spec, &app.panes.sections, &|r| {
        rows::section(report, r)
    });
}

fn elf(app: &App, report: &Report, frame: &mut Frame<'_>, area: Rect) {
    let widths = [
        Constraint::Length(3),
        Constraint::Min(10),
        Constraint::Length(10),
        Constraint::Length(14),
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(9),
    ];
    let spec = TableSpec {
        title: format!(
            " Section headers ({}) · s: segments ",
            app.panes.sections.len()
        ),
        header: &rows::ELF_SECTION_COLUMNS,
        widths: &widths,
        empty: "No section headers (stripped, truncated or hand-crafted ELF). Press s for the program headers."
            .into(),
    };
    table::draw(frame, area, &spec, &app.panes.sections, &|r| {
        rows::section(report, r)
    });
}

fn segments(app: &App, report: &Report, frame: &mut Frame<'_>, area: Rect) {
    let widths = [
        Constraint::Length(3),
        Constraint::Min(12),
        Constraint::Length(4),
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(9),
        Constraint::Length(9),
        Constraint::Length(7),
    ];
    let spec = TableSpec {
        title: format!(
            " Segments ({}) · s: section headers ",
            app.panes.segments.len()
        ),
        header: &rows::ELF_SEGMENT_COLUMNS,
        widths: &widths,
        empty: "No program headers.".into(),
    };
    table::draw(frame, area, &spec, &app.panes.segments, &|r| {
        rows::segment(report, r)
    });
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use ratatui::crossterm::event::KeyCode;

    use crate::testkit::{glibc_elf, key, ready_app, render, suspicious_pe};
    use crate::update::update;

    #[test]
    fn pe_sections_80x24() {
        let mut app = ready_app("s.exe", suspicious_pe(), (80, 24));
        update(&mut app, key(KeyCode::Char('2')));
        insta::assert_snapshot!(render(&app));
    }

    #[test]
    fn elf_sections_120x40() {
        let mut app = ready_app("t.elf", glibc_elf(), (120, 40));
        update(&mut app, key(KeyCode::Char('2')));
        insta::assert_snapshot!(render(&app));
    }

    #[test]
    fn elf_segments_120x40() {
        let mut app = ready_app("t.elf", glibc_elf(), (120, 40));
        update(&mut app, key(KeyCode::Char('2')));
        update(&mut app, key(KeyCode::Char('s')));
        insta::assert_snapshot!(render(&app));
    }

    #[test]
    fn unknown_format_tabs_say_not_applicable() {
        let mut app = ready_app("notes.txt", b"just some text here".to_vec(), (80, 24));
        for tab in ['2', '3'] {
            update(&mut app, key(KeyCode::Char(tab)));
            let screen = render(&app);
            assert!(
                screen.contains("Not applicable for unknown format"),
                "{screen}"
            );
            // Keys on an empty table are harmless.
            for k in [KeyCode::Down, KeyCode::End, KeyCode::PageUp, KeyCode::Enter] {
                assert!(update(&mut app, key(k)).is_empty());
            }
        }
    }

    #[test]
    fn hostile_section_name_is_escaped() {
        let mut app = ready_app("s.exe", suspicious_pe(), (100, 24));
        if let crate::app::Phase::Ready(r) = &mut app.phase {
            let s = r.facts.pe.as_mut().unwrap().sections.as_mut().unwrap();
            s[0].name = "\x1b[31m.t\u{202e}xt".into();
        }
        update(&mut app, key(KeyCode::Char('2')));
        let screen = render(&app);
        assert!(screen.contains(r"\x1b[31m.t\u{202e}xt"), "{screen}");
    }

    #[test]
    fn search_prompt_80x24() {
        let mut app = ready_app("s.exe", suspicious_pe(), (80, 24));
        update(&mut app, key(KeyCode::Char('2')));
        update(&mut app, key(KeyCode::Char('/')));
        for c in ".ev\x1bil".chars() {
            update(&mut app, key(KeyCode::Char(c)));
        }
        let screen = render(&app);
        assert!(screen.contains(r"/.ev\x1bil▏"), "{screen}");
        insta::assert_snapshot!(screen);
    }
}

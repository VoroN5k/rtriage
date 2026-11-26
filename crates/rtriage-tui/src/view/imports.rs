//! Imports tab: PE functions grouped by DLL, or ELF imported symbols.

use ratatui::layout::{Constraint, Rect};
use ratatui::text::Line;
use ratatui::Frame;
use rtriage_core::{Format, Report};
use rtriage_sanitize::single_line;

use super::format_name;
use super::table::{self, TableSpec};
use crate::app::App;
use crate::rows;

pub(super) fn draw(app: &App, report: &Report, frame: &mut Frame<'_>, area: Rect) {
    let title = match report.file.format {
        Format::Pe => pe_title(report),
        Format::Elf => elf_title(report),
        other => {
            let text = format!(
                "Not applicable for {}: only PE and ELF files have imports.",
                format_name(other)
            );
            table::note(frame, area, "Imports", vec![Line::from(text)]);
            return;
        }
    };
    let cells = rows::imports(report);
    // ELF symbols are not bound to a library: no Library column.
    let pe = report.file.format == Format::Pe;
    let (header, widths): (&[&str], &[Constraint]) = if pe {
        (
            &rows::IMPORT_COLUMNS,
            &[Constraint::Percentage(35), Constraint::Percentage(65)],
        )
    } else {
        (&["Symbol"], &[Constraint::Percentage(100)])
    };
    let spec = TableSpec {
        title,
        header,
        widths,
        empty: "No imports.".into(),
    };
    table::draw(frame, area, &spec, &app.panes.imports, &|r| {
        cells.get(r).map(|[lib, sym]| {
            if pe {
                vec![lib.clone(), sym.clone()]
            } else {
                vec![sym.clone()]
            }
        })
    });
}

fn pe_title(report: &Report) -> String {
    let Some(i) = report.facts.pe.as_ref().and_then(|p| p.imports.as_ref()) else {
        return " Imports (no import table) ".into();
    };
    let limit = if i.limit_reached {
        " · limit reached"
    } else {
        ""
    };
    let imphash = i
        .imphash
        .as_deref()
        .map(|h| format!(" · imphash {h}"))
        .unwrap_or_default();
    format!(
        " Imports ({} functions from {} DLLs{limit}){imphash} ",
        i.total_functions,
        i.libraries.len()
    )
}

fn elf_title(report: &Report) -> String {
    let Some(d) = report.facts.elf.as_ref().and_then(|e| e.dynamic.as_ref()) else {
        return " Imports (no dynamic section: static or stripped) ".into();
    };
    let needed: Vec<String> = d
        .needed
        .iter()
        .map(|n| single_line(n).into_owned())
        .collect();
    let needed = if needed.is_empty() {
        String::new()
    } else {
        format!(" · needed: {}", needed.join(", "))
    };
    format!(" Imported symbols ({}){needed} ", d.imports.len())
}

#[cfg(test)]
mod tests {
    use ratatui::crossterm::event::KeyCode;

    use crate::testkit::{glibc_elf, key, ready_app, render, suspicious_pe};
    use crate::update::update;

    #[test]
    fn pe_imports_grouped_by_library_80x24() {
        let mut app = ready_app("s.exe", suspicious_pe(), (80, 24));
        update(&mut app, key(KeyCode::Char('3')));
        let screen = render(&app);
        assert_eq!(screen.matches("KERNEL32.dll").count(), 1, "{screen}");
        insta::assert_snapshot!(screen);
    }

    #[test]
    fn elf_imports_120x40() {
        let mut app = ready_app("t.elf", glibc_elf(), (120, 40));
        update(&mut app, key(KeyCode::Char('3')));
        insta::assert_snapshot!(render(&app));
    }
}

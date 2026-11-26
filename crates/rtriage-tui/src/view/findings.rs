//! Findings tab: list on the left, details and evidence on the right.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;
use rtriage_core::{Evidence, Finding, Report, Severity};
use rtriage_sanitize::single_line;

use super::{level_name, snake};
use crate::app::{App, Focus};
use crate::jump::{self, RangeInfo, RANGE_ENTROPY_CAP};
use crate::list::ListState;

pub(super) fn draw(app: &App, report: &Report, frame: &mut Frame<'_>, area: Rect) {
    let [left, right] =
        Layout::horizontal([Constraint::Percentage(42), Constraint::Percentage(58)]).areas(area);
    let p = &app.panes;
    list(report, &p.findings, p.focus == Focus::List, frame, left);
    let finding = p.findings.selected().and_then(|i| report.findings.get(i));
    details(
        finding,
        p.focus == Focus::Evidence,
        &p.evidence,
        p.range.as_ref(),
        frame,
        right,
    );
}

fn pane(title: String, focused: bool) -> Block<'static> {
    let title = if focused {
        format!(" ▶ {title} ")
    } else {
        format!(" {title} ")
    };
    let style = if focused {
        Style::new().add_modifier(Modifier::BOLD)
    } else {
        Style::new()
    };
    Block::new()
        .borders(Borders::ALL)
        .title(title)
        .border_style(style)
}

/// Style of the selected row: reversed in the focused pane, bold otherwise.
fn cursor_style(focused: bool) -> Style {
    if focused {
        Style::new().add_modifier(Modifier::REVERSED)
    } else {
        Style::new().add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
    }
}

fn severity_name(s: Severity) -> &'static str {
    match s {
        Severity::High => "HIGH",
        Severity::Medium => "MED",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    }
}

fn list(report: &Report, state: &ListState, focused: bool, frame: &mut Frame<'_>, area: Rect) {
    let block = pane(format!("Findings ({})", report.findings.len()), focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if report.findings.is_empty() {
        frame.render_widget(Paragraph::new("No findings."), inner);
        return;
    }
    let rows = usize::from(inner.height);
    let lines: Vec<Line<'_>> = state
        .window(rows)
        .filter_map(|i| report.findings.get(i).map(|f| (i, f)))
        .map(|(i, f)| {
            // `~` marks findings that are explained away and score 0.
            let mark = if f.suppressed.is_some() { '~' } else { ' ' };
            let text = format!(
                "{:<4} {mark}{} {}",
                severity_name(f.severity),
                f.id,
                single_line(&f.title)
            );
            let line = Line::from(text);
            if Some(i) == state.selected() {
                line.style(cursor_style(focused))
            } else {
                line
            }
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), inner);
}

fn details(
    finding: Option<&Finding>,
    focused: bool,
    evidence: &ListState,
    range: Option<&RangeInfo>,
    frame: &mut Frame<'_>,
    area: Rect,
) {
    let block = pane("Details".to_owned(), focused);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let Some(f) = finding else {
        return;
    };
    let text = detail_lines(f);
    let wanted = wrapped_height(&text, inner.width);
    let range_h = if range.is_some() { 5 } else { 0 };
    // Evidence list sized to its items, the range details right below it.
    let ev_rows = u16::try_from(f.evidence.len())
        .unwrap_or(u16::MAX)
        .saturating_add(1);
    let [top, _gap, ev, bottom, _rest] = Layout::vertical([
        Constraint::Length(wanted.min(inner.height / 2)),
        Constraint::Length(1),
        Constraint::Length(ev_rows),
        Constraint::Length(range_h),
        Constraint::Min(0),
    ])
    .areas(inner);
    frame.render_widget(Paragraph::new(text).wrap(Wrap { trim: false }), top);
    evidence_list(f, evidence, focused, frame, ev);
    if let Some(r) = range {
        frame.render_widget(range_panel(r), bottom);
    }
}

fn detail_lines(f: &Finding) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::styled(
            single_line(&f.title).into_owned(),
            Style::new().add_modifier(Modifier::BOLD),
        ),
        Line::from(format!(
            "{} · confidence {} · {} · {}",
            severity_name(f.severity),
            snake(&f.confidence),
            snake(&f.category),
            f.id
        )),
    ];
    if !f.attack.is_empty() {
        lines.push(Line::from(format!("ATT&CK: {}", f.attack.join(", "))));
    }
    if let Some(s) = &f.suppressed {
        let by = s.by.map(|b| format!(" ({b})")).unwrap_or_default();
        lines.push(Line::from(format!(
            "~ suppressed: explained by {} {}{by}; scores 0",
            snake(&s.kind),
            s.name
        )));
    }
    if let Some(level) = f.risk_floor {
        lines.push(Line::from(format!(
            "raises the risk to at least {}",
            level_name(level)
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(single_line(&f.detail).into_owned()));
    lines
}

/// Rows `lines` take when wrapped to `width` columns (approximate: by chars).
fn wrapped_height(lines: &[Line<'_>], width: u16) -> u16 {
    let width = usize::from(width.max(1));
    let rows: usize = lines.iter().map(|l| l.width().div_ceil(width).max(1)).sum();
    u16::try_from(rows).unwrap_or(u16::MAX)
}

fn evidence_list(f: &Finding, state: &ListState, focused: bool, frame: &mut Frame<'_>, area: Rect) {
    let [head, body] = Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).areas(area);
    let hint = if focused {
        "Enter jump · ← list · Backspace back"
    } else {
        "→ or Enter to select"
    };
    frame.render_widget(
        Line::from(vec![
            Span::styled(
                format!("Evidence ({}) ", f.evidence.len()),
                Style::new().add_modifier(Modifier::BOLD),
            ),
            Span::styled(hint, Style::new().add_modifier(Modifier::DIM)),
        ]),
        head,
    );
    let rows = usize::from(body.height);
    let lines: Vec<Line<'_>> = state
        .window(rows)
        .filter_map(|i| f.evidence.get(i).map(|e| (i, e)))
        .map(|(i, e)| {
            // `→` marks items that open another pane.
            let arrow = if jump::target(e).is_some() {
                '→'
            } else {
                ' '
            };
            let line = Line::from(format!("{arrow} {}", evidence_text(e)));
            if focused && Some(i) == state.selected() {
                line.style(cursor_style(true))
            } else {
                line
            }
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), body);
}

/// One-line, sanitized description of an evidence item.
pub(crate) fn evidence_text(e: &Evidence) -> String {
    match e {
        Evidence::Range { offset, len } => format!("range 0x{offset:08x} (+{len} bytes)"),
        Evidence::Section { index, name } => {
            format!("section #{index} \"{}\"", single_line(name))
        }
        Evidence::Import { library, symbol } => match library {
            Some(lib) => format!("import {}!{}", single_line(lib), single_line(symbol)),
            None => format!("import {}", single_line(symbol)),
        },
        Evidence::String {
            offset,
            encoding,
            value,
        } => format!(
            "string 0x{offset:08x} {} \"{}\"",
            snake(encoding),
            single_line(value)
        ),
        Evidence::Metric { name, value } => format!("{name} = {value:.3}"),
        Evidence::Field { name, value } => format!("{name} = {}", single_line(value)),
        _ => "(evidence type not shown by this version)".to_owned(),
    }
}

fn range_panel(r: &RangeInfo) -> Paragraph<'static> {
    let end = r.offset.saturating_add(r.len);
    let mut lines = vec![Line::from(format!(
        "0x{:08x}..0x{end:08x} ({} bytes)",
        r.offset, r.len
    ))];
    lines.push(Line::from(match &r.section {
        Some(name) => format!("in section \"{}\"", single_line(name)),
        None => "not inside any section (headers or appended data)".to_owned(),
    }));
    lines.push(Line::from(match r.entropy {
        Some(e) if r.sampled => format!(
            "entropy {e:.2} bits/byte (first {} MiB)",
            RANGE_ENTROPY_CAP >> 20
        ),
        Some(e) => format!("entropy {e:.2} bits/byte"),
        None => "entropy n/a: no bytes of this range are in the file".to_owned(),
    }));
    if r.past_eof > 0 {
        lines.push(Line::styled(
            format!("warning: {} bytes lie past the end of the file", r.past_eof),
            Style::new().add_modifier(Modifier::BOLD),
        ));
    }
    Paragraph::new(lines).block(Block::new().borders(Borders::TOP).title(" Byte range "))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use ratatui::backend::TestBackend;
    use ratatui::crossterm::event::KeyCode;
    use ratatui::Terminal;
    use rtriage_core::Evidence;
    use rtriage_fixtures::pe::{profiles, Arch};

    use crate::app::{App, Phase};
    use crate::testkit::{key, ready_app, suspicious_pe};
    use crate::update::update;

    fn render(app: &App) -> String {
        let (w, h) = app.size;
        let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
        t.draw(|f| crate::view::view(app, f)).unwrap();
        t.backend().to_string()
    }

    #[test]
    fn findings_80x24() {
        insta::assert_snapshot!(render(&ready_app("s.exe", suspicious_pe(), (80, 24))));
    }

    #[test]
    fn findings_120x40() {
        insta::assert_snapshot!(render(&ready_app("s.exe", suspicious_pe(), (120, 40))));
    }

    #[test]
    fn range_evidence_panel_120x40() {
        let mut app = ready_app("s.exe", suspicious_pe(), (120, 40));
        let row = app
            .report()
            .unwrap()
            .findings
            .iter()
            .position(|f| f.id == "PE-OVERLAY-HIGH-ENTROPY")
            .unwrap();
        for _ in 0..row {
            update(&mut app, key(KeyCode::Down));
        }
        update(&mut app, key(KeyCode::Enter));
        let screen = render(&app);
        assert!(screen.contains("Byte range"), "{screen}");
        insta::assert_snapshot!(screen);
    }

    #[test]
    fn missing_target_note_80x24() {
        let mut app = ready_app("s.exe", suspicious_pe(), (80, 24));
        if let Phase::Ready(r) = &mut app.phase {
            r.findings[0].evidence[0] = Evidence::Section {
                index: 999,
                name: "gone".into(),
            };
        }
        update(&mut app, key(KeyCode::Enter));
        update(&mut app, key(KeyCode::Enter));
        let screen = render(&app);
        assert!(screen.contains("cannot jump: section #999"), "{screen}");
    }

    #[test]
    fn hostile_finding_text_is_escaped() {
        let mut app = ready_app("s.exe", suspicious_pe(), (120, 40));
        if let Phase::Ready(r) = &mut app.phase {
            let f = &mut r.findings[0];
            f.title = "evil\x1b[2Jtitle\u{202e}cod.exe".into();
            f.detail = "line1\nline2\x1b]52;c;aGk=\x07".into();
            f.evidence[0] = Evidence::String {
                offset: 1,
                encoding: rtriage_core::report::StringEncoding::Ascii,
                value: "a\u{200b}b\u{9b}31m".into(),
            };
        }
        update(&mut app, key(KeyCode::Enter));
        let screen = render(&app);
        for needle in [
            r"evil\x1b[2Jtitle\u{202e}cod.exe",
            r"line1\nline2\x1b]52",
            r"a\u{200b}b\x9b31m",
        ] {
            assert!(screen.contains(needle), "{needle} missing:\n{screen}");
        }
        assert!(!screen.contains(['\x1b', '\u{202e}', '\u{200b}', '\u{9b}', '\x07']));
    }

    #[test]
    fn suppressed_findings_are_marked() {
        let data = profiles::upx_like(Arch::X64).build().bytes;
        let mut app = ready_app("packed.exe", data, (120, 40));
        let r = app.report().unwrap();
        let row = r
            .findings
            .iter()
            .position(|f| f.suppressed.is_some())
            .expect("upx-like fixture has a suppressed finding");
        let id = r.findings[row].id;
        for _ in 0..row {
            update(&mut app, key(KeyCode::Down));
        }
        let screen = render(&app);
        assert!(screen.contains(&format!("~{id}")), "{screen}");
        assert!(
            screen.contains("~ suppressed: explained by packer"),
            "{screen}"
        );
    }

    #[test]
    fn empty_findings_80x24() {
        let screen = render(&ready_app("t.txt", b"plain".to_vec(), (80, 24)));
        assert!(screen.contains("No findings."), "{screen}");
    }

    #[test]
    fn jump_lands_on_the_sections_tab_80x24() {
        let mut app = ready_app("s.exe", suspicious_pe(), (80, 24));
        let row = app
            .report()
            .unwrap()
            .findings
            .iter()
            .position(|f| f.id == "PE-SECTION-RWX")
            .unwrap();
        for _ in 0..row {
            update(&mut app, key(KeyCode::Down));
        }
        update(&mut app, key(KeyCode::Enter));
        update(&mut app, key(KeyCode::Enter));
        let screen = render(&app);
        assert!(screen.contains("row 2 of 4"), "{screen}");
    }
}

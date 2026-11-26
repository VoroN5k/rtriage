//! The only place [`App`] changes. Pure: no I/O, no clock; effects are
//! returned as [`Cmd`]s for the runtime.

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::app::{App, Focus, Panes, PendingCopy, Phase, Tab};
use crate::copy::{self, OSC52_LIMIT};
use crate::filter::{self, FilterDialog, StringFilter};
use crate::jump::{self, Location, Target};
use crate::list::ListState;
use crate::model;
use crate::msg::{Cmd, Msg};
use crate::rows;
use crate::search::{self, Direction, MAX_QUERY_CHARS};

/// Applies `msg` to `app` and returns the effects to perform, in order.
pub fn update(app: &mut App, msg: Msg) -> Vec<Cmd> {
    match msg {
        Msg::Key(key) => on_key(app, key),
        Msg::Resize(w, h) => {
            app.size = (w, h);
            Vec::new()
        }
        Msg::Tick => {
            app.ticks = app.ticks.wrapping_add(1);
            Vec::new()
        }
        Msg::AnalysisDone(report) => {
            app.panes = Panes {
                findings: ListState::new(report.findings.len()),
                sections: ListState::new(model::section_count(&report)),
                segments: ListState::new(rows::segment_count(&report)),
                iocs: ListState::new(rows::ioc_count(&report)),
                imports: ListState::new(model::import_rows(&report).len()),
                string_rows: report
                    .facts
                    .strings
                    .as_ref()
                    .map(|s| filter::rebuild(&s.items, &StringFilter::default()))
                    .unwrap_or_default(),
                ..Panes::default()
            };
            app.panes.strings = ListState::new(app.panes.string_rows.len());
            app.phase = Phase::Ready(report);
            finding_changed(app);
            Vec::new()
        }
        Msg::AnalysisFailed => {
            app.phase = Phase::Failed;
            Vec::new()
        }
    }
}

fn on_key(app: &mut App, key: KeyEvent) -> Vec<Cmd> {
    app.status = None;
    let ctrl_c = key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL);
    if ctrl_c {
        return quit(app);
    }
    if let Some(pending) = app.confirm.take() {
        return confirm_key(app, key.code, pending);
    }
    if app.filter_dialog.is_some() {
        dialog_key(app, key.code);
        return Vec::new();
    }
    if app.prompt.is_some() {
        prompt_key(app, key.code);
        return Vec::new();
    }
    if key.code == KeyCode::Char('q') {
        return quit(app);
    }
    if key.code == KeyCode::Esc {
        return escape(app);
    }
    if app.too_small() {
        return Vec::new();
    }
    match key.code {
        KeyCode::Char('?') => app.help = !app.help,
        _ if app.help || app.report().is_none() => {}
        KeyCode::Char('/') => open_prompt(app),
        KeyCode::Char('n') => search_step(app, Direction::Next),
        KeyCode::Char('N') => search_step(app, Direction::Previous),
        KeyCode::Char('s') if app.tab == Tab::Sections => toggle_segments(app),
        KeyCode::Char('f') if app.tab == Tab::Strings => open_filter_dialog(app),
        KeyCode::Char('d') if app.tab == Tab::Iocs => app.panes.raw_iocs = !app.panes.raw_iocs,
        KeyCode::Char('y') => return copy(app, false),
        KeyCode::Char('Y') => return copy(app, true),
        KeyCode::Char('x') if app.tab == Tab::Strings => clear_string_filter(app),
        KeyCode::Tab => app.tab = app.tab.cycle(1),
        KeyCode::BackTab => app.tab = app.tab.cycle(-1),
        KeyCode::Char(c @ '1'..='9') => {
            let n = usize::from(u8::try_from(c).unwrap_or(b'1').saturating_sub(b'1'));
            if let Some(tab) = Tab::ALL.get(n) {
                app.tab = *tab;
            }
        }
        KeyCode::Backspace => back(app),
        KeyCode::Left if key.modifiers.contains(KeyModifiers::ALT) => back(app),
        code => navigate(app, code),
    }
    Vec::new()
}

/// `y` copies the safe form; `Y` the raw value after a confirmation (our
/// own hashes need none).
fn copy(app: &mut App, raw: bool) -> Vec<Cmd> {
    let Some(target) = copy::target(app) else {
        app.status = Some("nothing to copy here".into());
        return Vec::new();
    };
    if target.verbatim {
        return send_copy(app, target.safe, &target.label, "as is");
    }
    if !raw {
        return send_copy(app, target.safe, &target.label, "sanitized");
    }
    app.status = Some(format!(
        "copy RAW {} ({} B) as found in the file? It may hold control characters. y = copy, any other key = cancel",
        target.label,
        target.raw.len()
    ));
    app.confirm = Some(PendingCopy {
        payload: target.raw,
        label: target.label,
    });
    Vec::new()
}

/// The key after `Y`: only `y` confirms.
fn confirm_key(app: &mut App, code: KeyCode, pending: PendingCopy) -> Vec<Cmd> {
    if code == KeyCode::Char('y') {
        send_copy(app, pending.payload, &pending.label, "raw")
    } else {
        app.status = Some("raw copy cancelled".into());
        Vec::new()
    }
}

fn send_copy(app: &mut App, payload: String, label: &str, mode: &str) -> Vec<Cmd> {
    let len = payload.len();
    if len > OSC52_LIMIT {
        app.status = Some(format!(
            "not copied: {label} is {len} B, which exceeds 64 KiB (the OSC 52 limit)"
        ));
        return Vec::new();
    }
    app.status = Some(format!(
        "copied {label} ({mode}, {len} B) via OSC 52, if your terminal allows it"
    ));
    vec![Cmd::Copy(payload)]
}

fn open_prompt(app: &mut App) {
    if app.panes.list(app.tab).is_some() {
        app.prompt = Some(String::new());
    } else {
        app.status = Some(format!("search is not available in {}", app.tab.title()));
    }
}

/// Keys while the search prompt is open: everything is text except
/// Enter (search), Esc (cancel) and Backspace (delete).
fn prompt_key(app: &mut App, code: KeyCode) {
    let Some(text) = app.prompt.as_mut() else {
        return;
    };
    match code {
        KeyCode::Esc => app.prompt = None,
        KeyCode::Backspace => {
            text.pop();
        }
        KeyCode::Char(c) if text.chars().count() < MAX_QUERY_CHARS => text.push(c),
        KeyCode::Enter => {
            let query = app.prompt.take().unwrap_or_default();
            if !query.is_empty() {
                app.query = Some(query);
                search_step(app, Direction::Here);
            }
        }
        _ => {}
    }
}

/// Moves the current list's cursor to the next match of the last search.
fn search_step(app: &mut App, dir: Direction) {
    let Some(query) = app.query.clone() else {
        app.status = Some("no search yet: press / to search".into());
        return;
    };
    let (Some(report), Some(list)) = (app.report(), app.panes.list(app.tab)) else {
        return;
    };
    let Some(text) = rows::searchable(app, report) else {
        return;
    };
    let found = search::find(list.len(), list.selected().unwrap_or(0), dir, &query, &text);
    drop(text);
    let shown = rtriage_sanitize::single_line(&query).into_owned();
    let Some(found) = found else {
        app.status = Some(format!("no match for \"{shown}\""));
        return;
    };
    let rows = app.list_rows();
    let tab = app.tab;
    if let Some(list) = app.panes.list_mut(tab) {
        list.select(found.row);
        list.follow(rows);
    }
    if tab == Tab::Findings {
        finding_changed(app);
    }
    let wrapped = if found.wrapped { " · wrapped" } else { "" };
    app.status = Some(format!(
        "\"{shown}\": match {} of {}{wrapped} · n next · N previous",
        found.nth, found.total
    ));
}

/// Keys while the strings filter dialog is open.
fn dialog_key(app: &mut App, code: KeyCode) {
    let Some(d) = app.filter_dialog.as_mut() else {
        return;
    };
    match code {
        KeyCode::Esc => app.filter_dialog = None,
        KeyCode::Up | KeyCode::Char('k') => d.move_by(-1),
        KeyCode::Down | KeyCode::Char('j') => d.move_by(1),
        KeyCode::Char(' ') => d.toggle(),
        KeyCode::Char(c) => d.digit(c),
        KeyCode::Backspace => d.backspace(),
        KeyCode::Enter => match d.to_filter() {
            Ok(filter) => {
                app.filter_dialog = None;
                app.panes.string_filter = filter;
                apply_string_filter(app);
            }
            Err(why) => app.status = Some(why),
        },
        _ => {}
    }
}

fn open_filter_dialog(app: &mut App) {
    if app.report().is_some_and(|r| r.facts.strings.is_some()) {
        app.filter_dialog = Some(FilterDialog::new(&app.panes.string_filter));
    } else {
        app.status = Some("no strings to filter".into());
    }
}

fn clear_string_filter(app: &mut App) {
    if app.panes.string_filter.is_active() {
        app.panes.string_filter = StringFilter::default();
        apply_string_filter(app);
    } else {
        app.status = Some("no filter to clear".into());
    }
}

/// Rebuilds the visible strings for the current filter, keeping the cursor
/// on the same string (or the next one shown) when possible.
fn apply_string_filter(app: &mut App) {
    let p = &mut app.panes;
    let before = p
        .strings
        .selected()
        .and_then(|r| p.string_rows.get(r))
        .copied();
    let (rows, total) = match app.phase {
        Phase::Ready(ref r) => r.facts.strings.as_ref().map_or((Vec::new(), 0), |s| {
            (filter::rebuild(&s.items, &p.string_filter), s.items.len())
        }),
        _ => (Vec::new(), 0),
    };
    p.strings = ListState::new(rows.len());
    if let Some(item) = before {
        let at = rows.partition_point(|&i| i < item);
        p.strings.select(at.min(rows.len().saturating_sub(1)));
    }
    let shown = rows.len();
    p.string_rows = rows;
    let page = app.rows_for(Tab::Strings);
    app.panes.strings.follow(page);
    let what = if app.panes.string_filter.is_active() {
        format!("filter {}", app.panes.string_filter.describe())
    } else {
        "no filter".to_owned()
    };
    app.status = Some(format!(
        "{what}: {shown} of {total} strings · f edit · x clear"
    ));
}

/// Visible row of string item `item`; clears a filter that hides it.
fn visible_string_row(app: &mut App, item: usize) -> Option<usize> {
    let item = u32::try_from(item).ok()?;
    if let Ok(row) = app.panes.string_rows.binary_search(&item) {
        return Some(row);
    }
    app.panes.string_filter = StringFilter::default();
    apply_string_filter(app);
    let row = app.panes.string_rows.binary_search(&item).ok();
    app.status = Some("strings filter cleared to show this string".into());
    row
}

fn toggle_segments(app: &mut App) {
    let is_elf = app.report().is_some_and(|r| r.facts.elf.is_some());
    if is_elf {
        app.panes.show_segments = !app.panes.show_segments;
    } else {
        app.status = Some("only ELF files have segments (program headers)".into());
    }
}

/// Cursor movement for `code` (the `usize` is the page height); `None` if
/// `code` is not a movement key.
fn movement(code: KeyCode) -> Option<fn(&mut ListState, usize)> {
    Some(match code {
        KeyCode::Up | KeyCode::Char('k') => |l, _| l.move_by(-1),
        KeyCode::Down | KeyCode::Char('j') => |l, _| l.move_by(1),
        KeyCode::PageUp => |l, p| l.move_by(-p.cast_signed()),
        KeyCode::PageDown => |l, p| l.move_by(p.cast_signed()),
        KeyCode::Home => |l, _| l.home(),
        KeyCode::End => |l, _| l.end(),
        _ => return None,
    })
}

/// Keys inside the current tab.
fn navigate(app: &mut App, code: KeyCode) {
    let rows = app.list_rows();
    if app.tab == Tab::Findings {
        findings_key(app, code, rows);
    } else if let (Some(step), Some(list)) = (movement(code), app.panes.list_mut(app.tab)) {
        step(list, rows);
        list.follow(rows);
    }
}

fn findings_key(app: &mut App, code: KeyCode, rows: usize) {
    let p = &mut app.panes;
    match code {
        KeyCode::Left | KeyCode::Char('h') => p.focus = Focus::List,
        KeyCode::Right | KeyCode::Char('l') => focus_evidence(p),
        KeyCode::Enter if p.focus == Focus::List => focus_evidence(p),
        KeyCode::Enter => jump_to_evidence(app),
        code => {
            let Some(step) = movement(code) else {
                return;
            };
            match p.focus {
                Focus::List => {
                    let before = p.findings.selected();
                    step(&mut p.findings, rows);
                    p.findings.follow(rows);
                    if p.findings.selected() != before {
                        finding_changed(app);
                    }
                }
                Focus::Evidence => {
                    step(&mut p.evidence, rows);
                    evidence_changed(app);
                }
            }
        }
    }
}

fn focus_evidence(p: &mut Panes) {
    if !p.evidence.is_empty() {
        p.focus = Focus::Evidence;
    }
}

/// A new finding is selected: fresh evidence list.
fn finding_changed(app: &mut App) {
    let len = app
        .report()
        .zip(app.panes.findings.selected())
        .and_then(|(r, i)| r.findings.get(i))
        .map_or(0, |f| f.evidence.len());
    app.panes.evidence = ListState::new(len);
    if len == 0 {
        app.panes.focus = Focus::List;
    }
    evidence_changed(app);
}

/// Recomputes the byte-range details for the selected evidence item.
fn evidence_changed(app: &mut App) {
    let range = selected_target(app).and_then(|t| match t {
        Target::Range { offset, len } => {
            let report = app.report()?;
            Some(jump::range_info(&app.input, report, offset, len))
        }
        _ => None,
    });
    app.panes.range = range;
}

fn selected_target(app: &App) -> Option<Target> {
    let report = app.report()?;
    let finding = report.findings.get(app.panes.findings.selected()?)?;
    jump::target(finding.evidence.get(app.panes.evidence.selected()?)?)
}

fn jump_to_evidence(app: &mut App) {
    let Some(report) = app.report() else {
        return;
    };
    let Some(target) = selected_target(app) else {
        app.status = Some("this evidence is a value, there is nothing to jump to".into());
        return;
    };
    match jump::resolve(report, &target) {
        Ok((tab, mut row)) => {
            let here = location(app);
            let rows = app.rows_for(tab);
            if tab == Tab::Sections {
                // Section evidence names section headers, not segments.
                app.panes.show_segments = false;
            }
            if tab == Tab::Strings {
                // `row` is an item index; the list shows filtered rows.
                let Some(visible) = visible_string_row(app, row) else {
                    return;
                };
                row = visible;
            }
            if let Some(list) = app.panes.list_mut(tab) {
                list.select(row);
                list.follow(rows);
            }
            app.history.push(here);
            app.tab = tab;
        }
        Err(why) => app.status = Some(format!("cannot jump: {why}")),
    }
}

/// Where the user is now, to come back to.
fn location(app: &App) -> Location {
    Location {
        tab: app.tab,
        row: app.panes.list(app.tab).and_then(ListState::selected),
        evidence: app.panes.evidence.selected(),
        focus: app.panes.focus,
    }
}

fn back(app: &mut App) {
    let Some(loc) = app.history.pop() else {
        app.status = Some("nothing to go back to".into());
        return;
    };
    let rows = app.list_rows();
    app.tab = loc.tab;
    if let (Some(list), Some(row)) = (app.panes.list_mut(loc.tab), loc.row) {
        list.select(row);
        list.follow(rows);
    }
    if loc.tab == Tab::Findings {
        finding_changed(app);
        if let Some(e) = loc.evidence {
            app.panes.evidence.select(e);
        }
        app.panes.focus = loc.focus;
        focus_evidence_if(app, loc.focus);
        evidence_changed(app);
    }
}

/// Restores a saved focus without focusing an empty evidence list.
fn focus_evidence_if(app: &mut App, focus: Focus) {
    if focus == Focus::Evidence && app.panes.evidence.is_empty() {
        app.panes.focus = Focus::List;
    }
}

/// Cancels a running analysis (once), then quits.
fn quit(app: &mut App) -> Vec<Cmd> {
    let mut cmds = request_cancel(app);
    cmds.push(Cmd::Quit);
    cmds
}

/// Esc: close the help overlay, else clear the search, else cancel a
/// running analysis.
fn escape(app: &mut App) -> Vec<Cmd> {
    if app.help {
        app.help = false;
        return Vec::new();
    }
    if app.query.take().is_some() {
        app.status = Some("search cleared".into());
        return Vec::new();
    }
    request_cancel(app)
}

fn request_cancel(app: &mut App) -> Vec<Cmd> {
    match &mut app.phase {
        Phase::Loading { cancel_sent } if !*cancel_sent => {
            *cancel_sent = true;
            vec![Cmd::Cancel]
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use std::sync::Arc;

    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use rtriage_core::{AnalysisLimit, Config, Input, Registry};

    use super::*;
    use crate::app::Tab;

    fn app() -> App {
        App::new(
            Arc::new(Input::from_bytes("x.bin", b"abc".to_vec())),
            (80, 24),
        )
    }

    fn key(code: KeyCode) -> Msg {
        Msg::Key(KeyEvent::new(code, KeyModifiers::NONE))
    }

    fn ctrl_c() -> Msg {
        Msg::Key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL))
    }

    fn done(app: &mut App) {
        let report = Registry::default().analyze(&app.input, &Config::default());
        update(app, Msg::AnalysisDone(Box::new(report)));
    }

    #[test]
    fn esc_while_loading_emits_cancel_once() {
        let mut a = app();
        assert_eq!(update(&mut a, key(KeyCode::Esc)), [Cmd::Cancel]);
        assert_eq!(a.phase, Phase::Loading { cancel_sent: true });
        assert!(update(&mut a, key(KeyCode::Esc)).is_empty());
    }

    #[test]
    fn q_quits_and_cancels_while_loading() {
        assert_eq!(
            update(&mut app(), key(KeyCode::Char('q'))),
            [Cmd::Cancel, Cmd::Quit]
        );
    }

    #[test]
    fn q_after_cancel_does_not_cancel_again() {
        let mut a = app();
        update(&mut a, key(KeyCode::Esc));
        assert_eq!(update(&mut a, key(KeyCode::Char('q'))), [Cmd::Quit]);
    }

    #[test]
    fn ctrl_c_quits_and_cancels_in_any_state() {
        let mut a = app();
        assert_eq!(update(&mut a, ctrl_c()), [Cmd::Cancel, Cmd::Quit]);
        let mut b = app();
        done(&mut b);
        update(&mut b, key(KeyCode::Char('?')));
        assert!(b.help);
        assert_eq!(update(&mut b, ctrl_c()), [Cmd::Quit]);
    }

    #[test]
    fn cancel_after_done_does_nothing() {
        let mut a = app();
        done(&mut a);
        assert!(update(&mut a, key(KeyCode::Esc)).is_empty());
        assert!(!crate::app::is_partial(a.report().unwrap()));
    }

    #[test]
    fn done_after_cancel_shows_the_report_as_it_is() {
        // The analysis may finish before the token is noticed: the report is
        // then complete and must not be labelled partial.
        let mut a = app();
        update(&mut a, key(KeyCode::Esc));
        done(&mut a);
        let r = a.report().unwrap();
        assert!(!r.analysis_limited.contains(&AnalysisLimit::Partial));
    }

    #[test]
    fn failed_analysis_can_be_quit() {
        let mut a = app();
        update(&mut a, Msg::AnalysisFailed);
        assert_eq!(a.phase, Phase::Failed);
        assert_eq!(update(&mut a, key(KeyCode::Char('q'))), [Cmd::Quit]);
    }

    #[test]
    fn tab_keys_switch_tabs() {
        let mut a = app();
        done(&mut a);
        update(&mut a, key(KeyCode::Char('3')));
        assert_eq!(a.tab, Tab::Imports);
        update(&mut a, key(KeyCode::Tab));
        assert_eq!(a.tab, Tab::Strings);
        update(&mut a, key(KeyCode::BackTab));
        update(&mut a, key(KeyCode::BackTab));
        assert_eq!(a.tab, Tab::Sections);
        update(&mut a, key(KeyCode::Char('1')));
        update(&mut a, key(KeyCode::BackTab));
        assert_eq!(a.tab, Tab::Explain, "wraps around");
        update(&mut a, key(KeyCode::Char('9')));
        assert_eq!(a.tab, Tab::Explain, "no such tab: ignored");
    }

    #[test]
    fn tabs_do_not_switch_while_loading() {
        let mut a = app();
        update(&mut a, key(KeyCode::Char('3')));
        assert_eq!(a.tab, Tab::Findings);
    }

    #[test]
    fn help_toggles_and_esc_closes_it() {
        let mut a = app();
        done(&mut a);
        update(&mut a, key(KeyCode::Char('?')));
        assert!(a.help);
        assert!(update(&mut a, key(KeyCode::Esc)).is_empty());
        assert!(!a.help);
        update(&mut a, key(KeyCode::Char('?')));
        update(&mut a, key(KeyCode::Char('?')));
        assert!(!a.help);
    }

    #[test]
    fn resize_and_tick_update_state() {
        let mut a = app();
        update(&mut a, Msg::Resize(59, 15));
        assert!(a.too_small());
        update(&mut a, Msg::Resize(80, 24));
        assert!(!a.too_small());
        update(&mut a, Msg::Tick);
        assert_eq!(a.ticks, 1);
    }

    #[test]
    fn too_small_and_back_keeps_state() {
        let mut a = app();
        done(&mut a);
        update(&mut a, key(KeyCode::Char('5')));
        update(&mut a, Msg::Resize(40, 10));
        // Nothing is visible, so navigation is ignored; quitting still works.
        assert!(update(&mut a, key(KeyCode::Tab)).is_empty());
        update(&mut a, Msg::Resize(120, 40));
        assert_eq!(a.tab, Tab::Iocs);
        update(&mut a, Msg::Resize(40, 10));
        assert_eq!(update(&mut a, key(KeyCode::Char('q'))), [Cmd::Quit]);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod findings_tests {
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use rtriage_core::Evidence;

    use super::*;
    use crate::app::{Focus, Tab};
    use crate::testkit::{key, ready_app, suspicious_pe};

    fn app() -> App {
        ready_app("s.exe", suspicious_pe(), (100, 30))
    }

    /// Selects the first finding with id `id` and the first evidence item
    /// matching `pick`, with the evidence pane focused.
    fn select(app: &mut App, id: &str, pick: fn(&Evidence) -> bool) {
        let r = app.report().unwrap();
        let f = r.findings.iter().position(|f| f.id == id).unwrap();
        let e = r.findings[f].evidence.iter().position(pick).unwrap();
        update(app, key(KeyCode::Home));
        for _ in 0..f {
            update(app, key(KeyCode::Down));
        }
        update(app, key(KeyCode::Right));
        for _ in 0..e {
            update(app, key(KeyCode::Down));
        }
        assert_eq!(app.panes.focus, Focus::Evidence);
        assert_eq!(app.panes.evidence.selected(), Some(e));
    }

    #[test]
    fn lists_are_sized_when_the_report_arrives() {
        let a = app();
        let r = a.report().unwrap();
        assert_eq!(a.panes.findings.len(), r.findings.len());
        assert_eq!(a.panes.evidence.len(), r.findings[0].evidence.len());
        assert_eq!(
            a.panes.sections.len(),
            4,
            ".text .evil .data + import section"
        );
        assert_eq!(a.panes.imports.len(), 6);
        assert!(!a.panes.strings.is_empty());
    }

    #[test]
    fn moving_in_the_list_resets_the_evidence_cursor() {
        let mut a = app();
        update(&mut a, key(KeyCode::Right));
        update(&mut a, key(KeyCode::Down));
        assert_eq!(a.panes.evidence.selected(), Some(1));
        update(&mut a, key(KeyCode::Left));
        update(&mut a, key(KeyCode::Char('j')));
        assert_eq!(a.panes.findings.selected(), Some(1));
        assert_eq!(a.panes.evidence.selected(), Some(0));
        let n = a.report().unwrap().findings[1].evidence.len();
        assert_eq!(a.panes.evidence.len(), n);
    }

    #[test]
    fn enter_on_the_list_focuses_evidence() {
        let mut a = app();
        update(&mut a, key(KeyCode::Enter));
        assert_eq!(a.panes.focus, Focus::Evidence);
    }

    #[test]
    fn enter_on_section_evidence_jumps_and_backspace_returns() {
        let mut a = app();
        select(&mut a, "PE-SECTION-RWX", |e| {
            matches!(e, Evidence::Section { .. })
        });
        let from_finding = a.panes.findings.selected();
        assert!(update(&mut a, key(KeyCode::Enter)).is_empty());
        assert_eq!(a.tab, Tab::Sections);
        assert_eq!(a.panes.sections.selected(), Some(1), "section #1 .evil");
        assert_eq!(a.history.len(), 1);

        update(&mut a, key(KeyCode::Backspace));
        assert_eq!(a.tab, Tab::Findings);
        assert_eq!(a.panes.findings.selected(), from_finding);
        assert_eq!(a.panes.evidence.selected(), Some(0));
        assert_eq!(a.panes.focus, Focus::Evidence);
        assert!(a.history.is_empty());
    }

    #[test]
    fn alt_left_goes_back_too() {
        let mut a = app();
        select(&mut a, "PE-SECTION-RWX", |e| {
            matches!(e, Evidence::Section { .. })
        });
        update(&mut a, key(KeyCode::Enter));
        update(
            &mut a,
            Msg::Key(KeyEvent::new(KeyCode::Left, KeyModifiers::ALT)),
        );
        assert_eq!(a.tab, Tab::Findings);
    }

    #[test]
    fn jump_to_import_selects_symbol() {
        let mut a = app();
        select(
            &mut a,
            "PE-API-INJECTION",
            |e| matches!(e, Evidence::Import { symbol, .. } if symbol == "WriteProcessMemory"),
        );
        update(&mut a, key(KeyCode::Enter));
        assert_eq!(a.tab, Tab::Imports);
        assert_eq!(a.panes.imports.selected(), Some(2));
    }

    #[test]
    fn jump_to_string_selects_it() {
        let mut a = app();
        select(&mut a, "PE-API-NETWORK", |e| {
            matches!(e, Evidence::String { .. })
        });
        update(&mut a, key(KeyCode::Enter));
        assert_eq!(a.tab, Tab::Strings);
        let row = a.panes.strings.selected().unwrap();
        let s = &a.report().unwrap().facts.strings.as_ref().unwrap().items[row];
        assert_eq!(s.value, "http://c2.evil-example.ru/gate.php");
    }

    #[test]
    fn jump_to_missing_target_stays_and_notes() {
        let mut a = app();
        if let Phase::Ready(r) = &mut a.phase {
            r.findings[0].evidence[0] = Evidence::Section {
                index: 999,
                name: "gone".into(),
            };
        }
        update(&mut a, key(KeyCode::Home));
        update(&mut a, key(KeyCode::Right));
        update(&mut a, key(KeyCode::Enter));
        assert_eq!(a.tab, Tab::Findings);
        assert!(a.history.is_empty());
        let status = a.status.clone().unwrap();
        assert!(status.contains("section #999"), "{status}");
        // The next key clears the note.
        update(&mut a, key(KeyCode::Down));
        assert_eq!(a.status, None);
    }

    #[test]
    fn values_are_not_jump_targets() {
        let mut a = app();
        select(&mut a, "PE-SECTION-RWX", |e| {
            matches!(e, Evidence::Field { .. })
        });
        update(&mut a, key(KeyCode::Enter));
        assert_eq!(a.tab, Tab::Findings);
        assert!(a.status.is_some());
    }

    #[test]
    fn range_evidence_shows_range_details() {
        let mut a = app();
        select(&mut a, "PE-OVERLAY-HIGH-ENTROPY", |e| {
            matches!(e, Evidence::Range { .. })
        });
        let info = a.panes.range.clone().unwrap();
        assert_eq!((info.offset, info.len), (3072, 4096));
        assert_eq!(info.past_eof, 0);
        assert_eq!(info.section, None, "overlay is outside every section");
        assert!(info.entropy.unwrap() > 7.5);
        // Moving off the range hides it.
        update(&mut a, key(KeyCode::Down));
        assert_eq!(a.panes.range, None);
    }

    #[test]
    fn empty_findings_enter_is_noop() {
        let mut a = ready_app("t.txt", b"plain".to_vec(), (80, 24));
        assert_eq!(a.panes.findings.len(), 0);
        for k in [
            KeyCode::Enter,
            KeyCode::Right,
            KeyCode::Enter,
            KeyCode::Down,
            KeyCode::End,
        ] {
            assert!(update(&mut a, key(k)).is_empty());
        }
        assert_eq!(a.tab, Tab::Findings);
        assert_eq!(a.panes.focus, Focus::List);
    }

    #[test]
    fn back_with_empty_history_notes() {
        let mut a = app();
        update(&mut a, key(KeyCode::Backspace));
        assert!(a.status.clone().unwrap().contains("nothing to go back to"));
    }

    #[test]
    fn page_keys_move_by_a_screen() {
        let mut a = ready_app("s.exe", suspicious_pe(), (80, 16));
        update(&mut a, key(KeyCode::PageDown));
        let rows = a.list_rows();
        let n = a.panes.findings.len();
        assert_eq!(a.panes.findings.selected(), Some(rows.min(n - 1)));
        update(&mut a, key(KeyCode::End));
        assert_eq!(a.panes.findings.selected(), Some(n - 1));
        update(&mut a, key(KeyCode::PageUp));
        update(&mut a, key(KeyCode::PageUp));
        assert_eq!(a.panes.findings.selected(), Some(0));
    }

    #[test]
    fn other_tabs_move_their_own_cursor() {
        let mut a = app();
        update(&mut a, key(KeyCode::Char('3')));
        update(&mut a, key(KeyCode::Down));
        assert_eq!(a.panes.imports.selected(), Some(1));
        assert_eq!(a.panes.findings.selected(), Some(0));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod search_tests {
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use rtriage_core::Evidence;

    use super::*;
    use crate::app::Tab;
    use crate::testkit::{glibc_elf, key, ready_app, suspicious_pe};

    fn app() -> App {
        ready_app("s.exe", suspicious_pe(), (100, 30))
    }

    fn type_text(app: &mut App, text: &str) {
        for c in text.chars() {
            update(app, key(KeyCode::Char(c)));
        }
    }

    fn search(app: &mut App, text: &str) {
        update(app, key(KeyCode::Char('/')));
        assert_eq!(app.prompt.as_deref(), Some(""));
        type_text(app, text);
        update(app, key(KeyCode::Enter));
        assert_eq!(app.prompt, None);
    }

    #[test]
    fn search_finds_next_and_wraps() {
        let mut a = app();
        update(&mut a, key(KeyCode::Char('3')));
        search(&mut a, "virtualalloc");
        assert_eq!(a.panes.imports.selected(), Some(1), "VirtualAllocEx");

        search(&mut a, "PROCESS");
        // From the cursor (row 1) forwards: WriteProcessMemory.
        assert_eq!(a.panes.imports.selected(), Some(2));
        assert!(a.status.clone().unwrap().contains("match 2 of 2"));
        update(&mut a, key(KeyCode::Char('n')));
        assert_eq!(
            a.panes.imports.selected(),
            Some(0),
            "wrapped to OpenProcess"
        );
        assert!(a.status.clone().unwrap().contains("wrapped"));
        update(&mut a, key(KeyCode::Char('n')));
        assert_eq!(a.panes.imports.selected(), Some(2));
        update(&mut a, key(KeyCode::Char('N')));
        assert_eq!(a.panes.imports.selected(), Some(0));
    }

    #[test]
    fn search_matches_the_library_too() {
        let mut a = app();
        update(&mut a, key(KeyCode::Char('3')));
        search(&mut a, "winhttp.dll");
        assert_eq!(a.panes.imports.selected(), Some(4), "WinHttpOpen");
    }

    #[test]
    fn search_no_match_keeps_cursor() {
        let mut a = app();
        update(&mut a, key(KeyCode::Char('3')));
        update(&mut a, key(KeyCode::Down));
        search(&mut a, "nope-not-here");
        assert_eq!(a.panes.imports.selected(), Some(1));
        assert!(a.status.clone().unwrap().contains("no match"));
    }

    #[test]
    fn search_in_findings_updates_the_evidence() {
        let mut a = app();
        search(&mut a, "overlay-high");
        let r = a.report().unwrap();
        let f = &r.findings[a.panes.findings.selected().unwrap()];
        assert_eq!(f.id, "PE-OVERLAY-HIGH-ENTROPY");
        assert_eq!(a.panes.evidence.len(), f.evidence.len());
    }

    #[test]
    fn prompt_takes_every_character() {
        let mut a = app();
        update(&mut a, key(KeyCode::Char('/')));
        type_text(&mut a, "q?2/nN");
        assert_eq!(a.prompt.as_deref(), Some("q?2/nN"));
        assert_eq!(a.tab, Tab::Findings);
        assert!(!a.help);
        update(&mut a, key(KeyCode::Backspace));
        assert_eq!(a.prompt.as_deref(), Some("q?2/n"));
        // Ctrl-C still quits while typing.
        let ctrl_c = Msg::Key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert_eq!(update(&mut a, ctrl_c), [Cmd::Quit]);
    }

    #[test]
    fn prompt_length_is_capped() {
        let mut a = app();
        update(&mut a, key(KeyCode::Char('/')));
        type_text(&mut a, &"x".repeat(1000));
        assert_eq!(
            a.prompt.as_ref().unwrap().chars().count(),
            crate::search::MAX_QUERY_CHARS
        );
    }

    #[test]
    fn esc_cancels_the_prompt_then_clears_the_search() {
        let mut a = app();
        search(&mut a, "rwx");
        assert_eq!(a.query.as_deref(), Some("rwx"));
        update(&mut a, key(KeyCode::Char('/')));
        type_text(&mut a, "abc");
        update(&mut a, key(KeyCode::Esc));
        assert_eq!(a.prompt, None);
        assert_eq!(
            a.query.as_deref(),
            Some("rwx"),
            "cancelled prompt keeps the old search"
        );
        update(&mut a, key(KeyCode::Esc));
        assert_eq!(a.query, None);
    }

    #[test]
    fn empty_search_is_ignored() {
        let mut a = app();
        search(&mut a, "");
        assert_eq!(a.query, None);
    }

    #[test]
    fn n_without_a_search_notes() {
        let mut a = app();
        update(&mut a, key(KeyCode::Char('n')));
        assert!(a.status.clone().unwrap().contains("press /"));
    }

    #[test]
    fn search_is_unavailable_without_a_list() {
        let mut a = app();
        update(&mut a, key(KeyCode::Char('6')));
        update(&mut a, key(KeyCode::Char('/')));
        assert_eq!(a.prompt, None);
        assert!(a.status.is_some());
    }

    #[test]
    fn s_toggles_elf_segments() {
        let mut a = ready_app("t.elf", glibc_elf(), (100, 30));
        update(&mut a, key(KeyCode::Char('2')));
        assert!(!a.panes.show_segments);
        update(&mut a, key(KeyCode::Char('s')));
        assert!(a.panes.show_segments);
        assert!(!a.panes.segments.is_empty());
        update(&mut a, key(KeyCode::Down));
        assert_eq!(a.panes.segments.selected(), Some(1));
        assert_eq!(a.panes.sections.selected(), Some(0), "own cursor");
        search(&mut a, "gnu_stack");
        let row = a.panes.segments.selected().unwrap();
        let seg = &a
            .report()
            .unwrap()
            .facts
            .elf
            .as_ref()
            .unwrap()
            .segments
            .as_ref()
            .unwrap()[row];
        assert_eq!(seg.kind, "GNU_STACK");
        update(&mut a, key(KeyCode::Char('s')));
        assert!(!a.panes.show_segments);
    }

    #[test]
    fn s_on_a_pe_notes() {
        let mut a = app();
        update(&mut a, key(KeyCode::Char('2')));
        update(&mut a, key(KeyCode::Char('s')));
        assert!(!a.panes.show_segments);
        assert!(a.status.clone().unwrap().contains("ELF"));
    }

    #[test]
    fn section_jump_shows_section_headers() {
        let mut a = ready_app("t.elf", glibc_elf(), (100, 30));
        update(&mut a, key(KeyCode::Char('2')));
        update(&mut a, key(KeyCode::Char('s')));
        update(&mut a, key(KeyCode::Char('1')));
        if let Phase::Ready(r) = &mut a.phase {
            let f = rtriage_core::Finding::new(
                "TEST",
                rtriage_core::Severity::Info,
                rtriage_core::Category::Metadata,
                "t",
            )
            .evidence(Evidence::Section {
                index: 1,
                name: ".interp".into(),
            });
            r.findings.insert(0, f);
            a.panes.findings = ListState::new(r.findings.len());
        }
        update(&mut a, key(KeyCode::Home));
        finding_changed(&mut a);
        update(&mut a, key(KeyCode::Right));
        update(&mut a, key(KeyCode::Enter));
        assert_eq!(a.tab, Tab::Sections, "{:?}", a.status);
        assert!(!a.panes.show_segments);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod strings_tests {
    use ratatui::crossterm::event::KeyCode;
    use rtriage_core::report::StringKind;
    use rtriage_core::Evidence;

    use super::*;
    use crate::app::Tab;
    use crate::filter::FilterDialog;
    use crate::testkit::{key, mixed_strings, strings_app};

    fn app() -> App {
        let mut a = strings_app(mixed_strings(), (100, 30));
        update(&mut a, key(KeyCode::Char('4')));
        a
    }

    fn values(a: &App) -> Vec<String> {
        let items = &a.report().unwrap().facts.strings.as_ref().unwrap().items;
        a.panes
            .string_rows
            .iter()
            .map(|&i| items[i as usize].value.clone())
            .collect()
    }

    fn type_keys(a: &mut App, text: &str) {
        for c in text.chars() {
            update(a, key(KeyCode::Char(c)));
        }
    }

    #[test]
    fn all_strings_are_visible_without_a_filter() {
        let a = app();
        assert_eq!(a.panes.string_rows, [0, 1, 2, 3, 4, 5]);
        assert_eq!(a.panes.strings.len(), 6);
    }

    #[test]
    fn filter_by_kind_and_length() {
        let mut a = app();
        update(&mut a, key(KeyCode::Char('f')));
        assert!(a.filter_dialog.is_some());
        // Url is the first class; tick it, then go to the minimum length.
        update(&mut a, key(KeyCode::Char(' ')));
        for _ in 0..FilterDialog::MIN_ROW {
            update(&mut a, key(KeyCode::Down));
        }
        type_keys(&mut a, "20");
        update(&mut a, key(KeyCode::Enter));
        assert!(a.filter_dialog.is_none());
        assert_eq!(values(&a), ["http://c2.evil-example.ru/gate.php"]);
        assert_eq!(a.panes.strings.len(), 1);
        assert!(a.status.clone().unwrap().contains("1 of 6"));
    }

    #[test]
    fn dialog_keys_do_not_leak() {
        let mut a = app();
        update(&mut a, key(KeyCode::Char('f')));
        type_keys(&mut a, "q?1/n");
        assert!(a.filter_dialog.is_some());
        assert_eq!(a.tab, Tab::Strings);
        assert!(!a.help && a.prompt.is_none());
        update(&mut a, key(KeyCode::Esc));
        assert!(a.filter_dialog.is_none());
        assert_eq!(a.panes.string_rows.len(), 6, "Esc discards the draft");
    }

    #[test]
    fn invalid_lengths_keep_the_dialog_open() {
        let mut a = app();
        update(&mut a, key(KeyCode::Char('f')));
        for _ in 0..FilterDialog::MIN_ROW {
            update(&mut a, key(KeyCode::Down));
        }
        type_keys(&mut a, "50");
        update(&mut a, key(KeyCode::Down));
        type_keys(&mut a, "10");
        update(&mut a, key(KeyCode::Enter));
        assert!(a.filter_dialog.is_some());
        assert!(a.status.clone().unwrap().contains("greater than"));
    }

    #[test]
    fn x_clears_the_filter_and_keeps_the_selection() {
        let mut a = app();
        a.panes.string_filter.kinds = [StringKind::Ipv4].into();
        apply_string_filter(&mut a);
        assert_eq!(values(&a), ["10.0.0.1"]);
        update(&mut a, key(KeyCode::Char('x')));
        assert_eq!(a.panes.string_rows.len(), 6);
        assert_eq!(a.panes.strings.selected(), Some(2), "still on 10.0.0.1");
    }

    #[test]
    fn empty_after_filter_is_safe() {
        let mut a = app();
        a.panes.string_filter.min_len = Some(10_000);
        apply_string_filter(&mut a);
        assert!(a.panes.strings.is_empty());
        for k in [
            KeyCode::Enter,
            KeyCode::Down,
            KeyCode::End,
            KeyCode::Char('n'),
        ] {
            assert!(update(&mut a, key(k)).is_empty());
        }
        update(&mut a, key(KeyCode::Char('/')));
        type_keys(&mut a, "http");
        update(&mut a, key(KeyCode::Enter));
        assert!(a.status.clone().unwrap().contains("no match"));
    }

    #[test]
    fn search_runs_over_visible_strings_only() {
        let mut a = app();
        a.panes.string_filter.kinds = [StringKind::Url].into();
        apply_string_filter(&mut a);
        update(&mut a, key(KeyCode::Char('/')));
        type_keys(&mut a, "a.ru");
        update(&mut a, key(KeyCode::Enter));
        assert_eq!(a.panes.strings.selected(), Some(1));
        assert!(a.status.clone().unwrap().contains("match 1 of 1"));
    }

    fn jump_to_string_at(a: &mut App, offset: u64) {
        if let Phase::Ready(r) = &mut a.phase {
            let f = rtriage_core::Finding::new(
                "TEST",
                rtriage_core::Severity::Info,
                rtriage_core::Category::Metadata,
                "t",
            )
            .evidence(Evidence::String {
                offset,
                encoding: rtriage_core::report::StringEncoding::Ascii,
                value: "v".into(),
            });
            r.findings.insert(0, f);
            a.panes.findings = ListState::new(r.findings.len());
        }
        update(a, key(KeyCode::Char('1')));
        update(a, key(KeyCode::Home));
        finding_changed(a);
        update(a, key(KeyCode::Right));
        update(a, key(KeyCode::Enter));
    }

    #[test]
    fn jump_to_string_maps_to_the_visible_row() {
        let mut a = app();
        a.panes.string_filter.kinds = [StringKind::Url].into();
        apply_string_filter(&mut a);
        jump_to_string_at(&mut a, 0xc0);
        assert_eq!(a.tab, Tab::Strings);
        assert_eq!(a.panes.strings.selected(), Some(1), "second visible row");
        assert!(a.panes.string_filter.is_active(), "filter kept");
    }

    #[test]
    fn jump_to_string_clears_hiding_filter_with_note() {
        let mut a = app();
        a.panes.string_filter.kinds = [StringKind::Url].into();
        apply_string_filter(&mut a);
        jump_to_string_at(&mut a, 0x80);
        assert_eq!(a.tab, Tab::Strings);
        assert!(!a.panes.string_filter.is_active());
        assert_eq!(a.panes.strings.selected(), Some(2));
        assert!(a.status.clone().unwrap().contains("filter cleared"));
    }

    #[test]
    fn jump_to_string_not_in_capped_list_notes() {
        let mut a = app();
        jump_to_string_at(&mut a, 0x9999);
        assert_eq!(a.tab, Tab::Findings);
        assert!(a
            .status
            .clone()
            .unwrap()
            .contains("not in the extracted list"));
    }

    #[test]
    fn f_outside_strings_does_nothing() {
        let mut a = app();
        update(&mut a, key(KeyCode::Char('2')));
        update(&mut a, key(KeyCode::Char('f')));
        assert!(a.filter_dialog.is_none());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod copy_tests {
    use ratatui::crossterm::event::KeyCode;

    use super::*;
    use crate::app::{Focus, Tab};
    use crate::copy::OSC52_LIMIT;
    use crate::testkit::{key, ready_app, string, strings_app, suspicious_pe};

    fn iocs_app() -> App {
        let mut a = ready_app("s.exe", suspicious_pe(), (100, 30));
        update(&mut a, key(KeyCode::Char('5')));
        a
    }

    /// Moves the IOCs cursor to the first row whose kind cell is `kind`.
    fn select_ioc(a: &mut App, kind: &str) {
        let r = a.report().unwrap();
        let row = (0..rows::ioc_count(r))
            .position(|i| rows::ioc(r, i, false).unwrap()[0] == kind)
            .unwrap();
        a.panes.iocs.select(row);
    }

    fn copied(cmds: &[Cmd]) -> &str {
        match cmds {
            [Cmd::Copy(p)] => p,
            other => panic!("expected one copy, got {other:?}"),
        }
    }

    #[test]
    fn iocs_list_hashes_then_indicators() {
        let a = iocs_app();
        let r = a.report().unwrap();
        assert_eq!(a.panes.iocs.len(), rows::ioc_count(r));
        assert_eq!(rows::ioc(r, 0, false).unwrap()[0], "md5");
        assert_eq!(rows::ioc(r, 2, false).unwrap()[0], "sha256");
        assert!(a.panes.iocs.len() > 3);
    }

    #[test]
    fn d_toggles_defanged_display() {
        let mut a = iocs_app();
        assert!(!a.panes.raw_iocs, "defanged by default");
        update(&mut a, key(KeyCode::Char('d')));
        assert!(a.panes.raw_iocs);
        update(&mut a, key(KeyCode::Char('d')));
        assert!(!a.panes.raw_iocs);
    }

    #[test]
    fn y_copies_the_defanged_ioc() {
        let mut a = iocs_app();
        select_ioc(&mut a, "url");
        let cmds = update(&mut a, key(KeyCode::Char('y')));
        assert_eq!(copied(&cmds), "hxxp://c2[.]evil-example[.]ru/gate.php");
        let status = a.status.clone().unwrap();
        assert!(
            status.contains("copied url IOC (sanitized, 38 B) via OSC 52"),
            "{status}"
        );
        // The display mode does not change what `y` copies.
        update(&mut a, key(KeyCode::Char('d')));
        let cmds = update(&mut a, key(KeyCode::Char('y')));
        assert_eq!(copied(&cmds), "hxxp://c2[.]evil-example[.]ru/gate.php");
    }

    #[test]
    fn shift_y_asks_then_copies_raw() {
        let mut a = iocs_app();
        select_ioc(&mut a, "url");
        assert!(update(&mut a, key(KeyCode::Char('Y'))).is_empty());
        assert!(a.confirm.is_some());
        assert!(a.status.clone().unwrap().contains("RAW"));
        let cmds = update(&mut a, key(KeyCode::Char('y')));
        assert_eq!(copied(&cmds), "http://c2.evil-example.ru/gate.php");
        assert!(a.confirm.is_none());
        assert!(a.status.clone().unwrap().contains("(raw, 34 B)"));
    }

    #[test]
    fn raw_copy_is_cancelled_by_any_other_key() {
        let mut a = iocs_app();
        select_ioc(&mut a, "url");
        update(&mut a, key(KeyCode::Char('Y')));
        assert!(
            update(&mut a, key(KeyCode::Char('q'))).is_empty(),
            "q only cancels here"
        );
        assert!(a.confirm.is_none());
        assert!(a.status.clone().unwrap().contains("cancelled"));
    }

    #[test]
    fn hashes_copy_as_is_in_both_modes() {
        let mut a = iocs_app();
        a.panes.iocs.select(2);
        let sha = a.report().unwrap().file.hashes.clone().unwrap().sha256;
        let cmds = update(&mut a, key(KeyCode::Char('y')));
        assert_eq!(copied(&cmds), sha);
        let cmds = update(&mut a, key(KeyCode::Char('Y')));
        assert_eq!(copied(&cmds), sha, "no confirmation for our own hex");
        assert!(a.status.clone().unwrap().contains("as is"));
    }

    #[test]
    fn strings_copy_sanitized_and_defanged() {
        let items = vec![string(0, "beacon http://evil.ru/x\x1b[2J", &[])];
        let mut a = strings_app(items, (100, 30));
        update(&mut a, key(KeyCode::Char('4')));
        let cmds = update(&mut a, key(KeyCode::Char('y')));
        assert_eq!(copied(&cmds), r"beacon hxxp://evil[.]ru/x\x1b[2J");
    }

    #[test]
    fn findings_copy_the_selected_evidence() {
        let mut a = ready_app("s.exe", suspicious_pe(), (100, 30));
        let cmds = update(&mut a, key(KeyCode::Char('y')));
        let first = &a.report().unwrap().findings[0];
        assert_eq!(copied(&cmds), format!("{}: {}", first.id, first.title));
        update(&mut a, key(KeyCode::Right));
        assert_eq!(a.panes.focus, Focus::Evidence);
        let cmds = update(&mut a, key(KeyCode::Char('y')));
        assert_eq!(copied(&cmds), "KERNEL32.dll!OpenProcess");
    }

    #[test]
    fn too_large_payloads_are_refused() {
        let items = vec![string(0, &"A".repeat(OSC52_LIMIT + 1), &[])];
        let mut a = strings_app(items, (100, 30));
        update(&mut a, key(KeyCode::Char('4')));
        assert!(update(&mut a, key(KeyCode::Char('y'))).is_empty());
        assert!(a.status.clone().unwrap().contains("exceeds 64 KiB"));
    }

    #[test]
    fn empty_iocs_y_is_noop() {
        let mut a = ready_app("t.txt", b"plain".to_vec(), (100, 30));
        if let Phase::Ready(r) = &mut a.phase {
            r.file.hashes = None;
        }
        a.panes.iocs = ListState::new(0);
        update(&mut a, key(KeyCode::Char('5')));
        assert!(update(&mut a, key(KeyCode::Char('y'))).is_empty());
        assert!(update(&mut a, key(KeyCode::Char('Y'))).is_empty());
        assert!(a.confirm.is_none());
        assert!(a.status.clone().unwrap().contains("nothing to copy"));
    }

    #[test]
    fn explain_has_nothing_to_copy() {
        let mut a = iocs_app();
        update(&mut a, key(KeyCode::Char('6')));
        assert!(update(&mut a, key(KeyCode::Char('y'))).is_empty());
        assert_eq!(a.tab, Tab::Explain);
    }
}

//! The only place [`App`] changes. Pure: no I/O, no clock; effects are
//! returned as [`Cmd`]s for the runtime.

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::app::{App, Focus, Panes, Phase, Tab};
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
                imports: ListState::new(model::import_rows(&report).len()),
                strings: ListState::new(model::string_count(&report)),
                ..Panes::default()
            };
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
        Ok((tab, row)) => {
            let here = location(app);
            let rows = app.rows_for(tab);
            if tab == Tab::Sections {
                // Section evidence names section headers, not segments.
                app.panes.show_segments = false;
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

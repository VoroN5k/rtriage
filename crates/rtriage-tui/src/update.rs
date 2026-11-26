//! The only place [`App`] changes. Pure: no I/O, no clock; effects are
//! returned as [`Cmd`]s for the runtime.

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::app::{App, Phase, Tab};
use crate::msg::{Cmd, Msg};

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
            app.phase = Phase::Ready(report);
            Vec::new()
        }
        Msg::AnalysisFailed => {
            app.phase = Phase::Failed;
            Vec::new()
        }
    }
}

fn on_key(app: &mut App, key: KeyEvent) -> Vec<Cmd> {
    let ctrl_c = key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL);
    if ctrl_c || key.code == KeyCode::Char('q') {
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
        KeyCode::Tab => app.tab = app.tab.cycle(1),
        KeyCode::BackTab => app.tab = app.tab.cycle(-1),
        KeyCode::Char(c @ '1'..='9') => {
            let n = usize::from(u8::try_from(c).unwrap_or(b'1').saturating_sub(b'1'));
            if let Some(tab) = Tab::ALL.get(n) {
                app.tab = *tab;
            }
        }
        _ => {}
    }
    Vec::new()
}

/// Cancels a running analysis (once), then quits.
fn quit(app: &mut App) -> Vec<Cmd> {
    let mut cmds = request_cancel(app);
    cmds.push(Cmd::Quit);
    cmds
}

/// Esc: close the help overlay, else cancel a running analysis.
fn escape(app: &mut App) -> Vec<Cmd> {
    if app.help {
        app.help = false;
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

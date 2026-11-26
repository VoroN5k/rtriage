//! Screen snapshots rendered into an in-memory terminal.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::sync::Arc;

use ratatui::backend::TestBackend;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Terminal;
use rtriage_core::{AnalysisLimit, CancelToken, Config, Deadline, Input, Registry, RiskLevel};
use rtriage_tui::{risk_badge, update, view, App, Msg};

fn render(app: &App) -> String {
    let (w, h) = app.size;
    let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
    terminal.draw(|f| view(app, f)).unwrap();
    terminal.backend().to_string()
}

fn input(name: &str) -> Arc<Input> {
    let data = rtriage_fixtures::pe::PeBuilder::new(rtriage_fixtures::pe::Arch::X64)
        .build()
        .bytes;
    Arc::new(Input::from_bytes(name, data))
}

fn ready(name: &str, size: (u16, u16)) -> App {
    let mut app = App::new(input(name), size);
    let report = Registry::default().analyze(&app.input, &Config::default());
    update(&mut app, Msg::AnalysisDone(Box::new(report)));
    app
}

fn cancelled_report(input: &Input) -> rtriage_core::Report {
    let token = CancelToken::default();
    token.cancel();
    Registry::default().analyze_with_deadline(
        input,
        &Config::default(),
        Deadline::never().with_cancel(token),
    )
}

fn key(code: KeyCode) -> Msg {
    Msg::Key(KeyEvent::new(code, KeyModifiers::NONE))
}

#[test]
fn loading_screen_80x24() {
    let app = App::new(input("sample.exe"), (80, 24));
    insta::assert_snapshot!(render(&app));
}

#[test]
fn loading_after_cancel_80x24() {
    let mut app = App::new(input("sample.exe"), (80, 24));
    update(&mut app, key(KeyCode::Esc));
    insta::assert_snapshot!(render(&app));
}

#[test]
fn hostile_file_name_is_escaped() {
    let app = App::new(input("evil\x1b[2J\u{202e}fdp.exe"), (80, 24));
    let screen = render(&app);
    assert!(screen.contains(r"evil\x1b[2J\u{202e}fdp.exe"), "{screen}");
}

#[test]
fn report_80x24() {
    insta::assert_snapshot!(render(&ready("sample.exe", (80, 24))));
}

#[test]
fn report_120x40() {
    insta::assert_snapshot!(render(&ready("sample.exe", (120, 40))));
}

#[test]
fn partial_report_80x24() {
    let mut app = App::new(input("sample.exe"), (80, 24));
    update(&mut app, key(KeyCode::Esc));
    let report = cancelled_report(&app.input);
    update(&mut app, Msg::AnalysisDone(Box::new(report)));
    let screen = render(&app);
    assert!(screen.contains("PARTIAL"), "{screen}");
    assert!(!screen.to_lowercase().contains("clean-looking"), "{screen}");
    insta::assert_snapshot!(screen);
}

#[test]
fn partial_risk_is_shown_as_incomplete() {
    let input = input("x.exe");
    let mut r = cancelled_report(&input);
    assert_eq!(r.risk.level, RiskLevel::CleanLooking);
    assert_eq!(
        risk_badge(&r),
        format!("INCOMPLETE (score so far {})", r.risk.score)
    );
    r.risk.level = RiskLevel::High;
    assert_eq!(risk_badge(&r), "HIGH (incomplete)");

    let mut complete = Registry::default().analyze(&input, &Config::default());
    complete.risk.level = RiskLevel::CleanLooking;
    complete.risk.score = 0;
    assert_eq!(risk_badge(&complete), "CLEAN-LOOKING (score 0)");
    assert!(!complete.analysis_limited.contains(&AnalysisLimit::Partial));
}

#[test]
fn failed_analysis_80x24() {
    let mut app = App::new(input("sample.exe"), (80, 24));
    update(&mut app, Msg::AnalysisFailed);
    insta::assert_snapshot!(render(&app));
}

#[test]
fn help_overlay_80x24() {
    let mut app = ready("sample.exe", (80, 24));
    update(&mut app, key(KeyCode::Char('?')));
    insta::assert_snapshot!(render(&app));
}

#[test]
fn too_small_59x15() {
    let mut app = ready("sample.exe", (80, 24));
    update(&mut app, Msg::Resize(59, 15));
    let screen = render(&app);
    assert!(screen.contains("window too small"), "{screen}");
    insta::assert_snapshot!(screen);
}

#[test]
fn tiny_terminal_does_not_panic() {
    for (w, h) in [(1, 1), (5, 2), (60, 16), (200, 3)] {
        let mut app = ready("sample.exe", (w, h));
        update(&mut app, key(KeyCode::Char('?')));
        render(&app);
    }
}

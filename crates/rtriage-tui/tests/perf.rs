//! Wall-clock check for the strings list at the largest default size.
//! Timing depends on the machine, so it is not run in CI:
//! `cargo test -p rtriage-tui --release --test perf -- --ignored`.
//! The CI guarantee is the row-counter unit test in `view::strings`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use ratatui::backend::TestBackend;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Terminal;
use rtriage_core::report::{ExtractedString, StringEncoding, StringKind, StringsFacts};
use rtriage_core::{Config, Input, Registry, StringsIncluded};
use rtriage_tui::{update, view, App, Msg};

fn key(c: char) -> Msg {
    Msg::Key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE))
}

#[test]
#[ignore = "timing; run locally with --release -- --ignored"]
fn filter_and_frame_over_200k_is_fast() {
    let items: Vec<ExtractedString> = (0..200_000u64)
        .map(|i| ExtractedString {
            offset: i * 32,
            encoding: StringEncoding::Ascii,
            len: 24,
            value: format!("http://host{i}.example.com/"),
            truncated: false,
            kinds: if i % 3 == 0 {
                vec![StringKind::Domain, StringKind::Url]
            } else {
                Vec::new()
            },
        })
        .collect();
    let mut app = App::new(
        Arc::new(Input::from_bytes("big.bin", b"x".to_vec())),
        (120, 40),
    );
    let mut report = Registry::default().analyze(&app.input, &Config::default());
    report.facts.strings = Some(StringsFacts {
        min_len: 5,
        total: 200_000,
        limit_reached: false,
        items_included: StringsIncluded::All,
        items,
    });
    update(&mut app, Msg::AnalysisDone(Box::new(report)));
    update(&mut app, key('4'));
    let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();

    let start = Instant::now();
    // Filter to URLs (dialog: tick the first class, apply), then draw.
    update(&mut app, key('f'));
    update(&mut app, key(' '));
    update(
        &mut app,
        Msg::Key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)),
    );
    terminal.draw(|f| view(&app, f)).unwrap();
    let elapsed = start.elapsed();

    assert_eq!(app.panes.string_rows.len(), 66_667);
    assert!(
        elapsed < Duration::from_millis(100),
        "filter + frame took {elapsed:?}"
    );
}

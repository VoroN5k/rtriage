//! Strings tab over 200 000 strings: filter rebuild and one frame.
//! `cargo bench -p rtriage-tui --bench strings_list`
#![allow(clippy::unwrap_used, clippy::expect_used, missing_docs)]

use std::hint::black_box;
use std::sync::Arc;

use criterion::{criterion_group, criterion_main, Criterion};
use ratatui::backend::TestBackend;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Terminal;
use rtriage_core::report::{ExtractedString, StringEncoding, StringKind, StringsFacts};
use rtriage_core::{Config, Input, Registry, StringsIncluded};
use rtriage_tui::{update, view, App, Msg};

fn key(code: KeyCode) -> Msg {
    Msg::Key(KeyEvent::new(code, KeyModifiers::NONE))
}

fn app() -> App {
    let items: Vec<ExtractedString> = (0..200_000u64)
        .map(|i| ExtractedString {
            offset: i * 32,
            encoding: StringEncoding::Ascii,
            len: 24 + i % 40,
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
    update(&mut app, key(KeyCode::Char('4')));
    app
}

fn bench(c: &mut Criterion) {
    let mut app = app();
    let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
    c.bench_function("strings: frame at the end of 200k", |b| {
        update(&mut app, key(KeyCode::End));
        b.iter(|| {
            terminal.draw(|f| view(black_box(&app), f)).unwrap();
        });
    });
    c.bench_function("strings: toggle url filter on 200k", |b| {
        b.iter(|| {
            update(&mut app, key(KeyCode::Char('f')));
            update(&mut app, key(KeyCode::Char(' ')));
            update(&mut app, key(KeyCode::Enter));
        });
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);

//! Hostile input and arbitrary key sequences against the whole TUI:
//! nothing may panic, and no rendered cell may hold a control, bidi or
//! invisible character (the terminal would act on it).
//!
//! `PROPTEST_CASES` raises the case count (the weekly workflow uses many).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::sync::{Arc, OnceLock};

use proptest::prelude::*;
use ratatui::backend::TestBackend;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Terminal;
use rtriage_core::report::{
    Evidence, ExtractedString, Ioc, IocKind, RiskFloor, StringEncoding, StringKind,
};
use rtriage_core::{
    AnalysisLimit, CancelToken, Category, Config, Deadline, Finding, Input, Registry, Report,
    RiskLevel, Severity,
};
use rtriage_tui::{update, view, App, Msg};

/// Characters a terminal could act on, or that change how text reads.
fn forbidden(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061c}'
                | '\u{200b}'..='\u{200f}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
                | '\u{feff}'
        )
}

/// Renders `app` at its size and checks every cell.
fn render_clean(app: &App) -> String {
    let (w, h) = app.size;
    let mut t = Terminal::new(TestBackend::new(w.max(1), h.max(1))).unwrap();
    t.draw(|f| view(app, f)).unwrap();
    for (i, cell) in t.backend().buffer().content.iter().enumerate() {
        let bad: Vec<char> = cell.symbol().chars().filter(|c| forbidden(*c)).collect();
        assert!(
            bad.is_empty(),
            "cell {i} holds {bad:?} at {w}x{h} on {:?}",
            app.tab
        );
    }
    let screen = t.backend().to_string();
    assert_escaped(&screen);
    screen
}

/// Every kind of attacker-controlled text the TUI draws, in one place.
const EVIL: &str =
    "e\x1b[2J\x1b]52;c;aGk=\x07\u{9b}31m\u{202e}\u{2066}\u{200b}\u{feff}\r\n\u{2028}\x7fvil";

fn key(code: KeyCode) -> Msg {
    Msg::Key(KeyEvent::new(code, KeyModifiers::NONE))
}

fn suspicious_pe() -> Vec<u8> {
    use rtriage_fixtures::pe::{Arch, PeBuilder, Section};
    PeBuilder::new(Arch::X64)
        .section(Section::code(".text", vec![0xC3; 512]))
        .section(Section::rwx(".evil", vec![0x90; 512]))
        .section(Section::data(
            ".data",
            b"\0http://c2.evil-example.ru/gate.php\0".to_vec(),
        ))
        .import(
            "KERNEL32.dll",
            &[
                "OpenProcess",
                "VirtualAllocEx",
                "WriteProcessMemory",
                "CreateRemoteThread",
            ],
        )
        .overlay(
            (0..4096u32)
                .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
                .collect(),
        )
        .build()
        .bytes
}

/// A real analysis with attacker text injected into every displayed field.
fn hostile_report(input: &Input) -> Report {
    let mut r = Registry::default().analyze(input, &Config::default());
    for f in &mut r.findings {
        f.title = format!("{EVIL} title");
        f.detail = format!("{EVIL} detail");
    }
    r.findings.push(
        Finding::new("TEST-EVIL", Severity::High, Category::Injection, EVIL)
            .detail(EVIL)
            .evidence(Evidence::String {
                offset: 1,
                encoding: StringEncoding::Ascii,
                value: EVIL.into(),
            })
            .evidence(Evidence::Field {
                name: "field",
                value: EVIL.into(),
            })
            .evidence(Evidence::Import {
                library: Some(EVIL.into()),
                symbol: EVIL.into(),
            })
            .evidence(Evidence::Section {
                index: 0,
                name: EVIL.into(),
            })
            .evidence(Evidence::Range { offset: 0, len: 64 }),
    );
    if let Some(pe) = r.facts.pe.as_mut() {
        for s in pe.sections.iter_mut().flatten() {
            s.name = EVIL.into();
        }
        for lib in pe.imports.iter_mut().flat_map(|i| i.libraries.iter_mut()) {
            lib.name = EVIL.into();
            for f in &mut lib.functions {
                f.name = Some(EVIL.into());
            }
        }
    }
    if let Some(elf) = r.facts.elf.as_mut() {
        for s in elf.sections.iter_mut().flatten() {
            s.name = EVIL.into();
            s.kind = EVIL.into();
        }
        for s in elf.segments.iter_mut().flatten() {
            s.kind = EVIL.into();
        }
        if let Some(d) = elf.dynamic.as_mut() {
            d.needed = vec![EVIL.into()];
            d.imports = vec![EVIL.into()];
        }
    }
    let strings = r
        .facts
        .strings
        .get_or_insert_with(|| rtriage_core::report::StringsFacts {
            min_len: 5,
            total: 0,
            limit_reached: false,
            items_included: rtriage_core::StringsIncluded::All,
            items: Vec::new(),
        });
    strings.items.insert(
        0,
        ExtractedString {
            offset: 0,
            encoding: StringEncoding::Ascii,
            len: 40,
            value: EVIL.into(),
            truncated: true,
            kinds: vec![StringKind::Url],
        },
    );
    let iocs = r.facts.iocs.get_or_insert_with(Default::default);
    iocs.items.push(Ioc {
        kind: IocKind::Url,
        value: EVIL.into(),
        value_defanged: EVIL.into(),
        scope: None,
        allowlisted: false,
        count: 1,
        offsets: vec![0],
    });
    r.risk.floor = Some(RiskFloor {
        level: RiskLevel::High,
        finding: "YARA-MATCH",
        title: EVIL.into(),
    });
    r
}

fn ready(name: &str, data: Vec<u8>, size: (u16, u16)) -> App {
    let input = Input::from_bytes(name, data);
    let report = hostile_report(&input);
    let mut app = App::new(Arc::new(input), size);
    update(&mut app, Msg::AnalysisDone(Box::new(report)));
    app
}

/// Visits every screen and overlay, checking each frame.
fn visit_everything(app: &mut App) {
    let press = |app: &mut App, codes: &[KeyCode]| {
        for c in codes {
            update(app, key(*c));
        }
        render_clean(app);
    };
    use KeyCode::{BackTab, Char, Down, End, Enter, Esc, Right};
    press(app, &[]);
    press(app, &[End, Right]);
    for _ in 0..6 {
        press(app, &[Down]);
    }
    press(app, &[Enter]); // jump from the last evidence item (range → hex)
    press(app, &[Char('1'), Char('?')]);
    press(app, &[End]);
    press(app, &[Char('?')]);
    for tab in '2'..='7' {
        press(app, &[Char(tab)]);
        press(app, &[Down, End]);
    }
    press(app, &[Char('2'), Char('s')]);
    press(app, &[Char('4'), Char('f'), Char(' ')]);
    press(app, &[Esc, Char('/'), Char('\x1b')]);
    press(app, &[Esc, Char('5'), Char('d')]);
    press(app, &[Char('d'), Char('Y')]);
    press(app, &[Esc, Char('7'), Char('g'), Char('x')]);
    press(app, &[Esc, BackTab, Char('y')]);
}

#[test]
fn rendered_cells_hold_no_control_chars() {
    let name = format!("{EVIL}.exe");
    for size in [(80, 24), (120, 40), (60, 16)] {
        let mut pe = ready(&name, suspicious_pe(), size);
        visit_everything(&mut pe);
        let elf = rtriage_fixtures::elf::profiles::glibc_pie().build().bytes;
        let mut elf = ready(&name, elf, size);
        visit_everything(&mut elf);
    }
}

#[test]
fn loading_and_partial_screens_are_clean() {
    let input = Input::from_bytes(format!("{EVIL}.bin"), suspicious_pe());
    let mut app = App::new(Arc::new(input), (80, 24));
    render_clean(&app);
    update(&mut app, key(KeyCode::Esc));
    render_clean(&app);
    let token = CancelToken::default();
    token.cancel();
    let mut report = Registry::default().analyze_with_deadline(
        &app.input,
        &Config::default(),
        Deadline::never().with_cancel(token),
    );
    assert!(report.analysis_limited.contains(&AnalysisLimit::Partial));
    report.findings = hostile_report(&app.input).findings;
    update(&mut app, Msg::AnalysisDone(Box::new(report)));
    let screen = render_clean(&app);
    assert!(screen.contains("PARTIAL"), "{screen}");
    update(&mut app, Msg::AnalysisFailed);
    render_clean(&app);
}

/// Reports for every fixture of the corpora plus the hostile ones, built
/// once: analysing is the slow part, the property is about the UI.
fn corpus() -> &'static [(String, Arc<Input>, Report)] {
    static CORPUS: OnceLock<Vec<(String, Arc<Input>, Report)>> = OnceLock::new();
    CORPUS.get_or_init(|| {
        let mut all: Vec<(String, Vec<u8>)> = rtriage_fixtures::pe::corpus()
            .into_iter()
            .chain(rtriage_fixtures::elf::corpus())
            .map(|(n, d)| (n.to_owned(), d))
            .collect();
        all.push((format!("{EVIL}.exe"), suspicious_pe()));
        all.push(("empty".into(), Vec::new()));
        all.push(("text".into(), b"just text".to_vec()));
        all.into_iter()
            .map(|(name, data)| {
                let input = Input::from_bytes(name.clone(), data);
                let report = hostile_report(&input);
                (name, Arc::new(input), report)
            })
            .collect()
    })
}

fn cases() -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(64)
}

fn any_msg() -> impl Strategy<Value = Msg> {
    let codes = prop_oneof![
        Just(KeyCode::Up),
        Just(KeyCode::Down),
        Just(KeyCode::Left),
        Just(KeyCode::Right),
        Just(KeyCode::PageUp),
        Just(KeyCode::PageDown),
        Just(KeyCode::Home),
        Just(KeyCode::End),
        Just(KeyCode::Enter),
        Just(KeyCode::Esc),
        Just(KeyCode::Backspace),
        Just(KeyCode::Tab),
        Just(KeyCode::BackTab),
        Just(KeyCode::Delete),
        Just(KeyCode::F(1)),
        prop::sample::select(b"1234567/nNsfxdyYgq? hjkl0xab\x1b".to_vec())
            .prop_map(|b| KeyCode::Char(char::from(b))),
        any::<char>().prop_map(KeyCode::Char),
    ];
    let mods = prop_oneof![
        8 => Just(KeyModifiers::NONE),
        1 => Just(KeyModifiers::SHIFT),
        1 => Just(KeyModifiers::ALT),
        // Not Ctrl-C only: other Ctrl combinations must be harmless too.
        1 => Just(KeyModifiers::CONTROL),
    ];
    prop_oneof![
        20 => (codes, mods).prop_map(|(c, m)| Msg::Key(KeyEvent::new(c, m))),
        2 => (1u16..200, 1u16..80).prop_map(|(w, h)| Msg::Resize(w, h)),
        1 => Just(Msg::Tick),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases()))]

    #[test]
    fn random_keys_never_panic_and_never_leak(
        which in any::<prop::sample::Index>(),
        msgs in prop::collection::vec(any_msg(), 0..300),
        size in (1u16..200, 1u16..80),
    ) {
        let all = corpus();
        let (_, input, report) = &all[which.index(all.len())];
        let mut app = App::new(Arc::clone(input), size);
        update(&mut app, Msg::AnalysisDone(Box::new(report.clone())));
        for (i, msg) in msgs.into_iter().enumerate() {
            // Quit is just a command: the loop goes on, as a test should.
            let _ = update(&mut app, msg);
            if i % 25 == 0 {
                render_clean(&app);
            }
        }
        render_clean(&app);
    }
}

/// ratatui itself drops control and zero-width characters from cells, so
/// the cell check alone would pass even without sanitizing. What sanitizing
/// adds is that the hidden characters stay *visible* as escapes. Without
/// it, `EVIL` renders as glued fragments; these must never appear.
const UNSANITIZED_FRAGMENTS: [&str; 3] = ["e[2J", "aGk=31m", "31mvil"];

fn assert_escaped(screen: &str) {
    for frag in UNSANITIZED_FRAGMENTS {
        assert!(
            !screen.contains(frag),
            "unsanitized text ({frag}) on screen:\n{screen}"
        );
    }
}

/// Both checks must be able to fail: unsanitized text is caught by the
/// fragment check (the cell check cannot see it, see above), sanitized
/// text passes both.
#[test]
fn the_checks_catch_unsanitized_text() {
    use ratatui::widgets::Paragraph;
    let draw = |text: String| {
        let mut t = Terminal::new(TestBackend::new(120, 1)).unwrap();
        t.draw(|f| f.render_widget(Paragraph::new(text), f.area()))
            .unwrap();
        t.backend().to_string()
    };
    let raw = draw(EVIL.to_owned());
    assert!(
        UNSANITIZED_FRAGMENTS.iter().any(|f| raw.contains(f)),
        "the fragment check would miss raw text: {raw}"
    );
    let safe = draw(rtriage_sanitize::single_line(EVIL).into_owned());
    assert_escaped(&safe);
    assert!(safe.contains(r"\x1b[2J"), "{safe}");
}

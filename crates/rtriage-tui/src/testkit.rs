//! Synthetic inputs for unit tests (no real samples, ever).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use rtriage_core::{Config, Input, Registry, Report};
use rtriage_fixtures::pe::{Arch, PeBuilder, Section};

use crate::app::App;
use crate::msg::Msg;
use crate::update::update;

/// A PE with an RWX section, an injection import set, a C2-looking URL and
/// a high-entropy overlay: findings with section, import, string and range
/// evidence.
pub fn suspicious_pe() -> Vec<u8> {
    let mut overlay = Vec::with_capacity(4096);
    let mut x: u32 = 0x1234_5678;
    for _ in 0..4096 {
        // xorshift: incompressible enough for a high-entropy overlay.
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        overlay.push(x.to_le_bytes()[0]);
    }
    PeBuilder::new(Arch::X64)
        .section(Section::code(".text", vec![0xC3; 512]))
        .section(Section::rwx(".evil", vec![0x90; 512]))
        .section(Section::data(
            ".data",
            b"\0http://c2.evil-example.ru/gate.php\0WinHttpOpen\0".to_vec(),
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
        .import("WINHTTP.dll", &["WinHttpOpen", "WinHttpConnect"])
        .overlay(overlay)
        .build()
        .bytes
}

/// `App` for `data` named `name`, with the analysis finished.
pub fn ready_app(name: &str, data: Vec<u8>, size: (u16, u16)) -> App {
    let mut app = App::new(Arc::new(Input::from_bytes(name, data)), size);
    let report = analyze(&app.input);
    update(&mut app, Msg::AnalysisDone(Box::new(report)));
    app
}

/// Default analysis of `input`.
pub fn analyze(input: &Input) -> Report {
    Registry::default().analyze(input, &Config::default())
}

/// A key press without modifiers.
pub fn key(code: KeyCode) -> Msg {
    Msg::Key(KeyEvent::new(code, KeyModifiers::NONE))
}

//! ELF path: header/program-header parser, then the dynamic/symbol and note
//! parsers directly (with a finite budget), then the full analysis pipeline
//! with report invariants. Seeds: `cargo run -p rtriage-fixtures --example
//! fuzz_corpus -- fuzz/corpus/elf_parse elf`.
#![no_main]

use std::time::Duration;

use libfuzzer_sys::fuzz_target;
use rtriage_core::analyzers::elf;
use rtriage_core::{Config, Deadline, Input, Registry};

fuzz_target!(|data: &[u8]| {
    let mut config = Config::default();
    // Slow inputs show up as timeouts in the report rather than hanging the fuzzer.
    config.limits.max_analysis_time = Duration::from_secs(5);

    // Reached even when sniffing would not classify the input as ELF.
    if let Ok(image) = elf::parse(data, &config.limits) {
        let deadline = Deadline::after(config.limits.max_analysis_time);
        let _ = elf::dynamic::parse(&image, data, &config.limits, &deadline);
        let _ = elf::notes::parse(&image, data, &config.limits, &deadline);
    }

    let report =
        Registry::default().analyze(&Input::from_bytes("fuzz.elf", data.to_vec()), &config);
    let sum: u32 = report.risk.breakdown.iter().map(|e| e.points).sum();
    assert_eq!(sum, report.risk.score);
    assert!(report.findings.iter().all(|f| f.suppressed.is_none()
        || !(f.id.starts_with("PE-API-") || f.id.starts_with("ELF-API-"))));
});

//! Property tests for the YARA path (feature `yara`): yara-x's `pe` and `elf`
//! modules parse the hostile file themselves, so the mutated PE and ELF
//! corpora are scanned with rules that touch those modules. A panic inside
//! yara-x would surface as an `Internal` error from the `yara` analyzer;
//! only timeouts are acceptable.
#![cfg(feature = "yara")]
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

mod common;

use std::sync::{Arc, OnceLock};

use common::{analyze, apply, cases, mutation};
use proptest::prelude::*;
use rtriage_core::yara::{YaraRules, YaraSource};
use rtriage_core::{AnalysisError, Config};

const RULES: &str = r#"
import "pe"
import "elf"
import "hash"
import "math"
rule pe_shape {
  condition:
    pe.is_pe and (pe.number_of_sections > 3 or pe.imports("kernel32.dll") > 0
      or pe.exports("x") or pe.number_of_resources > 0 or pe.is_signed)
}
rule pe_loop {
  condition:
    for any s in pe.sections : (s.raw_data_size > 0 and math.entropy(s.raw_data_offset, s.raw_data_size) > 7.0)
}
rule elf_shape {
  condition:
    elf.type == elf.ET_DYN or elf.number_of_sections > 5 or
    for any seg in elf.segments : (seg.flags & elf.PF_X != 0)
}
rule elf_symbols {
  condition: for any s in elf.dynsym : (s.name == "socket")
}
rule bytes { strings: $mz = "MZ" $elf = { 7F 45 4C 46 } condition: any of them }
rule hashing { condition: hash.md5(0, filesize) != "" }
"#;

fn config() -> &'static Config {
    static C: OnceLock<Config> = OnceLock::new();
    C.get_or_init(|| {
        let rules = YaraRules::compile(&[YaraSource {
            origin: "robustness.yar".into(),
            namespace: "r".into(),
            text: RULES.into(),
        }])
        .unwrap();
        Config {
            yara: Some(Arc::new(rules)),
            ..Config::default()
        }
    })
}

fn corpus() -> &'static [Vec<u8>] {
    static C: OnceLock<Vec<Vec<u8>>> = OnceLock::new();
    C.get_or_init(|| {
        rtriage_fixtures::pe::corpus()
            .into_iter()
            .chain(rtriage_fixtures::elf::corpus())
            .map(|(_, b)| b)
            .collect()
    })
}

fn check_yara(bytes: Vec<u8>) -> Result<(), TestCaseError> {
    let r = analyze("fuzz.bin", bytes, config());
    for e in r.errors.iter().filter(|e| e.analyzer == "yara") {
        prop_assert!(
            matches!(e.error, AnalysisError::Timeout { .. }),
            "yara error: {:?}",
            e.error
        );
    }
    prop_assert!(r.facts.yara.is_some() || r.errors.iter().any(|e| e.analyzer == "yara"));
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(cases()))]

    #[test]
    fn mutated_pe_and_elf_through_yara_modules(
        idx in 0usize..1000,
        mutations in prop::collection::vec(mutation(), 1..12),
    ) {
        check_yara(apply(corpus()[idx % corpus().len()].clone(), &mutations))?;
    }

    #[test]
    fn arbitrary_bytes_through_yara(bytes in prop::collection::vec(any::<u8>(), 0..4096)) {
        check_yara(bytes)?;
    }
}

#[test]
fn unmutated_corpus_matches_expected_rules() {
    let r = analyze("t.exe", corpus()[0].clone(), config());
    let names: Vec<_> = r
        .facts
        .yara
        .unwrap()
        .matches
        .into_iter()
        .map(|m| m.rule)
        .collect();
    assert!(names.contains(&"bytes".to_owned()), "{names:?}");
}

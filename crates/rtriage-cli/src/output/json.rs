//! JSON renderer. The schema is versioned: bump [`SCHEMA_VERSION`] on any
//! breaking change (removing/renaming fields or changing their meaning).
//! Adding fields is not breaking.

use std::io::{self, Write};

use rtriage_core::Report;
use serde::Serialize;

use super::{Failure, Run};

/// Current JSON schema version.
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Serialize)]
struct Document<'a> {
    schema_version: u32,
    tool: Tool,
    reports: &'a [Report],
    failures: &'a [Failure],
}

#[derive(Serialize)]
struct Tool {
    name: &'static str,
    version: &'static str,
}

/// Writes `run` as pretty-printed JSON followed by a newline.
pub fn render(run: &Run, out: &mut dyn Write) -> io::Result<()> {
    let doc = Document {
        schema_version: SCHEMA_VERSION,
        tool: Tool {
            name: "rtriage",
            version: env!("CARGO_PKG_VERSION"),
        },
        reports: &run.reports,
        failures: &run.failures,
    };
    serde_json::to_writer_pretty(&mut *out, &doc)?;
    writeln!(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::prepare;
    use rtriage_core::{Config, Input, Registry};

    fn sample_run(all_strings: bool) -> Run {
        let mut data = b"\x00\x00MZ-not-really\x00http://c2.example.ru/gate.php\x00".to_vec();
        data.extend((0..4096).map(|i| (i % 256) as u8));
        data.extend(b"\x00just some text\x00");
        let input = Input::from_bytes("sample.bin", data);
        let mut report = Registry::default().analyze(&input, &Config::default());
        prepare(&mut report, all_strings);
        Run {
            reports: vec![report],
            failures: vec![Failure {
                path: "missing.bin".into(),
                error: "cannot read missing.bin: not found".into(),
            }],
        }
    }

    fn render_value(run: &Run) -> serde_json::Value {
        let mut buf = Vec::new();
        render(run, &mut buf).unwrap();
        let mut v: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        v["tool"]["version"] = "[version]".into();
        v
    }

    #[test]
    fn snapshot_default() {
        let v = render_value(&sample_run(false));
        insta::assert_snapshot!(serde_json::to_string_pretty(&v).unwrap());
    }

    #[test]
    fn all_strings_keeps_unclassified() {
        let v = render_value(&sample_run(true));
        let strings = &v["reports"][0]["facts"]["strings"];
        assert_eq!(strings["items_included"], "all");
        assert!(strings["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["value"] == "just some text"));
    }

    #[test]
    fn default_keeps_only_classified() {
        let v = render_value(&sample_run(false));
        let strings = &v["reports"][0]["facts"]["strings"];
        assert_eq!(strings["items_included"], "classified");
        assert!(strings["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|s| s["kinds"].is_array()));
    }

    #[test]
    fn hostile_strings_are_json_escaped() {
        let input = Input::from_bytes("x", b"\x00evil\x1b[2Jhttp://a.ru/\x00".to_vec());
        let report = Registry::default().analyze(&input, &Config::default());
        let mut buf = Vec::new();
        render(
            &Run {
                reports: vec![report],
                failures: vec![],
            },
            &mut buf,
        )
        .unwrap();
        assert!(!buf.contains(&0x1b));
    }
}

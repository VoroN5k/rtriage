//! JSON renderer. The schema is versioned: bump [`SCHEMA_VERSION`] on any
//! breaking change (removing/renaming fields or changing their meaning).
//! Adding fields is not breaking.

use std::io::{self, Write};

use rtriage_core::{Report, RiskLevel};

use crate::worker::Summary;
use serde::Serialize;

use super::{Failure, Run, SkippedPath};

/// Current JSON schema version.
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Serialize)]
struct Document<'a> {
    schema_version: u32,
    tool: Tool,
    reports: &'a [Report],
    failures: &'a [Failure],
    skipped: &'a [SkippedPath],
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
        skipped: &run.skipped,
    };
    serde_json::to_writer_pretty(&mut *out, &doc)?;
    writeln!(out)
}

// ---------------------------------------------------------------- streaming

/// Starts a document whose reports arrive one by one (worker bodies): the
/// same keys and order as [`render`], so consumers cannot tell the difference.
pub fn begin_document(out: &mut dyn Write) -> io::Result<()> {
    write!(
        out,
        "{{\n  \"schema_version\": {SCHEMA_VERSION},\n  \"tool\": {},\n  \"reports\": [",
        indent(&serde_json::to_string_pretty(&tool())?, 2)
    )
}

/// Appends one pretty-printed report body (from a worker).
pub fn document_report(out: &mut dyn Write, body: &str, first: bool) -> io::Result<()> {
    if !first {
        out.write_all(b",")?;
    }
    write!(out, "\n    {}", indent(body.trim_end(), 4))
}

/// Closes the document with the failures and skipped paths.
pub fn end_document(
    out: &mut dyn Write,
    failures: &[Failure],
    skipped: &[SkippedPath],
) -> io::Result<()> {
    write!(
        out,
        "\n  ],\n  \"failures\": {},\n  \"skipped\": {}\n}}\n",
        indent(&serde_json::to_string_pretty(failures)?, 2),
        indent(&serde_json::to_string_pretty(skipped)?, 2)
    )
}

fn tool() -> Tool {
    Tool {
        name: "rtriage",
        version: env!("CARGO_PKG_VERSION"),
    }
}

/// Indents every line after the first by `by` spaces.
fn indent(json: &str, by: usize) -> String {
    json.replace('\n', &format!("\n{}", " ".repeat(by)))
}

// ---------------------------------------------------------------- NDJSON (scan)

/// `{"type":"report","schema_version":1,"report":{...}}` with a one-line body.
pub fn ndjson_report(out: &mut dyn Write, compact_body: &str) -> io::Result<()> {
    writeln!(
        out,
        "{{\"type\":\"report\",\"schema_version\":{SCHEMA_VERSION},\"report\":{}}}",
        compact_body.trim_end()
    )
}

#[derive(Serialize)]
struct FailureLine<'a> {
    #[serde(rename = "type")]
    line: &'static str,
    #[serde(flatten)]
    failure: &'a Failure,
}

/// `{"type":"failure","path":...,"kind":...,"error":...}`.
pub fn ndjson_failure(out: &mut dyn Write, failure: &Failure) -> io::Result<()> {
    serde_json::to_writer(
        &mut *out,
        &FailureLine {
            line: "failure",
            failure,
        },
    )?;
    writeln!(out)
}

/// Files per risk level.
#[derive(Debug, Default, PartialEq, Eq, Serialize)]
pub struct Counts {
    /// `high`.
    pub high: u64,
    /// `medium`.
    pub medium: u64,
    /// `low`.
    pub low: u64,
    /// `clean_looking`.
    pub clean_looking: u64,
}

impl Counts {
    /// Counts `rows` by level.
    pub fn of(rows: &[Summary]) -> Self {
        let mut c = Counts::default();
        for r in rows {
            let slot = match r.level {
                RiskLevel::High => &mut c.high,
                RiskLevel::Medium => &mut c.medium,
                RiskLevel::Low => &mut c.low,
                RiskLevel::CleanLooking => &mut c.clean_looking,
            };
            *slot += 1;
        }
        c
    }
}

#[derive(Serialize)]
struct SummaryLine<'a> {
    #[serde(rename = "type")]
    line: &'static str,
    schema_version: u32,
    tool: Tool,
    rows: &'a [Summary],
    counts: Counts,
    failures: &'a [Failure],
    skipped: &'a [SkippedPath],
}

/// The final scan line: sorted rows, counts, failures and skipped paths.
pub fn ndjson_summary(
    out: &mut dyn Write,
    rows: &[Summary],
    failures: &[Failure],
    skipped: &[SkippedPath],
) -> io::Result<()> {
    serde_json::to_writer(
        &mut *out,
        &SummaryLine {
            line: "summary",
            schema_version: SCHEMA_VERSION,
            tool: tool(),
            rows,
            counts: Counts::of(rows),
            failures,
            skipped,
        },
    )?;
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
        prepare(&mut report, all_strings, rtriage_core::Severity::Info);
        Run {
            reports: vec![report],
            failures: vec![Failure {
                kind: crate::output::FailureKind::Io,
                path: "missing.bin".into(),
                error: "cannot read missing.bin: not found".into(),
            }],
            skipped: vec![],
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
        let v = sorted(render_value(&sample_run(false)));
        insta::assert_snapshot!(serde_json::to_string_pretty(&v).unwrap());
    }

    /// Keys sorted at every level, so the snapshot does not depend on
    /// serde_json's `preserve_order` feature (yara-x enables it).
    fn sorted(v: serde_json::Value) -> serde_json::Value {
        match v {
            serde_json::Value::Object(m) => {
                let b: std::collections::BTreeMap<_, _> =
                    m.into_iter().map(|(k, v)| (k, sorted(v))).collect();
                serde_json::Value::Object(b.into_iter().collect())
            }
            serde_json::Value::Array(a) => {
                serde_json::Value::Array(a.into_iter().map(sorted).collect())
            }
            other => other,
        }
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
                skipped: vec![],
            },
            &mut buf,
        )
        .unwrap();
        assert!(!buf.contains(&0x1b));
    }
}

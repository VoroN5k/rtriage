//! Multi-file runs through the worker pool: output parity with in-process
//! analysis, ordering, the scan table/NDJSON, and isolation (crash, hang,
//! endless output, workers that cannot start) via the `test-hooks` feature.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn rtriage(args: &[&str], env: &[(&str, &str)]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rtriage"))
        .args(args)
        .env("NO_COLOR", "1")
        .envs(env.iter().copied())
        .output()
        .unwrap()
}

/// A fresh directory with `files` (name, contents).
fn dir(name: &str, files: &[(&str, Vec<u8>)]) -> PathBuf {
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    for (f, bytes) in files {
        std::fs::write(root.join(f), bytes).unwrap();
    }
    root
}

fn injection() -> Vec<u8> {
    use rtriage_fixtures::pe::{Arch, PeBuilder};
    PeBuilder::minimal(Arch::X64)
        .import(
            "KERNEL32.dll",
            &[
                "OpenProcess",
                "VirtualAllocEx",
                "WriteProcessMemory",
                "CreateRemoteThread",
            ],
        )
        .build()
        .bytes
}

fn plain() -> Vec<u8> {
    b"plain text, nothing to see".to_vec()
}

fn mixed(name: &str) -> PathBuf {
    let mut files = vec![
        ("inject.exe", injection()),
        (
            "upx.elf",
            rtriage_fixtures::elf::profiles::upx_elf().build().bytes,
        ),
        (
            "go.elf",
            rtriage_fixtures::elf::profiles::go_static().build().bytes,
        ),
    ];
    for i in 0..9 {
        files.push((
            ["p0", "p1", "p2", "p3", "p4", "p5", "p6", "p7", "p8"][i],
            plain(),
        ));
    }
    dir(name, &files)
}

fn json(out: &Output) -> serde_json::Value {
    serde_json::from_slice(&out.stdout).unwrap()
}

fn ndjson(out: &Output) -> Vec<serde_json::Value> {
    String::from_utf8(out.stdout.clone())
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn pooled_reports_equal_in_process_reports_in_input_order() {
    let root = mixed("pool-parity");
    let pooled = json(&rtriage(&["-f", "json", "-j", "4", s(&root)], &[]));
    let reports = pooled["reports"].as_array().unwrap();
    assert_eq!(reports.len(), 12);
    let mut paths: Vec<String> = reports
        .iter()
        .map(|r| r["file"]["path"].as_str().unwrap().to_owned())
        .collect();
    let in_order = paths.clone();
    paths.sort();
    assert_eq!(in_order, paths, "walk order (sorted) is preserved");
    // Every pooled report is identical to the in-process one.
    for r in reports {
        let path = r["file"]["path"].as_str().unwrap();
        let single = json(&rtriage(&["-f", "json", path], &[]));
        assert_eq!(&single["reports"][0], r, "{path}");
    }
    assert_eq!(pooled["schema_version"], 1);
    assert!(pooled["failures"].as_array().unwrap().is_empty());
}

#[test]
fn pooled_text_has_every_report() {
    let root = mixed("pool-text");
    let out = rtriage(&["-j", "3", s(&root)], &[]);
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8(out.stdout).unwrap();
    assert_eq!(text.matches("SHA-256").count(), 12, "{text}");
    assert!(text.contains("PE-API-INJECTION"));
}

#[test]
fn scan_table_is_sorted_by_risk() {
    let root = mixed("pool-scan");
    let out = rtriage(&["scan", s(&root)], &[]);
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        text.contains("12 file(s): 0 high, 1 medium, 1 low, 10 clean-looking"),
        "{text}"
    );
    let first_row = text.lines().find(|l| l.contains("[MEDIUM]")).unwrap();
    assert!(first_row.contains("inject.exe") && first_row.contains("PE-API-INJECTION"));
    let medium = text.find("[MEDIUM]").unwrap();
    let low = text.find("[LOW]").unwrap();
    assert!(medium < low);
    assert!(text.contains("(packed)"));
}

#[test]
fn scan_ndjson_is_one_summary_line_without_full() {
    let root = mixed("pool-ndjson");
    let lines = ndjson(&rtriage(&["scan", "-f", "json", s(&root)], &[]));
    assert_eq!(lines.len(), 1);
    let sum = &lines[0];
    assert_eq!(
        (sum["type"].as_str(), sum["schema_version"].as_u64()),
        (Some("summary"), Some(1))
    );
    let rows = sum["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 12);
    let scores: Vec<u64> = rows.iter().map(|r| r["score"].as_u64().unwrap()).collect();
    assert!(scores.windows(2).all(|w| w[0] >= w[1]), "{scores:?}");
    assert_eq!(
        sum["counts"],
        serde_json::json!({"high":0,"medium":1,"low":1,"clean_looking":10})
    );
}

#[test]
fn scan_full_ndjson_streams_reports_then_summary() {
    let root = mixed("pool-full");
    let lines = ndjson(&rtriage(&["scan", "--full", "-f", "json", s(&root)], &[]));
    assert_eq!(lines.len(), 13);
    assert!(lines[..12]
        .iter()
        .all(|l| l["type"] == "report" && l["report"]["risk"].is_object()));
    assert_eq!(lines[12]["type"], "summary");
}

#[test]
fn scan_fail_on_and_missing_files() {
    let root = mixed("pool-gate");
    assert_eq!(
        rtriage(&["scan", "--fail-on", "medium", s(&root)], &[])
            .status
            .code(),
        Some(3)
    );
    assert_eq!(
        rtriage(&["scan", "--fail-on", "high", s(&root)], &[])
            .status
            .code(),
        Some(0)
    );
    let out = rtriage(&["scan", "-f", "json", s(&root), "no-such-file.bin"], &[]);
    assert_eq!(out.status.code(), Some(1));
    let lines = ndjson(&out);
    let failure = lines.iter().find(|l| l["type"] == "failure").unwrap();
    assert_eq!(
        (failure["kind"].as_str(), failure["path"].as_str()),
        (Some("io"), Some("no-such-file.bin"))
    );
    assert_eq!(lines.last().unwrap()["failures"][0]["kind"], "io");
}

#[test]
fn two_files_use_the_pool_and_one_file_does_not() {
    let root = dir("pool-two", &[("a", plain()), ("b", plain())]);
    let out = rtriage(&["-f", "json", s(&root.join("a")), s(&root.join("b"))], &[]);
    assert_eq!(json(&out)["reports"].as_array().unwrap().len(), 2);
}

// ------------------------------------------------------------------ isolation

#[cfg(feature = "test-hooks")]
mod isolation {
    use super::*;
    use std::time::{Duration, Instant};

    const HOOK: &str = "RTRIAGE_TEST_WORKER";

    fn failures_by_path(v: &serde_json::Value) -> Vec<(String, String)> {
        v["failures"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| {
                let p = f["path"].as_str().unwrap();
                let name = Path::new(p)
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                (name, f["kind"].as_str().unwrap().to_owned())
            })
            .collect()
    }

    #[test]
    fn a_crash_loses_only_its_file() {
        let root = mixed("iso-crash");
        let out = rtriage(&["-f", "json", "-j", "2", s(&root)], &[(HOOK, "crash:p3")]);
        assert_eq!(out.status.code(), Some(1));
        let v = json(&out);
        assert_eq!(
            failures_by_path(&v),
            [("p3".to_owned(), "crashed".to_owned())]
        );
        assert_eq!(v["reports"].as_array().unwrap().len(), 11);
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains("worker isolation stopped files: 1 crashed"),
            "{err}"
        );
    }

    #[test]
    fn a_hang_is_killed_after_timeout_plus_grace() {
        let root = dir("iso-hang", &[("hang.bin", plain()), ("ok.bin", plain())]);
        let start = Instant::now();
        let out = rtriage(
            &["scan", "-f", "json", "--timeout", "1", "-j", "2", s(&root)],
            &[(HOOK, "hang:hang.bin")],
        );
        let took = start.elapsed();
        assert!(
            took >= Duration::from_secs(6) && took < Duration::from_secs(30),
            "{took:?}"
        );
        let lines = ndjson(&out);
        let sum = lines.last().unwrap();
        assert_eq!(sum["rows"].as_array().unwrap().len(), 1);
        assert_eq!(
            failures_by_path(sum),
            [("hang.bin".to_owned(), "timed_out".to_owned())]
        );
        assert_eq!(out.status.code(), Some(1));
    }

    #[test]
    fn endless_output_is_cut_off() {
        let root = dir("iso-spam", &[("spam.bin", plain()), ("ok.bin", plain())]);
        let out = rtriage(&["-f", "json", s(&root)], &[(HOOK, "spam:spam.bin")]);
        let v = json(&out);
        assert_eq!(
            failures_by_path(&v),
            [("spam.bin".to_owned(), "invalid_response".to_owned())]
        );
        assert_eq!(v["reports"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn workers_that_cannot_start_stop_the_run() {
        let root = dir("iso-start", &[("a", plain()), ("b", plain())]);
        let out = rtriage(&[s(&root)], &[(HOOK, "startfail:1")]);
        assert_eq!(out.status.code(), Some(1));
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("worker processes cannot start"), "{err}");
    }

    #[test]
    fn several_crashes_with_fail_on_still_warn() {
        let root = mixed("iso-gate");
        let out = rtriage(
            &["scan", "--fail-on", "medium", s(&root)],
            &[(HOOK, "crash:p1,crash:p2")],
        );
        assert_eq!(out.status.code(), Some(3));
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("2 crashed"), "{err}");
        assert!(err.contains("takes precedence"), "{err}");
    }
}

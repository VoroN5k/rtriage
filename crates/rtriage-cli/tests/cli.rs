//! End-to-end tests of the `rtriage` binary: exit codes and failure handling.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::path::PathBuf;
use std::process::{Command, Output};

/// Runs the binary with JSON output so results can be parsed.
fn rtriage(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rtriage"))
        .args(["-f", "json"])
        .args(args)
        .env("NO_COLOR", "1")
        .output()
        .unwrap()
}

/// Scratch file under cargo's per-target temp dir.
fn scratch(name: &str, contents: &[u8]) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    std::fs::write(&path, contents).unwrap();
    path
}

fn json(out: &Output) -> serde_json::Value {
    serde_json::from_slice(&out.stdout).unwrap()
}

#[test]
fn analyzes_file_and_exits_zero() {
    let f = scratch("ok.bin", b"\x7fELF\x00http://x.example.com/\x00");
    let out = rtriage(&[f.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0));
    let v = json(&out);
    assert_eq!(v["schema_version"], 1);
    assert_eq!(v["reports"][0]["file"]["format"], "elf");
    assert_eq!(v["failures"].as_array().unwrap().len(), 0);
}

#[test]
fn missing_file_exits_one_but_reports_others() {
    let f = scratch("ok2.bin", b"hello world");
    let out = rtriage(&[f.to_str().unwrap(), "definitely-missing-file.bin"]);
    assert_eq!(out.status.code(), Some(1));
    let v = json(&out);
    assert_eq!(v["reports"].as_array().unwrap().len(), 1);
    assert_eq!(v["failures"][0]["path"], "definitely-missing-file.bin");
}

#[test]
fn directory_is_a_failure_with_hint() {
    let out = rtriage(&[env!("CARGO_TARGET_TMPDIR")]);
    assert_eq!(out.status.code(), Some(1));
    let v = json(&out);
    assert!(v["failures"][0]["error"]
        .as_str()
        .unwrap()
        .contains("directory"));
}

#[test]
fn file_over_max_size_fails() {
    let f = scratch("big.bin", &[0u8; 100]);
    let out = rtriage(&["--max-size", "10", f.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn text_is_default_and_piped_output_has_no_color() {
    let f = scratch("text.bin", b"\x00http://x.example.com/\x00");
    let out = Command::new(env!("CARGO_BIN_EXE_rtriage"))
        .arg(f.to_str().unwrap())
        .env_remove("NO_COLOR")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("[CLEAN-LOOKING]"));
    assert!(text.contains("http://x.example.com/"));
    // stdout is a pipe here, so AutoStream must strip all styling.
    assert!(!text.contains('\x1b'));
}

#[test]
fn no_arguments_is_usage_error() {
    assert_eq!(rtriage(&[]).status.code(), Some(2));
}

#[test]
fn hostile_file_name_is_escaped_on_stderr() {
    let out = rtriage(&["missing-\x1b[31m-name.bin"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(!out.stderr.contains(&0x1b));
    assert!(String::from_utf8_lossy(&out.stderr).contains("\\x1b[31m"));
}

#[test]
fn output_flag_writes_file() {
    let f = scratch("ok3.bin", b"hello world");
    let report = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("report.json");
    let out = rtriage(&["-o", report.to_str().unwrap(), f.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0));
    assert!(out.stdout.is_empty());
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&report).unwrap()).unwrap();
    assert_eq!(v["schema_version"], 1);
}

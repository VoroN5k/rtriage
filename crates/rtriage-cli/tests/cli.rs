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

/// Writes an injection-chain PE to a per-test file (tests run in parallel).
fn injection_pe(name: &str) -> PathBuf {
    use rtriage_fixtures::pe::{Arch, PeBuilder};
    let bytes = PeBuilder::minimal(Arch::X64)
        .import(
            "KERNEL32.dll",
            &[
                "OpenProcess",
                "VirtualAllocEx",
                "WriteProcessMemory",
                "CreateRemoteThread",
                "Beep",
            ],
        )
        .build()
        .bytes;
    scratch(name, &bytes)
}

fn finding_ids(v: &serde_json::Value) -> Vec<String> {
    v["reports"][0]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn bundled_api_rules_apply_by_default() {
    let out = rtriage(&[injection_pe("inject-1.exe").to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0));
    assert!(finding_ids(&json(&out)).contains(&"PE-API-INJECTION".to_owned()));
}

#[test]
fn custom_api_rules_replace_bundled() {
    let rules = scratch(
        "custom-rules.toml",
        br#"
schema_version = 1
[[group]]
id = "PE-API-BEEP"
title = "Beeps"
severity = "info"
confidence = "high"
category = "metadata"
rationale = "Imports Beep."
[[group.when]]
slots = [["Beep"]]
"#,
    );
    let out = rtriage(&[
        "--api-rules",
        rules.to_str().unwrap(),
        injection_pe("inject-2.exe").to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(0));
    let ids = finding_ids(&json(&out));
    assert!(ids.contains(&"PE-API-BEEP".to_owned()));
    assert!(!ids.contains(&"PE-API-INJECTION".to_owned()));
}

#[test]
fn invalid_api_rules_are_a_usage_error() {
    let rules = scratch(
        "bad-rules.toml",
        b"schema_version = 1\n[[group]]\nid = \"nope\"\n",
    );
    let out = rtriage(&[
        "--api-rules",
        rules.to_str().unwrap(),
        injection_pe("inject-3.exe").to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot load API rules"));
}

#[test]
fn missing_api_rules_file_is_a_usage_error() {
    let out = rtriage(&["--api-rules", "no-such-rules.toml", "x.bin"]);
    assert_eq!(out.status.code(), Some(2));
}

fn upx_pe(name: &str) -> PathBuf {
    let bytes = rtriage_fixtures::pe::profiles::upx_like(rtriage_fixtures::pe::Arch::X86)
        .build()
        .bytes;
    scratch(name, &bytes)
}

#[test]
fn json_carries_breakdown_suppression_and_packed_flag() {
    let out = rtriage(&[upx_pe("upx-json.exe").to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0));
    let v = json(&out);
    let r = &v["reports"][0];
    assert_eq!(r["risk"]["score"], 15);
    assert_eq!(r["risk"]["level"], "low");
    assert_eq!(r["analysis_limited"][0], "packed");
    let rwx = r["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["id"] == "PE-SECTION-RWX")
        .unwrap();
    assert_eq!(rwx["suppressed"]["kind"], "packer");
    assert_eq!(rwx["suppressed"]["name"], "UPX");
    assert_eq!(rwx["suppressed"]["by"], "PE-PACKER-KNOWN");
    assert!(r["risk"]["breakdown"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["id"] == "PE-SECTION-RWX" && e["reduced_by"]["kind"] == "suppressed"));
}

#[test]
fn min_severity_filters_findings_but_not_the_score() {
    let f = injection_pe("inject-minsev.exe");
    let all = json(&rtriage(&[f.to_str().unwrap()]));
    let high = json(&rtriage(&["--min-severity", "high", f.to_str().unwrap()]));
    assert_eq!(all["reports"][0]["risk"], high["reports"][0]["risk"]);
    let ids = finding_ids(&high);
    assert_eq!(ids, ["PE-API-INJECTION"]);
    assert!(finding_ids(&all).len() > ids.len());
}

#[test]
fn explain_prints_breakdown_in_text() {
    let out = Command::new(env!("CARGO_BIN_EXE_rtriage"))
        .args(["--explain", upx_pe("upx-explain.exe").to_str().unwrap()])
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("Score breakdown"));
    assert!(text.contains("explained by UPX"));
    assert!(text.contains("[PACKED: analysis limited]"));
}

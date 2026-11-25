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

/// A fresh directory tree under cargo's temp dir; names ending in `/` are dirs.
fn tree(name: &str, spec: &[&str]) -> PathBuf {
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    for s in spec {
        let p = root.join(s.trim_end_matches('/'));
        if s.ends_with('/') {
            std::fs::create_dir_all(&p).unwrap();
        } else {
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, b"plain text, nothing to see").unwrap();
        }
    }
    root
}

fn report_paths(v: &serde_json::Value) -> Vec<String> {
    v["reports"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["file"]["path"].as_str().unwrap().replace('\\', "/"))
        .collect()
}

#[test]
fn directories_are_walked_recursively_in_sorted_order() {
    let root = tree(
        "walk-order",
        &["b.bin", "a/z.bin", "a/sub/c.bin", "a/a.bin", "empty/"],
    );
    let out = rtriage(&[root.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0));
    let v = json(&out);
    let paths = report_paths(&v);
    let tail: Vec<_> = paths
        .iter()
        .map(|p| p.rsplit("walk-order/").next().unwrap().to_owned())
        .collect();
    assert_eq!(tail, ["a/a.bin", "a/sub/c.bin", "a/z.bin", "b.bin"]);
    assert_eq!(v["skipped"].as_array().unwrap().len(), 0);
}

#[test]
fn files_and_directories_mix_and_dedupe() {
    let root = tree("walk-mix", &["x.bin", "y.bin"]);
    let x = root.join("x.bin");
    let out = rtriage(&[x.to_str().unwrap(), root.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(report_paths(&json(&out)).len(), 2);
}

#[test]
fn empty_directory_warns_and_succeeds() {
    let root = tree("walk-empty", &[]);
    let out = rtriage(&[root.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stderr).contains("no files found"));
    assert_eq!(report_paths(&json(&out)).len(), 0);
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

/// A rules directory under cargo's per-target temp dir with `files`.
fn rules_dir(name: &str, files: &[(&str, &[u8])]) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    for (file, contents) in files {
        std::fs::write(dir.join(file), contents).unwrap();
    }
    dir
}

const BEEP_RULES: &[u8] = br#"
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
"#;

#[test]
fn rules_dir_api_rules_replace_bundled() {
    let dir = rules_dir("rules-replace", &[("api_groups.toml", BEEP_RULES)]);
    let out = rtriage(&[
        "--rules-dir",
        dir.to_str().unwrap(),
        injection_pe("inject-2.exe").to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(0));
    let ids = finding_ids(&json(&out));
    assert!(ids.contains(&"PE-API-BEEP".to_owned()));
    assert!(!ids.contains(&"PE-API-INJECTION".to_owned()));
}

#[test]
fn rules_dir_include_defaults_keeps_bundled() {
    let mut text = b"include_defaults = true\n".to_vec();
    text.extend_from_slice(BEEP_RULES);
    let dir = rules_dir("rules-merge", &[("api_groups.toml", &text)]);
    let out = rtriage(&[
        "--rules-dir",
        dir.to_str().unwrap(),
        injection_pe("inject-4.exe").to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(0));
    let ids = finding_ids(&json(&out));
    assert!(ids.contains(&"PE-API-BEEP".to_owned()));
    assert!(ids.contains(&"PE-API-INJECTION".to_owned()));
}

#[test]
fn rules_dir_allowlist_is_added() {
    let dir = rules_dir(
        "rules-allow",
        &[(
            "ioc_allowlist.toml",
            b"schema_version = 1\ndomains = [\"corp.example.ru\"]\n",
        )],
    );
    let f = scratch(
        "allow.bin",
        b"\0\0http://intranet.corp.example.ru/x\0http://schemas.microsoft.com/y\0http://c2.evil.top/z\0",
    );
    let v = json(&rtriage(&[
        "--rules-dir",
        dir.to_str().unwrap(),
        f.to_str().unwrap(),
    ]));
    let items = v["reports"][0]["facts"]["iocs"]["items"]
        .as_array()
        .unwrap()
        .clone();
    let allowlisted = |value: &str| {
        items
            .iter()
            .find(|i| i["value"] == value)
            .map(|i| i["allowlisted"].as_bool().unwrap())
            .unwrap()
    };
    assert!(allowlisted("http://intranet.corp.example.ru/x"));
    assert!(allowlisted("http://schemas.microsoft.com/y"));
    assert!(!allowlisted("http://c2.evil.top/z"));
}

#[test]
fn invalid_rules_file_is_a_usage_error() {
    let dir = rules_dir(
        "rules-bad",
        &[(
            "api_groups.toml",
            b"schema_version = 1\n[[group]]\nid = \"nope\"\n",
        )],
    );
    let out = rtriage(&[
        "--rules-dir",
        dir.to_str().unwrap(),
        injection_pe("inject-3.exe").to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("cannot load rules") && err.contains("api_groups.toml"),
        "{err}"
    );
}

#[test]
fn missing_rules_dir_is_a_usage_error() {
    let out = rtriage(&["--rules-dir", "no-such-rules-dir", "x.bin"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn unknown_rules_files_are_warned_about() {
    let dir = rules_dir("rules-typo", &[("api-groups.toml", BEEP_RULES)]);
    let out = rtriage(&[
        "--rules-dir",
        dir.to_str().unwrap(),
        injection_pe("inject-5.exe").to_str().unwrap(),
    ]);
    assert_eq!(out.status.code(), Some(0));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("ignoring unknown rules file api-groups.toml"),
        "{err}"
    );
    assert!(err.contains("no known rules files"), "{err}");
    // Bundled rules still apply.
    assert!(finding_ids(&json(&out)).contains(&"PE-API-INJECTION".to_owned()));
}

#[test]
fn api_rules_flag_is_gone() {
    let out = rtriage(&["--api-rules", "x.toml", "x.bin"]);
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

#[test]
fn defang_changes_text_but_not_json() {
    let f = scratch(
        "defang.bin",
        b"\0\0beacon to http://c2.evil.top/gate 45.13.227.8\0\0",
    );
    let path = f.to_str().unwrap();
    let text = |args: &[&str]| {
        let out = Command::new(env!("CARGO_BIN_EXE_rtriage"))
            .args(args)
            .env("NO_COLOR", "1")
            .output()
            .unwrap();
        String::from_utf8(out.stdout).unwrap()
    };
    let raw = text(&[path]);
    assert!(raw.contains("http://c2.evil.top/gate"));
    let safe = text(&["--defang", path]);
    assert!(safe.contains("hxxp://c2[.]evil[.]top/gate"));
    assert!(safe.contains("45[.]13[.]227[.]8"));
    assert!(!safe.contains("http://c2.evil.top"));
    // JSON keeps the raw value and always carries the defanged one.
    let v = json(&rtriage(&["--defang", path]));
    let items = &v["reports"][0]["facts"]["iocs"]["items"];
    let url = items
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["kind"] == "url")
        .unwrap();
    assert_eq!(url["value"], "http://c2.evil.top/gate");
    assert_eq!(url["value_defanged"], "hxxp://c2[.]evil[.]top/gate");
}

#[test]
fn fail_on_sets_exit_code_three() {
    // A full injection chain scores 40: medium.
    let pe = injection_pe("inject-gate.exe");
    let pe = pe.to_str().unwrap();
    assert_eq!(rtriage(&["--fail-on", "medium", pe]).status.code(), Some(3));
    assert_eq!(rtriage(&["--fail-on", "low", pe]).status.code(), Some(3));
    assert_eq!(rtriage(&["--fail-on", "high", pe]).status.code(), Some(0));
    assert_eq!(rtriage(&[pe]).status.code(), Some(0));
    let clean = scratch("clean-gate.bin", b"plain text, nothing to see");
    assert_eq!(
        rtriage(&["--fail-on", "low", clean.to_str().unwrap()])
            .status
            .code(),
        Some(0)
    );
}

#[test]
fn fail_on_beats_failures_and_warns() {
    let pe = injection_pe("inject-gate2.exe");
    let args = [pe.to_str().unwrap(), "no-such-file.bin"];
    assert_eq!(rtriage(&args).status.code(), Some(1));
    let out = rtriage(&["--fail-on", "medium", args[0], args[1]]);
    assert_eq!(out.status.code(), Some(3));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("exit code 3 (--fail-on) takes precedence"),
        "{err}"
    );
}

#[test]
fn fail_on_rejects_unknown_levels() {
    for bad in ["clean_looking", "critical", ""] {
        assert_eq!(
            rtriage(&["--fail-on", bad, "x.bin"]).status.code(),
            Some(2),
            "{bad}"
        );
    }
}

//! YARA rule loading end to end: bundled rules, `--yara`, `--no-yara`,
//! `<rules-dir>/yara/` + `yara.toml`, compiled rules handed to workers, and
//! the error for builds without YARA.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn rtriage(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rtriage"))
        .args(args)
        .env("NO_COLOR", "1")
        .output()
        .unwrap()
}

fn dir(name: &str, files: &[(&str, &[u8])]) -> PathBuf {
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    for (f, bytes) in files {
        let p = root.join(f);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, bytes).unwrap();
    }
    root
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

const CUSTOM: &[u8] = br#"rule custom_marker {
  meta: severity = "high" confidence = "high" category = "impact" risk_floor = "high"
  strings: $m = "rtriage-test-marker"
  condition: $m
}"#;

#[cfg(feature = "yara")]
mod with_yara {
    use super::*;

    fn json(out: &Output) -> serde_json::Value {
        assert!(
            out.status.code().is_some_and(|c| c != 2),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    }

    fn rules_hit(report: &serde_json::Value) -> Vec<String> {
        report["facts"]["yara"]["matches"]
            .as_array()
            .map(|m| {
                m.iter()
                    .map(|m| m["rule"].as_str().unwrap().to_owned())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn pe_like() -> Vec<u8> {
        let mut v = b"MZ".to_vec();
        v.extend([0u8; 0x3e]);
        v.extend(b"This program cannot be run in DOS mode.\r\r\n$");
        v
    }

    fn carrier() -> Vec<u8> {
        let mut v = b"\0\0container rtriage-test-marker ".to_vec();
        v.extend(pe_like());
        v
    }

    #[test]
    fn bundled_rules_run_by_default_and_no_yara_disables_them() {
        let root = dir("y-bundled", &[("c.bin", &carrier())]);
        let f = root.join("c.bin");
        let v = json(&rtriage(&["-f", "json", s(&f)]));
        assert_eq!(rules_hit(&v["reports"][0]), ["embedded_pe_dos_stub"]);
        assert_eq!(v["reports"][0]["facts"]["yara"]["rules_loaded"], 2);
        let v = json(&rtriage(&["-f", "json", "--no-yara", s(&f)]));
        assert!(v["reports"][0]["facts"]["yara"].is_null());
    }

    #[test]
    fn extra_rules_and_risk_floor() {
        let root = dir(
            "y-extra",
            &[("c.bin", &carrier()), ("rules/custom.yar", CUSTOM)],
        );
        let f = root.join("c.bin");
        let out = rtriage(&["-f", "json", "--yara", s(&root.join("rules")), s(&f)]);
        let v = json(&out);
        let r = &v["reports"][0];
        assert_eq!(rules_hit(r), ["embedded_pe_dos_stub", "custom_marker"]);
        assert_eq!(r["risk"]["level"], "high");
        let m = r["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["title"].as_str().unwrap().contains("custom_marker"))
            .unwrap();
        assert_eq!(m["evidence"][0]["value"], "custom:custom_marker");
        // risk_floor = high meets the gate.
        let code = rtriage(&[
            "--fail-on",
            "high",
            "--yara",
            s(&root.join("rules/custom.yar")),
            s(&f),
        ])
        .status
        .code();
        assert_eq!(code, Some(3));
    }

    #[test]
    fn rules_dir_yara_and_settings() {
        let root = dir(
            "y-rulesdir",
            &[
                ("c.bin", &carrier()),
                ("rules/yara/custom.yar", CUSTOM),
                (
                    "rules/yara.toml",
                    b"schema_version = 1\ninclude_bundled = false\n",
                ),
            ],
        );
        let v = json(&rtriage(&[
            "-f",
            "json",
            "--rules-dir",
            s(&root.join("rules")),
            s(&root.join("c.bin")),
        ]));
        assert_eq!(rules_hit(&v["reports"][0]), ["custom_marker"]);
        assert_eq!(v["reports"][0]["facts"]["yara"]["rules_loaded"], 1);
    }

    #[test]
    fn bad_rules_and_limits_are_usage_errors() {
        let root = dir(
            "y-bad",
            &[
                ("bad.yar", b"rule broken { condition: nope_undefined }"),
                (
                    "meta.yar",
                    b"rule m { meta: severity = \"critical\" condition: true }",
                ),
                ("many/a.yar", b"rule a { condition: true }"),
                ("many/b.yar", b"rule b { condition: true }"),
                (
                    "limits/yara.toml",
                    b"schema_version = 1\n[limits]\nmax_files = 1\n",
                ),
                ("limits/yara/a.yar", b"rule a { condition: true }"),
                ("limits/yara/b.yar", b"rule b { condition: true }"),
                ("x.bin", b"x"),
            ],
        );
        let x = root.join("x.bin");
        for (args, needle) in [
            (vec!["--yara", s(&root.join("bad.yar"))], "bad.yar"),
            (vec!["--yara", s(&root.join("meta.yar"))], "severity"),
            (vec!["--rules-dir", s(&root.join("limits"))], "max_files"),
            (vec!["--yara", "no-such-rules.yar"], "no-such-rules.yar"),
        ] {
            let mut all = args.clone();
            all.push(s(&x));
            let out = rtriage(&all);
            assert_eq!(out.status.code(), Some(2), "{args:?}");
            let err = String::from_utf8_lossy(&out.stderr);
            assert!(err.contains(needle), "{args:?}: {err}");
            assert!(out.stdout.is_empty());
        }
        assert_eq!(
            rtriage(&["--yara", s(&root.join("many")), "--no-yara", s(&x)])
                .status
                .code(),
            Some(2)
        );
    }

    /// Workers get the parent's compiled rules: same reports as in-process.
    #[test]
    fn pooled_reports_with_yara_equal_in_process_reports() {
        let root = dir(
            "y-pool",
            &[
                ("files/a.bin", &carrier()),
                ("files/b.bin", b"plain text rtriage-test-marker"),
                ("files/c.bin", b"plain text"),
                ("rules/custom.yar", CUSTOM),
            ],
        );
        let rules = root.join("rules");
        let pooled = json(&rtriage(&[
            "-f",
            "json",
            "-j",
            "3",
            "--yara",
            s(&rules),
            s(&root.join("files")),
        ]));
        let reports = pooled["reports"].as_array().unwrap();
        assert_eq!(reports.len(), 3);
        for r in reports {
            let path = r["file"]["path"].as_str().unwrap();
            let single = json(&rtriage(&["-f", "json", "--yara", s(&rules), path]));
            assert_eq!(&single["reports"][0], r, "{path}");
        }
        assert_eq!(rules_hit(&reports[1]), ["custom_marker"]);
        // And the scan table shows the floored file first.
        let out = rtriage(&["scan", "--yara", s(&rules), s(&root.join("files"))]);
        let text = String::from_utf8(out.stdout).unwrap();
        let first = text.lines().find(|l| l.contains("[HIGH]")).unwrap();
        assert!(first.contains("a.bin") || first.contains("b.bin"), "{text}");
    }

    #[test]
    fn scan_limits_from_yara_toml_reach_the_workers() {
        let root = dir(
            "y-limits",
            &[
                ("files/a.bin", b"aaa bbb ccc"),
                ("files/b.bin", b"aaa bbb ccc"),
                ("rules/yara.toml", b"schema_version = 1\ninclude_bundled = false\n[limits]\nmax_matches = 1\n"),
                ("rules/yara/r.yar", b"rule a { strings: $x = \"aaa\" condition: $x }\nrule b { strings: $x = \"bbb\" condition: $x }"),
            ],
        );
        let v = json(&rtriage(&[
            "-f",
            "json",
            "--rules-dir",
            s(&root.join("rules")),
            s(&root.join("files")),
        ]));
        for r in v["reports"].as_array().unwrap() {
            assert_eq!(r["facts"]["yara"]["matches"].as_array().unwrap().len(), 1);
            assert_eq!(r["facts"]["yara"]["limit_reached"], true);
        }
    }

    #[test]
    fn text_shows_the_yara_section_and_the_floor() {
        let root = dir("y-text", &[("c.bin", &carrier()), ("custom.yar", CUSTOM)]);
        let out = rtriage(&[
            "--yara",
            s(&root.join("custom.yar")),
            s(&root.join("c.bin")),
        ]);
        let text = String::from_utf8(out.stdout).unwrap();
        assert!(text.contains("YARA  3 rule(s) loaded, 2 matched"), "{text}");
        assert!(
            text.contains("level raised to high by YARA rule custom_marker matched"),
            "{text}"
        );
    }
}

#[cfg(not(feature = "yara"))]
mod without_yara {
    use super::*;

    #[test]
    fn rules_given_to_a_build_without_yara_are_an_error() {
        let root = dir(
            "ny",
            &[
                ("x.bin", b"x"),
                ("custom.yar", CUSTOM),
                ("rules/yara/custom.yar", CUSTOM),
            ],
        );
        let x = root.join("x.bin");
        for args in [
            vec!["--yara", s(&root.join("custom.yar"))],
            vec!["--rules-dir", s(&root.join("rules"))],
        ] {
            let mut all = args.clone();
            all.push(s(&x));
            let out = rtriage(&all);
            assert_eq!(out.status.code(), Some(2), "{args:?}");
            assert!(String::from_utf8_lossy(&out.stderr).contains("built without YARA support"));
        }
        // --no-yara makes the rules directory usable again.
        let out = rtriage(&["--no-yara", "--rules-dir", s(&root.join("rules")), s(&x)]);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        // And without any rules nothing changes.
        assert_eq!(rtriage(&[s(&x)]).status.code(), Some(0));
    }
}

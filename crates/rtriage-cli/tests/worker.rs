//! The hidden `--worker` mode, driven over its line protocol like the parent
//! will drive it.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

fn scratch(name: &str, contents: &[u8]) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    std::fs::write(&path, contents).unwrap();
    path
}

/// Starts a worker, writes `input` to its stdin, closes it, collects output.
fn worker(args: &[&str], input: &[u8], env: &[(&str, &str)]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rtriage"))
        .arg("--worker")
        .args(args)
        .env_clear()
        .envs(env.iter().copied())
        .env(
            "SystemRoot",
            std::env::var("SystemRoot").unwrap_or_default(),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

fn request(id: u64, path: &std::path::Path) -> String {
    let p = serde_json::json!({ "id": id, "path": { "utf8": path.to_str().unwrap() } });
    format!("{p}\n")
}

fn messages(out: &Output) -> Vec<serde_json::Value> {
    String::from_utf8(out.stdout.clone())
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

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
            ],
        )
        .build()
        .bytes;
    scratch(name, &bytes)
}

#[test]
fn ready_then_one_response_per_request_in_order() {
    let a = injection_pe("w-inject.exe");
    let b = scratch("w-plain.bin", b"plain text, nothing to see");
    let input = format!("{}{}", request(1, &a), request(2, &b));
    let out = worker(&[], input.as_bytes(), &[]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let m = messages(&out);
    assert_eq!(m.len(), 3);
    assert_eq!(m[0], serde_json::json!({ "type": "ready", "protocol": 2 }));
    assert_eq!(
        (m[1]["type"].as_str(), m[1]["id"].as_u64()),
        (Some("report"), Some(1))
    );
    assert_eq!(m[1]["summary"]["level"], "medium");
    assert_eq!(m[1]["summary"]["top_finding"]["id"], "PE-API-INJECTION");
    assert_eq!(m[1]["summary"]["format"], "pe");
    assert!(m[1]["body"].as_str().unwrap().contains("PE-API-INJECTION"));
    assert_eq!(m[2]["id"], 2);
    assert_eq!(m[2]["summary"]["level"], "clean_looking");
    assert!(m[2]["summary"]["top_finding"].is_null());
}

#[test]
fn body_follows_the_output_format() {
    let a = injection_pe("w-json.exe");
    let out = worker(&["-f", "json"], request(1, &a).as_bytes(), &[]);
    let m = messages(&out);
    let body: serde_json::Value = serde_json::from_str(m[1]["body"].as_str().unwrap()).unwrap();
    assert_eq!(body["risk"]["level"], "medium");
    // Text bodies are plain unless the parent asks for color.
    let out = worker(&[], request(1, &a).as_bytes(), &[]);
    assert!(!messages(&out)[1]["body"].as_str().unwrap().contains('\x1b'));
    let out = worker(&["--worker-color"], request(1, &a).as_bytes(), &[]);
    assert!(messages(&out)[1]["body"].as_str().unwrap().contains('\x1b'));
}

#[test]
fn summary_ignores_min_severity_but_body_does_not() {
    let a = injection_pe("w-minsev.exe");
    let all = messages(&worker(&[], request(1, &a).as_bytes(), &[]));
    assert!(all[1]["body"].as_str().unwrap().contains("PE-IMPORTS-FEW"));
    let m = messages(&worker(
        &["--min-severity", "high"],
        request(1, &a).as_bytes(),
        &[],
    ));
    // The score (injection 40 + low imports-few 2) comes from every finding...
    assert_eq!(m[1]["summary"]["score"], 42);
    assert_eq!(m[1]["summary"]["top_finding"]["id"], "PE-API-INJECTION");
    // ...while the rendered report drops the low finding for display.
    let body = m[1]["body"].as_str().unwrap();
    assert!(body.contains("PE-API-INJECTION"));
    assert!(!body.contains("PE-IMPORTS-FEW"));
}
#[test]
fn missing_files_are_failures_not_crashes() {
    let out = worker(
        &[],
        request(5, std::path::Path::new("no-such-file.bin")).as_bytes(),
        &[],
    );
    assert_eq!(out.status.code(), Some(0));
    let m = messages(&out);
    assert_eq!(m[1]["type"], "failure");
    assert_eq!(m[1]["id"], 5);
}

#[test]
fn malformed_requests_end_the_worker() {
    for bad in [
        &b"not json\n"[..],
        b"{\"id\":1}\n",
        b"{\"id\":1,\"path\":{\"utf8\":\"a\"},\"x\":2}\n",
    ] {
        let out = worker(&[], bad, &[]);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{}",
            String::from_utf8_lossy(bad)
        );
        assert_eq!(messages(&out).len(), 1, "only ready was sent");
    }
    let huge = vec![b'x'; (1 << 20) + 10];
    assert_eq!(worker(&[], &huge, &[]).status.code(), Some(2));
}

#[test]
fn empty_input_is_a_clean_exit() {
    let out = worker(&[], b"", &[]);
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(messages(&out).len(), 1);
}

#[cfg(unix)]
#[test]
fn non_utf8_paths_are_analyzed() {
    use std::os::unix::ffi::OsStrExt;
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let name = std::ffi::OsStr::from_bytes(b"w-bad\xffname.bin");
    std::fs::write(dir.join(name), b"plain text, nothing to see").unwrap();
    let bytes: Vec<u8> = dir.join(name).as_os_str().as_bytes().to_vec();
    let req = format!(
        "{}\n",
        serde_json::json!({ "id": 1, "path": { "unix": bytes } })
    );
    let m = messages(&worker(&[], req.as_bytes(), &[]));
    assert_eq!(m[1]["type"], "report");
}

#[cfg(feature = "test-hooks")]
#[test]
fn test_hooks_crash_and_spam() {
    let a = scratch("w-crash-me.bin", b"x");
    let out = worker(
        &[],
        request(1, &a).as_bytes(),
        &[("RTRIAGE_TEST_WORKER", "crash:w-crash-me.bin")],
    );
    assert!(!out.status.success());
    assert_eq!(messages(&out).len(), 1, "crashed before answering");

    let b = scratch("w-spam-me.bin", b"x");
    let mut child = Command::new(env!("CARGO_BIN_EXE_rtriage"))
        .arg("--worker")
        .env("RTRIAGE_TEST_WORKER", "spam:w-spam-me.bin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(request(1, &b).as_bytes())
        .unwrap();
    // Read a bounded amount, then kill: the line never ends.
    let mut stdout = child.stdout.take().unwrap();
    let mut buf = vec![0u8; 1 << 20];
    let mut got = 0;
    while got < buf.len() {
        let n = std::io::Read::read(&mut stdout, &mut buf[got..]).unwrap();
        if n == 0 {
            break;
        }
        got += n;
    }
    assert_eq!(got, buf.len(), "spam keeps writing");
    child.kill().unwrap();
    child.wait().unwrap();
}

#[test]
fn bad_rules_preambles_end_the_worker_before_ready() {
    let huge = format!("{{\"type\":\"rules\",\"len\":{}}}\n", (256u64 << 20) + 1);
    for bad in [
        &b""[..],
        b"not json\n",
        b"{\"type\":\"rules\"}\n",
        huge.as_bytes(),
        b"{\"type\":\"rules\",\"len\":100}\nshort",
        b"{\"type\":\"rules\",\"len\":9}\nnot rules",
    ] {
        let out = worker(&["--worker-yara"], bad, &[]);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{}",
            String::from_utf8_lossy(bad)
        );
        assert!(out.stdout.is_empty(), "no ready before rules are installed");
    }
}

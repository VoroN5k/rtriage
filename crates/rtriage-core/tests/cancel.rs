//! Cancellation latency: a cancelled analysis must stop promptly even while
//! an analyzer is deep in a long loop.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use rtriage_core::{AnalysisError, AnalysisLimit, CancelToken, Config, Deadline, Input, Registry};

/// 64 MiB of short URL-looking strings separated by NULs: string extraction,
/// classification and IOC extraction keep the analyzers busy for seconds.
fn heavy_input() -> Input {
    let unit = b"http://a.example.com/x\0";
    let data: Vec<u8> = unit.iter().copied().cycle().take(64 << 20).collect();
    Input::from_bytes("heavy.bin", data)
}

#[test]
fn cancel_stops_a_heavy_analysis_quickly() {
    let input = heavy_input();
    let token = CancelToken::default();
    let deadline = Deadline::never().with_cancel(token.clone());
    let (tx, rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        let report =
            Registry::default().analyze_with_deadline(&input, &Config::default(), deadline);
        let _ = tx.send(Instant::now());
        report
    });

    // Let it get well into the heavy part, and make sure it is still running.
    thread::sleep(Duration::from_millis(150));
    assert!(
        rx.try_recv().is_err(),
        "fixture finished before cancel; it no longer exercises a long loop"
    );
    let cancelled_at = Instant::now();
    token.cancel();

    let finished_at = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("analysis did not stop after cancel");
    let latency = finished_at.saturating_duration_since(cancelled_at);
    let report = worker.join().unwrap();
    eprintln!("cancel latency: {latency:?}");

    assert!(
        latency < Duration::from_millis(200),
        "cancel latency {latency:?}"
    );
    assert!(report.analysis_limited.contains(&AnalysisLimit::Partial));
    assert!(report
        .errors
        .iter()
        .any(|e| e.error == AnalysisError::Cancelled));
}

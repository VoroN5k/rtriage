# Fuzzing

`cargo-fuzz` targets (libFuzzer). They need a nightly toolchain and work
best on Linux; CI runs them weekly (`.github/workflows/fuzz.yml`).

| Target | What it exercises |
|---|---|
| `pe_parse` | PE header/section parser directly, then the full analysis pipeline, asserting report invariants (score = breakdown sum, API groups never suppressed). |
| `strings` | String extraction and classification on arbitrary bytes. |

```bash
cargo install cargo-fuzz --version 0.13.2 --locked
# Seed corpus: synthetic fixtures only. Never add real malware here.
cargo run -p rtriage-fixtures --example fuzz_corpus -- fuzz/corpus/pe_parse
cargo +nightly fuzz run pe_parse -- -max_total_time=600 -timeout=30 -rss_limit_mb=2048
```

`-timeout` and `-rss_limit_mb` turn hangs and memory blow-ups into
reported failures, complementing rtriage's own deadline and limits.

**Every crash becomes a regression test.** Minimise it
(`cargo +nightly fuzz tmin <target> <artifact>`), then add the bytes to a
unit test next to the code that crashed (hex literal or a fixture builder
recipe), never as a binary file of unknown origin.

Stable-toolchain property tests with the same invariants live in
`crates/rtriage-core/tests/robustness_pe.rs` and run on every push;
`PROPTEST_CASES=100000 cargo test -p rtriage-core --test robustness_pe --release`
gives a longer local run.

# rtriage

Fast, static malware triage CLI for PE and ELF binaries.

Given one or more files, `rtriage` tells you what the file is, whether it looks
suspicious, and **why**, with concrete evidence for every finding. It never
executes, loads, or emulates the files it analyzes.

> Status: early development (milestone 1, skeleton).

## Building

```bash
cargo build --workspace
cargo run -p rtriage-cli -- <file>
```

**MSRV:** Rust 1.95 (pinned in `rust-toolchain.toml`).

## License

Licensed under the GNU General Public License v3.0 or later; see [LICENSE](LICENSE).

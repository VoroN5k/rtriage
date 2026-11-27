# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/) (before 1.0, a minor version may
change the CLI).

## [Unreleased]

## [0.1.0] - unreleased

First public pre-release.

### Added

- **Core:** input loading with resource limits (file size, counts, string
  lengths, a time budget per file), format sniffing, MD5/SHA-1/SHA-256,
  Shannon entropy for the whole file and high-entropy regions, ASCII and
  UTF-16LE string extraction with classification.
- **PE:** headers, sections, imports with a pefile-compatible imphash, API
  behavior groups from data rules (injection, persistence, C2, credential
  access and more), exports, resources, Rich header, TLS callbacks, debug
  and PDB paths, overlay, Authenticode presence (not validated), packer
  detection (UPX confirmed by several indicators).
- **ELF:** headers, interpreter, segments and sections, dynamic section
  and a checksec-style hardening summary, symbols and API behavior groups,
  notes, UPX, Go and Rust runtime recognition.
- **IOCs:** URLs, domains, IPs with scope, emails and wallets, with
  deduplication, an allowlist and defanged output.
- **YARA** (`yara` feature, on in release binaries): bundled rules plus
  your own (`--yara`, `--rules-dir`), with rtriage metadata for severity,
  category, ATT&CK and risk floors.
- **Scoring:** transparent, deterministic risk levels (clean-looking, low,
  medium, high) with caps against score inflation, explanations for packers
  and runtimes, and `--explain` for the full breakdown.
- **Batch mode:** directories and several files analyzed in isolated worker
  processes; `scan` prints a table sorted by risk (or NDJSON), and
  `--fail-on` returns exit code 3 for CI.
- **TUI** (`rtriage tui`): findings with evidence, sections, imports,
  strings, IOCs, score breakdown and a hex view, with search and safe
  clipboard copy.
- **Output:** text (sanitized against terminal escape injection), versioned
  JSON (`schema_version` 1, see `docs/output-schema.md`) and Markdown for
  tickets and issues (every file value in code spans, defanged, size-limited).

### Notes

- The JSON schema is version 1; from this release on, a shape change bumps
  it.
- The Linux binary is static (musl) and runs on any x86_64 distribution;
  it is slightly slower to start than a glibc build (about 6 ms).
- Release binaries are not code-signed; verify them with `SHA256SUMS` and
  `gh attestation verify` (see the README).
- rtriage never executes, loads or emulates the files it analyzes.

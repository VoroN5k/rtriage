# rtriage

Fast, static malware triage for PE and ELF binaries.

Given files or directories, `rtriage` answers in seconds: *what is this file,
does it look suspicious, and why?* Every finding carries the concrete
evidence that triggered it (offset, section, import, string, entropy value),
and the risk score is explainable down to each point.

**rtriage never executes, loads or emulates the files it analyzes.** Every
input is treated as hostile: parsers are bounded and panic-free, output is
sanitized against terminal escape injection, and batch runs analyse each
file in an isolated worker process.

> Status: milestones 1–4 done (core, PE, ELF + IOCs, YARA + batch mode).
> Next: the TUI (M5). Pre-release: the JSON schema is version 1 and may
> still change before the first release (see `docs/output-schema.md`).

## What it looks at

- **Any file:** hashes, entropy (whole file and high-entropy regions),
  ASCII/UTF-16 strings with classification, IOCs (URLs, domains, IPs with
  scope, emails, wallets; allowlist; defang), YARA rules.
- **PE:** headers, sections, imports + pefile-compatible imphash, API
  behavior groups (injection, persistence, C2, credential access, ...),
  exports, resources, Rich header, TLS callbacks, debug/PDB paths, overlay,
  Authenticode presence, packers (UPX confirmed by several indicators).
- **ELF:** headers, interpreter, segments/sections, dynamic section and a
  checksec-style hardening summary, symbols and API behavior groups, notes,
  UPX, Go/Rust runtime recognition.

Findings, their thresholds and false-positive notes:
[`docs/heuristics.md`](docs/heuristics.md).

## Building

```bash
cargo build --release -p rtriage-cli                  # without YARA (small, fast to build)
cargo build --release -p rtriage-cli --features yara  # with YARA (yara-x)
```

| Build | Binary | Clean release build | Dependencies |
|---|---|---|---|
| default | ~4 MiB | ~1 min | 43 crates (core) |
| `--features yara` | ~17 MiB | ~6 min | 277 crates (core) |

**MSRV:** Rust 1.95 (pinned in `rust-toolchain.toml`). The `test-hooks`
feature exists only for the worker-isolation tests; never enable it in a
build you ship.

## Usage

```bash
rtriage sample.exe                        # full report, analyzed in-process
rtriage --explain sample.exe              # ... plus the score breakdown
rtriage -f json -o report.json sample.exe # versioned JSON
rtriage --defang sample.exe               # hxxp://evil[.]com, 1[.]2[.]3[.]4 in text

rtriage samples/                          # every file, full reports, worker processes
rtriage scan samples/ -j 8                # batch table sorted by risk
rtriage scan samples/ -f json > out.ndjson          # NDJSON, one summary line
rtriage scan samples/ --full -f json > out.ndjson   # ... plus one line per report

rtriage scan samples/ --fail-on medium    # exit 3 if any file is medium or worse (CI)
rtriage --rules-dir my-rules/ sample.exe  # your rules layered over the bundled ones
rtriage --yara extra.yar --yara rules/ x  # extra YARA rules (yara build)
rtriage --no-yara sample.exe              # skip YARA, even the bundled rules
```

| Invocation | Where files are analyzed | Output |
|---|---|---|
| one file | in this process | full report |
| several files, any directory | isolated worker processes (`-j`) | full reports in input order |
| `scan` | isolated worker processes | table sorted by risk (or NDJSON) |

Directories are walked recursively, sorted, without following symlinks;
FIFOs and devices are skipped. A worker that crashes, hangs past
`--timeout` + 5 s, or floods its output loses only the file it was on; the
file is reported as `crashed`, `timed_out` or `invalid_response` and a
fresh worker continues.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Every file analyzed (and no `--fail-on` threshold met). |
| `1` | At least one file could not be analyzed, or the output could not be written. |
| `2` | Usage error: bad flags, invalid rules, YARA rules for a build without YARA. |
| `3` | `--fail-on` threshold met. Takes precedence over `1` (with a warning). |

## Custom rules

`--rules-dir DIR` reads only these names; each is optional and falls back to
the bundled data in [`rules/`](rules/):

| In `DIR` | Effect |
|---|---|
| `api_groups.toml`, `elf_api_groups.toml` | PE / ELF behavior groups: replace the bundled ones, or merge with `include_defaults = true` |
| `packers.toml` | packer and runtime explanations (same merge rule) |
| `ioc_allowlist.toml` | domains added to the IOC allowlist |
| `yara/` | YARA rule files added to the bundled ones |
| `yara.toml` | `include_bundled`, and YARA load/scan limits |

YARA rules may carry rtriage metadata (`severity`, `confidence`,
`category`, `attack`, `risk_floor`, `description`), validated when the rules
are loaded. Formats and limits: [`docs/heuristics.md`](docs/heuristics.md).

## Documentation

- [`docs/heuristics.md`](docs/heuristics.md): every finding, scoring v1, caps, explained-by, custom rules.
- [`docs/output-schema.md`](docs/output-schema.md): JSON and NDJSON schema, compatibility rule, exit codes.
- [`docs/robustness.md`](docs/robustness.md): limits, deadlines, panic safety, worker isolation, how it is tested.
- [`fuzz/README.md`](fuzz/README.md): fuzz targets.

## Development

```bash
cargo test --workspace                    # default features
cargo test --workspace --all-features     # with YARA and the worker test hooks
cargo clippy --workspace --all-targets --all-features -- -D warnings
PROPTEST_CASES=100000 cargo test -p rtriage-core --release --all-features --test robustness_elf
```

Tests use synthetic, programmatically built fixtures only; no real malware
is, or will be, part of this repository.

## License

Licensed under the GNU General Public License v3.0 or later; see [LICENSE](LICENSE).

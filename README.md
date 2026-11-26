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

> Status: milestones 1–5 done (core, PE, ELF + IOCs, YARA + batch mode,
> TUI). Next: polish (M6). Pre-release: the JSON schema is version 1 and may
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
cargo build --release -p rtriage-cli                        # TUI, no YARA (small, fast to build)
cargo build --release -p rtriage-cli --features yara        # TUI + YARA (yara-x)
cargo build --release -p rtriage-cli --no-default-features  # neither: plain CLI
```

| Build | Binary | Clean release build | Dependencies of `rtriage-cli` |
|---|---|---|---|
| default (TUI) | ~4.7 MiB | ~1 min | 116 crates |
| `--no-default-features` | ~4.2 MiB | ~1 min | 73 crates |
| `--features yara` | ~17 MiB | ~6 min | 262 crates |

(Windows x86_64; crates counted with `cargo tree -e normal`.)

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

rtriage tui sample.exe                    # interactive view (see below)
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

## TUI

`rtriage tui <FILE>` analyses one file in the background (Esc or `q`
cancels; a cancelled report is marked **PARTIAL** and its risk shows as
`INCOMPLETE`, never `clean-looking`) and opens an interactive view. The
analysis options (`--rules-dir`, `--yara`, `--timeout`, `--max-size`) apply.
It needs a terminal on stdin and stdout; in a pipe it exits with code 2.

| Tab | Shows |
|---|---|
| `1` Findings | findings list; details and evidence on the right, `Enter` jumps to the evidence |
| `2` Sections | PE sections, ELF section headers (`s`: program headers) |
| `3` Imports | PE functions by DLL with imphash, ELF symbols |
| `4` Strings | every extracted string; `f` filters by class and length, `x` clears |
| `5` IOCs | file hashes, then indicators; defanged, `d` shows raw values |
| `6` Explain | how the score was computed; `Enter` opens the finding |
| `7` Hex | read-only dump; byte-range evidence opens it highlighted, `g` goes to an offset |

`Backspace` (or Alt-←) goes back after a jump. `/` searches the current list,
`n`/`N` step through matches. `?` lists every key. The view needs at least
60×16; everything taken from the file is shown with control, bidi and
invisible characters escaped.

**Copying.** `y` copies the selected value sanitized: one line, escapes
visible, URLs and IPs defanged. `Y` copies it exactly as found, after asking
(it may contain control characters). Hashes are copied as they are. Copying
uses the terminal's clipboard sequence (OSC 52), so it also works over SSH,
up to 64 KiB, if the terminal allows it. Many modern terminals do (for
example Windows Terminal, kitty, WezTerm); some need it switched on first
(iTerm2's clipboard-access setting, xterm's `disallowedWindowOps`). The
status line says what was sent, not whether the terminal accepted it.

- **tmux:** set `set -g set-clipboard on`. With `external`, which user
  reports give as the default, tmux ignores the sequence from applications.
  rtriage sends the plain sequence inside tmux, so `allow-passthrough` is
  not needed (it only matters for the `\ePtmux;` wrapper).
- **GNU screen:** the sequence is wrapped for screen automatically.

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
PROPTEST_CASES=10000 cargo test -p rtriage-tui --release --test robustness   # random keys, whole TUI
cargo test -p rtriage-tui --release --test perf -- --ignored                 # strings list timing
cargo bench -p rtriage-tui --bench strings_list
cargo insta review                        # after an intended change to a screen
```

TUI screens are snapshot-tested at 80×24 and larger with `insta`.

Tests use synthetic, programmatically built fixtures only; no real malware
is, or will be, part of this repository.

## License

Licensed under the GNU General Public License v3.0 or later; see [LICENSE](LICENSE).

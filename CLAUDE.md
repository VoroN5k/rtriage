# CLAUDE.md — `rtriage`

Guidance for Claude Code when working in this repository. Read this fully before making changes.

## 1. Project overview

**`rtriage`** is a fast, static **malware triage CLI/TUI for PE and ELF binaries**, written in Rust.

Given one or more files, it answers in seconds: *"What is this file, is it suspicious, and why?"*, with **evidence**, not just a verdict.

**Target users:** SOC analysts, incident responders, malware analysts, CTF players, students learning reverse engineering.

**Core principles**
1. **Evidence over verdicts.** Every finding carries the concrete data that triggered it (offset, string, import, entropy value). A bare score is never acceptable.
2. **Static only.** The tool never executes, loads, or emulates input files.
3. **Hostile input by default.** Every input file is assumed to be crafted to crash or exploit the parser.
4. **Fast.** Typical single file triage in well under a second; batch mode scales across cores.
5. **Good UX.** Readable terminal output, sensible defaults, machine-readable output for pipelines.

### Non-goals (do not build these)
- Disassembler, decompiler, or emulator (future projects).
- Dynamic analysis / sandboxing.
- Any code that generates, modifies, obfuscates, or weaponizes malware.
- Cloud upload of samples. Hash lookups against online services are **opt-in only** and send only hashes, never file contents.
- Mach-O, .NET IL, scripts, Office docs (possible later; out of scope for v1).

## 2. Safety rules (non-negotiable)

- **NEVER execute, `dlopen`, `LoadLibrary`, or otherwise run an input file.**
- **No real malware in the repository.** Tests use synthetic, minimal, hand-built or generated binaries. Do not download samples, and do not add them to tests or fixtures.
- Parsing code must **never panic** on any input: no `unwrap()`, `expect()`, unchecked indexing, or unchecked arithmetic on file-derived values in non-test code. Use `get()`, `checked_*`, and return errors.
- **No `unsafe`** unless explicitly approved; `#![forbid(unsafe_code)]` is set in the library crates.
- Enforce **resource limits** on file-derived sizes: max file size (default 512 MiB, configurable), max number of sections/imports/strings, max string length, bounded recursion/loops. A header claiming 4 billion sections must produce a clean error, not an allocation.
- Never print raw attacker-controlled strings to a terminal unescaped (terminal escape injection). Sanitize control characters and ANSI sequences in all rendered output.
- No network access by default. Any networked feature sits behind an explicit flag and cargo feature.

## 3. Tech stack

- **Language:** Rust, stable toolchain, edition 2021 (pin via `rust-toolchain.toml`). MSRV documented in README.
- **Parsing:** `goblin` for PE/ELF (supplement with `object` if useful). Hand-write small parsers where the crates lack detail (Rich header, overlay).
- **CLI:** `clap` (derive).
- **TUI:** `ratatui` + `crossterm`.
- **Serialization:** `serde`, `serde_json` (also SARIF/Markdown output later).
- **Hashing:** `sha2`, `sha1`, `md-5`; fuzzy hashes (`ssdeep`/`tlsh` equivalents) are a later milestone.
- **Rules:** `yara-x` (pure Rust YARA), behind the `yara` cargo feature.
- **Errors:** `thiserror` in libraries, `anyhow` only in the binary crate.
- **Concurrency:** `rayon` for batch mode. `memmap2` for large files (read-only).
- **Logging:** `tracing` + `tracing-subscriber`.
- **Testing:** `insta` (snapshots), `proptest`, `criterion` (benches), `cargo-fuzz` (fuzz targets).

> Do not hardcode crate versions from memory. Run `cargo add <crate>` to get current versions, and **ask before adding any new dependency** not listed here, with one line on why it is needed.

## 4. Repository layout (Cargo workspace)

```
rtriage/
├── Cargo.toml                # workspace
├── rust-toolchain.toml
├── CLAUDE.md
├── README.md
├── crates/
│   ├── rtriage-core/         # library: parsing, analyzers, scoring, report model
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── error.rs
│   │       ├── limits.rs     # resource limits & config
│   │       ├── input.rs      # file loading, format sniffing
│   │       ├── report.rs     # Report, Finding, Severity, Evidence
│   │       ├── analyzers/
│   │       │   ├── mod.rs    # Analyzer trait + registry
│   │       │   ├── hashes.rs
│   │       │   ├── entropy.rs
│   │       │   ├── strings.rs
│   │       │   ├── pe/       # headers, sections, imports, exports, resources, rich, tls, overlay, signature
│   │       │   ├── elf/      # headers, segments, sections, dynamic, symbols, notes
│   │       │   ├── packers.rs
│   │       │   ├── iocs.rs
│   │       │   └── yara.rs   # feature-gated
│   │       └── scoring.rs
│   ├── rtriage-cli/          # binary: clap, output renderers (text, json, markdown)
│   └── rtriage-tui/          # ratatui interface (milestone 4)
├── rules/                    # first-party YARA + heuristic rule definitions (data, not code)
├── tests/
│   ├── fixtures/             # SYNTHETIC binaries only (see §9)
│   └── integration/
├── fuzz/                     # cargo-fuzz targets
├── benches/
└── docs/
    ├── heuristics.md         # every heuristic: rationale, thresholds, false-positive notes
    └── output-schema.md      # JSON schema documentation
```

## 5. Architecture

### Data flow
```
file path → input (size check, mmap, format sniff)
          → Analyzer pipeline (each analyzer reads the parsed binary, emits Findings + Facts)
          → scoring (aggregate findings → risk level)
          → Report → renderer (text | json | markdown | tui)
```

### Core types (sketch; refine as needed)
```rust
pub struct Report {
    pub file: FileInfo,            // path, size, hashes, detected format
    pub facts: Facts,              // neutral extracted data (sections, imports, strings summary)
    pub findings: Vec<Finding>,    // things that matter
    pub risk: Risk,                // score + level
    pub errors: Vec<AnalysisError>,// partial failures; analysis continues where possible
}

pub struct Finding {
    pub id: &'static str,          // stable, e.g. "PE-SECTION-RWX"
    pub severity: Severity,        // Info | Low | Medium | High
    pub category: Category,        // Packing | Injection | Persistence | Network | Anomaly | ...
    pub title: String,
    pub detail: String,
    pub evidence: Vec<Evidence>,   // concrete data: offset, section name, API, string, value
    pub attack: Vec<&'static str>, // optional MITRE ATT&CK IDs, e.g. "T1055"
    pub confidence: Confidence,    // how likely this is meaningful (heuristic vs. strong)
}

pub trait Analyzer: Send + Sync {
    fn name(&self) -> &'static str;
    fn applies_to(&self, fmt: Format) -> bool;
    fn run(&self, ctx: &AnalysisContext, out: &mut ReportBuilder) -> Result<(), AnalysisError>;
}
```

### Rules
- Analyzers are **independent and order-agnostic**. A failing analyzer records an error and the rest continue.
- **Facts vs. Findings:** facts are neutral data; findings are judgments. Keep them separate so output can be re-scored without re-parsing.
- **Finding IDs are stable** and documented in `docs/heuristics.md`. Never rename an ID without a changelog note.
- Heuristic thresholds live in one config struct with documented defaults, not as magic numbers in analyzer code.
- Core is a **library first**; the CLI is a thin layer. Everything testable without spawning the binary.

## 6. Feature specification

### 6.1 Common (both formats)
- Hashes: MD5, SHA-1, SHA-256, file size, detected type, magic mismatch vs. extension.
- Shannon entropy: whole file and per section/segment; flag high-entropy regions.
- String extraction: ASCII and UTF-16LE, min length configurable (default 5); classify (URL, IPv4/IPv6, domain, file path, registry key, email, base64-like blobs, suspicious commands, crypto-wallet-like strings, user-agents).
- IOC extraction with dedup, normalization, and defanged output option (`hxxp://`, `1[.]2[.]3[.]4`).
- Optional YARA scan (user-supplied rules dir plus bundled `rules/`).
- Detect appended data (overlay) and its entropy/type.

### 6.2 PE
- Headers: machine, subsystem, characteristics, DLL/EXE/driver, 32/64-bit, entry point (and which section contains it), image base, timestamp (flag zero, future, or implausible values), checksum validity.
- Sections: names, virtual vs. raw size ratios, characteristics, flag: RWX sections, writable+executable, non-standard names, entry point outside `.text`/first executable section, zero raw size with large virtual size (typical of packers), high entropy.
- Imports: full table with DLL grouping; import hash (imphash); very few imports (+ `LoadLibrary`/`GetProcAddress` only); ordinal-only imports; **API behavior groups** (see §7).
- Exports: names, forwarders, anomalies (e.g. DLL with a single odd export).
- Rich header: parse and verify; flag mismatch/absence for MSVC-looking binaries (informational).
- TLS callbacks (flag presence, since commonly used for anti-debug/early execution).
- Resources: list types; flag large embedded PE/high-entropy resources.
- Authenticode: presence of a certificate table and basic structure only (signature *validation* is out of scope for v1; report "signed (unverified)").
- Debug info: PDB path extraction (often leaks build paths/usernames).
- Packer hints: known section names (UPX0/UPX1, .aspack, .themida, etc.), entropy + low import count combination.

### 6.3 ELF
- Headers: class, endianness, OS/ABI, type (EXEC/DYN/REL/CORE), machine, entry point.
- Program headers: flag RWX segments, executable stack (`PT_GNU_STACK`), unusual `PT_INTERP`, missing `PT_GNU_RELRO`.
- Section headers: flag stripped/missing/truncated section headers (common with packed/hand-crafted ELF), section/segment inconsistencies.
- Dynamic: `DT_NEEDED`, RPATH/RUNPATH oddities, `DT_FLAGS` (BIND_NOW), PIE, NX, RELRO summary (checksec-style).
- Symbols/imports: suspicious libc/syscall usage groups (`ptrace`, `fork`+`setsid` daemonization, `dlopen`, `mprotect` with exec, `execve`, socket APIs, crypto APIs).
- Packer hints: UPX signature/overlay, tiny binary with high entropy, static-linked Go/Rust detection (informational, to set analyst expectations).
- Notes: `.note.gnu.build-id`, Go build info presence.

### 6.4 Scoring
- Findings carry severity and confidence; the aggregate **risk level** is `Clean-looking | Low | Medium | High` with a numeric score for sorting in batch mode.
- Scoring must be **explainable**: `--explain` prints exactly which findings contributed and how much.
- Prefer a small number of strong signals over many weak ones; cap the contribution of repeated weak findings to avoid score inflation.
- **No ML in v1.** Keep scoring transparent and deterministic.

## 7. Suspicious API behavior groups (PE)

Group by *behavior*, flag **combinations**, not single APIs (single APIs like `CreateFileW` are everywhere). Examples:

| Behavior | Example combination | ATT&CK |
|---|---|---|
| Process injection | `OpenProcess` + `VirtualAllocEx` + `WriteProcessMemory` + (`CreateRemoteThread` or `NtCreateThreadEx` or `QueueUserAPC`) | T1055 |
| Dynamic API resolution | `LoadLibrary*` + `GetProcAddress` and very small import table | T1027.007 |
| Anti-debug | `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess` | T1622 |
| Persistence (registry) | `RegSetValueEx`/`RegCreateKeyEx` + run-key strings | T1547.001 |
| Persistence (service) | `CreateService*`, `StartService` | T1543.003 |
| Network C2 | `InternetOpen*`/`WinHttp*`/`WSAStartup`+`connect` + URL/IP strings | T1071 |
| Crypto (ransomware-like) | `CryptEncrypt`/`BCryptEncrypt` + file enumeration (`FindFirstFile`/`FindNextFile`) + many file extension strings | T1486 |
| Credential access | `LsaEnumerate*`, `CredEnumerate*`, `CryptUnprotectData` | T1555 |
| Keylogging / input | `SetWindowsHookEx`, `GetAsyncKeyState` | T1056 |

Keep the table in `rules/` as data (TOML/YAML) so it can be extended without recompiling; document each entry's rationale and known false positives in `docs/heuristics.md`.

## 8. CLI specification

```
rtriage <FILE|DIR>...            # triage one or more files (dirs scanned recursively)
rtriage scan <DIR> --jobs N      # batch mode, sorted by risk
rtriage tui <FILE>               # interactive view (milestone 4)

Common flags:
  -f, --format <text|json|md>    # output format (default: text)
  -o, --output <PATH>            # write report to file
      --min-severity <LEVEL>     # filter findings
      --explain                  # show scoring breakdown
      --strings-min <N>          # min string length (default 5)
      --defang                   # defang URLs/IPs in output
      --yara <DIR>               # extra YARA rules
      --max-size <BYTES>         # override file size limit
      --no-color                 # also honor NO_COLOR
  -q / -v / -vv                  # verbosity
```

**Output requirements**
- Text output: a compact header (file, type, hashes, size), a risk badge, findings grouped by severity with evidence, then optional sections (sections table, imports summary, IOCs). Color is used, but never as the only carrier of meaning.
- JSON output: stable, documented schema, versioned with a `schema_version` field. Never break it without bumping the version.
- Exit codes: `0` success; `1` runtime error; `2` usage error; with `--fail-on <level>` return `3` if risk ≥ level (for CI/pipelines).
- Batch mode: one failing file never aborts the run; failures are reported in the summary.

## 9. Testing strategy

- **Unit tests** for every analyzer using small synthetic inputs.
- **Fixtures:** generated programmatically (a `fixture-builder` helper in tests that assembles minimal valid and deliberately malformed PE/ELF byte buffers) or compiled from tiny benign source. **No real malware, ever.** EICAR-style benign test strings are acceptable.
- **Snapshot tests** (`insta`) for text/JSON output on fixtures.
- **Property tests** (`proptest`): arbitrary and mutated bytes must never panic and must finish within limits.
- **Fuzzing** (`cargo-fuzz`): targets for the PE path, ELF path, and string extractor. Any crash found becomes a regression test.
- **Negative tests:** truncated headers, huge counts, overlapping sections, circular/oversized offsets, zero-length files, directory passed as file, unreadable files.
- **Benchmarks** (`criterion`): large-file throughput for entropy, strings, and hashing.
- Every new heuristic ships with: a positive test, a negative test (benign look-alike), and an entry in `docs/heuristics.md`.

## 10. Coding conventions

- `cargo fmt` and `cargo clippy --all-targets --all-features -- -D warnings` must pass.
- Library errors: typed enums (`thiserror`). No `String` errors. Binary: `anyhow` with context.
- No `unwrap`/`expect`/`panic!`/indexing in non-test code (enforce with `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]` in the core crate).
- Prefer iterators and small pure functions; keep analyzers side-effect free.
- Public items are documented with `///`; modules start with a `//!` summary.
- Keep functions focused; extract helpers instead of deep nesting.
- Use `tracing` for diagnostics, never `println!` in library code.
- Deterministic output: sort collections before rendering so snapshots are stable.
- Platform-independent: the tool analyzes Windows binaries on Linux/macOS and vice versa; no OS-specific APIs in core.

## 11. Common commands

```bash
cargo build --workspace
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all --check
cargo run -p rtriage-cli -- <file>
cargo bench -p rtriage-core
cargo +nightly fuzz run pe_parse        # requires cargo-fuzz
cargo insta review                      # review snapshot changes
```

## 12. Milestones

1. **M1 – Skeleton:** workspace, input loading with limits, format sniffing, hashes, entropy, string extraction, text + JSON output, CI (fmt, clippy, test).
2. **M2 – PE analysis:** headers, sections, imports + imphash, API behavior groups from data rules, overlay, TLS, PDB path, packer hints; scoring v1 with `--explain`.
3. **M3 – ELF analysis:** headers, segments, dynamic/checksec summary, symbols, packer hints; IOC extraction with defang.
4. **M4 – YARA + batch:** `yara-x` integration, `scan` command with rayon, sorted summary table, `--fail-on` exit codes.
5. **M5 – TUI:** ratatui interface with sections, imports, strings, and findings panes; search/filter; jump from a finding to its evidence.
6. **M6 – Polish:** Markdown/SARIF output, fuzzy hashing, opt-in hash reputation lookups, docs, release binaries.

## 13. How to work in this repo (instructions for Claude)

- **Plan before large changes.** For anything touching multiple modules, outline the approach first, then implement in small, reviewable steps.
- Implement **one milestone item at a time**; keep the build green and tests passing between steps.
- When adding a heuristic, always update `docs/heuristics.md` with rationale, thresholds, and false-positive notes.
- If a requirement is ambiguous or a design decision is irreversible (public JSON schema, finding IDs, CLI flags), **ask before choosing**.
- Never weaken safety rules in §2 to make a feature easier. If a feature seems to need executing or emulating a sample, stop and ask.
- Do not add dependencies without asking (§3). Prefer the standard library for small utilities.
- Prefer correctness and clear evidence over cleverness; false positives erode trust, so when a heuristic is weak, lower its confidence rather than inflating severity.
- Commits user does on his own, you are allowed to read only operations with git. User needs only text foo commit after every step done (conventional-commit style: `feat(pe): flag RWX sections`).
# Robustness against hostile input

Every input file is assumed to be crafted to crash, hang or exhaust the
analyzer. This document lists the defences and where they live.

## 1. Size and count limits (`Limits`, `crates/rtriage-core/src/limits.rs`)

| Limit | Default | Applies to |
|---|---|---|
| `max_file_size` | 512 MiB | Checked before reading; the read itself is bounded (`take(limit + 1)`). |
| `max_sections` | 4096 | PE section table / ELF section headers, checked **before** any parser allocates. |
| `max_segments` | 4096 | ELF program headers. |
| `max_imports` | 65 536 | Import thunks across **all** libraries of a file, so many descriptors sharing one thunk array cannot multiply the work. |
| `max_import_libraries` | 4096 | Import descriptors per file. |
| `max_tls_callbacks` | 256 | TLS callback array entries. |
| `max_debug_entries` | 64 | Debug directory entries (CodeView records are capped at 1 KiB). |
| `max_exports` | 65 536 | `NumberOfFunctions` and `NumberOfNames` are each capped; every export array must map contiguously into one section. |
| `max_resources` | 4096 | Resource leaves. The walk is fixed at depth 3 and visits each directory offset once, so cycles and shared subdirectories cannot loop or multiply work. |
| `max_certificates` | 16 | `WIN_CERTIFICATE` entries; zero or oversized lengths stop the walk. |
| `max_dynamic_entries` | 4096 | ELF `PT_DYNAMIC` entries (reading stops at `DT_NULL`). |
| `max_symbols` | 200 000 | ELF symbols per table. Counts derived from `DT_HASH` / `DT_GNU_HASH` are capped here, and reading stops at EOF; `DT_GNU_HASH` bucket/bloom counts above 2^20 are ignored and chain walks consume budget steps. |
| `max_notes` | 256 | ELF notes across all `PT_NOTE` segments; descriptors are cut to 1 KiB, and a note whose sizes run past its segment stops that segment. |
| `max_strings` | 200 000 | Strings kept (the rest are only counted). |
| `max_string_len` | 4096 | Characters copied per string. |
| `max_iocs` | 10 000 | Distinct IOCs kept (8 offsets each). |
| `max_analysis_time` | 30 s | Wall-clock limit per file (`--timeout`). |
| `max_parser_steps` | 10 000 000 | Loop steps per format parser. |

The Rich header search is limited to the first 4 KiB, whatever `e_lfanew`
claims.

**ELF.** `EI_CLASS` / `EI_DATA` are checked first; every multi-byte read is
byte-order aware. `e_phnum` is checked against `max_segments`, `e_phentsize`
must be 32 / 56, and the table must lie inside the file *before* goblin
parses it. Section headers are optional: a bad `e_shentsize`, an
oversized count, a table past EOF or a bad `e_shstrndx` is recorded as a
section problem instead of aborting. `PT_INTERP` is read up to 4096 bytes.
UPX signature and banner searches look only at the first and last 4 KiB /
64 KiB; the Go build-info search checks the deadline every MiB.

Exceeding a limit yields `AnalysisError::LimitExceeded`, never an allocation
of the claimed size.

## 2. Directory walking (`crates/rtriage-core/src/walk.rs`)

- Paths named on the command line are used as given (a symlink root is
  followed). Inside directories **symlinks are never followed** (no cycles,
  no escaping the tree; Windows junctions count as symlinks) and FIFOs,
  sockets and devices are skipped: opening a FIFO would block forever.
- Bounds (`WalkOptions`): 32 directory levels below a root, 100 000 files in
  total, 10 million entries read per directory. Hitting a bound is reported
  under `skipped` (`depth_limit` / `file_limit`) and as a warning.
- Deterministic: each directory keeps only its `room + 1` smallest names in
  a bounded heap and sorts them, so the chosen files never depend on the
  order the filesystem returns entries (ext4 is unsorted, NTFS is sorted).
  Found by running the tests on Linux.
- Files reached twice (overlapping roots) are analyzed once (canonical path).
- Walking never opens files; size and format checks happen at load time.

## 3. Time limit (`crates/rtriage-core/src/deadline.rs`)

Rust threads cannot be killed from outside, so the limit is **cooperative**:

- `Deadline` is created when analysis of a file starts.
- The registry checks it before every analyzer. Once expired, all remaining
  analyzers are recorded as `AnalysisError::Timeout` and skipped; the report
  stays valid but partial.
- Linear scanners (hashes, entropy, strings) check it once per chunk
  (1 MiB / 64 Ki units / 256 windows / 1024 strings).
- Format parsers walking attacker-controlled structures use a `Budget`:
  every loop iteration is one step, the deadline is re-checked every 1024
  steps, and more than `max_parser_steps` steps is a `LimitExceeded` error.
- Third-party parser calls (goblin) cannot be interrupted. They are only
  given inputs whose sizes and counts were validated first, so their work is
  bounded by the limits in §1.

The CLI exposes `--timeout <SECONDS>` (default 30, `0` is rejected).

## 4. Panics

- Core code is panic-free by construction: `unwrap`, `expect`, `panic!` and
  slice indexing are denied by clippy outside tests.
- Third-party parsers may still panic on malformed input. Each such call is
  wrapped in `std::panic::catch_unwind`; a panic becomes
  `AnalysisError::Internal` and the other analyzers keep running.
- `catch_unwind` only works with `panic = "unwind"`. The core crate refuses
  to compile otherwise (`compile_error!` under `cfg(not(panic = "unwind"))`).
- The CLI installs a panic hook that prints a sanitized message, because the
  default hook would echo a panic payload (possibly containing file data)
  to the terminal unescaped.

## 5. How this is tested

- **Property tests** (stable, every push): `crates/rtriage-core/tests/robustness_pe.rs`
  and `robustness_elf.rs`, sharing mutations and report invariants in
  `tests/common`. Synthetic corpora (PE; ELF in both classes and byte
  orders) are mutated with byte, dword and qword edge values in either byte
  order and truncation, or followed by random bytes behind real headers.
  Every report must be coherent (score = breakdown sum, sorted findings, API
  groups never suppressed); a tiny `max_parser_steps` may only produce
  budget errors reporting that limit; an expired deadline yields no
  findings and only timeouts; 16 MiB of noise under a 1 ms deadline
  finishes in seconds. Long run:
  `PROPTEST_CASES=100000 cargo test -p rtriage-core --test robustness_elf --release`
  (500 000 ELF cases passed when step 8 of M3 landed).
- **Unit tests** for each bounded parser: huge header counts, oversized
  note sizes, `max_notes`, budget and deadline on long note walks, GNU hash
  chains without an end bit.
- **Fuzzing** (nightly, weekly in CI): `pe_parse`, `elf_parse`, `strings`;
  see `fuzz/README.md`.

## 6. Planned: process isolation for `rtriage scan` (M4)

In-process defences cannot stop everything: a stack overflow or an
allocation failure aborts the whole process, and a hung third-party call
cannot be interrupted. Batch mode will therefore run analysis in **child
processes**:

- `rtriage scan` spawns workers (`rtriage` itself in a hidden worker mode),
  each analysing a slice of the file list and streaming one JSON report per
  file over stdout.
- The parent enforces a hard wall-clock limit per file
  (`--timeout` plus a grace period) and kills the worker if it is exceeded.
- A crashed or killed worker only loses the file it was working on: that file
  is reported in `failures` (`crashed` / `timed out`) and a new worker
  continues with the rest of the list.
- Workers are started with an explicit, empty environment except what they
  need, and only receive file paths, never file contents, on the command line.
- Platform memory caps (Job Objects on Windows, `setrlimit` on Unix) are a
  possible follow-up; they need OS-specific code outside the core crate.

Single-file mode (`rtriage <FILE>`) keeps running in-process for speed and
simplicity; the cooperative deadline and limits apply there.

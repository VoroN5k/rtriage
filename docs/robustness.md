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
| `max_exports` | 65 536 | Export entries. |
| `max_strings` | 200 000 | Strings kept (the rest are only counted). |
| `max_string_len` | 4096 | Characters copied per string. |
| `max_analysis_time` | 30 s | Wall-clock limit per file (`--timeout`). |
| `max_parser_steps` | 10 000 000 | Loop steps per format parser. |

Exceeding a limit yields `AnalysisError::LimitExceeded`, never an allocation
of the claimed size.

## 2. Time limit (`crates/rtriage-core/src/deadline.rs`)

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

## 3. Panics

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

## 4. Planned: process isolation for `rtriage scan` (M4)

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

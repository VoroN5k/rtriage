# M5 — TUI design

Status: approved approaches (1A, 2A, 3A, 4, 5 + additions), 2026-11-26.

## Intent

`rtriage tui <FILE>` gives an analyst an interactive view of one file's
triage: start from the findings, read why each one fired, and jump straight
to the data behind it (a section, an import, a string, a byte range), then
come back. The text report answers "is it suspicious"; the TUI is for
"show me exactly where".

## Goals

- First screen: findings list on the left, the selected finding's details and
  evidence on the right.
- Tabs: **Findings**, **Sections**, **Imports**, **Strings**, **IOCs**,
  **Explain**, and (last step) **Hex**.
- Jump from an evidence item to its target in the matching tab, with a
  back history (several levels).
- Explain tab: score breakdown, category caps, risk floor, suppressed
  findings and why they were suppressed.
- Search: substring within the current panel. Strings additionally filter
  by class (`StringKind`) and length. The strings list is virtualized (up to
  200 000 items).
- IOCs are defanged by default, with a toggle; copy sanitized or raw.
- Analysis runs on a background thread and can be cancelled; a cancelled
  report is shown and marked as **partial**.
- Robust terminal handling: restore on panic and on every exit path, act
  only on `KeyEventKind::Press` (Windows sends press + release), a "window
  too small" screen, a clean error when stdout/stdin is not a TTY.

## Non-goals

- Regex search (later).
- Editing, patching or exporting binaries; the hex view is read-only.
- Multi-file / directory browsing in the TUI (that is `scan`).
- Disassembly.
- Mouse support (keyboard only in M5).

## Anti-goals (failure even if it "works")

- Any attacker-controlled byte reaching the terminal unescaped, including
  through the clipboard path.
- A UI that freezes while a large file is being analysed, or that leaves the
  terminal in raw mode / alternate screen after a crash.
- Rendering cost proportional to the number of strings instead of the
  number of visible rows.

## Constraints

- CLAUDE.md §2 safety rules apply unchanged (no panics on file data, no
  unsafe, limits, sanitize everything rendered).
- Dependencies: `ratatui` + `crossterm` (already allowed in §3); versions via
  `cargo add`. No clipboard crate.
- Platform-independent; tested on Linux, Windows, macOS in CI.
- Single file runs in-process (M4 decision); the TUI reuses the CLI's config,
  rules and YARA loading.

## Approaches (decided)

1. **Wiring — A (chosen):** `rtriage-tui` is a library exposing `run(...)`;
   `rtriage-cli` depends on it, subcommand `tui` behind the cargo feature `tui`
   (default **on**). Config/rules/YARA loading stays in the CLI. Rejected B:
   separate binary, which would duplicate config loading.
2. **Cancellation — A (chosen):** a cancel token (`Arc<AtomicBool>`) inside
   `Deadline`; every existing `Deadline::check`/`Budget` call honours it.
   Rejected B: abandoning the thread, which keeps burning CPU until
   `max_analysis_time`.
3. **Clipboard — A (chosen):** OSC 52, no dependency, works over SSH.
   Rejected B: `arboard` (new dependency, X11/Wayland deps, no SSH).
4. **Shared sanitizer:** new crate `rtriage-sanitize`, **zero dependencies**;
   `sanitize.rs` moves there unchanged in behaviour. `defang` stays in core.
5. **TUI structure:** `App` state + pure `update` + `view`; side effects are
   returned as commands (see below). Tests use `ratatui::TestBackend` + insta.

## Design

### Crates

```
rtriage-sanitize   (no deps)        sanitize(), single_line() helpers
rtriage-core       (+ cancel token)  unchanged API except Deadline/CancelToken
rtriage-tui        (ratatui, crossterm, rtriage-core, rtriage-sanitize)
rtriage-cli        (+ rtriage-tui behind feature `tui`, default on)
```

`rtriage-sanitize` exports:
- `sanitize(&str) -> Cow<str>`: current behaviour (visible escapes for C0,
  DEL, C1, bidi controls, zero-width, line/paragraph separators, BOM).
- `single_line(&str) -> Cow<str>`: like `sanitize`, guaranteed to contain no
  line breaks; used for clipboard "sanitized" copies and table cells.

Required tests: U+202E (RLO) and the other bidi controls, zero-width
characters (U+200B..U+200D, U+FEFF), C1 (U+0080..U+009F, incl. U+009B CSI),
ESC-based OSC (`\x1b]52;c;...\x07`) and CSI (`\x1b[2J`) sequences, borrowed
fast path for clean input.

### Cancellation (core)

- `CancelToken` (cheap clone, `Arc<AtomicBool>`); `Deadline::with_cancel`.
- `Deadline::check` returns `AnalysisError::Cancelled` when the token is set
  (checked before the time limit).
- New `AnalysisLimit::Partial` added to `report.analysis_limited` when any
  analyzer was cancelled; the remaining analyzers are recorded as cancelled,
  exactly like timeouts today.
- YARA: yara-x scans cannot be interrupted from outside. The analyzer checks
  the token before scanning and right after it returns; a scan that finished
  while cancelled is discarded as `Cancelled`. The scan itself stays bounded
  by its existing timeout. The UI never waits for it (see threading).
- The CLI never sets the token, so CLI/JSON output never contains the new
  variants; `schema_version` stays 1, and `docs/output-schema.md` documents
  both variants as "only produced by interactive cancellation".

### Threading

- The UI thread owns the terminal. `analyze` runs on a spawned thread and
  sends `AnalysisDone(Box<Report>)` over a channel; the event loop polls
  crossterm with a short timeout (≈50 ms) and drains the channel.
- `Esc`/`q` during analysis sets the token; the UI shows the partial report
  as soon as it arrives. Quitting does not join the thread beyond ~200 ms;
  process exit ends it.
- The `Input` (file bytes) is kept in an `Arc` for the hex view and range
  entropy.

### State, update, commands

```rust
enum Msg { Key(KeyEvent), Resize(u16, u16), AnalysisDone(Box<Report>), Tick }
enum Cmd { Copy { payload: String, label: String }, Cancel, Quit }
fn update(app: &mut App, msg: Msg) -> Vec<Cmd>   // no I/O, no clock
fn view(app: &App, frame: &mut Frame)
```

The runtime executes commands (OSC 52 write, set token, exit). Key events are
filtered to `KeyEventKind::Press` in the runtime before they become `Msg`.

### Screens and keys

Loading screen: file name, size, spinner, "Esc to cancel".

Layout (≥ 80×24): tab bar, body, one status line (key hints, copy status,
"PARTIAL" badge, risk badge).

| Key | Action |
|---|---|
| `1`–`7`, `Tab`/`Shift-Tab` | switch tab |
| `↑↓`/`j k`, `PgUp/PgDn`, `Home/End` | move |
| `Enter` | jump to the selected evidence's target |
| `Backspace` / `Alt-←` | back in history |
| `/`, `n`/`N`, `Esc` | substring search in the panel, next/prev, clear |
| `f` (Strings) | filter dialog: classes, min/max length |
| `d` (IOCs) | toggle defanged/raw display |
| `y` / `Y` | copy sanitized / raw (raw asks for confirmation) |
| `?` | help overlay |
| `q`, `Ctrl-C` | quit (cancels analysis first) |

Findings tab: left list (severity, id, title, suppressed marker); right
details: title, detail, severity/confidence/category, ATT&CK ids, evidence
list with a cursor. Evidence targets:
- `Section` → Sections tab, row selected.
- `Import` → Imports tab, row selected.
- `String` → Strings tab at that offset (filters are cleared if they would
  hide it, with a status note).
- `Range` → before Hex exists: an inline text panel with offset, length,
  containing section (from facts) and entropy of the range (computed over at
  most a capped number of bytes). After the Hex step: Hex tab at that offset,
  range highlighted.
- `Metric` / `Field`: shown inline, not jumpable.

Sections: PE sections or ELF sections + segments (sub-toggle). Imports: PE
library → functions, ELF needed libs + imported symbols. IOCs: kind, value,
offset(s); defanged by default. Explain: breakdown rows (finding id, points,
cap applied), total, level, floor, then suppressed findings with reason.

Small window (< 60×16): a centered "window too small (need 60×16)" message;
state is preserved, nothing else drawn.

### Copy (OSC 52)

- `y` sanitized: `single_line` + URLs/IPs defanged (`defang_text`).
- `Y` raw: confirmation prompt with a warning first; payload sent as-is,
  base64-encoded inside OSC 52 (no injection possible).
- Hashes (MD5/SHA-1/SHA-256) are copied as they are by both keys.
- Payload limit: 64 KiB before encoding (my call; many terminals cap around
  74–100 KB). Over the limit: nothing copied, status says so.
- Status line shows what was copied: label + byte count + mode, e.g.
  `copied IOC url (sanitized, 31 B) via OSC 52, if your terminal allows it`.
- Inside tmux the plain sequence is sent (needs `set -g set-clipboard on`);
  inside GNU screen it is wrapped in DCS.

### Strings list performance

`StringsFacts.items` stays untouched; the panel keeps `Vec<u32>` of visible
indices, rebuilt only when the filter/search changes. Rendering formats only
the rows in the viewport. Tests:
- deterministic: a counter proves rendering one frame formats ≤ viewport rows
  with 200 000 items;
- timing (release-sensitive, generous bound in debug): build filter + render
  one frame over 200 000 items; plus a criterion bench.

### Terminal robustness

- `TerminalGuard` enables raw mode + alternate screen and restores in `Drop`.
- Panic hook: restore the terminal, then call the previous hook.
- No TTY (stdin or stdout not a terminal): exit code 2 with a message
  pointing to `-f text|json`.

### Testing

- Unit tests for `update` (navigation, history, search, filters, copy
  commands, cancel) with no terminal.
- Snapshots at 80×24 and 120×40 for each tab, the loading screen, partial
  report, help overlay and the too-small screen; fixtures from
  `rtriage-fixtures` (synthetic only).
- Hostile-text snapshots: findings/strings containing ESC, CSI, OSC, RLO and
  zero-width characters render as visible escapes.
- Property test: random key sequences over a fixture report never panic.

## Left to the builder

- Exact colours and widths (colour is never the only carrier of meaning).
- Spinner style, help overlay layout.
- Whether Sections/Imports share a generic table widget.

## Calls I made (check these)

- Feature `tui` on by default (unlike `yara`).
- New error/limit variants `Cancelled` / `Partial` without a schema bump,
  since the CLI never emits them.
- OSC 52 limit 64 KiB; small-window threshold 60×16; jump history depth 64.
- Mouse support deferred.

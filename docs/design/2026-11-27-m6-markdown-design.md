# M6.1 — Markdown output design

Status: approved approach A + user additions, 2026-11-27. First of the M6
sub-projects (goal of M6: the first public release on GitHub).

## Intent

`-f md` produces a report an analyst pastes into a ticket, issue or wiki
page. The rendered page must show exactly what the text report shows,
without any file-derived text being able to become markup: no links, no
images (a remote image leaks the viewer's IP), no HTML, no @mentions or
#issue references, no broken tables.

## Goals

- `rtriage -f md <FILE>`, multi-file/directory runs (one document) and
  `scan -f md` (table first, then `--full` reports).
- Same content and section order as text output; `--explain`,
  `--min-severity`, `--all-strings` apply.
- IOCs/URLs/IPs always defanged in md; `--no-defang` (md only) shows raw
  values; `--defang` is accepted and changes nothing in md. Documented in
  `--help` and README.
- Document size limit (`--md-limit <N>` characters, default 60 000, `0` =
  unlimited) with a truncation note.
- Exit codes and `--fail-on` unaffected by md rendering or truncation.

## Non-goals

- HTML output, `<details>` collapsibles, colours.
- A new JSON-like schema: md is for humans; JSON stays the machine format.
- Rewriting the text renderer (approach B, rejected below).

## Anti-goals

- Any file-derived character outside a code span.
- A truncated document that cuts a table row or code span in half, or
  loses the Failed/Skipped tail.

## Approaches (decided)

- **A (chosen):** a separate `output/markdown.rs` renderer next to
  `text.rs`, same section order; all escaping in a small `output/md.rs`
  module; shared pieces extracted into `output/common.rs`; document limit
  by a `Budget` writer wrapper.
- B (rejected): an intermediate document model rendered by text and md:
  cleaner long-term, but rewrites `text.rs` right before the release.
- C (rejected): converting text output: cannot guarantee code spans.

## Design

### Escaping (`output/md.rs`)

Every dynamic value (file name in headings, section/import/symbol names,
strings, evidence values, IOC values, YARA rule names/tags/meta, PDB paths,
error messages that quote file data, finding titles/details) goes through
one of:

- `code(value) -> String`: `single_line` (control/bidi/invisible escaped,
  no line breaks) → cut to the value limit (200 chars, then
  ` … [N chars total]` *outside* the span) → wrap in a backtick run one
  longer than the longest run inside → pad with one space on each side
  when the content starts or ends with a backtick or space → an empty
  value renders as the static italic marker `_empty_` (no code span).
- `cell(value) -> String`: `code(value)` with `|` escaped as `\|` (GFM
  splits rows on `|` even inside code spans).
- Static text (headings, labels, column titles) is written raw; it never
  contains file data. Numbers we format ourselves (offsets, sizes, scores)
  are written raw.

Defang: values that can hold IOCs (strings, evidence, IOC list) are passed
through `defang_text` / `value_defanged` before `code`, unless
`--no-defang`.

### Document budget (`Budget` writer)

- Counts **characters** (Unicode scalar values), not bytes.
- Holds back the current line until `\n`, so cuts happen only on line
  boundaries; a table row or code span is never split.
- Reserve: a fixed `TAIL_RESERVE` of 4 000 characters is kept for the tail
  (Failed, Skipped, summary). The body may use `limit − reserve`; the tail
  is written with `finish_body()` → `tail()` and may use what is left
  (including the reserve). If the tail alone exceeds it, it is cut the same
  way with its own note.
- After the cut it keeps counting dropped lines and characters. The note
  goes after a blank line:
  `> **truncated:** 1 234 more lines (56 789 characters) not shown. Use -f json or --md-limit 0 for everything.`
- `--md-limit 0`: no limit, no reserve.

### Layout

Single report:
```
# rtriage report: `sample.exe`
**Risk: HIGH (score 61)** · PE · 7.0 KiB (7168 bytes)
| | |   (hashes table: MD5, SHA-1, SHA-256 as code)
## Findings      (one ### per finding: severity, id in code, title in code;
                  detail, evidence list, ATT&CK)
## Score breakdown (with --explain)
## PE / ELF, Sections, Imports, Exports, Resources, Entropy, YARA, IOCs,
   Strings, Analyzer errors   (tables where text has columns)
```
Several files: `# rtriage report` + one `## `file`` section per file in
input order (worker bodies), `---` between them, then the tail.

`scan -f md`: counts line + table sorted by risk (rank, level, score,
file, top finding, flags), then with `--full` every report, then the tail.
Table rows come from worker summaries.

### scan `--full` and memory (conflict with M4)

M4 keeps only compact rows in memory during `scan` and streams full
reports. Putting the table *first* needs every body before the table is
written. Resolution: bodies are buffered, but only up to the remaining
budget (once the budget is used, further bodies only count lines and
characters for the note). With `--md-limit 0` bodies are buffered in full
(documented: memory grows with the number of files; use `-f json` for huge
batches). Plain `scan -f md` without `--full` keeps the M4 behaviour.

**Known trade-off (future):** with `--md-limit 0`, spill the buffered
bodies to a temporary file instead of memory, so `scan --full -f md` stays
bounded on huge batches. Not done in M6.1.

### Exit codes

`Gate` keeps coming from worker summaries (and from the report itself
in-process). Rendering and truncation never touch it; a test runs
`--fail-on` with a tiny `--md-limit`.

### CLI

- `OutputFormat::Md` (`-f md`), passed to workers as `-f md`.
- `--no-defang`: md only; with another format → usage error (exit 2).
  Passed to workers.
- `--md-limit <N>`: md only; with another format → usage error (exit 2).
  Applied in the parent only (workers render bodies without a limit; the
  value limit of 200 always applies).

### Testing

- Unit: `code`/`cell` (backtick runs, padding, empty, `|`, lengths,
  sanitizing), `Budget` (chars vs bytes, line boundary, reserve, note,
  counts, limit 0).
- Snapshots: single PE, single ELF, `--explain`, multi-file, `scan`,
  `scan --full`, truncated document.
- Injection: hostile fixtures with `@mention`, `#123`, `[x](http://…)`,
  `![x](http://…)`, `<img src=…>`, `<details>`, `|`, backtick runs,
  `\n`, `*`, `_`, `<http://…>`, `javascript:`, HTML entities, in every
  displayed field. The generated md is parsed with pulldown-cmark
  (tables, strikethrough, footnotes and task lists enabled):
  no `Link`, `Image`, `Html`, `InlineHtml`, `FootnoteReference`,
  `TaskListMarker` events; every file-derived marker appears only inside
  `Code` events; table rows keep their column count.
- Truncation: a document cut inside a large table still parses with whole
  rows; note after a blank line; tail present.
- CLI: `--no-defang`/`--md-limit` with `-f text` → exit 2; `--fail-on`
  unaffected by truncation.

## Calls I made (check these)

- `TAIL_RESERVE` = 4 000 characters.
- `--no-defang` / `--md-limit` with a non-md format is a usage error, not a
  silent no-op.
- Empty value shown as the static italic marker `_empty_` (user, 2026-11-27).
- The 200-char value limit also applies with `--md-limit 0`.

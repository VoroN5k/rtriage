//! Markdown safety: every file-derived value becomes one inline code span,
//! and a [`Budget`] writer keeps documents under a character limit.
//!
//! Inside a code span Markdown renders nothing: no links, images, HTML,
//! @mentions or #references, and GitHub does not autolink. Values are
//! sanitized with [`single_line`] first (control, bidi and invisible
//! characters escaped, no line breaks), cut to [`VALUE_LIMIT`] characters,
//! then fenced with a backtick run longer than any inside them.

use std::io::{self, Write};

use rtriage_sanitize::single_line;

use super::common::group_digits;

/// Longest value shown, in characters; the rest is summarized.
pub const VALUE_LIMIT: usize = 200;

/// Longest finding detail shown, in characters: details are our own prose
/// (with file values inside), longer than a single value but still bounded.
pub const DETAIL_LIMIT: usize = 1_000;

/// Default document limit in characters (GitHub's comment/issue body limit
/// is 65 536; this leaves room for what the user adds).
pub const DEFAULT_LIMIT: usize = 60_000;

/// Characters kept back for the tail (Failed, Skipped, summary).
pub const TAIL_RESERVE: usize = 4_000;

/// `value` as one inline code span (or `_empty_`).
pub fn code(value: &str) -> String {
    span(value, false, VALUE_LIMIT)
}

/// [`code`] with its own character limit instead of [`VALUE_LIMIT`].
pub fn code_limited(value: &str, limit: usize) -> String {
    span(value, false, limit)
}

/// `value` as a code span for a table cell: `|` is escaped, because GFM
/// splits rows on it even inside code spans.
pub fn cell(value: &str) -> String {
    span(value, true, VALUE_LIMIT)
}

fn span(value: &str, in_table: bool, limit: usize) -> String {
    let clean = single_line(value);
    if clean.is_empty() {
        return "_empty_".to_owned();
    }
    let total = value.chars().count();
    let shown: String = clean.chars().take(limit).collect();
    let cut = clean.chars().count() > limit;
    let body = if in_table {
        shown.replace('|', "\\|")
    } else {
        shown
    };
    let fence = "`".repeat(longest_backtick_run(&body) + 1);
    // CommonMark strips one space from each side when both are spaces, so a
    // value that starts/ends with a backtick or space gets one pad each side.
    let edge = |c: Option<char>| matches!(c, Some('`' | ' '));
    let all_spaces = body.chars().all(|c| c == ' ');
    let pad = if !all_spaces && (edge(body.chars().next()) || edge(body.chars().last())) {
        " "
    } else {
        ""
    };
    let mut out = format!("{fence}{pad}{body}{pad}{fence}");
    if cut {
        out.push_str(&format!(" … [{total} chars total]"));
    }
    out
}

fn longest_backtick_run(s: &str) -> usize {
    let mut longest = 0;
    let mut run = 0;
    for c in s.chars() {
        if c == '`' {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    longest
}

/// What was left out of one part of the document.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Dropped {
    lines: u64,
    chars: u64,
}

impl Dropped {
    fn any(self) -> bool {
        self.lines > 0
    }
}

/// A writer that passes whole lines through until a character budget is
/// used, then drops everything that follows and says so.
///
/// The body may use `limit - reserve` characters; after [`Budget::begin_tail`]
/// the tail may use what is left, reserve included. Lines are never split, so
/// table rows and code spans stay whole. Characters are Unicode scalar values.
/// The truncation notes themselves are not counted (one line each, at most
/// two), so a document can exceed `limit` by their length.
#[derive(Debug)]
pub struct Budget<W: Write> {
    inner: W,
    limit: Option<usize>,
    reserve: usize,
    used: usize,
    held: Vec<u8>,
    in_tail: bool,
    /// A blank line is owed before the next written line (after a note).
    gap: bool,
    body: Dropped,
    tail: Dropped,
}

impl<W: Write> Budget<W> {
    /// `limit`: `None` writes everything (no reserve either).
    pub fn new(inner: W, limit: Option<usize>, reserve: usize) -> Budget<W> {
        Budget {
            inner,
            limit,
            reserve,
            used: 0,
            held: Vec::new(),
            in_tail: false,
            gap: false,
            body: Dropped::default(),
            tail: Dropped::default(),
        }
    }

    /// `true` once anything was dropped.
    // Only tests ask today; the document itself carries the note.
    #[allow(dead_code)]
    pub fn truncated(&self) -> bool {
        self.body.any() || self.tail.any()
    }

    /// Ends the body (writing its note if it was cut) and starts the tail.
    ///
    /// # Errors
    /// Errors of the inner writer.
    pub fn begin_tail(&mut self) -> io::Result<()> {
        if self.in_tail {
            return Ok(());
        }
        self.flush_held()?;
        let body = self.body;
        self.note(body)?;
        // A tail after the note starts its own block (written with its first line).
        self.gap = body.any();
        self.in_tail = true;
        Ok(())
    }

    /// Writes what is held, the notes, and returns the inner writer.
    ///
    /// # Errors
    /// Errors of the inner writer.
    pub fn finish(mut self) -> io::Result<W> {
        self.begin_tail()?;
        self.flush_held()?;
        let tail = self.tail;
        self.note(tail)?;
        self.inner.flush()?;
        Ok(self.inner)
    }

    fn allowance(&self) -> usize {
        let Some(limit) = self.limit else {
            return usize::MAX;
        };
        let cap = if self.in_tail {
            limit
        } else {
            limit.saturating_sub(self.reserve)
        };
        cap.saturating_sub(self.used)
    }

    fn line(&mut self, bytes: &[u8]) -> io::Result<()> {
        let chars = String::from_utf8_lossy(bytes).chars().count();
        let dropped = if self.in_tail {
            &mut self.tail
        } else {
            &mut self.body
        };
        // Once a part is cut, later (shorter) lines are dropped too, so the
        // document never has holes in the middle.
        if !dropped.any() && chars <= self.allowance() {
            self.used = self.used.saturating_add(chars);
            if std::mem::take(&mut self.gap) {
                self.inner.write_all(
                    b"
",
                )?;
            }
            return self.inner.write_all(bytes);
        }
        let dropped = if self.in_tail {
            &mut self.tail
        } else {
            &mut self.body
        };
        dropped.lines = dropped.lines.saturating_add(1);
        dropped.chars = dropped
            .chars
            .saturating_add(u64::try_from(chars).unwrap_or(u64::MAX));
        Ok(())
    }

    fn flush_held(&mut self) -> io::Result<()> {
        if self.held.is_empty() {
            return Ok(());
        }
        let held = std::mem::take(&mut self.held);
        self.line(&held)
    }

    fn note(&mut self, d: Dropped) -> io::Result<()> {
        if !d.any() {
            return Ok(());
        }
        // The note goes after a blank line, so it never joins a table.
        let text = format!(
            "\n> **truncated:** {} more lines ({} characters) not shown. Use -f json or --md-limit 0 for everything.\n",
            group_digits(d.lines),
            group_digits(d.chars)
        );
        // Notes are not counted: they are small (one line each, at most two
        // per document) and must never push the tail out.
        self.inner.write_all(text.as_bytes())
    }
}

impl<W: Write> Write for Budget<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.limit.is_none() {
            self.inner.write_all(buf)?;
            return Ok(buf.len());
        }
        let mut rest = buf;
        while let Some(pos) = rest.iter().position(|&b| b == b'\n') {
            let (line, after) = rest.split_at(pos + 1);
            if self.held.is_empty() {
                self.line(line)?;
            } else {
                self.held.extend_from_slice(line);
                let held = std::mem::take(&mut self.held);
                self.line(&held)?;
            }
            rest = after;
        }
        self.held.extend_from_slice(rest);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        // Held bytes are a partial line: they wait for its end.
        self.inner.flush()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use pulldown_cmark::{Event, Options, Parser, Tag, TagEnd};

    use super::*;

    /// The inline events of a one-paragraph document.
    fn events(md: &str) -> Vec<Event<'_>> {
        Parser::new_ext(md, Options::ENABLE_TABLES)
            .filter(|e| {
                !matches!(
                    e,
                    Event::Start(Tag::Paragraph) | Event::End(TagEnd::Paragraph)
                )
            })
            .collect()
    }

    /// `code(v)` renders as exactly one code span holding the sanitized value.
    fn assert_single_span(v: &str) {
        let md = code(v);
        let ev = events(&md);
        assert_eq!(ev.len(), 1, "{v:?} -> {md:?} -> {ev:?}");
        let Event::Code(text) = &ev[0] else {
            panic!("{v:?} -> {md:?} -> {ev:?}");
        };
        assert_eq!(text.as_ref(), single_line(v).as_ref(), "{md:?}");
    }

    #[test]
    fn code_picks_a_longer_backtick_run() {
        assert_eq!(code("a`b"), "``a`b``");
        assert_eq!(code("a``b```c"), "````a``b```c````");
        for v in ["a`b", "a``b```c", "plain", "x\\y"] {
            assert_single_span(v);
        }
    }

    #[test]
    fn code_pads_leading_trailing_backtick_and_space() {
        assert_eq!(code("`x"), "`` `x ``");
        assert_eq!(code("x`"), "`` x` ``");
        assert_eq!(code(" x "), "`  x  `");
        for v in ["`x", "x`", " x ", " x", "x "] {
            assert_single_span(v);
        }
    }

    #[test]
    fn only_backticks_and_only_spaces() {
        assert_single_span("`");
        assert_single_span("```");
        assert_single_span(" ");
        assert_single_span("   ");
    }

    #[test]
    fn empty_value_is_italic_empty() {
        assert_eq!(code(""), "_empty_");
        assert_eq!(cell(""), "_empty_");
        let ev = events("_empty_");
        assert!(matches!(ev[0], Event::Start(Tag::Emphasis)), "{ev:?}");
    }

    #[test]
    fn code_sanitizes_and_never_breaks_lines() {
        let v = "a\nb\r\x1b[2J\u{202e}\u{200b}c";
        let md = code(v);
        assert!(!md.contains(['\n', '\r', '\x1b', '\u{202e}', '\u{200b}']));
        assert_single_span(v);
    }

    #[test]
    fn markup_inside_values_stays_text() {
        for v in [
            "[x](http://e.ru/)",
            "![x](http://e.ru/p.png)",
            "<img src=x>",
            "<details>",
            "@octocat #123",
            "<http://e.ru>",
            "*b* _i_ **s**",
            "&lt;&amp;",
        ] {
            assert_single_span(v);
        }
    }

    #[test]
    fn long_value_cut_at_200_chars_with_total() {
        let v = "ж".repeat(250);
        let md = code(&v);
        assert!(md.ends_with(" … [250 chars total]"), "{md}");
        let inside = md.split('`').nth(1).unwrap();
        assert_eq!(inside.chars().count(), VALUE_LIMIT);
        assert_eq!(code(&"a".repeat(200)), format!("`{}`", "a".repeat(200)));
    }

    #[test]
    fn cell_escapes_pipes() {
        assert_eq!(cell("a|b"), "`a\\|b`");
        let row = format!("| h1 | h2 |\n|---|---|\n| {} | x |\n", cell("a|b|c"));
        let cells = Parser::new_ext(&row, Options::ENABLE_TABLES)
            .filter(|e| matches!(e, Event::Start(Tag::TableCell)))
            .count();
        assert_eq!(cells, 4, "two header cells, two body cells: {row}");
        let codes: Vec<String> = Parser::new_ext(&row, Options::ENABLE_TABLES)
            .filter_map(|e| match e {
                Event::Code(c) => Some(c.into_string()),
                _ => None,
            })
            .collect();
        assert_eq!(codes, ["a|b|c"]);
    }

    fn run(limit: Option<usize>, reserve: usize, body: &str, tail: &str) -> String {
        let mut b = Budget::new(Vec::new(), limit, reserve);
        b.write_all(body.as_bytes()).unwrap();
        b.begin_tail().unwrap();
        b.write_all(tail.as_bytes()).unwrap();
        String::from_utf8(b.finish().unwrap()).unwrap()
    }

    #[test]
    fn limit_none_writes_everything() {
        assert_eq!(run(None, 10, "a\nb", "c\n"), "a\nbc\n");
    }

    #[test]
    fn budget_counts_chars_not_bytes() {
        // 5 lines of 4 Cyrillic chars + \n = 25 chars, 45 bytes.
        let body = "жжжж\n".repeat(5);
        assert_eq!(run(Some(25), 0, &body, ""), body);
        let cut = run(Some(24), 0, &body, "");
        assert!(cut.starts_with(&"жжжж\n".repeat(4)), "{cut}");
        assert!(cut.contains("1 more lines (5 characters)"), "{cut}");
    }

    #[test]
    fn budget_multibyte_emoji_and_combining_marks() {
        // 👍🏽 = 2 scalars, 👨‍👩‍👧 = 5 scalars, é (e + U+0301) = 2 scalars.
        let line = "👍🏽👨‍👩‍👧e\u{301}\n";
        assert_eq!(line.chars().count(), 10);
        let body = line.repeat(3);
        assert_eq!(run(Some(30), 0, &body, ""), body);
        let cut = run(Some(29), 0, &body, "");
        assert!(cut.starts_with(&line.repeat(2)));
        assert!(cut.contains("1 more lines (10 characters)"), "{cut}");
        // Whole lines only: no half of a ZWJ sequence or combining pair.
        let kept = cut.split("\n\n>").next().unwrap();
        assert_eq!(
            format!(
                "{kept}
"
            ),
            line.repeat(2)
        );
    }

    #[test]
    fn budget_cuts_on_line_boundaries_only() {
        let table = format!("| a | b |\n|---|---|\n{}", "| 1 | 2 |\n".repeat(50));
        let out = run(Some(120), 0, &table, "");
        let kept = out.split("\n\n> **truncated").next().unwrap();
        assert!(
            kept.lines().all(|l| l.starts_with('|') && l.ends_with('|')),
            "{out}"
        );
        let rows = Parser::new_ext(&out, Options::ENABLE_TABLES)
            .filter(|e| matches!(e, Event::Start(Tag::TableRow)))
            .count();
        assert_eq!(
            rows,
            kept.lines().count() - 2,
            "every kept row parses as a row"
        );
    }

    #[test]
    fn budget_note_after_blank_line_with_counts() {
        let out = run(Some(4), 0, "aaa\nbbb\nccc\n", "");
        assert_eq!(
            out,
            "aaa\n\n> **truncated:** 2 more lines (8 characters) not shown. Use -f json or --md-limit 0 for everything.\n"
        );
        let quote = Parser::new(&out).any(|e| matches!(e, Event::Start(Tag::BlockQuote(_))));
        assert!(quote, "the note is its own block quote");
    }

    #[test]
    fn note_groups_digits_and_leaves_a_blank_line_before_the_tail() {
        let body = "x
"
        .repeat(1_500);
        let out = run(
            Some(20),
            15,
            &body,
            "## Failed
",
        );
        assert!(out.contains("1 498 more lines (2 996 characters)"), "{out}");
        assert!(
            out.contains(
                "for everything.

## Failed
"
            ),
            "{out}"
        );
    }

    #[test]
    fn budget_reserve_keeps_room_for_the_tail() {
        let body = "x\n".repeat(100);
        let out = run(Some(50), 20, &body, "## Failed\n- `a`\n");
        assert!(out.starts_with(&"x\n".repeat(15)), "{out}");
        assert!(!out.starts_with(&"x\n".repeat(16)), "{out}");
        assert!(out.ends_with("## Failed\n- `a`\n"), "{out}");
        assert!(out.contains("85 more lines"), "{out}");
    }

    #[test]
    fn tail_larger_than_reserve_gets_its_own_note() {
        let tail = "- `f`\n".repeat(20);
        let out = run(Some(30), 10, "a\n", &tail);
        let notes = out.matches("> **truncated:**").count();
        assert_eq!(notes, 1, "only the tail was cut: {out}");
        assert!(out.starts_with("a\n- `f`\n"), "{out}");
    }

    #[test]
    fn single_line_longer_than_budget() {
        let out = run(Some(10), 0, &format!("{}\nshort\n", "y".repeat(50)), "");
        assert!(out.starts_with("\n> **truncated:** 2 more lines"), "{out}");
    }

    #[test]
    fn limit_smaller_than_reserve() {
        let out = run(Some(5), 4_000, "body\n", "tail\n");
        assert!(
            out.contains("1 more lines (5 characters)"),
            "body dropped: {out}"
        );
        assert!(!out.contains("body"));
    }

    #[test]
    fn a_partial_last_line_is_kept_or_dropped_whole() {
        assert_eq!(run(Some(100), 0, "a\nno newline", ""), "a\nno newline");
        let out = run(Some(3), 0, "a\nno newline", "");
        assert!(
            out.starts_with("a\n\n> **truncated:** 1 more lines"),
            "{out}"
        );
    }
}

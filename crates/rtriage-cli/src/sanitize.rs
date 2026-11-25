//! Escaping of attacker-controlled text before it reaches a terminal.
//!
//! Strings from input files (and file names themselves) may contain ANSI
//! escape sequences, carriage returns or Unicode bidi overrides that rewrite
//! what the analyst sees. Every such character is replaced with a visible
//! escape. Backslashes are left alone so Windows paths stay readable.

use std::borrow::Cow;
use std::fmt::Write;

/// Returns `s` with control, bidi and invisible characters escaped.
/// Borrows when nothing needs escaping.
pub fn sanitize(s: &str) -> Cow<'_, str> {
    if !s.chars().any(needs_escape) {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if needs_escape(c) => {
                let cp = u32::from(c);
                // Writing to a String cannot fail.
                let _ = if cp < 0x100 {
                    write!(out, "\\x{cp:02x}")
                } else {
                    write!(out, "\\u{{{cp:04x}}}")
                };
            }
            c => out.push(c),
        }
    }
    Cow::Owned(out)
}

/// Control characters (C0, DEL, C1), bidi controls and invisible separators.
fn needs_escape(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061c}'                    // Arabic letter mark
            | '\u{200b}'..='\u{200f}'     // zero-width space/joiners, LRM, RLM
            | '\u{2028}' | '\u{2029}'     // line/paragraph separator
            | '\u{202a}'..='\u{202e}'     // LRE, RLE, PDF, LRO, RLO
            | '\u{2066}'..='\u{2069}'     // LRI, RLI, FSI, PDI
            | '\u{feff}' // BOM / zero-width no-break space
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_is_borrowed() {
        assert!(matches!(
            sanitize(r"C:\Windows\notepad.exe"),
            Cow::Borrowed(_)
        ));
    }

    #[test]
    fn ansi_escape_is_neutralised() {
        assert_eq!(sanitize("\x1b[2J\x1b[31mred"), "\\x1b[2J\\x1b[31mred");
    }

    #[test]
    fn whitespace_controls_are_visible() {
        assert_eq!(sanitize("a\tb\r\nc"), "a\\tb\\r\\nc");
    }

    #[test]
    fn bidi_override_is_escaped() {
        // "invoice\u{202e}fdp.exe" renders as "invoiceexe.pdf".
        assert_eq!(
            sanitize("invoice\u{202e}fdp.exe"),
            "invoice\\u{202e}fdp.exe"
        );
    }

    #[test]
    fn c1_and_del_are_escaped() {
        assert_eq!(sanitize("\u{9b}31m\u{7f}"), "\\x9b31m\\x7f");
    }

    #[test]
    fn non_ascii_letters_are_kept() {
        assert_eq!(sanitize("Привіт"), "Привіт");
    }
}

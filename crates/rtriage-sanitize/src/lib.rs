//! Escaping of attacker-controlled text before it reaches a terminal.
//!
//! Strings from input files (and file names themselves) may contain ANSI
//! escape sequences, carriage returns or Unicode bidi overrides that rewrite
//! what the analyst sees. Every such character is replaced with a visible
//! escape. Backslashes are left alone so Windows paths stay readable.

#![forbid(unsafe_code)]

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

/// Like [`sanitize`], for places that must stay on one line (table cells,
/// status lines, clipboard payloads). The output never contains a line
/// break of any kind: `\n`, `\r`, VT, FF, NEL, U+2028 and U+2029 all become
/// visible escapes. Today this is exactly [`sanitize`]; the separate name
/// pins the guarantee so a future relaxation of `sanitize` cannot break it.
pub fn single_line(s: &str) -> Cow<'_, str> {
    sanitize(s)
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

    const BIDI: [char; 12] = [
        '\u{061c}', '\u{200e}', '\u{200f}', '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}',
        '\u{202e}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
    ];

    #[test]
    fn rlo_and_all_bidi_controls_escape() {
        for c in BIDI {
            let s = format!("a{c}b");
            let out = sanitize(&s);
            assert!(!out.contains(c), "{:04x}", u32::from(c));
            assert_eq!(out, format!("a\\u{{{:04x}}}b", u32::from(c)));
        }
        assert_eq!(sanitize("evil\u{202e}fdp.exe"), "evil\\u{202e}fdp.exe");
    }

    #[test]
    fn zero_width_escape() {
        for c in ['\u{200b}', '\u{200c}', '\u{200d}', '\u{feff}'] {
            let s = format!("x{c}y");
            assert_eq!(sanitize(&s), format!("x\\u{{{:04x}}}y", u32::from(c)));
        }
    }

    #[test]
    fn every_c0_and_c1_control_escapes() {
        for cp in (0u32..0x20).chain(0x7f..=0x9f) {
            let Some(c) = char::from_u32(cp) else {
                unreachable!()
            };
            let out = sanitize(&c.to_string()).into_owned();
            assert!(out.starts_with('\\'), "{cp:#x} -> {out:?}");
            assert!(!out.chars().any(char::is_control), "{cp:#x}");
        }
        // 8-bit CSI must not survive as a raw code point.
        assert_eq!(sanitize("\u{9b}2J"), "\\x9b2J");
    }

    #[test]
    fn osc_and_csi_sequences_lose_their_esc() {
        assert_eq!(sanitize("\x1b]52;c;aGk=\x07"), "\\x1b]52;c;aGk=\\x07");
        assert_eq!(sanitize("\x1b]0;title\x1b\\"), "\\x1b]0;title\\x1b\\");
        assert_eq!(sanitize("\x1b[2J"), "\\x1b[2J");
    }

    #[test]
    fn single_line_never_breaks() {
        for s in [
            "a\nb",
            "a\r\nb",
            "a\u{2028}b",
            "a\u{2029}b",
            "a\u{85}b",
            "a\x0bb",
            "a\x0cb",
        ] {
            let out = single_line(s);
            assert!(
                !out.contains(['\n', '\r', '\u{2028}', '\u{2029}', '\u{85}', '\x0b', '\x0c']),
                "{s:?} -> {out:?}"
            );
        }
    }

    #[test]
    fn single_line_matches_sanitize() {
        let s = "x\x1b[31m\u{202e}\u{200b}\ny";
        assert_eq!(single_line(s), sanitize(s));
    }

    #[test]
    fn clean_input_borrows() {
        assert!(matches!(single_line(r"C:\x\y"), Cow::Borrowed(_)));
    }
}

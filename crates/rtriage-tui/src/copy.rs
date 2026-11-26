//! Clipboard copy through the terminal (OSC 52): no clipboard library, works
//! over SSH. The payload travels base64-encoded, so its bytes can never be
//! interpreted by the terminal as control sequences.
//!
//! Inside tmux the plain sequence is sent; tmux forwards it when
//! `set -g set-clipboard on` (with `external` it ignores applications).
//! GNU screen needs the DCS wrapper, in chunks.

use std::borrow::Cow;

use rtriage_core::analyzers::iocs::defang_text;
use rtriage_core::Evidence;
use rtriage_sanitize::single_line;

use crate::app::{App, Focus, Tab};
use crate::model;
use crate::rows::{self, IocRow};
use crate::view::snake;

/// Largest payload copied, in bytes before encoding (many terminals cap
/// OSC 52 at roughly 74–100 KB of encoded data).
pub const OSC52_LIMIT: usize = 64 * 1024;

/// Base64 characters per DCS chunk for GNU screen (it limits string length).
const SCREEN_CHUNK: usize = 76;

/// Terminal multiplexer between us and the terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mux {
    /// None, or tmux (which handles plain OSC 52 itself).
    None,
    /// GNU screen: needs the DCS passthrough wrapper.
    Screen,
}

/// Why nothing was copied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyError {
    /// The payload exceeds [`OSC52_LIMIT`].
    TooLarge {
        /// Payload size in bytes.
        len: usize,
    },
}

/// The safe-to-paste form of `text`: one line, control and invisible
/// characters escaped, URLs/domains/IPs/emails defanged.
pub fn sanitized(text: &str) -> String {
    match single_line(text) {
        Cow::Borrowed(s) => defang_text(s).into_owned(),
        Cow::Owned(s) => defang_text(&s).into_owned(),
    }
}

/// Standard base64 (RFC 4648, with padding).
pub fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let sym = |v: u32| {
        let i = usize::try_from(v & 63).unwrap_or(0);
        ALPHABET.get(i).map_or('=', |b| char::from(*b))
    };
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = |i: usize| u32::from(chunk.get(i).copied().unwrap_or(0));
        let n = (b(0) << 16) | (b(1) << 8) | b(2);
        out.push(sym(n >> 18));
        out.push(sym(n >> 12));
        out.push(if chunk.len() > 1 { sym(n >> 6) } else { '=' });
        out.push(if chunk.len() > 2 { sym(n) } else { '=' });
    }
    out
}

/// The escape sequence that puts `payload` on the clipboard.
///
/// # Errors
/// [`CopyError::TooLarge`] above [`OSC52_LIMIT`].
pub fn osc52(payload: &str, mux: Mux) -> Result<String, CopyError> {
    if payload.len() > OSC52_LIMIT {
        return Err(CopyError::TooLarge { len: payload.len() });
    }
    let encoded = base64(payload.as_bytes());
    Ok(match mux {
        Mux::None => format!("\x1b]52;c;{encoded}\x07"),
        Mux::Screen => {
            let chunks: Vec<&str> = encoded
                .as_bytes()
                .chunks(SCREEN_CHUNK)
                .filter_map(|c| std::str::from_utf8(c).ok())
                .collect();
            format!("\x1bP\x1b]52;c;{}\x07\x1b\\", chunks.join("\x1b\\\x1bP"))
        }
    })
}

/// What `y` / `Y` would copy in the current pane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Copyable {
    /// What it is, for the status line (no file-derived text).
    pub label: String,
    /// The value exactly as found (raw attacker data, `Y` only).
    pub raw: String,
    /// The safe-to-paste form (`y`).
    pub safe: String,
    /// Our own output (hashes): copied as is, no confirmation needed.
    pub verbatim: bool,
}

impl Copyable {
    fn of(label: &str, raw: String) -> Copyable {
        Copyable {
            label: label.to_owned(),
            safe: sanitized(&raw),
            raw,
            verbatim: false,
        }
    }
}

/// The value under the cursor of the current pane, if it has one.
pub fn target(app: &App) -> Option<Copyable> {
    let report = app.report()?;
    let p = &app.panes;
    match app.tab {
        Tab::Findings => {
            let f = report.findings.get(p.findings.selected()?)?;
            if p.focus == Focus::Evidence {
                let e = f.evidence.get(p.evidence.selected()?)?;
                Some(Copyable::of("evidence", evidence_value(e)))
            } else {
                Some(Copyable::of("finding", format!("{}: {}", f.id, f.title)))
            }
        }
        Tab::Sections => {
            let row = p.list(Tab::Sections)?.selected()?;
            let name = if p.show_segments {
                let s = report.facts.elf.as_ref()?.segments.as_ref()?.get(row)?;
                s.kind.clone()
            } else if let Some(s) = report.facts.pe.as_ref().and_then(|x| x.sections.as_ref()) {
                s.get(row)?.name.clone()
            } else {
                let s = report.facts.elf.as_ref()?.sections.as_ref()?.get(row)?;
                s.name.clone()
            };
            Some(Copyable::of("section", name))
        }
        Tab::Imports => {
            let rows = model::import_rows(report);
            let r = rows.get(p.imports.selected()?)?;
            let text = match r.library {
                Some(lib) => format!("{lib}!{}", r.symbol),
                None => r.symbol.to_string(),
            };
            Some(Copyable::of("import", text))
        }
        Tab::Strings => {
            let item = usize::try_from(*p.string_rows.get(p.strings.selected()?)?).ok()?;
            let s = report.facts.strings.as_ref()?.items.get(item)?;
            Some(Copyable::of("string", s.value.clone()))
        }
        Tab::Iocs => Some(match rows::ioc_row(report, p.iocs.selected()?)? {
            IocRow::Hash(alg, hex) => Copyable {
                label: format!("{alg} hash"),
                raw: hex.to_owned(),
                safe: hex.to_owned(),
                verbatim: true,
            },
            IocRow::Ioc(i) => Copyable {
                label: format!("{} IOC", snake(&i.kind)),
                raw: i.value.clone(),
                safe: single_line(&i.value_defanged).into_owned(),
                verbatim: false,
            },
        }),
        Tab::Explain | Tab::Hex => None,
    }
}

/// The value of an evidence item (raw).
fn evidence_value(e: &Evidence) -> String {
    match e {
        Evidence::Range { offset, len } => format!("0x{offset:x}+{len}"),
        Evidence::Section { name, .. } => name.clone(),
        Evidence::Import { library, symbol } => match library {
            Some(lib) => format!("{lib}!{symbol}"),
            None => symbol.clone(),
        },
        Evidence::String { value, .. } | Evidence::Field { value, .. } => value.clone(),
        Evidence::Metric { name, value } => format!("{name} = {value:.3}"),
        _ => String::new(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn base64_rfc4648_vectors() {
        for (plain, enc) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(plain.as_bytes()), enc, "{plain}");
        }
        assert_eq!(base64(&[0xff, 0xfe, 0xfd]), "//79");
    }

    #[test]
    fn osc52_encodes_base64_and_terminates() {
        assert_eq!(osc52("hi", Mux::None).unwrap(), "\x1b]52;c;aGk=\x07");
    }

    #[test]
    fn osc52_payload_with_escapes_cannot_break_out() {
        let seq = osc52("\x1b]0;pwned\x07\x1b[2J\u{9b}31m", Mux::None).unwrap();
        assert_eq!(seq.matches('\x1b').count(), 1, "only the introducer");
        assert_eq!(seq.matches('\x07').count(), 1, "only the terminator");
        assert!(!seq.contains('\u{9b}'));
        let body = seq
            .strip_prefix("\x1b]52;c;")
            .unwrap()
            .strip_suffix('\x07')
            .unwrap();
        assert!(body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b)));
    }

    #[test]
    fn osc52_screen_wrapper() {
        let seq = osc52("hi", Mux::Screen).unwrap();
        assert_eq!(seq, "\x1bP\x1b]52;c;aGk=\x07\x1b\\");
        // Long payloads are split into several DCS strings.
        let long = osc52(&"x".repeat(300), Mux::Screen).unwrap();
        assert!(long.starts_with("\x1bP\x1b]52;c;"));
        assert!(long.ends_with("\x07\x1b\\"));
        assert_eq!(
            long.matches("\x1bP").count(),
            400usize.div_ceil(SCREEN_CHUNK)
        );
    }

    #[test]
    fn osc52_over_limit_is_refused() {
        assert!(osc52(&"a".repeat(OSC52_LIMIT), Mux::None).is_ok());
        assert_eq!(
            osc52(&"a".repeat(OSC52_LIMIT + 1), Mux::None),
            Err(CopyError::TooLarge {
                len: OSC52_LIMIT + 1
            })
        );
    }

    #[test]
    fn sanitized_is_one_line_escaped_and_defanged() {
        assert_eq!(sanitized("http://evil.ru/a\nb"), r"hxxp://evil[.]ru/a\nb");
        assert_eq!(sanitized("x\x1b[2J\u{202e}y"), r"x\x1b[2J\u{202e}y");
        assert_eq!(sanitized("plain"), "plain");
    }
}

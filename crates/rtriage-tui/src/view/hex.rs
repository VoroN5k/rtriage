//! Hex tab: a read-only dump of the visible rows only.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;
use rtriage_sanitize::single_line;

use super::human_size;
use crate::app::App;
use crate::hex::{ascii, ROW_BYTES};

#[cfg(test)]
thread_local! {
    /// Bytes of the file read by the last frames, to prove the view reads
    /// only what it shows.
    pub(crate) static BYTES_READ: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

pub(super) fn draw(app: &App, frame: &mut Frame<'_>, area: Rect) {
    let h = &app.panes.hex;
    let size = app.input.size();
    let mut title = format!(" Hex · {} · cursor 0x{:08x}", human_size(size), h.cursor);
    if let Some((start, end)) = h.highlight {
        title.push_str(&format!(
            " · range 0x{start:08x}..0x{end:08x} ({} bytes)",
            end.saturating_sub(start)
        ));
    }
    title.push_str(" · g go to ");
    let block = Block::new().borders(Borders::ALL).title(title);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if size == 0 {
        frame.render_widget(Paragraph::new("Empty file."), inner);
        return;
    }
    let info = h.info.as_ref().map(info_line);
    let info_h = u16::from(info.is_some());
    let [head, body] =
        Layout::vertical([Constraint::Length(info_h), Constraint::Min(1)]).areas(inner);
    if let Some(line) = info {
        frame.render_widget(line, head);
    }
    let rows = u64::from(body.height);
    let top = top_for(h.top, h.cursor, rows);
    let lines: Vec<Line<'_>> = (0..rows)
        .map_while(|r| {
            let offset = top.checked_add(r.checked_mul(ROW_BYTES)?)?;
            (offset < size).then(|| row(app, offset))
        })
        .collect();
    frame.render_widget(Paragraph::new(lines), body);
}

/// The stored top, corrected so the cursor is visible in `rows` rows
/// (the real height may differ from the one `update` assumed).
fn top_for(top: u64, cursor: u64, rows: u64) -> u64 {
    let mut state = crate::hex::HexState {
        cursor,
        top,
        ..crate::hex::HexState::default()
    };
    state.follow(rows);
    state.top
}

fn info_line(r: &crate::jump::RangeInfo) -> Line<'static> {
    let section = r.section.as_deref().map_or_else(
        || "outside any section".to_owned(),
        |s| format!("in \"{}\"", single_line(s)),
    );
    let entropy = r
        .entropy
        .map_or_else(|| "entropy n/a".to_owned(), |e| format!("entropy {e:.2}"));
    let past = if r.past_eof > 0 {
        format!(" · {} bytes past end of file", r.past_eof)
    } else {
        String::new()
    };
    Line::styled(
        format!("highlighted: {section} · {entropy}{past} · Backspace back"),
        Style::new().add_modifier(Modifier::DIM),
    )
}

/// One row starting at `offset` (inside the file).
fn row(app: &App, offset: u64) -> Line<'static> {
    let h = &app.panes.hex;
    let start = usize::try_from(offset).unwrap_or(usize::MAX);
    let end = start.saturating_add(16);
    let data = &app.input.data;
    let bytes = data.get(start..end.min(data.len())).unwrap_or_default();
    #[cfg(test)]
    BYTES_READ.with(|c| c.set(c.get() + bytes.len()));

    let mut spans = vec![Span::raw(format!("{offset:08x}  "))];
    let mut text = String::with_capacity(16);
    for i in 0..16u64 {
        let at = offset.saturating_add(i);
        let cell = bytes.get(usize::try_from(i).unwrap_or(usize::MAX));
        let hex = cell.map_or_else(|| "  ".to_owned(), |b| format!("{b:02x}"));
        spans.push(Span::styled(hex, byte_style(h, at, cell.is_some())));
        // An extra space between the two halves of the row.
        spans.push(Span::raw(if i == 7 { "  " } else { " " }));
        if let Some(b) = cell {
            text.push(ascii(*b));
        }
    }
    spans.push(Span::raw(format!("|{text}|")));
    Line::from(spans)
}

/// Cursor: reversed. Highlighted range: bold + underlined (no colour needed).
fn byte_style(h: &crate::hex::HexState, at: u64, present: bool) -> Style {
    if !present {
        Style::new()
    } else if at == h.cursor {
        Style::new().add_modifier(Modifier::REVERSED)
    } else if h.is_highlighted(at) {
        Style::new().add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
    } else {
        Style::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::sync::Arc;

    use ratatui::crossterm::event::KeyCode;
    use rtriage_core::Input;

    use super::*;
    use crate::app::App;
    use crate::msg::Msg;
    use crate::testkit::{analyze, key, ready_app, render, suspicious_pe};
    use crate::update::update;

    fn hex_app(size: (u16, u16)) -> App {
        let mut a = ready_app("s.exe", suspicious_pe(), size);
        update(&mut a, key(KeyCode::Char('7')));
        a
    }

    #[test]
    fn hex_80x24() {
        insta::assert_snapshot!(render(&hex_app((80, 24))));
    }

    #[test]
    fn hex_120x40() {
        insta::assert_snapshot!(render(&hex_app((120, 40))));
    }

    #[test]
    fn range_jump_120x40() {
        let mut a = ready_app("s.exe", suspicious_pe(), (120, 40));
        let row = a
            .report()
            .unwrap()
            .findings
            .iter()
            .position(|f| f.id == "PE-OVERLAY-HIGH-ENTROPY")
            .unwrap();
        for _ in 0..row {
            update(&mut a, key(KeyCode::Down));
        }
        update(&mut a, key(KeyCode::Enter));
        update(&mut a, key(KeyCode::Enter));
        let screen = render(&a);
        assert!(
            screen.contains("range 0x00000c00..0x00001c00 (4096 bytes)"),
            "{screen}"
        );
        assert!(
            screen.contains("highlighted: outside any section · entropy 7.95"),
            "{screen}"
        );
        insta::assert_snapshot!(screen);
    }

    #[test]
    fn goto_prompt_is_shown() {
        let mut a = hex_app((80, 24));
        update(&mut a, key(KeyCode::Char('g')));
        update(&mut a, key(KeyCode::Char('0')));
        update(&mut a, key(KeyCode::Char('\x1b')));
        let screen = render(&a);
        assert!(screen.contains(r"go to offset: 0\x1b▏"), "{screen}");
    }

    #[test]
    fn ascii_column_hides_control_bytes() {
        let data: Vec<u8> = (0..=255u8).collect();
        let mut a = ready_app("all.bin", data, (80, 24));
        update(&mut a, key(KeyCode::Char('7')));
        let screen = render(&a);
        assert!(screen.contains("|................|"), "{screen}");
        assert!(screen.contains(r"| !"), "{screen}");
        assert!(!screen.chars().any(|c| c.is_control() && c != '\n'));
    }

    #[test]
    fn empty_file_hex_is_safe() {
        let mut a = ready_app("empty.bin", Vec::new(), (80, 24));
        update(&mut a, key(KeyCode::Char('7')));
        for k in [
            KeyCode::Down,
            KeyCode::End,
            KeyCode::PageDown,
            KeyCode::Right,
        ] {
            assert!(update(&mut a, key(k)).is_empty());
        }
        assert!(render(&a).contains("Empty file."));
    }

    #[test]
    fn render_reads_only_viewport() {
        let input = Input::from_bytes("big.bin", vec![0x41; 64 << 20]);
        let report = analyze_light(&input);
        let mut a = App::new(Arc::new(input), (80, 24));
        update(&mut a, Msg::AnalysisDone(Box::new(report)));
        update(&mut a, key(KeyCode::Char('7')));
        update(&mut a, key(KeyCode::End));
        BYTES_READ.with(|c| c.set(0));
        let screen = render(&a);
        let read = BYTES_READ.with(std::cell::Cell::get);
        assert!(read > 0 && read <= 24 * 16, "{read} bytes read");
        assert!(screen.contains("03fffff0"), "{screen}");
    }

    /// A report without running every analyzer over 64 MiB in a unit test.
    fn analyze_light(input: &Input) -> rtriage_core::Report {
        let small = Input::from_bytes("big.bin", b"AAAA".to_vec());
        let mut r = analyze(&small);
        r.file.size = input.size();
        r
    }
}

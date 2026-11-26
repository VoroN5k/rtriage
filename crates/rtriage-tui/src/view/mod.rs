//! Drawing. Reads [`App`], never changes it. Every string that comes from
//! the analysed file goes through [`rtriage_sanitize::single_line`].

mod explain;
mod findings;
mod help;
mod imports;
mod iocs;
mod loading;
mod sections;
mod strings;
mod table;

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Tabs, Wrap};
use ratatui::Frame;
use rtriage_core::{Format, Report, RiskLevel};
use rtriage_sanitize::single_line;

use crate::app::{is_partial, App, Phase, Tab, MIN_SIZE};

/// Draws the whole screen for `app`.
pub fn view(app: &App, frame: &mut Frame<'_>) {
    let area = frame.area();
    if app.too_small() {
        too_small(app, frame, area);
        return;
    }
    match &app.phase {
        Phase::Loading { cancel_sent } => loading::draw(app, *cancel_sent, frame, area),
        Phase::Failed => failed(frame, area),
        Phase::Ready(report) => ready(app, report, frame, area),
    }
    if let Some(d) = &app.filter_dialog {
        strings::dialog(d, frame, area);
    }
    if app.help {
        help::draw(frame, area);
    }
}

/// Risk label for the status line. A partial (cancelled) report never
/// claims `clean-looking`: missing analyzers could have found anything.
pub fn risk_badge(report: &Report) -> String {
    let level = level_name(report.risk.level);
    match (is_partial(report), report.risk.level) {
        (true, RiskLevel::CleanLooking) => {
            format!("INCOMPLETE (score so far {})", report.risk.score)
        }
        (true, _) => format!("{level} (incomplete)"),
        (false, _) => format!("{level} (score {})", report.risk.score),
    }
}

fn level_name(level: RiskLevel) -> &'static str {
    match level {
        RiskLevel::High => "HIGH",
        RiskLevel::Medium => "MEDIUM",
        RiskLevel::Low => "LOW",
        RiskLevel::CleanLooking => "CLEAN-LOOKING",
    }
}

fn risk_style(report: &Report) -> Style {
    let color = if is_partial(report) {
        Color::Yellow
    } else {
        match report.risk.level {
            RiskLevel::High => Color::Red,
            RiskLevel::Medium => Color::LightRed,
            RiskLevel::Low => Color::Yellow,
            RiskLevel::CleanLooking => Color::Green,
        }
    };
    Style::new().fg(color).add_modifier(Modifier::BOLD)
}

/// Display name of a format.
pub(crate) fn format_name(format: Format) -> &'static str {
    match format {
        Format::Pe => "PE",
        Format::Elf => "ELF",
        _ => "unknown format",
    }
}

/// `1.5 KiB (1536 bytes)`-style size.
pub(crate) fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["KiB", "MiB", "GiB", "TiB"];
    if bytes < 1024 {
        return format!("{bytes} bytes");
    }
    // Precision loss is irrelevant for a one-decimal display value.
    #[allow(clippy::cast_precision_loss)]
    let mut value = bytes as f64 / 1024.0;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    let name = UNITS.get(unit).copied().unwrap_or("KiB");
    format!("{value:.1} {name} ({bytes} bytes)")
}

/// The file name as given, made safe for display.
pub(crate) fn file_name(app: &App) -> String {
    single_line(&app.input.path.to_string_lossy()).into_owned()
}

/// A `width`×`height` rectangle centred in `area`, clamped to it.
pub(crate) fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let w = width.min(area.width);
    let h = height.min(area.height);
    Rect {
        x: area.x.saturating_add(area.width.saturating_sub(w) / 2),
        y: area.y.saturating_add(area.height.saturating_sub(h) / 2),
        width: w,
        height: h,
    }
}

fn too_small(app: &App, frame: &mut Frame<'_>, area: Rect) {
    let text = vec![
        Line::from(format!(
            "window too small (need {}×{}, have {}×{})",
            MIN_SIZE.0, MIN_SIZE.1, app.size.0, app.size.1
        )),
        Line::from("enlarge the terminal, or press q to quit"),
    ];
    let rect = centered(area, area.width, 2);
    frame.render_widget(Paragraph::new(text).wrap(Wrap { trim: true }), rect);
}

fn failed(frame: &mut Frame<'_>, area: Rect) {
    let text = vec![
        Line::from(Span::styled(
            "The analysis stopped unexpectedly (internal error).",
            Style::new().add_modifier(Modifier::BOLD),
        )),
        Line::from("No report is available. Run `rtriage <FILE>` for details."),
        Line::from(""),
        Line::from("q quit"),
    ];
    let block = Block::new().borders(Borders::ALL).title(" rtriage ");
    let rect = centered(area, 64, 6);
    frame.render_widget(
        Paragraph::new(text).block(block).wrap(Wrap { trim: true }),
        rect,
    );
}

fn ready(app: &App, report: &Report, frame: &mut Frame<'_>, area: Rect) {
    let [header, tabs, body, status] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .areas(area);

    // Risk first: a long file name may be cut off, the verdict must not.
    let spans = vec![
        Span::styled(" rtriage ", Style::new().add_modifier(Modifier::REVERSED)),
        Span::raw(" "),
        Span::styled(format!("[{}]", risk_badge(report)), risk_style(report)),
        Span::raw("  "),
        Span::raw(file_name(app)),
        Span::raw(format!(
            " · {} · {}",
            format_name(report.file.format),
            human_size(report.file.size)
        )),
    ];
    frame.render_widget(Line::from(spans), header);

    let titles = Tab::ALL
        .iter()
        .enumerate()
        .map(|(i, t)| format!("{} {}", i + 1, t.title()));
    frame.render_widget(
        Tabs::new(titles)
            .select(app.tab.index())
            .highlight_style(Style::new().add_modifier(Modifier::REVERSED)),
        tabs,
    );

    match app.tab {
        Tab::Findings => findings::draw(app, report, frame, body),
        Tab::Sections => sections::draw(app, report, frame, body),
        Tab::Imports => imports::draw(app, report, frame, body),
        Tab::Strings => strings::draw(app, report, frame, body),
        Tab::Iocs => iocs::draw(app, report, frame, body),
        Tab::Explain => explain::draw(app, report, frame, body),
    }

    let mut status_spans = Vec::new();
    if is_partial(report) {
        status_spans.push(Span::styled(
            " PARTIAL: cancelled, results incomplete ",
            Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ));
    }
    if let Some(text) = &app.prompt {
        // What the user types is shown escaped like everything else.
        status_spans.push(Span::styled(
            format!(" /{}▏", single_line(text)),
            Style::new().add_modifier(Modifier::BOLD),
        ));
        status_spans.push(Span::styled(
            "  Enter search · Esc cancel",
            Style::new().add_modifier(Modifier::DIM),
        ));
        frame.render_widget(Line::from(status_spans), status);
        return;
    }
    match &app.status {
        // Status notes are built from sanitized text only.
        Some(note) => status_spans.push(Span::styled(
            format!(" {note}"),
            Style::new().add_modifier(Modifier::BOLD),
        )),
        None => status_spans.push(Span::styled(
            " ? help · Tab/1-6 tabs · / search · Backspace back · q quit",
            Style::new().add_modifier(Modifier::DIM),
        )),
    }
    frame.render_widget(Line::from(status_spans), status);
}

/// The snake_case name serde uses for a unit enum variant, from its `Debug`
/// form (`CredentialAccess` → `credential_access`), so the TUI and the JSON
/// output agree.
pub(crate) fn snake<T: std::fmt::Debug>(value: &T) -> String {
    let debug = format!("{value:?}");
    let mut out = String::with_capacity(debug.len() + 4);
    for (i, c) in debug.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// Rows `lines` take when wrapped to `width` columns (approximate: by
/// display width, ignoring word boundaries).
pub(crate) fn wrapped_height(lines: &[Line<'_>], width: u16) -> u16 {
    let width = usize::from(width.max(1));
    let rows: usize = lines.iter().map(|l| l.width().div_ceil(width).max(1)).sum();
    u16::try_from(rows).unwrap_or(u16::MAX)
}

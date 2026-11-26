//! Explain tab: how the score was computed, entry by entry.

use std::collections::BTreeMap;

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;
use rtriage_core::report::Reduction;
use rtriage_core::scoring::{category_cap, level_for, LOW_SEVERITY_CAP};
use rtriage_core::{Report, Severity};
use rtriage_sanitize::single_line;

use super::table::{self, TableSpec};
use super::{level_name, snake, wrapped_height};
use crate::app::{is_partial, App};
use crate::{model, rows};

pub(super) fn draw(app: &App, report: &Report, frame: &mut Frame<'_>, area: Rect) {
    let lines = summary(report);
    // At most half the body, so the table always has room.
    let height = wrapped_height(&lines, area.width.saturating_sub(2))
        .saturating_add(2)
        .min(area.height / 2);
    let [top, bottom] =
        Layout::vertical([Constraint::Length(height), Constraint::Min(3)]).areas(area);
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::new().borders(Borders::ALL).title(" Score ")),
        top,
    );
    let widths = [
        Constraint::Length(6),
        Constraint::Length(28),
        Constraint::Length(18),
        Constraint::Fill(1),
    ];
    let spec = TableSpec {
        title: format!(
            " Breakdown ({} entries) · Enter: show the finding ",
            report.risk.breakdown.len()
        ),
        header: &rows::EXPLAIN_COLUMNS,
        widths: &widths,
        highlight: true,
        empty: "No findings, so nothing was scored.".into(),
    };
    table::draw(frame, bottom, &spec, &app.panes.explain, &|r| {
        rows::explain(report, r)
    });
}

/// The lines above the table: total, level, floor, caps, suppressions.
fn summary(report: &Report) -> Vec<Line<'static>> {
    let risk = &report.risk;
    let bold = Style::new().add_modifier(Modifier::BOLD);
    let mut lines = Vec::new();
    if is_partial(report) {
        lines.push(Line::styled(
            format!(
                "score so far {}: INCOMPLETE, cancelled analyzers could have added more",
                risk.score
            ),
            bold,
        ));
    } else {
        lines.push(Line::styled(
            format!(
                "score {} = sum of the points below · level {}",
                risk.score,
                level_name(risk.level)
            ),
            bold,
        ));
    }
    if let Some(f) = &risk.floor {
        lines.push(Line::from(format!(
            "level raised from {} to {} by {} ({}); the score is unchanged",
            level_name(level_for(risk.score)),
            level_name(f.level),
            f.finding,
            single_line(&f.title)
        )));
    }
    if let Some(caps) = caps_line(report) {
        lines.push(Line::from(caps));
    }
    let suppressed = risk
        .breakdown
        .iter()
        .filter(|e| matches!(e.reduced_by, Some(Reduction::Suppressed { .. })))
        .count();
    if suppressed > 0 {
        lines.push(Line::from(format!(
            "~ {suppressed} findings are explained by a packer or runtime and score 0"
        )));
    }
    lines
}

/// `caps used: injection 40/40 · anomaly 5/20 · low severity 9/15`, for the
/// categories that scored.
fn caps_line(report: &Report) -> Option<String> {
    let mut per_category: BTreeMap<String, (u32, u32)> = BTreeMap::new();
    let mut low = 0u32;
    for (row, e) in report.risk.breakdown.iter().enumerate() {
        if e.table_points == 0 {
            continue;
        }
        let slot = per_category
            .entry(snake(&e.category))
            .or_insert((0, category_cap(e.category)));
        slot.0 = slot.0.saturating_add(e.points);
        let severity = model::finding_for_entry(report, row)
            .and_then(|i| report.findings.get(i))
            .map(|f| f.severity);
        if severity == Some(Severity::Low) {
            low = low.saturating_add(e.points);
        }
    }
    if per_category.is_empty() {
        return None;
    }
    let mut parts: Vec<String> = per_category
        .iter()
        .map(|(name, (used, cap))| format!("{name} {used}/{cap}"))
        .collect();
    parts.push(format!("low severity {low}/{LOW_SEVERITY_CAP}"));
    Some(format!("caps used: {}", parts.join(" · ")))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use ratatui::crossterm::event::KeyCode;
    use rtriage_core::report::RiskFloor;
    use rtriage_core::RiskLevel;
    use rtriage_fixtures::pe::{profiles, Arch};

    use crate::app::Phase;
    use crate::testkit::{key, ready_app, render, suspicious_pe};
    use crate::update::update;

    fn app(data: Vec<u8>, size: (u16, u16)) -> crate::app::App {
        let mut a = ready_app("s.exe", data, size);
        update(&mut a, key(KeyCode::Char('6')));
        a
    }

    #[test]
    fn explain_80x24() {
        insta::assert_snapshot!(render(&app(suspicious_pe(), (80, 24))));
    }

    #[test]
    fn explain_120x40() {
        let screen = render(&app(suspicious_pe(), (120, 40)));
        assert!(
            screen.contains("score 61 = sum of the points below · level HIGH"),
            "{screen}"
        );
        assert!(screen.contains("caps used: "), "{screen}");
        insta::assert_snapshot!(screen);
    }

    #[test]
    fn explain_lists_suppressed_with_reason() {
        let screen = render(&app(profiles::upx_like(Arch::X64).build().bytes, (120, 40)));
        assert!(
            screen.contains("explained by UPX (PE-PACKER-KNOWN), not scored"),
            "{screen}"
        );
        assert!(
            screen.contains("findings are explained by a packer or runtime"),
            "{screen}"
        );
    }

    #[test]
    fn explain_shows_the_risk_floor() {
        let mut a = app(suspicious_pe(), (120, 40));
        if let Phase::Ready(r) = &mut a.phase {
            r.risk.floor = Some(RiskFloor {
                level: RiskLevel::High,
                finding: "YARA-MATCH",
                title: "YARA rule \x1b[2Jevil_family".into(),
            });
            r.risk.score = 12;
        }
        let screen = render(&a);
        assert!(
            screen.contains(
                r"level raised from LOW to HIGH by YARA-MATCH (YARA rule \x1b[2Jevil_family)"
            ),
            "{screen}"
        );
    }

    #[test]
    fn partial_explain_says_incomplete() {
        let mut a = app(suspicious_pe(), (120, 40));
        if let Phase::Ready(r) = &mut a.phase {
            r.analysis_limited
                .push(rtriage_core::AnalysisLimit::Partial);
        }
        let screen = render(&a);
        assert!(screen.contains("INCOMPLETE"), "{screen}");
        assert!(!screen.contains("= sum of the points"), "{screen}");
    }
}

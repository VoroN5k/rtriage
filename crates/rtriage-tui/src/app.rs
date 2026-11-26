//! TUI state. Only [`crate::update`] changes it; [`crate::view`] reads it.

use std::sync::Arc;

use rtriage_core::{AnalysisLimit, Input, Report};

/// Smallest terminal the TUI draws in; below it only a notice is shown.
pub const MIN_SIZE: (u16, u16) = (60, 16);

/// Top-level tabs, in tab-bar order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    /// Findings list with details and evidence.
    Findings,
    /// PE sections / ELF sections and segments.
    Sections,
    /// Imported libraries and symbols.
    Imports,
    /// Extracted strings.
    Strings,
    /// Indicators of compromise.
    Iocs,
    /// Score breakdown and suppressed findings.
    Explain,
}

impl Tab {
    /// Tabs shown in the tab bar, in order; key `1` selects the first.
    pub const ALL: [Tab; 6] = [
        Tab::Findings,
        Tab::Sections,
        Tab::Imports,
        Tab::Strings,
        Tab::Iocs,
        Tab::Explain,
    ];

    /// Tab-bar label.
    pub fn title(self) -> &'static str {
        match self {
            Tab::Findings => "Findings",
            Tab::Sections => "Sections",
            Tab::Imports => "Imports",
            Tab::Strings => "Strings",
            Tab::Iocs => "IOCs",
            Tab::Explain => "Explain",
        }
    }

    /// Position in [`Tab::ALL`].
    pub fn index(self) -> usize {
        Tab::ALL.iter().position(|t| *t == self).unwrap_or(0)
    }

    /// The tab `delta` places further, wrapping around.
    pub fn cycle(self, delta: isize) -> Tab {
        let n = Tab::ALL.len().cast_signed();
        let i = (self.index().cast_signed() + delta).rem_euclid(n);
        Tab::ALL
            .get(i.cast_unsigned())
            .copied()
            .unwrap_or(Tab::Findings)
    }
}

/// Where the analysis is.
#[derive(Debug, Clone, PartialEq)]
pub enum Phase {
    /// Running in the background.
    Loading {
        /// A cancel was already requested (it is requested at most once).
        cancel_sent: bool,
    },
    /// Finished (possibly cancelled, then the report says `partial`).
    Ready(Box<Report>),
    /// The analysis thread died without a report.
    Failed,
}

/// Whole TUI state.
#[derive(Debug, Clone)]
pub struct App {
    /// The file being analysed (kept for the hex view and range entropy).
    pub input: Arc<Input>,
    /// Analysis progress or result.
    pub phase: Phase,
    /// Selected tab.
    pub tab: Tab,
    /// Terminal size `(width, height)`.
    pub size: (u16, u16),
    /// Help overlay visible.
    pub help: bool,
    /// Ticks seen, for the spinner.
    pub ticks: u64,
}

impl App {
    /// State for a freshly started analysis of `input`.
    pub fn new(input: Arc<Input>, size: (u16, u16)) -> App {
        App {
            input,
            phase: Phase::Loading { cancel_sent: false },
            tab: Tab::Findings,
            size,
            help: false,
            ticks: 0,
        }
    }

    /// The report, once the analysis has finished.
    pub fn report(&self) -> Option<&Report> {
        match &self.phase {
            Phase::Ready(r) => Some(r),
            _ => None,
        }
    }

    /// `true` if the terminal is below [`MIN_SIZE`].
    pub fn too_small(&self) -> bool {
        self.size.0 < MIN_SIZE.0 || self.size.1 < MIN_SIZE.1
    }
}

/// `true` if the report is incomplete because the analysis was cancelled.
pub fn is_partial(report: &Report) -> bool {
    report.analysis_limited.contains(&AnalysisLimit::Partial)
}

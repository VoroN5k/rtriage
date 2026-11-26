//! Messages into [`crate::update`] and the effects it asks the runtime for.

use ratatui::crossterm::event::{Event, KeyEvent, KeyEventKind};
use rtriage_core::Report;

/// Something that happened: input, a resize, a clock tick, or the end of
/// the background analysis.
#[derive(Debug, Clone, PartialEq)]
pub enum Msg {
    /// A key press (releases and repeats never get here, see [`from_event`]).
    Key(KeyEvent),
    /// The terminal was resized to `(width, height)`.
    Resize(u16, u16),
    /// Periodic tick (drives the loading spinner).
    Tick,
    /// The analysis finished, possibly cancelled (then the report is partial).
    AnalysisDone(Box<Report>),
    /// The analysis thread ended without a report (it panicked).
    AnalysisFailed,
}

/// An effect for the runtime to perform; `update` itself does no I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cmd {
    /// Set the analysis cancel token.
    Cancel,
    /// Leave the TUI.
    Quit,
}

/// Turns a terminal event into a message. Only key *presses* count:
/// Windows reports press and release (and repeat) for every key, which would
/// otherwise act twice.
pub fn from_event(event: Event) -> Option<Msg> {
    match event {
        Event::Key(key) if key.kind == KeyEventKind::Press => Some(Msg::Key(key)),
        Event::Resize(w, h) => Some(Msg::Resize(w, h)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::crossterm::event::{KeyCode, KeyEventState, KeyModifiers};

    fn key(kind: KeyEventKind) -> Event {
        Event::Key(KeyEvent {
            code: KeyCode::Char('q'),
            modifiers: KeyModifiers::NONE,
            kind,
            state: KeyEventState::NONE,
        })
    }

    #[test]
    fn only_presses_become_messages() {
        assert!(matches!(
            from_event(key(KeyEventKind::Press)),
            Some(Msg::Key(_))
        ));
        assert_eq!(from_event(key(KeyEventKind::Release)), None);
        assert_eq!(from_event(key(KeyEventKind::Repeat)), None);
        assert_eq!(from_event(Event::Resize(80, 24)), Some(Msg::Resize(80, 24)));
        assert_eq!(from_event(Event::FocusGained), None);
    }
}

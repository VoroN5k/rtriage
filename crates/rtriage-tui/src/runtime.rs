//! Terminal ownership, event loop and the background analysis.
//!
//! The UI thread owns the terminal; the analysis runs on its own thread and
//! hands back the report over a channel. Cancelling sets the deadline's
//! [`CancelToken`]; quitting never waits for the analysis thread longer
//! than [`QUIT_GRACE`] (a YARA scan cannot be interrupted, process exit ends
//! it). The terminal is restored on every exit path, including a panic on
//! the UI thread.

use std::io::{self, IsTerminal, Stdout};
use std::path::Path;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::cursor::{Hide, Show};
use ratatui::crossterm::event;
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::Terminal;
use rtriage_core::{CancelToken, Config, Deadline, Input, Registry, Report};

use crate::app::{App, Phase};
use crate::msg::{from_event, Cmd, Msg};
use crate::update::update;
use crate::view::view;

/// How long the loop waits for input before drawing a tick.
const TICK: Duration = Duration::from_millis(50);
/// How long quitting waits for a cancelled analysis thread to finish.
const QUIT_GRACE: Duration = Duration::from_millis(200);

/// What the TUI needs from the CLI: the same configuration and analyzers a
/// plain `rtriage <FILE>` run would use.
#[derive(Debug)]
pub struct TuiOptions {
    /// Limits, thresholds, rules and compiled YARA rules.
    pub config: Config,
    /// Analyzers to run.
    pub registry: Registry,
}

/// Why the TUI could not run (errors inside the analysis are part of the
/// report instead).
#[derive(Debug, thiserror::Error)]
pub enum TuiError {
    /// stdin or stdout is not a terminal.
    #[error("the TUI needs an interactive terminal on stdin and stdout; use `-f text` or `-f json` for pipes and files")]
    NotATty,
    /// The path is a directory.
    #[error("is a directory (the TUI shows one file; use `rtriage scan` for directories)")]
    IsDirectory,
    /// The file could not be loaded.
    #[error(transparent)]
    Load(#[from] rtriage_core::Error),
    /// Terminal I/O failed.
    #[error("terminal error: {0}")]
    Io(#[from] io::Error),
}

/// Runs the TUI on `path` until the user quits.
///
/// # Errors
/// See [`TuiError`]. Nothing is drawn before the terminal and the file have
/// been checked, so these errors reach a normal, unmodified terminal.
pub fn run(path: &Path, opts: TuiOptions) -> Result<(), TuiError> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(TuiError::NotATty);
    }
    if path.is_dir() {
        return Err(TuiError::IsDirectory);
    }
    let input = Arc::new(rtriage_core::load(path, &opts.config.limits)?);
    let token = CancelToken::default();
    let (tx, rx) = mpsc::channel();
    let analysis = spawn_analysis(Arc::clone(&input), opts, token.clone(), tx)?;

    let result = {
        let _guard = TerminalGuard::enter()?;
        let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
        let size = terminal.size()?;
        let mut app = App::new(input, (size.width, size.height));
        event_loop(&mut terminal, &mut app, &rx, &token)
    };
    token.cancel();
    wait_briefly(&analysis, QUIT_GRACE);
    result
}

fn spawn_analysis(
    input: Arc<Input>,
    opts: TuiOptions,
    token: CancelToken,
    tx: mpsc::Sender<Box<Report>>,
) -> io::Result<JoinHandle<()>> {
    thread::Builder::new()
        .name("rtriage-analysis".into())
        .spawn(move || {
            let deadline = Deadline::after(opts.config.limits.max_analysis_time).with_cancel(token);
            let report = opts
                .registry
                .analyze_with_deadline(&input, &opts.config, deadline);
            // The UI may already be gone; nothing to do then.
            let _ = tx.send(Box::new(report));
        })
}

fn event_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut App,
    rx: &Receiver<Box<Report>>,
    token: &CancelToken,
) -> Result<(), TuiError> {
    loop {
        terminal.draw(|f| view(app, f))?;
        let mut msgs = Vec::with_capacity(2);
        if event::poll(TICK)? {
            msgs.extend(from_event(event::read()?));
        } else {
            msgs.push(Msg::Tick);
        }
        if let Some(msg) = analysis_msg(app, rx) {
            if msg == Msg::AnalysisFailed {
                // The panic message went to stderr over our screen.
                terminal.clear()?;
            }
            msgs.push(msg);
        }
        for msg in msgs {
            for cmd in update(app, msg) {
                match cmd {
                    Cmd::Cancel => token.cancel(),
                    Cmd::Quit => return Ok(()),
                }
            }
        }
    }
}

/// The analysis result, or `AnalysisFailed` if its thread ended without one.
fn analysis_msg(app: &App, rx: &Receiver<Box<Report>>) -> Option<Msg> {
    if !matches!(app.phase, Phase::Loading { .. }) {
        return None;
    }
    match rx.try_recv() {
        Ok(report) => Some(Msg::AnalysisDone(report)),
        Err(TryRecvError::Disconnected) => Some(Msg::AnalysisFailed),
        Err(TryRecvError::Empty) => None,
    }
}

fn wait_briefly(handle: &JoinHandle<()>, grace: Duration) {
    let start = Instant::now();
    while !handle.is_finished() && start.elapsed() < grace {
        thread::sleep(Duration::from_millis(5));
    }
}

/// Raw mode + alternate screen + hidden cursor while alive.
struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> io::Result<TerminalGuard> {
        install_panic_hook();
        enable_raw_mode()?;
        // From here on `Drop` undoes whatever part succeeded.
        let guard = TerminalGuard;
        execute!(io::stdout(), EnterAlternateScreen, Hide)?;
        Ok(guard)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore_terminal();
    }
}

/// Best effort: leave raw mode and the alternate screen, show the cursor.
fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen, Show);
}

/// Restores the terminal before the previous hook prints a panic on the UI
/// thread, so the message lands on a usable screen. Panics on other threads
/// (the analysis) leave the UI running; it shows "analysis failed".
fn install_panic_hook() {
    let ui = thread::current().id();
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if thread::current().id() == ui {
            restore_terminal();
        }
        previous(info);
    }));
}

//! Interactive terminal view of an rtriage report (`rtriage tui <FILE>`).
//!
//! Structure: [`App`] holds all state, [`update`] is the only function that
//! changes it (pure, returns [`Cmd`]s), [`view`] draws it. The runtime
//! ([`run`]) owns the terminal, turns terminal events into [`Msg`]s, runs the
//! analysis on a background thread and performs the commands. Everything
//! from the analysed file is passed through `rtriage-sanitize` before it is
//! drawn.

#![forbid(unsafe_code)]

mod app;
mod msg;
mod runtime;
mod update;
mod view;

pub use app::{is_partial, App, Phase, Tab, MIN_SIZE};
pub use msg::{from_event, Cmd, Msg};
pub use runtime::{run, TuiError, TuiOptions};
pub use update::update;
pub use view::{risk_badge, view};

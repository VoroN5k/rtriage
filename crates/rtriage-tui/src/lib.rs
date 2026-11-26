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
mod copy;
mod filter;
mod hex;
mod jump;
mod list;
mod model;
mod msg;
mod rows;
mod runtime;
mod search;
#[cfg(test)]
mod testkit;
mod update;
mod view;

pub use app::{is_partial, App, Focus, Panes, PendingCopy, Phase, Tab, MIN_SIZE};
pub use copy::{osc52, CopyError, Mux, OSC52_LIMIT};
pub use filter::{FilterDialog, StringFilter};
pub use hex::{HexState, ROW_BYTES};
pub use jump::{History, Location, RangeInfo, Target, RANGE_ENTROPY_CAP};
pub use list::ListState;
pub use msg::{from_event, Cmd, Msg};
pub use runtime::{run, TuiError, TuiOptions};
pub use update::update;
pub use view::{risk_badge, view};

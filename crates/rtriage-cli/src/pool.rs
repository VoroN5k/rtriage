//! Worker pool: analyses many files in isolated worker processes.
//!
//! - Up to `jobs` workers, each with exactly one file in flight.
//! - Every worker's stdout is read by its own thread; all of them feed one
//!   channel, so the pool waits once, until the next event or deadline.
//! - A file whose worker does not answer within `file_timeout` (the
//!   analysis `--timeout` plus [`GRACE`]) is reported `timed_out` and its
//!   worker is killed; a worker that dies mid-file reports `crashed`; an
//!   oversized or malformed answer reports `invalid_response`. In every case
//!   only that file is lost: a fresh worker continues with the rest.
//! - Files are never retried: a file that crashes a worker would crash the
//!   next one too.
//! - If workers keep dying before they are even ready
//!   ([`MAX_START_FAILURES`] in a row), the run stops with an error instead
//!   of respawning forever.

use std::path::PathBuf;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

use crate::output::{Failure, FailureKind};
use crate::worker::{Event, Request, Response, Spawn, Summary, Tag, WirePath, Worker, PROTOCOL};

/// Extra time a worker gets beyond the analysis timeout before it is killed
/// (startup, loading, rendering, the in-process deadline's own slack).
pub const GRACE: Duration = Duration::from_secs(5);
/// Consecutive workers that may die before `ready` until the run gives up.
pub const MAX_START_FAILURES: u32 = 3;
/// Most workers a run may use.
pub const MAX_JOBS: usize = 64;

/// One finished file.
#[derive(Debug)]
pub enum Outcome {
    /// Analyzed: `index` into the file list, the summary and the rendered body.
    Report {
        /// Position in the input list.
        index: usize,
        /// Parsed summary.
        summary: Summary,
        /// Rendered report (opaque).
        body: String,
    },
    /// Not analyzed.
    Failure {
        /// Position in the input list.
        index: usize,
        /// Why.
        failure: Failure,
    },
}

/// Pool settings.
#[derive(Debug, Clone)]
pub struct PoolOptions {
    /// How to start a worker.
    pub spawn: Spawn,
    /// Workers to run (clamped to `1..=MAX_JOBS` and to the file count).
    pub jobs: usize,
    /// Wall-clock limit per file, after which the worker is killed.
    pub file_timeout: Duration,
    /// How long a new worker may take to send `ready`.
    pub start_timeout: Duration,
}

/// Why the pool gave up.
#[derive(Debug)]
pub enum PoolError {
    /// Workers die before becoming ready.
    CannotStart(String),
    /// A worker speaks another protocol version.
    Protocol(u32),
    /// `on_outcome` failed (e.g. the output could not be written).
    Output(std::io::Error),
}

impl std::fmt::Display for PoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PoolError::CannotStart(why) => write!(f, "worker processes cannot start: {why}"),
            PoolError::Protocol(v) => {
                write!(f, "worker speaks protocol {v}, expected {PROTOCOL}")
            }
            PoolError::Output(e) => write!(f, "cannot write output: {e}"),
        }
    }
}

impl std::error::Error for PoolError {}

enum State {
    /// Spawned, waiting for `ready` until the deadline.
    Starting { deadline: Instant },
    /// Ready, nothing in flight.
    Idle,
    /// Analyzing `index` (request `id`) until the deadline.
    Busy {
        index: usize,
        id: u64,
        deadline: Instant,
    },
}

struct Slot {
    worker: Option<Worker>,
    generation: u64,
    state: State,
}

/// Analyses `files`, calling `on_outcome` once per file as each finishes
/// (completion order, from the calling thread).
///
/// # Errors
/// [`PoolError`]; outcomes already delivered stay delivered.
pub fn run(
    files: &[PathBuf],
    opts: &PoolOptions,
    mut on_outcome: impl FnMut(Outcome) -> std::io::Result<()>,
) -> Result<(), PoolError> {
    if files.is_empty() {
        return Ok(());
    }
    let jobs = opts.jobs.clamp(1, MAX_JOBS).min(files.len());
    let (tx, rx) = mpsc::channel::<(Tag, Event)>();
    let mut slots: Vec<Slot> = Vec::with_capacity(jobs);
    let mut start_failures = 0u32;
    let mut last_start_error = String::new();
    for slot in 0..jobs {
        let mut s = Slot {
            worker: None,
            generation: 0,
            state: State::Idle,
        };
        start(
            &mut s,
            slot,
            opts,
            &tx,
            &mut start_failures,
            &mut last_start_error,
        )?;
        slots.push(s);
    }

    let mut next = 0usize; // next file to dispatch
    let mut done = 0usize;
    let mut next_id = 0u64;
    let mut deliver = |o: Outcome, done: &mut usize| -> Result<(), PoolError> {
        *done += 1;
        on_outcome(o).map_err(PoolError::Output)
    };

    while done < files.len() {
        // Dispatch to idle workers.
        for s in slots.iter_mut() {
            if !matches!(s.state, State::Idle) || next >= files.len() {
                continue;
            }
            let Some(worker) = s.worker.as_mut() else {
                continue;
            };
            let index = next;
            next += 1;
            next_id += 1;
            let path = files.get(index).cloned().unwrap_or_default();
            let req = Request {
                id: next_id,
                path: WirePath::from_path(&path),
            };
            if worker.send(&req).is_err() {
                // Its Closed event follows shortly and reports it as crashed.
                s.state = State::Busy {
                    index,
                    id: next_id,
                    deadline: Instant::now() + Duration::from_secs(2),
                };
                continue;
            }
            s.state = State::Busy {
                index,
                id: next_id,
                deadline: Instant::now() + opts.file_timeout,
            };
        }

        let wait = slots
            .iter()
            .filter_map(|s| match s.state {
                State::Starting { deadline } | State::Busy { deadline, .. } => Some(deadline),
                State::Idle => None,
            })
            .min()
            .map_or(Duration::from_secs(1), |d| {
                d.saturating_duration_since(Instant::now())
            });

        match rx.recv_timeout(wait) {
            Ok((tag, event)) => {
                let Some(s) = slots.get_mut(tag.slot) else {
                    continue;
                };
                if s.generation != tag.generation {
                    continue; // from a worker already replaced
                }
                match event {
                    Event::Message(Response::Ready { protocol }) => {
                        if protocol != PROTOCOL {
                            return Err(PoolError::Protocol(protocol));
                        }
                        if matches!(s.state, State::Starting { .. }) {
                            s.state = State::Idle;
                            start_failures = 0;
                        } else {
                            let o = replace(
                                s,
                                tag.slot,
                                files,
                                FailureKind::InvalidResponse,
                                "unexpected ready message".into(),
                                opts,
                                &tx,
                                &mut start_failures,
                                &mut last_start_error,
                                next < files.len(),
                            )?;
                            if let Some(o) = o {
                                deliver(o, &mut done)?;
                            }
                        }
                    }
                    Event::Message(Response::Report { id, summary, body }) => match s.state {
                        State::Busy {
                            index, id: want, ..
                        } if want == id => {
                            s.state = State::Idle;
                            deliver(
                                Outcome::Report {
                                    index,
                                    summary,
                                    body,
                                },
                                &mut done,
                            )?;
                        }
                        _ => {
                            let o = replace(
                                s,
                                tag.slot,
                                files,
                                FailureKind::InvalidResponse,
                                "response for a request not in flight".into(),
                                opts,
                                &tx,
                                &mut start_failures,
                                &mut last_start_error,
                                next < files.len(),
                            )?;
                            if let Some(o) = o {
                                deliver(o, &mut done)?;
                            }
                        }
                    },
                    Event::Message(Response::Failure { id, kind, error }) => match s.state {
                        State::Busy {
                            index, id: want, ..
                        } if want == id => {
                            s.state = State::Idle;
                            let failure = Failure {
                                path: path_of(files, index),
                                kind,
                                error,
                            };
                            deliver(Outcome::Failure { index, failure }, &mut done)?;
                        }
                        _ => {
                            let o = replace(
                                s,
                                tag.slot,
                                files,
                                FailureKind::InvalidResponse,
                                "failure for a request not in flight".into(),
                                opts,
                                &tx,
                                &mut start_failures,
                                &mut last_start_error,
                                next < files.len(),
                            )?;
                            if let Some(o) = o {
                                deliver(o, &mut done)?;
                            }
                        }
                    },
                    Event::TooLong => {
                        let why = format!(
                            "worker response over {} bytes; worker killed",
                            opts.spawn.max_line
                        );
                        let o = replace(
                            s,
                            tag.slot,
                            files,
                            FailureKind::InvalidResponse,
                            why,
                            opts,
                            &tx,
                            &mut start_failures,
                            &mut last_start_error,
                            next < files.len(),
                        )?;
                        if let Some(o) = o {
                            deliver(o, &mut done)?;
                        }
                    }
                    Event::Invalid(e) => {
                        let why = format!("malformed worker response ({e}); worker killed");
                        let o = replace(
                            s,
                            tag.slot,
                            files,
                            FailureKind::InvalidResponse,
                            why,
                            opts,
                            &tx,
                            &mut start_failures,
                            &mut last_start_error,
                            next < files.len(),
                        )?;
                        if let Some(o) = o {
                            deliver(o, &mut done)?;
                        }
                    }
                    Event::Closed => {
                        let starting = matches!(s.state, State::Starting { .. });
                        let status = s.worker.take().and_then(Worker::kill);
                        let why = status.map_or_else(
                            || "worker process died".to_owned(),
                            |st| format!("worker process died ({st})"),
                        );
                        if starting {
                            start_failures += 1;
                            last_start_error = why;
                            if start_failures >= MAX_START_FAILURES {
                                return Err(PoolError::CannotStart(last_start_error));
                            }
                            start(
                                s,
                                tag.slot,
                                opts,
                                &tx,
                                &mut start_failures,
                                &mut last_start_error,
                            )?;
                        } else {
                            let o = replace(
                                s,
                                tag.slot,
                                files,
                                FailureKind::Crashed,
                                why,
                                opts,
                                &tx,
                                &mut start_failures,
                                &mut last_start_error,
                                next < files.len(),
                            )?;
                            if let Some(o) = o {
                                deliver(o, &mut done)?;
                            }
                        }
                    }
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                let now = Instant::now();
                for slot in 0..slots.len() {
                    let Some(s) = slots.get_mut(slot) else {
                        continue;
                    };
                    match s.state {
                        State::Busy { deadline, .. } if deadline <= now => {
                            let why = format!(
                                "no answer within {} s; worker killed",
                                opts.file_timeout.as_secs()
                            );
                            let o = replace(
                                s,
                                slot,
                                files,
                                FailureKind::TimedOut,
                                why,
                                opts,
                                &tx,
                                &mut start_failures,
                                &mut last_start_error,
                                next < files.len(),
                            )?;
                            if let Some(o) = o {
                                deliver(o, &mut done)?;
                            }
                        }
                        State::Starting { deadline } if deadline <= now => {
                            if let Some(w) = s.worker.take() {
                                w.kill();
                            }
                            start_failures += 1;
                            last_start_error = "worker did not become ready in time".into();
                            if start_failures >= MAX_START_FAILURES {
                                return Err(PoolError::CannotStart(last_start_error));
                            }
                            start(
                                s,
                                slot,
                                opts,
                                &tx,
                                &mut start_failures,
                                &mut last_start_error,
                            )?;
                        }
                        _ => {}
                    }
                }
            }
            Err(RecvTimeoutError::Disconnected) => {
                return Err(PoolError::CannotStart("worker channel closed".into()));
            }
        }
    }

    for s in slots {
        if let Some(w) = s.worker {
            w.finish();
        }
    }
    Ok(())
}

fn path_of(files: &[PathBuf], index: usize) -> String {
    files
        .get(index)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// (Re)starts the worker of slot `slot`, bumping its generation.
fn start(
    s: &mut Slot,
    slot: usize,
    opts: &PoolOptions,
    tx: &mpsc::Sender<(Tag, Event)>,
    start_failures: &mut u32,
    last_error: &mut String,
) -> Result<(), PoolError> {
    loop {
        s.generation += 1;
        let tag = Tag {
            slot,
            generation: s.generation,
        };
        match Worker::spawn(&opts.spawn, tag, tx.clone()) {
            Ok(w) => {
                s.worker = Some(w);
                s.state = State::Starting {
                    deadline: Instant::now() + opts.start_timeout,
                };
                return Ok(());
            }
            Err(e) => {
                *start_failures += 1;
                *last_error = e.to_string();
                if *start_failures >= MAX_START_FAILURES {
                    return Err(PoolError::CannotStart(last_error.clone()));
                }
            }
        }
    }
}

/// Kills the slot's worker; if a file was in flight, returns its failure.
/// A replacement is started only if work remains.
#[allow(clippy::too_many_arguments)]
fn replace(
    s: &mut Slot,
    slot: usize,
    files: &[PathBuf],
    kind: FailureKind,
    why: String,
    opts: &PoolOptions,
    tx: &mpsc::Sender<(Tag, Event)>,
    start_failures: &mut u32,
    last_error: &mut String,
    work_left: bool,
) -> Result<Option<Outcome>, PoolError> {
    if let Some(w) = s.worker.take() {
        w.kill();
    }
    let outcome = match s.state {
        State::Busy { index, .. } => Some(Outcome::Failure {
            index,
            failure: Failure {
                path: path_of(files, index),
                kind,
                error: why,
            },
        }),
        _ => None,
    };
    s.state = State::Idle;
    if work_left {
        start(s, slot, opts, tx, start_failures, last_error)?;
    }
    Ok(outcome)
}

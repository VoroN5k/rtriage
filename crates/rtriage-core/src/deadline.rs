//! Cooperative time limits and operation budgets.
//!
//! Rust threads cannot be killed from outside, so analysis stops itself:
//! - [`Deadline`]: wall-clock limit for the whole file. Long loops call
//!   [`Deadline::check`] periodically (linear scanners: once per chunk).
//! - [`Budget`]: per-parser step counter for format parsers walking
//!   attacker-controlled structures (import thunks, TLS callbacks, ...).
//!   Each step counts, the deadline is re-checked every [`Budget::CHECK_EVERY`]
//!   steps, and exceeding `max_steps` is a [`AnalysisError::LimitExceeded`].
//!
//! Third-party parsing calls cannot be interrupted; they are kept bounded by
//! validating sizes and counts *before* calling them.

use std::time::{Duration, Instant};

use crate::error::AnalysisError;

/// Wall-clock deadline for analysing one file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deadline {
    /// `None` = no deadline (limit too large to represent).
    at: Option<Instant>,
    limit: Duration,
}

impl Deadline {
    /// Deadline `limit` from now.
    pub fn after(limit: Duration) -> Self {
        Self {
            at: Instant::now().checked_add(limit),
            limit,
        }
    }

    /// A deadline that never expires (library use and tests).
    pub fn never() -> Self {
        Self {
            at: None,
            limit: Duration::MAX,
        }
    }

    /// A deadline that has already passed (tests of timeout handling).
    pub fn expired() -> Self {
        Self {
            at: Some(Instant::now()),
            limit: Duration::ZERO,
        }
    }

    /// `true` once the deadline has passed.
    pub fn is_expired(&self) -> bool {
        self.at.is_some_and(|at| Instant::now() >= at)
    }

    /// Returns [`AnalysisError::Timeout`] if the deadline has passed.
    pub fn check(&self) -> Result<(), AnalysisError> {
        if self.is_expired() {
            Err(self.timeout_error())
        } else {
            Ok(())
        }
    }

    /// Time left; `None` for a deadline that never expires, `Some(ZERO)` once
    /// it has passed.
    pub fn remaining(&self) -> Option<Duration> {
        self.at
            .map(|at| at.saturating_duration_since(Instant::now()))
    }

    /// The error reported when this deadline is exceeded.
    pub fn timeout_error(&self) -> AnalysisError {
        AnalysisError::Timeout {
            limit_ms: u64::try_from(self.limit.as_millis()).unwrap_or(u64::MAX),
        }
    }

    /// A step budget bound to this deadline.
    pub fn budget(&self, max_steps: u64) -> Budget {
        Budget {
            deadline: *self,
            steps: 0,
            max_steps,
        }
    }
}

/// Step counter for loops over attacker-controlled structures.
#[derive(Debug, Clone)]
pub struct Budget {
    deadline: Deadline,
    steps: u64,
    max_steps: u64,
}

impl Budget {
    /// How often (in steps) the wall-clock deadline is re-checked.
    pub const CHECK_EVERY: u64 = 1024;

    /// Consumes one step.
    ///
    /// # Errors
    /// [`AnalysisError::LimitExceeded`] (`max_parser_steps`) when the budget
    /// is spent, or [`AnalysisError::Timeout`] when the deadline has passed.
    pub fn step(&mut self) -> Result<(), AnalysisError> {
        self.steps = self.steps.saturating_add(1);
        if self.steps > self.max_steps {
            return Err(AnalysisError::LimitExceeded {
                limit: "max_parser_steps",
                value: self.steps,
                max: self.max_steps,
            });
        }
        if self.steps.is_multiple_of(Self::CHECK_EVERY) {
            self.deadline.check()?;
        }
        Ok(())
    }

    /// Steps consumed so far.
    pub fn used(&self) -> u64 {
        self.steps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_does_not_expire() {
        assert_eq!(Deadline::never().check(), Ok(()));
    }

    #[test]
    fn remaining_time() {
        assert_eq!(Deadline::never().remaining(), None);
        assert_eq!(Deadline::expired().remaining(), Some(Duration::ZERO));
        let r = Deadline::after(Duration::from_secs(60)).remaining();
        assert!(r.is_some_and(|r| r > Duration::from_secs(59) && r <= Duration::from_secs(60)));
    }

    #[test]
    fn expired_reports_timeout() {
        assert!(matches!(
            Deadline::expired().check(),
            Err(AnalysisError::Timeout { limit_ms: 0 })
        ));
    }

    #[test]
    fn timeout_reports_limit_in_ms() {
        let d = Deadline::after(Duration::from_secs(30));
        assert_eq!(
            d.timeout_error(),
            AnalysisError::Timeout { limit_ms: 30_000 }
        );
        assert_eq!(d.check(), Ok(()));
    }

    #[test]
    fn huge_limit_does_not_overflow() {
        let d = Deadline::after(Duration::MAX);
        assert_eq!(d.check(), Ok(()));
    }

    #[test]
    fn budget_enforces_max_steps() {
        let mut b = Deadline::never().budget(3);
        assert!(b.step().is_ok());
        assert!(b.step().is_ok());
        assert!(b.step().is_ok());
        assert!(matches!(
            b.step(),
            Err(AnalysisError::LimitExceeded {
                limit: "max_parser_steps",
                value: 4,
                max: 3
            })
        ));
    }

    #[test]
    fn budget_checks_deadline_periodically() {
        let mut b = Deadline::expired().budget(u64::MAX);
        let mut result = Ok(());
        for _ in 0..Budget::CHECK_EVERY {
            result = b.step();
            if result.is_err() {
                break;
            }
        }
        assert!(matches!(result, Err(AnalysisError::Timeout { .. })));
        assert_eq!(b.used(), Budget::CHECK_EVERY);
    }
}

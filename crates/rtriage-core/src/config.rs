//! Analysis configuration: resource limits plus heuristic thresholds.
//!
//! Every heuristic threshold lives in [`Thresholds`] with a documented default,
//! never as a magic number inside an analyzer.

use std::num::NonZeroUsize;

use serde::Serialize;

use crate::limits::Limits;

/// Everything an analysis run can be tuned with.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Config {
    /// Resource limits on file-derived values.
    pub limits: Limits,
    /// Heuristic thresholds.
    pub thresholds: Thresholds,
}

/// Heuristic thresholds. [`Thresholds::default`] gives the documented defaults.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Thresholds {
    /// Window size for sliding entropy, in bytes. Default: 4096.
    ///
    /// Shannon entropy of `n` bytes is capped at `log2(n)`, so windows must be
    /// large enough (>= 256) for values near 8.0 to be reachable at all.
    pub entropy_window: NonZeroUsize,
    /// Entropy (bits per byte, 0.0–8.0) at or above which a window counts as
    /// high-entropy. Default: 7.2.
    ///
    /// Typical values: plain code ~5.5–6.5, compressed/encrypted data 7.5–8.0.
    /// Legitimate compressed resources, installers and archives also exceed it.
    pub entropy_high: f64,
}

impl Thresholds {
    /// Default for [`Thresholds::entropy_window`].
    pub const DEFAULT_ENTROPY_WINDOW: NonZeroUsize = match NonZeroUsize::new(4096) {
        Some(n) => n,
        None => NonZeroUsize::MIN,
    };
    /// Default for [`Thresholds::entropy_high`].
    pub const DEFAULT_ENTROPY_HIGH: f64 = 7.2;
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            entropy_window: Self::DEFAULT_ENTROPY_WINDOW,
            entropy_high: Self::DEFAULT_ENTROPY_HIGH,
        }
    }
}

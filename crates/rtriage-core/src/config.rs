//! Analysis configuration: resource limits plus heuristic thresholds.
//!
//! Every heuristic threshold lives in [`Thresholds`] with a documented default,
//! never as a magic number inside an analyzer.

use std::num::NonZeroUsize;
use std::sync::Arc;

use serde::Serialize;

use crate::analyzers::iocs::IocAllowlist;
use crate::limits::Limits;
use crate::rules::{ApiRuleSet, PackerRuleSet};

/// Everything an analysis run can be tuned with.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Config {
    /// Resource limits on file-derived values.
    pub limits: Limits,
    /// Heuristic thresholds.
    pub thresholds: Thresholds,
    /// Minimum string length (in characters) for extraction. Default: 5.
    pub strings_min_len: NonZeroUsize,
    /// API behavior rules; `None` = the bundled `rules/api_groups.toml`.
    #[serde(skip)]
    pub api_rules: Option<Arc<ApiRuleSet>>,
    /// ELF API behavior rules; `None` = the bundled `rules/elf_api_groups.toml`.
    #[serde(skip)]
    pub elf_api_rules: Option<Arc<ApiRuleSet>>,
    /// IOC allowlist; `None` = the bundled `rules/ioc_allowlist.toml`.
    #[serde(skip)]
    pub ioc_allowlist: Option<Arc<IocAllowlist>>,
    /// Packer explanations; `None` = the bundled `rules/packers.toml`.
    #[serde(skip)]
    pub packer_rules: Option<Arc<PackerRuleSet>>,
    /// Compiled YARA rules; `None` = no YARA scan.
    #[cfg(feature = "yara")]
    #[serde(skip)]
    pub yara: Option<Arc<crate::yara::YaraRules>>,
}

impl Config {
    /// Default for [`Config::strings_min_len`].
    pub const DEFAULT_STRINGS_MIN_LEN: NonZeroUsize = match NonZeroUsize::new(5) {
        Some(n) => n,
        None => NonZeroUsize::MIN,
    };
}

impl Default for Config {
    fn default() -> Self {
        Self {
            limits: Limits::default(),
            thresholds: Thresholds::default(),
            strings_min_len: Self::DEFAULT_STRINGS_MIN_LEN,
            api_rules: None,
            elf_api_rules: None,
            ioc_allowlist: None,
            packer_rules: None,
            #[cfg(feature = "yara")]
            yara: None,
        }
    }
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
    /// Sections with fewer raw bytes than this get no entropy value (it would
    /// be biased low and meaningless). Default: 512.
    pub section_entropy_min_size: usize,
    /// Minimum `VirtualSize` for an executable section with no raw data to be
    /// reported as `PE-SECTION-VIRTUAL-ONLY`. Default: 4096 (one page).
    pub virtual_only_min_size: u32,
    /// `PE-IMPORTS-FEW` fires at or below this many imported functions.
    /// Default: 10 (CRT-linked programs import dozens).
    pub imports_few_max: u64,
    /// `PE-IMPORTS-DYNAMIC-RESOLUTION` requires the import table to be at most
    /// this many functions. Default: 20.
    pub dynamic_resolution_max_imports: u64,
    /// Resources smaller than this are not judged by `PE-RESOURCE-HIGH-ENTROPY`.
    /// Default: 4096.
    pub resource_entropy_min_size: usize,
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
            section_entropy_min_size: 512,
            virtual_only_min_size: 0x1000,
            imports_few_max: 10,
            dynamic_resolution_max_imports: 20,
            resource_entropy_min_size: 4096,
        }
    }
}

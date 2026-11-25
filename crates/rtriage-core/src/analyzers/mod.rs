//! Analyzer trait and registry.
//!
//! Analyzers are independent and order-agnostic: each reads the input and
//! writes facts/findings into a [`ReportBuilder`]. If one fails, the failure
//! is recorded in the report and the remaining analyzers still run.

pub mod entropy;
pub mod hashes;

use crate::config::{Config, Thresholds};
use crate::error::AnalysisError;
use crate::input::Input;
use crate::limits::Limits;
use crate::report::{Format, Report, ReportBuilder, Risk};

/// Read-only data shared by all analyzers for one file.
#[derive(Debug, Clone, Copy)]
pub struct AnalysisContext<'a> {
    /// The loaded file.
    pub input: &'a Input,
    /// Resource limits to enforce on file-derived values.
    pub limits: &'a Limits,
    /// Heuristic thresholds.
    pub thresholds: &'a Thresholds,
}

/// One independent analysis pass.
pub trait Analyzer: Send + Sync {
    /// Stable short name, used in error records (e.g. `"hashes"`).
    fn name(&self) -> &'static str;

    /// Whether this analyzer should run for the given format.
    fn applies_to(&self, format: Format) -> bool;

    /// Runs the analysis, writing results into `out`.
    ///
    /// # Errors
    /// Returns an [`AnalysisError`] on partial or total failure. Anything
    /// already written to `out` is kept.
    fn run(&self, ctx: &AnalysisContext<'_>, out: &mut ReportBuilder) -> Result<(), AnalysisError>;
}

/// Ordered set of analyzers to run on each file.
pub struct Registry {
    analyzers: Vec<Box<dyn Analyzer>>,
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.analyzers.iter().map(|a| a.name()))
            .finish()
    }
}

impl Default for Registry {
    /// All built-in analyzers.
    fn default() -> Self {
        Self::empty()
            .with(hashes::HashesAnalyzer)
            .with(entropy::EntropyAnalyzer)
    }
}

impl Registry {
    /// A registry with no analyzers.
    pub fn empty() -> Self {
        Self {
            analyzers: Vec::new(),
        }
    }

    /// Adds an analyzer.
    #[must_use]
    pub fn with(mut self, analyzer: impl Analyzer + 'static) -> Self {
        self.analyzers.push(Box::new(analyzer));
        self
    }

    /// Names of the registered analyzers, in registration order.
    pub fn names(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.analyzers.iter().map(|a| a.name())
    }

    /// Runs every applicable analyzer on `input` and assembles the report.
    pub fn analyze(&self, input: &Input, config: &Config) -> Report {
        let ctx = AnalysisContext {
            input,
            limits: &config.limits,
            thresholds: &config.thresholds,
        };
        let mut out = ReportBuilder::new(input.file_info());
        for analyzer in self.analyzers.iter().filter(|a| a.applies_to(input.format)) {
            if let Err(err) = analyzer.run(&ctx, &mut out) {
                out.push_error(analyzer.name(), err);
            }
        }
        // Scoring lands in M2; until then every report is clean-looking.
        out.finish(Risk::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{Category, Finding, Severity};

    struct Failing;
    impl Analyzer for Failing {
        fn name(&self) -> &'static str {
            "failing"
        }
        fn applies_to(&self, _: Format) -> bool {
            true
        }
        fn run(&self, _: &AnalysisContext<'_>, _: &mut ReportBuilder) -> Result<(), AnalysisError> {
            Err(AnalysisError::Malformed {
                what: "test",
                reason: "boom".into(),
            })
        }
    }

    struct EmitsFinding;
    impl Analyzer for EmitsFinding {
        fn name(&self) -> &'static str {
            "emits"
        }
        fn applies_to(&self, _: Format) -> bool {
            true
        }
        fn run(
            &self,
            _: &AnalysisContext<'_>,
            out: &mut ReportBuilder,
        ) -> Result<(), AnalysisError> {
            out.push_finding(Finding::new(
                "TEST-FINDING",
                Severity::Info,
                Category::Metadata,
                "t",
            ));
            Ok(())
        }
    }

    struct PeOnly;
    impl Analyzer for PeOnly {
        fn name(&self) -> &'static str {
            "pe-only"
        }
        fn applies_to(&self, format: Format) -> bool {
            format == Format::Pe
        }
        fn run(&self, _: &AnalysisContext<'_>, _: &mut ReportBuilder) -> Result<(), AnalysisError> {
            panic!("must not run on non-PE input");
        }
    }

    fn unknown_input() -> Input {
        Input::from_bytes("x.bin", b"not a binary".to_vec())
    }

    #[test]
    fn failing_analyzer_does_not_stop_others() {
        let report = Registry::empty()
            .with(Failing)
            .with(EmitsFinding)
            .analyze(&unknown_input(), &Config::default());
        assert_eq!(report.errors.len(), 1);
        assert_eq!(report.errors[0].analyzer, "failing");
        assert_eq!(report.findings.len(), 1);
    }

    #[test]
    fn analyzers_are_filtered_by_format() {
        let report = Registry::empty()
            .with(PeOnly)
            .analyze(&unknown_input(), &Config::default());
        assert!(report.errors.is_empty());
    }

    #[test]
    fn default_registry_includes_hashes() {
        assert!(Registry::default().names().any(|n| n == "hashes"));
    }
}

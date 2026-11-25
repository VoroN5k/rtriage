//! Analyzer trait and registry.
//!
//! Analyzers are independent and order-agnostic: each reads the input and
//! writes facts/findings into a [`ReportBuilder`]. If one fails, the failure
//! is recorded in the report and the remaining analyzers still run.
//!
//! Analyzers never read each other's output. Data several analyzers need
//! (extracted strings, later the parsed PE) is computed lazily, once, inside
//! [`AnalysisContext`].

pub mod elf;
pub mod entropy;
pub mod hashes;
pub mod pe;
pub mod strings;

use std::sync::OnceLock;
use std::time::SystemTime;

use crate::config::Config;
use crate::deadline::Deadline;
use crate::error::AnalysisError;
use crate::input::Input;
use crate::report::{Format, Report, ReportBuilder, Risk, StringsFacts};
use crate::rules::PackerRuleSet;

/// Data shared by all analyzers for one file. Derived data is computed on
/// first use and cached, so it is independent of analyzer order.
#[derive(Debug)]
pub struct AnalysisContext<'a> {
    /// The loaded file.
    pub input: &'a Input,
    /// Limits, thresholds and options for this run.
    pub config: &'a Config,
    /// Wall-clock deadline for this file.
    pub deadline: Deadline,
    /// Time the analysis started; used for "in the future" checks so all
    /// analyzers of one file agree on "now".
    pub now: SystemTime,
    strings: OnceLock<Result<StringsFacts, AnalysisError>>,
    pe: OnceLock<Result<pe::PeImage, AnalysisError>>,
    pe_imports: OnceLock<Option<pe::imports::ParsedImports>>,
    elf: OnceLock<Result<elf::ElfImage, AnalysisError>>,
    elf_dynamic: OnceLock<Option<Result<elf::dynamic::ElfDynamic, AnalysisError>>>,
}

impl<'a> AnalysisContext<'a> {
    /// Creates a context; nothing is computed yet.
    pub fn new(input: &'a Input, config: &'a Config, deadline: Deadline) -> Self {
        Self {
            input,
            config,
            deadline,
            now: SystemTime::now(),
            strings: OnceLock::new(),
            pe: OnceLock::new(),
            pe_imports: OnceLock::new(),
            elf: OnceLock::new(),
            elf_dynamic: OnceLock::new(),
        }
    }

    /// Dynamic section and symbols of an ELF (see [`elf::dynamic`]).
    /// `None` if the input is not an ELF or its headers failed to parse.
    pub fn elf_dynamic(&self) -> Option<Result<&elf::dynamic::ElfDynamic, AnalysisError>> {
        self.elf_dynamic
            .get_or_init(|| {
                let image = self.elf().ok()?;
                Some(elf::dynamic::parse(
                    image,
                    &self.input.data,
                    &self.config.limits,
                    &self.deadline,
                ))
            })
            .as_ref()
            .map(|r| r.as_ref().map_err(Clone::clone))
    }

    /// Parsed ELF headers and tables. Parsed on first call, then cached.
    ///
    /// # Errors
    /// [`AnalysisError::Malformed`] if the input is not an ELF file, otherwise
    /// whatever [`elf::parse`] reports.
    pub fn elf(&self) -> Result<&elf::ElfImage, AnalysisError> {
        self.elf
            .get_or_init(|| {
                if self.input.format == Format::Elf {
                    elf::parse(&self.input.data, &self.config.limits)
                } else {
                    Err(AnalysisError::Malformed {
                        what: "ELF",
                        reason: "input is not an ELF file".into(),
                    })
                }
            })
            .as_ref()
            .map_err(Clone::clone)
    }

    /// Parsed PE import table (best effort, see [`pe::imports::ParsedImports`]).
    /// `None` if the input is not a PE or its headers failed to parse.
    pub fn pe_imports(&self) -> Option<&pe::imports::ParsedImports> {
        self.pe_imports
            .get_or_init(|| {
                let image = self.pe().ok()?;
                Some(pe::imports::parse(
                    image,
                    &self.input.data,
                    &self.config.limits,
                    &self.deadline,
                ))
            })
            .as_ref()
    }

    /// Parsed PE headers and section table. Parsed on first call, then cached.
    ///
    /// # Errors
    /// [`AnalysisError::Malformed`] if the input is not a PE file, otherwise
    /// whatever [`pe::parse`] reports (truncation, limits, parser failure).
    pub fn pe(&self) -> Result<&pe::PeImage, AnalysisError> {
        self.pe
            .get_or_init(|| {
                if self.input.format == Format::Pe {
                    pe::parse(&self.input.data, &self.config.limits)
                } else {
                    Err(AnalysisError::Malformed {
                        what: "PE",
                        reason: "input is not a PE file".into(),
                    })
                }
            })
            .as_ref()
            .map_err(Clone::clone)
    }

    /// Extracted and classified strings (all of them, up to `max_strings`).
    /// Computed on first call; later calls return the cached result.
    ///
    /// # Errors
    /// [`AnalysisError::Timeout`] if the deadline passed during extraction,
    /// [`AnalysisError::Internal`] if the classifier is unavailable.
    pub fn strings(&self) -> Result<&StringsFacts, AnalysisError> {
        self.strings
            .get_or_init(|| strings::extract_classified(self.input, self.config, &self.deadline))
            .as_ref()
            .map_err(Clone::clone)
    }
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
            .with(strings::StringsAnalyzer)
            .with(pe::PeParseAnalyzer)
            .with(pe::headers::PeHeadersAnalyzer)
            .with(pe::sections::PeSectionsAnalyzer)
            .with(pe::imports::PeImportsAnalyzer)
            .with(pe::api_groups::PeApiGroupsAnalyzer)
            .with(pe::overlay::PeOverlayAnalyzer)
            .with(pe::tls::PeTlsAnalyzer)
            .with(pe::debug::PeDebugAnalyzer)
            .with(pe::packers::PePackersAnalyzer)
            .with(pe::rich::PeRichAnalyzer)
            .with(pe::exports::PeExportsAnalyzer)
            .with(pe::resources::PeResourcesAnalyzer)
            .with(pe::authenticode::PeSignatureAnalyzer)
            .with(elf::ElfParseAnalyzer)
            .with(elf::headers::ElfHeadersAnalyzer)
            .with(elf::segments::ElfSegmentsAnalyzer)
            .with(elf::checksec::ElfChecksecAnalyzer)
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

    /// Runs every applicable analyzer on `input` within
    /// `config.limits.max_analysis_time` and assembles the report.
    pub fn analyze(&self, input: &Input, config: &Config) -> Report {
        let deadline = Deadline::after(config.limits.max_analysis_time);
        self.analyze_with_deadline(input, config, deadline)
    }

    /// Like [`Registry::analyze`] with an explicit deadline. Once it passes,
    /// every remaining analyzer is recorded as timed out instead of running,
    /// so the report stays valid but partial.
    pub fn analyze_with_deadline(
        &self,
        input: &Input,
        config: &Config,
        deadline: Deadline,
    ) -> Report {
        let ctx = AnalysisContext::new(input, config, deadline);
        let mut out = ReportBuilder::new(input.file_info());
        for analyzer in self.analyzers.iter().filter(|a| a.applies_to(input.format)) {
            let result = deadline.check().and_then(|()| analyzer.run(&ctx, &mut out));
            if let Err(err) = result {
                out.push_error(analyzer.name(), err);
            }
        }
        let mut report = out.finish(Risk::default());
        let rules = match &config.packer_rules {
            Some(custom) => Some(custom.as_ref()),
            None => PackerRuleSet::bundled().ok(),
        };
        match rules {
            Some(rules) => crate::scoring::score(&mut report, rules),
            None => {
                // Bundled rules broken (a bug, prevented by tests): score
                // without explanations rather than not at all.
                report.errors.push(crate::report::AnalyzerFailure {
                    analyzer: "scoring",
                    error: AnalysisError::Internal {
                        reason: "bundled packer rules are invalid".into(),
                    },
                });
                crate::scoring::score(
                    &mut report,
                    &PackerRuleSet {
                        packers: Vec::new(),
                    },
                );
            }
        }
        report
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

    #[test]
    fn expired_deadline_yields_valid_partial_report() {
        let input = Input::from_bytes("x.bin", b"\x00http://a.example.com/\x00".to_vec());
        let report = Registry::default().analyze_with_deadline(
            &input,
            &Config::default(),
            Deadline::expired(),
        );
        let names: Vec<_> = report.errors.iter().map(|e| e.analyzer).collect();
        assert_eq!(names, ["entropy", "hashes", "strings"]);
        assert!(report
            .errors
            .iter()
            .all(|e| matches!(e.error, AnalysisError::Timeout { .. })));
        assert!(report.file.hashes.is_none());
    }

    /// Reads strings twice; both calls must return the same cached value.
    struct ReadsStringsTwice;
    impl Analyzer for ReadsStringsTwice {
        fn name(&self) -> &'static str {
            "reads-strings"
        }
        fn applies_to(&self, _: Format) -> bool {
            true
        }
        fn run(
            &self,
            ctx: &AnalysisContext<'_>,
            _: &mut ReportBuilder,
        ) -> Result<(), AnalysisError> {
            let a = ctx.strings()?;
            let b = ctx.strings()?;
            assert!(std::ptr::eq(a, b), "strings must be computed once");
            assert_eq!(a.items.len(), 1);
            Ok(())
        }
    }

    #[test]
    fn strings_are_computed_once_and_shared() {
        let input = Input::from_bytes("x.bin", b"\x00http://a.example.com/\x00".to_vec());
        let report = Registry::default()
            .with(ReadsStringsTwice)
            .analyze(&input, &Config::default());
        assert!(report.errors.is_empty());
        let strings = report.facts.strings.unwrap();
        assert_eq!(strings.items[0].value, "http://a.example.com/");
    }
}

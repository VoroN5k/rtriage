//! Report model: what analyzers produce and renderers consume.
//!
//! - **Facts** are neutral extracted data (sections, imports, ...).
//! - **Findings** are judgments, each backed by concrete [`Evidence`].
//!
//! Keeping them separate lets output be re-scored without re-parsing.

use serde::Serialize;

use crate::error::AnalysisError;

/// Detected container format of the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Format {
    /// Windows Portable Executable (`MZ` + `PE\0\0`).
    Pe,
    /// Executable and Linkable Format (`\x7fELF`).
    Elf,
    /// Anything else. Format-independent analyzers still run.
    Unknown,
}

/// Basic identity of the analysed file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileInfo {
    /// Path as given by the user, lossily converted to UTF-8.
    pub path: String,
    /// Size in bytes.
    pub size: u64,
    /// Detected format.
    pub format: Format,
    /// Cryptographic hashes; `None` until the hashes analyzer has run.
    pub hashes: Option<Hashes>,
}

/// Cryptographic hashes of the whole file, as lowercase hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Hashes {
    /// MD5 (32 hex chars). Weak, kept for compatibility with threat-intel feeds.
    pub md5: String,
    /// SHA-1 (40 hex chars). Weak, kept for compatibility with threat-intel feeds.
    pub sha1: String,
    /// SHA-256 (64 hex chars).
    pub sha256: String,
}

/// Neutral data extracted from the file. Analyzers add fields as they land.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Facts {
    /// Entropy profile; `None` until the entropy analyzer has run.
    pub entropy: Option<EntropyFacts>,
}

/// Shannon entropy summary of the whole file.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EntropyFacts {
    /// Entropy of the entire file, in bits per byte (0.0–8.0).
    pub whole_file: f64,
    /// Window size used for region detection, in bytes.
    pub window: u64,
    /// Threshold a window had to reach to count as high-entropy.
    pub high_threshold: f64,
    /// Maximal runs of consecutive high-entropy windows, in file order.
    pub high_regions: Vec<EntropyRegion>,
}

/// A contiguous byte range whose windows all reached the high-entropy threshold.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EntropyRegion {
    /// Start offset in the file.
    pub offset: u64,
    /// Length in bytes (a multiple of the window size).
    pub len: u64,
    /// Entropy of the whole region, in bits per byte.
    pub entropy: f64,
}

/// How serious a finding is if it is meaningful. Ordered `Info < Low < Medium < High`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Context for the analyst; does not raise suspicion on its own.
    Info,
    /// Weak signal.
    Low,
    /// Notable signal.
    Medium,
    /// Strong signal.
    High,
}

/// How likely the finding is to be meaningful rather than a false positive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Heuristic with known false positives.
    Low,
    /// Usually meaningful.
    Medium,
    /// Strong, specific indicator.
    High,
}

/// Behavioral area a finding belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Category {
    /// Packing, compression, encryption of code.
    Packing,
    /// Obfuscation such as dynamic API resolution.
    Obfuscation,
    /// Anti-debugging / anti-analysis tricks.
    AntiAnalysis,
    /// Code injection into other processes.
    Injection,
    /// Surviving reboots (run keys, services, cron, ...).
    Persistence,
    /// Network communication / C2.
    Network,
    /// Credential theft.
    CredentialAccess,
    /// Input capture, keylogging.
    Collection,
    /// Destructive or ransomware-like behaviour.
    Impact,
    /// Missing exploit mitigations (NX, RELRO, PIE, ...).
    Hardening,
    /// Structural oddities in the file format.
    Anomaly,
    /// Neutral metadata (compiler, build paths, signatures).
    Metadata,
}

/// Text encoding of an extracted string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StringEncoding {
    /// 7-bit printable ASCII.
    Ascii,
    /// UTF-16 little-endian.
    Utf16Le,
}

/// One concrete piece of data that supports a finding.
///
/// String fields hold raw, attacker-controlled data; renderers must sanitize them.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Evidence {
    /// A byte range in the file.
    Range {
        /// Start offset.
        offset: u64,
        /// Length in bytes.
        len: u64,
    },
    /// A section (PE) or section header (ELF).
    Section {
        /// Section index in the header table.
        index: usize,
        /// Section name.
        name: String,
    },
    /// An imported symbol.
    Import {
        /// Providing library (DLL for PE, `DT_NEEDED` is not per-symbol for ELF so may be `None`).
        library: Option<String>,
        /// Symbol name, or `#<ordinal>` for ordinal-only imports.
        symbol: String,
    },
    /// An extracted string.
    String {
        /// File offset of the string.
        offset: u64,
        /// Encoding it was found in.
        encoding: StringEncoding,
        /// Decoded value.
        value: String,
    },
    /// A numeric measurement, e.g. `entropy = 7.93`.
    Metric {
        /// What was measured.
        name: &'static str,
        /// Measured value.
        value: f64,
    },
    /// A named field and its value, e.g. `TimeDateStamp = 0`.
    Field {
        /// Field name.
        name: &'static str,
        /// Field value as text.
        value: String,
    },
}

/// A judgment about the file, always backed by evidence.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Finding {
    /// Stable identifier, e.g. `"PE-SECTION-RWX"`. Documented in `docs/heuristics.md`.
    pub id: &'static str,
    /// Severity if meaningful.
    pub severity: Severity,
    /// Likelihood of being meaningful.
    pub confidence: Confidence,
    /// Behavioral area.
    pub category: Category,
    /// One-line summary.
    pub title: String,
    /// Longer explanation for the analyst.
    pub detail: String,
    /// Concrete data that triggered the finding.
    pub evidence: Vec<Evidence>,
    /// MITRE ATT&CK technique IDs, e.g. `"T1055"`.
    pub attack: Vec<&'static str>,
}

impl Finding {
    /// Starts a finding with medium confidence and no detail, evidence or ATT&CK IDs.
    pub fn new(
        id: &'static str,
        severity: Severity,
        category: Category,
        title: impl Into<String>,
    ) -> Self {
        Self {
            id,
            severity,
            confidence: Confidence::Medium,
            category,
            title: title.into(),
            detail: String::new(),
            evidence: Vec::new(),
            attack: Vec::new(),
        }
    }

    /// Sets the confidence.
    #[must_use]
    pub fn confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    /// Sets the detail text.
    #[must_use]
    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }

    /// Appends one piece of evidence.
    #[must_use]
    pub fn evidence(mut self, evidence: Evidence) -> Self {
        self.evidence.push(evidence);
        self
    }

    /// Appends an ATT&CK technique ID.
    #[must_use]
    pub fn attack(mut self, technique: &'static str) -> Self {
        self.attack.push(technique);
        self
    }
}

/// Aggregate risk level. Ordered `CleanLooking < Low < Medium < High`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    /// Nothing notable found. Not a guarantee the file is benign.
    #[default]
    CleanLooking,
    /// Weak signals only.
    Low,
    /// Notable signals.
    Medium,
    /// Strong signals.
    High,
}

/// Aggregate risk: a numeric score for sorting plus its level.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Risk {
    /// Score used to sort files in batch mode.
    pub score: u32,
    /// Level derived from the score.
    pub level: RiskLevel,
}

/// An analyzer that failed, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnalyzerFailure {
    /// Name of the analyzer.
    pub analyzer: &'static str,
    /// What went wrong.
    pub error: AnalysisError,
}

/// Complete result of triaging one file.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Report {
    /// File identity.
    pub file: FileInfo,
    /// Neutral extracted data.
    pub facts: Facts,
    /// Judgments, sorted most severe first.
    pub findings: Vec<Finding>,
    /// Aggregate risk.
    pub risk: Risk,
    /// Analyzers that failed partially or completely.
    pub errors: Vec<AnalyzerFailure>,
}

/// Collects analyzer output and assembles a deterministic [`Report`].
#[derive(Debug)]
pub struct ReportBuilder {
    file: FileInfo,
    /// Facts, filled in directly by analyzers.
    pub facts: Facts,
    findings: Vec<Finding>,
    errors: Vec<AnalyzerFailure>,
}

impl ReportBuilder {
    /// Starts an empty report for `file`.
    pub fn new(file: FileInfo) -> Self {
        Self {
            file,
            facts: Facts::default(),
            findings: Vec::new(),
            errors: Vec::new(),
        }
    }

    /// Adds a finding.
    pub fn push_finding(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    /// Records a failed analyzer.
    pub fn push_error(&mut self, analyzer: &'static str, error: AnalysisError) {
        self.errors.push(AnalyzerFailure { analyzer, error });
    }

    /// Read-only view of findings collected so far (used by scoring).
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// Records the file hashes.
    pub fn set_hashes(&mut self, hashes: Hashes) {
        self.file.hashes = Some(hashes);
    }

    /// Finishes the report with the given risk.
    ///
    /// Findings are sorted by severity (desc), confidence (desc), then id, so
    /// output is deterministic regardless of analyzer order.
    pub fn finish(mut self, risk: Risk) -> Report {
        self.findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then(b.confidence.cmp(&a.confidence))
                .then(a.id.cmp(b.id))
        });
        self.errors.sort_by(|a, b| a.analyzer.cmp(b.analyzer));
        Report {
            file: self.file,
            facts: self.facts,
            findings: self.findings,
            risk,
            errors: self.errors,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file() -> FileInfo {
        FileInfo {
            path: "sample.bin".into(),
            size: 0,
            format: Format::Unknown,
            hashes: None,
        }
    }

    #[test]
    fn severity_orders_info_to_high() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
    }

    #[test]
    fn finish_sorts_findings_deterministically() {
        let mut b = ReportBuilder::new(file());
        b.push_finding(Finding::new("B-LOW", Severity::Low, Category::Anomaly, "b"));
        b.push_finding(Finding::new(
            "Z-HIGH",
            Severity::High,
            Category::Packing,
            "z",
        ));
        b.push_finding(Finding::new("A-LOW", Severity::Low, Category::Anomaly, "a"));
        b.push_finding(
            Finding::new("C-HIGH", Severity::High, Category::Packing, "c")
                .confidence(Confidence::Low),
        );

        let ids: Vec<_> = b
            .finish(Risk::default())
            .findings
            .iter()
            .map(|f| f.id)
            .collect();
        assert_eq!(ids, ["Z-HIGH", "C-HIGH", "A-LOW", "B-LOW"]);
    }

    #[test]
    fn finish_keeps_errors() {
        let mut b = ReportBuilder::new(file());
        b.push_error(
            "pe",
            AnalysisError::Malformed {
                what: "PE header",
                reason: "bad magic".into(),
            },
        );
        assert_eq!(b.finish(Risk::default()).errors.len(), 1);
    }

    #[test]
    fn finding_serializes_with_tagged_evidence() {
        let f = Finding::new(
            "PE-SECTION-RWX",
            Severity::High,
            Category::Anomaly,
            "RWX section",
        )
        .evidence(Evidence::Section {
            index: 1,
            name: ".text".into(),
        })
        .attack("T1055");

        let json = serde_json::to_value(&f).unwrap();
        assert_eq!(json["severity"], "high");
        assert_eq!(json["evidence"][0]["type"], "section");
        assert_eq!(json["evidence"][0]["name"], ".text");
        assert_eq!(json["attack"][0], "T1055");
    }
}

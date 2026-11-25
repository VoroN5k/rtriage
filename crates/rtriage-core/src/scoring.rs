//! Scoring v1: deterministic, integer-only, explainable.
//!
//! The full specification (points table, caps, ordering, levels, the
//! explained-by rule) is in `docs/heuristics.md`, "Scoring v1". This module
//! is a direct transcription of it; keep the two in sync.
//!
//! Scoring reads only findings and facts, never the input file, so a report
//! can be re-scored without re-parsing.

use std::collections::BTreeSet;

use crate::report::{
    AnalysisLimit, Category, Confidence, ExplainerKind, Finding, Reduction, Report, Risk,
    RiskLevel, ScoreEntry, Severity, Suppression,
};
use crate::rules::{PackerFormat, PackerRuleSet};

/// ID of the finding that names a packer; explanations are attributed to it.
pub const PACKER_FINDING: &str = "PE-PACKER-KNOWN";
/// Findings that make [`AnalysisLimit::Packed`] apply.
const PACKED_FINDINGS: &[&str] = &[
    "PE-PACKER-KNOWN",
    "PE-PACKED-LIKELY",
    "ELF-PACKER-KNOWN",
    "ELF-PACKED-LIKELY",
];
/// Global cap on points from low-severity findings.
pub const LOW_SEVERITY_CAP: u32 = 15;

/// Points for a finding: the fixed table from `docs/heuristics.md`.
pub fn table_points(severity: Severity, confidence: Confidence) -> u32 {
    use Confidence as C;
    use Severity as S;
    match (severity, confidence) {
        (S::High, C::High) => 40,
        (S::High, C::Medium) => 28,
        (S::High, C::Low) => 16,
        (S::Medium, C::High) => 15,
        (S::Medium, C::Medium) => 11,
        (S::Medium, C::Low) => 6,
        (S::Low, C::High) => 5,
        (S::Low, C::Medium) => 4,
        (S::Low, C::Low) => 2,
        (S::Info, _) => 0,
    }
}

/// Per-category cap. The match is exhaustive on purpose: a new category does
/// not compile until it is given a cap here and in `docs/heuristics.md`.
pub fn category_cap(category: Category) -> u32 {
    match category {
        Category::Packing | Category::Obfuscation => 30,
        Category::Anomaly => 20,
        Category::AntiAnalysis => 15,
        Category::Hardening => 10,
        Category::Metadata => 0,
        Category::Injection
        | Category::Persistence
        | Category::Network
        | Category::CredentialAccess
        | Category::Collection
        | Category::Impact => 40,
    }
}

/// Level for a score.
pub fn level_for(score: u32) -> RiskLevel {
    match score {
        0..=9 => RiskLevel::CleanLooking,
        10..=29 => RiskLevel::Low,
        30..=59 => RiskLevel::Medium,
        _ => RiskLevel::High,
    }
}

/// Applies packer explanations, sets `analysis_limited`, and computes the risk.
pub fn score(report: &mut Report, packer_rules: &PackerRuleSet) {
    explain(report, packer_rules);
    if report
        .findings
        .iter()
        .any(|f| PACKED_FINDINGS.contains(&f.id))
    {
        report.analysis_limited = vec![AnalysisLimit::Packed];
    }
    report.risk = compute(&report.findings);
}

/// Marks findings explained by a **confirmed** packer or runtime.
///
/// A packer is confirmed only when every indicator its rule requires was
/// found (per format: `facts.pe.packers` / `facts.elf.packers`); a runtime
/// when `facts.runtime` lists at least its `confirm_min` indicators. Packers
/// take precedence. API groups can never be explained (enforced when rules
/// are loaded, and again here).
pub fn explain(report: &mut Report, rules: &PackerRuleSet) {
    let pe = report
        .facts
        .pe
        .as_ref()
        .and_then(|pe| pe.packers.as_deref());
    let elf = report.facts.elf.as_ref().and_then(|e| e.packers.as_deref());
    let mut explainers: Vec<(Suppression, &[&'static str])> = Vec::new();
    for rule in &rules.packers {
        let detected = match rule.format {
            PackerFormat::Pe => pe,
            PackerFormat::Elf => elf,
        };
        let confirmed = detected.is_some_and(|d| {
            d.iter()
                .any(|d| d.name == rule.name && rule.is_confirmed_by(&d.indicators))
        });
        if confirmed {
            explainers.push((
                Suppression {
                    kind: ExplainerKind::Packer,
                    name: rule.name,
                    by: Some(rule.format.finding_id()),
                },
                rule.explains.as_slice(),
            ));
        }
    }
    if let Some(rt) = &report.facts.runtime {
        if let Some(rule) = rules
            .runtimes
            .iter()
            .find(|r| r.name == rt.language && rt.indicators.len() >= r.confirm_min)
        {
            explainers.push((
                Suppression {
                    kind: ExplainerKind::Runtime,
                    name: rule.name,
                    by: None,
                },
                rule.explains.as_slice(),
            ));
        }
    }
    for f in &mut report.findings {
        if f.suppressed.is_some() || f.id.starts_with("PE-API-") || f.id.starts_with("ELF-API-") {
            continue;
        }
        if let Some((s, _)) = explainers.iter().find(|(_, ids)| ids.contains(&f.id)) {
            f.suppressed = Some(s.clone());
        }
    }
}
/// Computes the score of `findings` (see module docs for the algorithm).
pub fn compute(findings: &[Finding]) -> Risk {
    let mut order: Vec<&Finding> = findings.iter().collect();
    // Stable: equal keys keep report order, which decides duplicate ties.
    order.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(b.confidence.cmp(&a.confidence))
            .then(a.id.as_bytes().cmp(b.id.as_bytes()))
    });

    let mut used_by_category: Vec<(Category, u32)> = Vec::new();
    let mut low_used = 0u32;
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut breakdown = Vec::with_capacity(order.len());
    let mut score = 0u32;

    for f in order {
        let table = table_points(f.severity, f.confidence);
        let mut entry = ScoreEntry {
            id: f.id,
            category: f.category,
            table_points: table,
            points: 0,
            reduced_by: None,
        };
        if let Some(s) = &f.suppressed {
            entry.reduced_by = (table > 0).then_some(Reduction::Suppressed {
                explainer: s.kind,
                name: s.name,
                by: s.by,
            });
            breakdown.push(entry);
            continue;
        }
        if !seen.insert(f.id) {
            entry.reduced_by = (table > 0).then_some(Reduction::Duplicate);
            breakdown.push(entry);
            continue;
        }
        let cap = category_cap(f.category);
        let used = used_by_category
            .iter()
            .find(|(c, _)| *c == f.category)
            .map_or(0, |(_, u)| *u);
        let cat_left = cap.saturating_sub(used);
        let low_left = if f.severity == Severity::Low {
            LOW_SEVERITY_CAP.saturating_sub(low_used)
        } else {
            u32::MAX
        };
        let points = table.min(cat_left).min(low_left);
        if points < table {
            entry.reduced_by = Some(if cat_left <= low_left {
                Reduction::CategoryCap { cap }
            } else {
                Reduction::LowSeverityCap {
                    cap: LOW_SEVERITY_CAP,
                }
            });
        }
        match used_by_category.iter_mut().find(|(c, _)| *c == f.category) {
            Some((_, u)) => *u += points,
            None => used_by_category.push((f.category, points)),
        }
        if f.severity == Severity::Low {
            low_used += points;
        }
        score += points;
        entry.points = points;
        breakdown.push(entry);
    }

    Risk {
        score,
        level: level_for(score),
        breakdown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Category as Cat;
    use Confidence as C;
    use Severity as S;

    fn f(id: &'static str, s: Severity, c: Confidence, cat: Category) -> Finding {
        Finding::new(id, s, cat, id).confidence(c)
    }

    #[test]
    fn table_matches_documented_formula() {
        // (severity weight * confidence% + 50) / 100, round half up.
        for (s, w) in [(S::High, 40), (S::Medium, 15), (S::Low, 5), (S::Info, 0)] {
            for (c, pct) in [(C::High, 100), (C::Medium, 70), (C::Low, 40)] {
                assert_eq!(table_points(s, c), (w * pct + 50) / 100, "{s:?} {c:?}");
            }
        }
    }

    #[test]
    fn levels() {
        assert_eq!(level_for(0), RiskLevel::CleanLooking);
        assert_eq!(level_for(9), RiskLevel::CleanLooking);
        assert_eq!(level_for(10), RiskLevel::Low);
        assert_eq!(level_for(29), RiskLevel::Low);
        assert_eq!(level_for(30), RiskLevel::Medium);
        assert_eq!(level_for(59), RiskLevel::Medium);
        assert_eq!(level_for(60), RiskLevel::High);
    }

    #[test]
    fn empty_is_clean() {
        let r = compute(&[]);
        assert_eq!((r.score, r.level), (0, RiskLevel::CleanLooking));
    }

    #[test]
    fn single_injection_is_medium() {
        let r = compute(&[f("PE-API-INJECTION", S::High, C::High, Cat::Injection)]);
        assert_eq!((r.score, r.level), (40, RiskLevel::Medium));
    }

    #[test]
    fn category_cap_cuts_weakest_last() {
        let r = compute(&[
            f("B", S::Medium, C::Medium, Cat::Packing), // 11
            f("A", S::Medium, C::High, Cat::Packing),   // 15, first
            f("C", S::Medium, C::Medium, Cat::Packing), // 11 -> 4
        ]);
        assert_eq!(r.score, 30);
        let pts: Vec<_> = r.breakdown.iter().map(|e| (e.id, e.points)).collect();
        assert_eq!(pts, [("A", 15), ("B", 11), ("C", 4)]);
        assert_eq!(
            r.breakdown[2].reduced_by,
            Some(Reduction::CategoryCap { cap: 30 })
        );
    }

    #[test]
    fn low_severity_cap() {
        let lows: Vec<Finding> = ["L1", "L2", "L3", "L4", "L5"]
            .into_iter()
            .map(|id| f(id, S::Low, C::Medium, Cat::Network)) // 4 each
            .collect();
        let r = compute(&lows);
        assert_eq!(r.score, LOW_SEVERITY_CAP);
        assert_eq!(
            r.breakdown[3].reduced_by,
            Some(Reduction::LowSeverityCap { cap: 15 })
        );
        assert_eq!(r.breakdown[4].points, 0);
    }

    #[test]
    fn duplicates_count_once_with_max_points() {
        let r = compute(&[
            f("X", S::Low, C::Low, Cat::Packing),
            f("X", S::Medium, C::Medium, Cat::Packing),
        ]);
        assert_eq!(r.score, 11);
        assert_eq!(r.breakdown[1].reduced_by, Some(Reduction::Duplicate));
    }

    #[test]
    fn suppressed_findings_score_nothing_and_use_no_cap() {
        let mut sup = f("S", S::Medium, C::High, Cat::Packing);
        sup.suppressed = Some(Suppression {
            kind: ExplainerKind::Packer,
            name: "UPX",
            by: Some(PACKER_FINDING),
        });
        let r = compute(&[
            sup,
            f("A", S::Medium, C::High, Cat::Packing),
            f("B", S::Medium, C::High, Cat::Packing),
        ]);
        // Without suppression A+B+S would be capped at 30; S takes no room.
        assert_eq!(r.score, 30);
        let s = r.breakdown.iter().find(|e| e.id == "S").unwrap();
        assert_eq!(s.points, 0);
        assert!(matches!(
            s.reduced_by,
            Some(Reduction::Suppressed { name: "UPX", .. })
        ));
    }

    #[test]
    fn result_is_independent_of_input_order() {
        let mut a = vec![
            f("P1", S::Medium, C::High, Cat::Packing),
            f("P2", S::Medium, C::Medium, Cat::Packing),
            f("P3", S::Medium, C::Medium, Cat::Packing),
            f("L", S::Low, C::Medium, Cat::AntiAnalysis),
            f("I", S::High, C::High, Cat::Injection),
        ];
        let r1 = compute(&a);
        a.reverse();
        let r2 = compute(&a);
        assert_eq!(r1, r2);
        assert_eq!(r1.score, 30 + 4 + 40);
    }

    #[test]
    fn metadata_never_scores() {
        let r = compute(&[f("M", S::High, C::High, Cat::Metadata)]);
        assert_eq!(r.score, 0);
    }

    // ------------------------------------------------- end-to-end on fixtures

    mod end_to_end {
        use super::super::*;
        use crate::config::Config;
        use crate::input::Input;
        use crate::Registry;
        use rtriage_fixtures::pe::{profiles, Arch, PeBuilder, Section};

        fn analyze(bytes: Vec<u8>) -> Report {
            let r =
                Registry::default().analyze(&Input::from_bytes("t.exe", bytes), &Config::default());
            assert!(r.errors.is_empty(), "{:?}", r.errors);
            r
        }

        fn suppressed(r: &Report) -> Vec<&'static str> {
            r.findings
                .iter()
                .filter(|f| f.suppressed.is_some())
                .map(|f| f.id)
                .collect()
        }

        const INJECTION: &[&str] = &[
            "OpenProcess",
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
        ];

        /// Positive: a confirmed UPX file scores only for being packed.
        #[test]
        fn confirmed_upx_scores_about_15() {
            for arch in [Arch::X86, Arch::X64] {
                let r = analyze(profiles::upx_like(arch).build().bytes);
                assert_eq!(r.risk.score, 15, "{:#?}", r.risk.breakdown);
                assert_eq!(r.risk.level, RiskLevel::Low);
                assert_eq!(r.analysis_limited, [AnalysisLimit::Packed]);
                let mut s = suppressed(&r);
                s.sort_unstable();
                assert_eq!(
                    s,
                    [
                        "PE-ENTRYPOINT-UNUSUAL",
                        "PE-IMPORTS-DYNAMIC-RESOLUTION",
                        "PE-SECTION-HIGH-ENTROPY",
                        "PE-SECTION-NAME-UNUSUAL",
                        "PE-SECTION-RWX",
                        "PE-SECTION-VIRTUAL-ONLY",
                    ]
                );
                // Suppressed findings are still in the report, with their reason.
                let rwx = r
                    .findings
                    .iter()
                    .find(|f| f.id == "PE-SECTION-RWX")
                    .unwrap();
                assert_eq!(
                    rwx.suppressed,
                    Some(Suppression {
                        kind: ExplainerKind::Packer,
                        name: "UPX",
                        by: Some("PE-PACKER-KNOWN"),
                    })
                );
                let entry = r
                    .risk
                    .breakdown
                    .iter()
                    .find(|e| e.id == "PE-SECTION-RWX")
                    .unwrap();
                assert_eq!((entry.table_points, entry.points), (11, 0));
            }
        }

        /// Negative: UPX section names alone (spoofed) suppress nothing.
        #[test]
        fn spoofed_upx_names_do_not_suppress() {
            let bytes = PeBuilder::new(Arch::X64)
                .section(Section::rwx("UPX0", vec![0x90; 64]))
                .section(Section::data("UPX1", vec![0; 64]))
                .import("KERNEL32.dll", &["LoadLibraryA", "GetProcAddress"])
                .build()
                .bytes;
            let r = analyze(bytes);
            assert!(r.findings.iter().any(|f| f.id == "PE-PACKER-KNOWN"));
            assert!(suppressed(&r).is_empty(), "{:?}", suppressed(&r));
            // RWX and dynamic resolution still score.
            let scored: Vec<_> = r
                .risk
                .breakdown
                .iter()
                .filter(|e| e.points > 0)
                .map(|e| e.id)
                .collect();
            assert!(scored.contains(&"PE-SECTION-RWX"));
            assert!(scored.contains(&"PE-IMPORTS-DYNAMIC-RESOLUTION"));
        }

        /// Names + signature but no stub layout: still not confirmed.
        #[test]
        fn two_of_three_indicators_do_not_suppress() {
            let bytes = PeBuilder::new(Arch::X64)
                .header_extra(b"UPX!".to_vec())
                .section(Section::rwx("UPX0", vec![0x90; 64]))
                .section(Section::data("UPX1", vec![0; 64]))
                .build()
                .bytes;
            assert!(suppressed(&analyze(bytes)).is_empty());
        }

        /// Packed + injection: API groups are never suppressed; not below medium.
        #[test]
        fn packed_injection_stays_at_least_medium() {
            let mut imports: Vec<&str> = vec!["LoadLibraryA", "GetProcAddress", "VirtualProtect"];
            imports.extend_from_slice(INJECTION);
            let mut b = profiles::upx_like(Arch::X64);
            b = b
                .import("ADVAPI32.dll", &["RegCloseKey"])
                .import("KERNEL32.dll", &imports);
            let r = analyze(b.build().bytes);
            let inj = r
                .findings
                .iter()
                .find(|f| f.id == "PE-API-INJECTION")
                .unwrap();
            assert!(inj.suppressed.is_none());
            assert!(r.risk.level >= RiskLevel::Medium, "{:#?}", r.risk);
            assert_eq!(r.risk.score, 15 + 40);
        }

        #[test]
        fn upx_explains_encrypted_resources() {
            use rtriage_fixtures::pe::ResourceSpec;
            let payload: Vec<u8> = (0..8192u32).map(|i| (i % 256) as u8).collect();
            let r = analyze(
                profiles::upx_like(Arch::X64)
                    .resource(ResourceSpec::new(10, 1, payload))
                    .build()
                    .bytes,
            );
            assert!(suppressed(&r).contains(&"PE-RESOURCE-HIGH-ENTROPY"));
            assert_eq!(r.risk.score, 15);
        }

        #[test]
        fn reflective_dll_with_injection_chain_hits_injection_cap() {
            use rtriage_fixtures::pe::ExportSpec;
            let r = analyze(
                PeBuilder::minimal(Arch::X64)
                    .dll(true)
                    .import("KERNEL32.dll", INJECTION)
                    .exports("t.exe", vec![ExportSpec::named("ReflectiveLoader")])
                    .build()
                    .bytes,
            );
            let injection: u32 = r
                .risk
                .breakdown
                .iter()
                .filter(|e| e.category == Category::Injection)
                .map(|e| e.points)
                .sum();
            // Two 40-point injection findings, one category cap of 40.
            assert_eq!(injection, 40);
            assert!(r.risk.level >= RiskLevel::Medium);
        }

        #[test]
        fn calibration_injection_alone_is_medium() {
            let r = analyze(
                PeBuilder::minimal(Arch::X64)
                    .import("KERNEL32.dll", INJECTION)
                    .build()
                    .bytes,
            );
            // Injection 40 + PE-IMPORTS-FEW (Low/Low) 2.
            assert_eq!(r.risk.score, 42);
            assert_eq!(r.risk.level, RiskLevel::Medium);
        }

        #[test]
        fn benign_profiles_are_clean_looking() {
            for b in [
                profiles::dotnet_like(Arch::X86),
                profiles::go_like(Arch::X64),
            ] {
                let r = analyze(b.build().bytes);
                assert_eq!(r.risk.level, RiskLevel::CleanLooking, "{:#?}", r.risk);
                assert!(r.analysis_limited.is_empty());
            }
        }

        #[test]
        fn non_pe_files_score_zero() {
            let r = analyze(b"plain text, nothing to see".to_vec());
            assert_eq!((r.risk.score, r.risk.level), (0, RiskLevel::CleanLooking));
        }
    }

    mod elf_end_to_end {
        use super::super::*;
        use crate::config::Config;
        use crate::input::Input;
        use crate::Registry;
        use rtriage_fixtures::elf::{profiles, ElfBuilder};

        fn analyze(bytes: Vec<u8>) -> Report {
            let r = Registry::default().analyze(&Input::from_bytes("t", bytes), &Config::default());
            assert!(r.errors.is_empty(), "{:?}", r.errors);
            r
        }

        fn ids(r: &Report, suppressed: bool) -> Vec<&'static str> {
            let mut v: Vec<_> = r
                .findings
                .iter()
                .filter(|f| f.suppressed.is_some() == suppressed)
                .map(|f| f.id)
                .collect();
            v.sort_unstable();
            v
        }

        /// Positive: confirmed UPX ELF scores only for being packed.
        #[test]
        fn confirmed_upx_elf_scores_only_the_packer() {
            let r = analyze(profiles::upx_elf().build().bytes);
            assert_eq!(
                ids(&r, true),
                [
                    "ELF-HARDENING-NO-PIE",
                    "ELF-PACKED-LIKELY",
                    "ELF-SECTIONS-MISSING",
                    "ELF-SEGMENT-HIGH-ENTROPY",
                    "ELF-SEGMENT-RWX"
                ],
                "{:#?}",
                r.risk.breakdown
            );
            assert!(ids(&r, false).contains(&"ELF-PACKER-KNOWN"));
            assert_eq!(r.analysis_limited, [AnalysisLimit::Packed]);
            // Only the packer finding scores; the ET_EXEC stub's NO-PIE is explained.
            assert_eq!(r.risk.score, 15, "{:#?}", r.risk.breakdown);
            assert_eq!(r.risk.level, RiskLevel::Low, "{:#?}", r.risk.breakdown);
            let s = r
                .findings
                .iter()
                .find(|f| f.id == "ELF-SEGMENT-RWX")
                .unwrap();
            assert_eq!(
                s.suppressed,
                Some(Suppression {
                    kind: ExplainerKind::Packer,
                    name: "UPX",
                    by: Some("ELF-PACKER-KNOWN"),
                })
            );
        }

        /// Negative: a spoofed `UPX!` magic without the banner is not confirmed.
        #[test]
        fn spoofed_upx_magic_suppresses_nothing() {
            let bytes = ElfBuilder::x86_64()
                .section_headers(false)
                .after_phdrs(b"\0\0\0\0UPX!".to_vec())
                .text((0..8192).map(|i| (i % 256) as u8).collect())
                .build()
                .bytes;
            let r = analyze(bytes);
            assert!(ids(&r, false).contains(&"ELF-PACKER-KNOWN"));
            assert!(ids(&r, true).is_empty(), "{:?}", ids(&r, true));
        }

        /// Runtime facts explain only small hardening findings.
        #[test]
        fn go_runtime_explains_hardening_only() {
            let r = analyze(profiles::go_static().build().bytes);
            let sup = ids(&r, true);
            assert!(
                !sup.is_empty(),
                "{:#?}",
                r.findings.iter().map(|f| f.id).collect::<Vec<_>>()
            );
            for id in &sup {
                assert!(crate::rules::RUNTIME_EXPLAINABLE_IDS.contains(id), "{id}");
                let f = r.findings.iter().find(|f| f.id == *id).unwrap();
                assert_eq!(
                    f.suppressed.as_ref().map(|s| (s.kind, s.name, s.by)),
                    Some((ExplainerKind::Runtime, "go", None))
                );
            }
            assert_eq!(r.risk.level, RiskLevel::CleanLooking);
            assert!(r.analysis_limited.is_empty());
        }

        #[test]
        fn non_go_static_binary_keeps_hardening_points() {
            let r = analyze(profiles::busybox_static().build().bytes);
            assert!(ids(&r, true).is_empty(), "{:?}", ids(&r, true));
        }
    }
}

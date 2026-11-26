//! YARA scan of the whole file (cargo feature `yara`).
//!
//! One `YARA-MATCH` finding per matching rule (category from the rule's
//! `meta`, default `signature`, cap 40), with the rule name, tags and the
//! first matched ranges as evidence. Facts: `facts.yara`.
//!
//! Bounds: yara-x's own timeout is set to the time left on the file's
//! deadline (yara-x may overrun it slightly; in batch mode the parent's
//! worker kill is the hard limit), at most `max_yara_pattern_matches`
//! matches per pattern, `max_yara_matches` rules and
//! `max_yara_strings_per_rule` ranges per rule are kept. The scan runs under
//! `catch_unwind` like every third-party parser.

use std::time::Duration;

use crate::analyzers::pe::guarded;
use crate::analyzers::{AnalysisContext, Analyzer};
use crate::error::AnalysisError;
use crate::limits::Limits;
use crate::report::{
    Evidence, Finding, Format, ReportBuilder, YaraFacts, YaraMatch, YaraStringMatch,
};
use crate::yara::YaraRules;

/// Runs the configured YARA rules, if any.
#[derive(Debug, Clone, Copy, Default)]
pub struct YaraAnalyzer;

impl Analyzer for YaraAnalyzer {
    fn name(&self) -> &'static str {
        "yara"
    }

    fn applies_to(&self, _format: Format) -> bool {
        true
    }

    fn run(&self, ctx: &AnalysisContext<'_>, out: &mut ReportBuilder) -> Result<(), AnalysisError> {
        let Some(rules) = ctx.config.yara.as_deref() else {
            return Ok(());
        };
        ctx.deadline.check()?;
        let remaining = ctx.deadline.remaining();
        if remaining == Some(Duration::ZERO) {
            return Err(ctx.deadline.timeout_error());
        }
        let facts = guarded("YARA", || {
            scan(rules, &ctx.input.data, &ctx.config.limits, remaining)
        })?
        .map_err(|e| match e {
            ScanFailure::Timeout => ctx.deadline.timeout_error(),
            ScanFailure::Other(reason) => AnalysisError::Internal {
                reason: format!("YARA scan failed: {reason}"),
            },
        })?;
        for m in &facts.matches {
            out.push_finding(finding(rules, m));
        }
        out.facts.yara = Some(facts);
        Ok(())
    }
}

enum ScanFailure {
    Timeout,
    Other(String),
}

fn scan(
    rules: &YaraRules,
    data: &[u8],
    limits: &Limits,
    remaining: Option<Duration>,
) -> Result<YaraFacts, ScanFailure> {
    let mut scanner = yara_x::Scanner::new(rules.inner());
    scanner.max_matches_per_pattern(limits.max_yara_pattern_matches);
    if let Some(t) = remaining {
        scanner.set_timeout(t);
    }
    let results = scanner.scan(data).map_err(|e| match e {
        yara_x::ScanError::Timeout => ScanFailure::Timeout,
        other => ScanFailure::Other(other.to_string()),
    })?;
    let mut facts = YaraFacts {
        rules_loaded: rules.len(),
        ..YaraFacts::default()
    };
    for rule in results.matching_rules() {
        if facts.matches.len() >= limits.max_yara_matches {
            facts.limit_reached = true;
            break;
        }
        let mut strings = Vec::new();
        'patterns: for p in rule.patterns() {
            for m in p.matches() {
                if strings.len() >= limits.max_yara_strings_per_rule {
                    break 'patterns;
                }
                let r = m.range();
                strings.push(YaraStringMatch {
                    id: p.identifier().to_owned(),
                    offset: r.start as u64,
                    len: r.len() as u64,
                });
            }
        }
        facts.matches.push(YaraMatch {
            rule: rule.identifier().to_owned(),
            namespace: rule.namespace().to_owned(),
            tags: rule.tags().map(|t| t.identifier().to_owned()).collect(),
            meta: rule
                .metadata()
                .map(|(k, v)| (k.to_owned(), meta_text(&v)))
                .collect(),
            strings,
        });
    }
    Ok(facts)
}

fn meta_text(v: &yara_x::MetaValue<'_>) -> String {
    match v {
        yara_x::MetaValue::Integer(i) => i.to_string(),
        yara_x::MetaValue::Float(f) => f.to_string(),
        yara_x::MetaValue::Bool(b) => b.to_string(),
        yara_x::MetaValue::String(s) => (*s).to_owned(),
        yara_x::MetaValue::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
    }
}

fn finding(rules: &YaraRules, m: &YaraMatch) -> Finding {
    let meta = rules.meta(&m.namespace, &m.rule);
    let detail = meta.description.clone().unwrap_or_else(|| {
        format!(
            "YARA rule {} from namespace {} matched this file.",
            m.rule, m.namespace
        )
    });
    let mut f = Finding::new(
        "YARA-MATCH",
        meta.severity,
        meta.category,
        format!("YARA rule {} matched", m.rule),
    )
    .confidence(meta.confidence)
    .detail(detail)
    .evidence(Evidence::Field {
        name: "rule",
        value: format!("{}:{}", m.namespace, m.rule),
    });
    if !m.tags.is_empty() {
        f = f.evidence(Evidence::Field {
            name: "tags",
            value: m.tags.join(", "),
        });
    }
    let mut ids: Vec<&str> = m.strings.iter().map(|s| s.id.as_str()).collect();
    ids.dedup();
    if !ids.is_empty() {
        f = f.evidence(Evidence::Field {
            name: "patterns",
            value: ids.join(", "),
        });
    }
    for s in &m.strings {
        f = f.evidence(Evidence::Range {
            offset: s.offset,
            len: s.len,
        });
    }
    for t in &meta.attack {
        f = f.attack(t);
    }
    if let Some(level) = meta.risk_floor {
        f = f.risk_floor(level);
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::input::Input;
    use crate::report::{Category, Report, RiskLevel, Severity};
    use crate::yara::YaraSource;
    use crate::Registry;
    use std::sync::Arc;

    fn config(rules: &str) -> Config {
        let rules = YaraRules::compile(&[YaraSource {
            origin: "t.yar".into(),
            namespace: "t".into(),
            text: rules.into(),
        }])
        .unwrap();
        Config {
            yara: Some(Arc::new(rules)),
            ..Config::default()
        }
    }

    fn analyze(data: &[u8], config: &Config) -> Report {
        let r = Registry::default().analyze(&Input::from_bytes("t", data.to_vec()), config);
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        r
    }

    fn yara(r: &Report) -> Vec<&crate::report::Finding> {
        r.findings.iter().filter(|f| f.id == "YARA-MATCH").collect()
    }

    const DATA: &[u8] = b"\0\0hello world, marker-one here and marker-two there\0";

    fn bundled() -> Config {
        Config {
            yara: Some(Arc::new(
                YaraRules::compile(&crate::yara_sources::bundled_sources()).unwrap(),
            )),
            ..Config::default()
        }
    }

    fn rules_hit(r: &Report) -> Vec<String> {
        r.facts
            .yara
            .as_ref()
            .unwrap()
            .matches
            .iter()
            .map(|m| m.rule.clone())
            .collect()
    }

    /// The EICAR test string, assembled at run time: neither this source nor
    /// the test binary contains it in one piece, and it is never written to disk.
    fn eicar() -> Vec<u8> {
        let parts = [
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$",
            "EICAR-STANDARD-",
            "ANTIVIRUS-TEST-FILE!$H+H*",
        ];
        parts.concat().into_bytes()
    }

    #[test]
    fn bundled_eicar_is_informational() {
        let r = analyze(&eicar(), &bundled());
        assert_eq!(rules_hit(&r), ["eicar_test_file"]);
        let f = yara(&r)[0];
        assert_eq!(
            (f.severity, f.category),
            (Severity::Info, Category::Metadata)
        );
        assert_eq!(r.risk.score, 0);
        // Not at the start, or with trailing bulk: no match.
        let mut shifted = b"x".to_vec();
        shifted.extend(eicar());
        assert!(rules_hit(&analyze(&shifted, &bundled())).is_empty());
        let mut big = eicar();
        big.extend([b' '; 200]);
        assert!(rules_hit(&analyze(&big, &bundled())).is_empty());
    }

    #[test]
    fn bundled_embedded_pe() {
        // The rule is byte-level (`MZ` at 0, count of DOS stub texts), so a
        // PE-like blob with a real stub text is enough. (The synthetic PE
        // fixtures carry no stub text at all.)
        let pe_like = |n: usize| {
            let mut v = b"MZ".to_vec();
            v.extend([0u8; 0x3e]);
            v.extend(b"This program cannot be run in DOS mode.\r\r\n$");
            v.extend(vec![0u8; n]);
            v
        };
        // A PE with its own single stub: no match.
        assert!(rules_hit(&analyze(&pe_like(64), &bundled())).is_empty());
        // A PE carrying another PE: match.
        let mut dropper = pe_like(64);
        dropper.extend(pe_like(64));
        assert_eq!(
            rules_hit(&analyze(&dropper, &bundled())),
            ["embedded_pe_dos_stub"]
        );
        // Any other file carrying a PE: match; low/low anomaly.
        let mut blob = b"\0\0zip-ish container".to_vec();
        blob.extend(pe_like(64));
        let r = analyze(&blob, &bundled());
        assert_eq!(rules_hit(&r), ["embedded_pe_dos_stub"]);
        let f = yara(&r)[0];
        assert_eq!((f.severity, f.category), (Severity::Low, Category::Anomaly));
        assert_eq!(f.attack, ["T1027.009"]);
        // The stub text alone at the very start of a non-PE: no match.
        assert!(rules_hit(&analyze(
            b"This program cannot be run in DOS mode",
            &bundled()
        ))
        .is_empty());
    }
    #[test]
    fn no_rules_no_facts() {
        let r = analyze(DATA, &Config::default());
        assert!(r.facts.yara.is_none() && yara(&r).is_empty());
    }

    #[test]
    fn match_becomes_finding_with_evidence() {
        let c = config(
            r#"rule two_markers : tag1 tag2 {
                 meta: severity = "high" confidence = "high" category = "injection" attack = "T1055"
                 strings: $a = "marker-one" $b = "marker-two"
                 condition: all of them }
               rule absent { strings: $x = "nope" condition: $x }"#,
        );
        let r = analyze(DATA, &c);
        let f = yara(&r);
        assert_eq!(f.len(), 1);
        let f = f[0];
        assert_eq!(
            (f.severity, f.category),
            (Severity::High, Category::Injection)
        );
        assert_eq!(f.attack, ["T1055"]);
        assert!(f.title.contains("two_markers"));
        assert!(f.evidence.contains(&Evidence::Field {
            name: "rule",
            value: "t:two_markers".into()
        }));
        let at = DATA.windows(10).position(|w| w == b"marker-one").unwrap() as u64;
        assert!(f.evidence.contains(&Evidence::Range {
            offset: at,
            len: 10
        }));
        let facts = r.facts.yara.as_ref().unwrap();
        assert_eq!(facts.rules_loaded, 2);
        assert_eq!(facts.matches[0].tags, ["tag1", "tag2"]);
        assert_eq!(facts.matches[0].strings.len(), 2);
        // High/High injection counts like an API group.
        assert_eq!(r.risk.score, 40);
    }

    #[test]
    fn defaults_are_medium_signature() {
        let r = analyze(
            DATA,
            &config(r#"rule plain { strings: $a = "hello" condition: $a }"#),
        );
        let f = yara(&r)[0];
        assert_eq!(
            (f.severity, f.category),
            (Severity::Medium, Category::Signature)
        );
        assert_eq!(r.risk.score, 11);
    }

    #[test]
    fn several_matches_count_once() {
        let r = analyze(
            DATA,
            &config(
                r#"rule a { meta: severity = "high" strings: $a = "hello" condition: $a }
                   rule b { meta: severity = "high" strings: $a = "world" condition: $a }"#,
            ),
        );
        assert_eq!(yara(&r).len(), 2, "both reported");
        // Same finding ID: only the strongest scores (28 = High/Medium).
        assert_eq!(r.risk.score, 28);
    }

    #[test]
    fn risk_floor_raises_the_level_not_the_score() {
        let r = analyze(
            DATA,
            &config(
                r#"rule known_bad { meta: severity = "info" risk_floor = "high" strings: $a = "hello" condition: $a }"#,
            ),
        );
        assert_eq!(r.risk.score, 0);
        assert_eq!(r.risk.level, RiskLevel::High);
        let floor = r.risk.floor.as_ref().unwrap();
        assert_eq!(
            (floor.level, floor.finding),
            (RiskLevel::High, "YARA-MATCH")
        );
        assert!(floor.title.contains("known_bad"));
        // A floor below the computed level changes nothing.
        let r = analyze(
            DATA,
            &config(r#"rule low { meta: risk_floor = "low" condition: false }"#),
        );
        assert!(r.risk.floor.is_none());
    }

    #[test]
    fn signature_category_is_capped_at_40() {
        let r = analyze(
            DATA,
            &config(r#"rule a { meta: severity = "high" confidence = "high" condition: true }"#),
        );
        assert_eq!(r.risk.score, 40);
        assert_eq!(crate::scoring::category_cap(Category::Signature), 40);
    }

    #[test]
    fn match_limits() {
        let mut c = config(
            r#"rule a { strings: $x = "o" condition: $x }
               rule b { strings: $x = "e" condition: $x }
               rule c { strings: $x = "r" condition: $x }"#,
        );
        c.limits.max_yara_matches = 2;
        c.limits.max_yara_strings_per_rule = 1;
        let r = analyze(DATA, &c);
        let facts = r.facts.yara.as_ref().unwrap();
        assert_eq!(facts.matches.len(), 2);
        assert!(facts.limit_reached);
        assert!(facts.matches.iter().all(|m| m.strings.len() == 1));
    }

    #[test]
    fn expired_deadline_is_a_timeout() {
        let c = config(r#"rule a { condition: true }"#);
        let r = Registry::default().analyze_with_deadline(
            &Input::from_bytes("t", DATA.to_vec()),
            &c,
            crate::Deadline::expired(),
        );
        assert!(r
            .errors
            .iter()
            .any(|e| e.analyzer == "yara" && matches!(e.error, AnalysisError::Timeout { .. })));
    }

    #[test]
    fn pe_and_elf_modules_work_on_fixtures() {
        let c = config(
            r#"import "pe" import "elf"
               rule is_pe { condition: pe.is_pe }
               rule is_elf { condition: elf.type == elf.ET_DYN }"#,
        );
        let pe = rtriage_fixtures::pe::PeBuilder::minimal(rtriage_fixtures::pe::Arch::X64)
            .build()
            .bytes;
        let names = |r: &Report| -> Vec<String> {
            r.facts
                .yara
                .as_ref()
                .unwrap()
                .matches
                .iter()
                .map(|m| m.rule.clone())
                .collect()
        };
        assert_eq!(names(&analyze(&pe, &c)), ["is_pe"]);
        let elf = rtriage_fixtures::elf::profiles::glibc_pie().build().bytes;
        assert_eq!(names(&analyze(&elf, &c)), ["is_elf"]);
    }
}

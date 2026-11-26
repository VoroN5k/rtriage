//! YARA rule sets (cargo feature `yara`, via yara-x).
//!
//! Rules are compiled once per run with `include` disabled (a rule file can
//! never pull in files outside the configured sources). The rtriage-specific
//! metadata a rule may carry is validated **at compile time**, so a typo in
//! `severity` is a load error, not a silently ignored value:
//!
//! | meta | values | default |
//! |---|---|---|
//! | `severity` | `info`, `low`, `medium`, `high` | `medium` |
//! | `confidence` | `low`, `medium`, `high` | `medium` |
//! | `category` | any finding category (`signature`, `injection`, ...) | `signature` |
//! | `attack` | ATT&CK IDs separated by commas or spaces (`T1055, T1055.012`) | none |
//! | `risk_floor` | `low`, `medium`, `high` | none |
//! | `description` | text, used as the finding detail | generic |
//!
//! Other meta keys (`author`, `reference`, ...) are kept as facts only.
//!
//! [`YaraRules::serialize`] / [`YaraRules::deserialize`] let a parent
//! compile once and hand the result to worker processes. Deserializing
//! loads precompiled code: only ever deserialize bytes this program
//! serialized itself (the worker pipe), never bytes from a file or a peer.

use std::collections::HashMap;
use std::fmt;

use crate::report::{Category, Confidence, RiskLevel, Severity};
use crate::rules::{intern, is_attack_id};

pub use crate::yara_sources::YaraSource;

/// Why a rule set could not be built or loaded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum YaraError {
    /// yara-x rejected a source.
    #[error("{origin}: {message}")]
    Compile {
        /// The source's origin.
        origin: String,
        /// Compiler message (with line and column).
        message: String,
    },
    /// A rule's rtriage metadata is invalid.
    #[error("rule {rule}: {reason}")]
    Meta {
        /// `namespace:rule`.
        rule: String,
        /// What is wrong.
        reason: String,
    },
    /// Serialization or deserialization failed.
    #[error("compiled YARA rules: {0}")]
    Serialized(String),
}

/// rtriage metadata of one rule, validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMeta {
    /// Finding severity.
    pub severity: Severity,
    /// Finding confidence.
    pub confidence: Confidence,
    /// Finding category.
    pub category: Category,
    /// ATT&CK technique IDs.
    pub attack: Vec<&'static str>,
    /// Minimum report risk level when the rule matches.
    pub risk_floor: Option<RiskLevel>,
    /// Finding detail.
    pub description: Option<String>,
}

impl Default for RuleMeta {
    fn default() -> Self {
        Self {
            severity: Severity::Medium,
            confidence: Confidence::Medium,
            category: Category::Signature,
            attack: Vec::new(),
            risk_floor: None,
            description: None,
        }
    }
}

/// A compiled, validated rule set.
pub struct YaraRules {
    rules: yara_x::Rules,
    meta: HashMap<(String, String), RuleMeta>,
}

impl fmt::Debug for YaraRules {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("YaraRules")
            .field("rules", &self.meta.len())
            .finish()
    }
}

/// Rule sets are compared by identity (configs are compared in tests).
impl PartialEq for YaraRules {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self, other)
    }
}

impl YaraRules {
    /// Compiles `sources` (each in its own namespace, includes disabled) and
    /// validates every rule's metadata.
    ///
    /// # Errors
    /// The first compile error, or the first invalid metadata value.
    pub fn compile(sources: &[YaraSource]) -> Result<Self, YaraError> {
        let mut compiler = yara_x::Compiler::new();
        compiler.enable_includes(false).colorize_errors(false);
        for s in sources {
            compiler.new_namespace(&s.namespace);
            let src = yara_x::SourceCode::from(s.text.as_str()).with_origin(s.origin.clone());
            compiler.add_source(src).map_err(|e| YaraError::Compile {
                origin: s.origin.clone(),
                message: e.to_string(),
            })?;
        }
        Self::from_rules(compiler.build())
    }

    fn from_rules(rules: yara_x::Rules) -> Result<Self, YaraError> {
        let mut meta = HashMap::new();
        for rule in rules.iter() {
            let key = (rule.namespace().to_owned(), rule.identifier().to_owned());
            let m = parse_meta(&key, rule.metadata())?;
            meta.insert(key, m);
        }
        Ok(Self { rules, meta })
    }

    /// Number of rules.
    pub fn len(&self) -> usize {
        self.meta.len()
    }

    /// `true` if the set has no rules.
    pub fn is_empty(&self) -> bool {
        self.meta.is_empty()
    }

    /// The validated metadata of `namespace:rule` (defaults if unknown).
    pub fn meta(&self, namespace: &str, rule: &str) -> RuleMeta {
        self.meta
            .get(&(namespace.to_owned(), rule.to_owned()))
            .cloned()
            .unwrap_or_default()
    }

    /// The underlying yara-x rules.
    pub(crate) fn inner(&self) -> &yara_x::Rules {
        &self.rules
    }

    /// Compiled form, for handing to worker processes.
    ///
    /// # Errors
    /// [`YaraError::Serialized`].
    pub fn serialize(&self) -> Result<Vec<u8>, YaraError> {
        self.rules
            .serialize()
            .map_err(|e| YaraError::Serialized(e.to_string()))
    }

    /// Loads bytes produced by [`YaraRules::serialize`] **in this program**.
    /// Never pass bytes from an untrusted source: they contain compiled code.
    ///
    /// # Errors
    /// [`YaraError::Serialized`], or invalid metadata.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, YaraError> {
        let rules =
            yara_x::Rules::deserialize(bytes).map_err(|e| YaraError::Serialized(e.to_string()))?;
        Self::from_rules(rules)
    }
}

fn parse_meta<'a>(
    key: &(String, String),
    items: impl Iterator<Item = (&'a str, yara_x::MetaValue<'a>)>,
) -> Result<RuleMeta, YaraError> {
    let bad = |reason: String| YaraError::Meta {
        rule: format!("{}:{}", key.0, key.1),
        reason,
    };
    let mut m = RuleMeta::default();
    for (name, value) in items {
        let text = match value {
            yara_x::MetaValue::String(s) => Some(s),
            _ => None,
        };
        let need_text =
            |what: &str| text.ok_or_else(|| bad(format!("meta {what} must be a string")));
        match name {
            "severity" => {
                m.severity = match need_text(name)? {
                    "info" => Severity::Info,
                    "low" => Severity::Low,
                    "medium" => Severity::Medium,
                    "high" => Severity::High,
                    other => return Err(bad(format!("severity {other:?} (info|low|medium|high)"))),
                }
            }
            "confidence" => {
                m.confidence = match need_text(name)? {
                    "low" => Confidence::Low,
                    "medium" => Confidence::Medium,
                    "high" => Confidence::High,
                    other => return Err(bad(format!("confidence {other:?} (low|medium|high)"))),
                }
            }
            "category" => {
                let v = need_text(name)?;
                m.category = category(v).ok_or_else(|| bad(format!("unknown category {v:?}")))?;
            }
            "risk_floor" => {
                m.risk_floor = Some(match need_text(name)? {
                    "low" => RiskLevel::Low,
                    "medium" => RiskLevel::Medium,
                    "high" => RiskLevel::High,
                    other => return Err(bad(format!("risk_floor {other:?} (low|medium|high)"))),
                })
            }
            "attack" => {
                for id in need_text(name)?
                    .split(|c: char| c == ',' || c.is_whitespace())
                    .filter(|s| !s.is_empty())
                {
                    if !is_attack_id(id) {
                        return Err(bad(format!("attack {id:?} is not an ATT&CK technique ID")));
                    }
                    if !m.attack.contains(&id) {
                        m.attack.push(intern(id.to_owned()));
                    }
                }
            }
            "description" => m.description = Some(need_text(name)?.to_owned()),
            _ => {}
        }
    }
    Ok(m)
}

fn category(name: &str) -> Option<Category> {
    Some(match name {
        "packing" => Category::Packing,
        "obfuscation" => Category::Obfuscation,
        "anti_analysis" => Category::AntiAnalysis,
        "injection" => Category::Injection,
        "persistence" => Category::Persistence,
        "network" => Category::Network,
        "credential_access" => Category::CredentialAccess,
        "collection" => Category::Collection,
        "impact" => Category::Impact,
        "hardening" => Category::Hardening,
        "anomaly" => Category::Anomaly,
        "metadata" => Category::Metadata,
        "signature" => Category::Signature,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src(text: &str) -> YaraSource {
        YaraSource {
            origin: "test.yar".into(),
            namespace: "test".into(),
            text: text.into(),
        }
    }

    #[test]
    fn compiles_and_reads_meta() {
        let r = YaraRules::compile(&[src(
            r#"rule a { meta: severity = "high" confidence = "low" category = "injection"
                 attack = "T1055, T1055.012" risk_floor = "medium" description = "x" author = "me"
                 strings: $s = "abc" condition: $s }
               rule b { condition: false }"#,
        )])
        .unwrap();
        assert_eq!(r.len(), 2);
        let m = r.meta("test", "a");
        assert_eq!(
            (m.severity, m.confidence, m.category),
            (Severity::High, Confidence::Low, Category::Injection)
        );
        assert_eq!(m.attack, ["T1055", "T1055.012"]);
        assert_eq!(m.risk_floor, Some(RiskLevel::Medium));
        assert_eq!(r.meta("test", "b"), RuleMeta::default());
    }

    #[test]
    fn invalid_meta_is_a_load_error() {
        for bad in [
            r#"severity = "critical""#,
            r#"confidence = 3"#,
            r#"category = "evil""#,
            r#"attack = "T99""#,
            r#"risk_floor = "clean_looking""#,
        ] {
            let text = format!("rule r {{ meta: {bad} condition: true }}");
            assert!(
                matches!(
                    YaraRules::compile(&[src(&text)]),
                    Err(YaraError::Meta { .. })
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn syntax_errors_name_the_origin() {
        let e = YaraRules::compile(&[src("rule { condition: true }")]).unwrap_err();
        assert!(
            matches!(&e, YaraError::Compile { origin, .. } if origin == "test.yar"),
            "{e}"
        );
        assert!(!e.to_string().contains('\x1b'), "no colors in errors");
    }

    #[test]
    fn includes_are_disabled() {
        let e = YaraRules::compile(&[src(r#"include "other.yar" rule r { condition: true }"#)]);
        assert!(matches!(e, Err(YaraError::Compile { .. })));
    }

    #[test]
    fn modules_outside_the_build_are_rejected() {
        // `vt`, `dotnet`, `macho`, ... are not compiled in.
        let e = YaraRules::compile(&[src(r#"import "dotnet" rule r { condition: true }"#)]);
        assert!(matches!(e, Err(YaraError::Compile { .. })));
        assert!(YaraRules::compile(&[src(
            r#"import "pe" import "elf" import "hash" rule r { condition: true }"#
        )])
        .is_ok());
    }

    #[test]
    fn serialize_roundtrip_keeps_meta() {
        let r = YaraRules::compile(&[src(r#"rule a { meta: severity = "low" condition: true }"#)])
            .unwrap();
        let back = YaraRules::deserialize(&r.serialize().unwrap()).unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back.meta("test", "a").severity, Severity::Low);
        assert!(YaraRules::deserialize(b"not rules").is_err());
    }

    #[test]
    fn bundled_rules_compile() {
        let r = YaraRules::compile(&crate::yara_sources::bundled_sources()).unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(
            r.meta("rtriage", "eicar_test_file").severity,
            Severity::Info
        );
    }

    #[test]
    fn equal_names_in_different_namespaces() {
        let mut a = src("rule same { condition: true }");
        let mut b = a.clone();
        a.namespace = "one".into();
        b.namespace = "two".into();
        assert_eq!(YaraRules::compile(&[a, b]).unwrap().len(), 2);
    }
}

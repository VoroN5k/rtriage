//! Data-driven API behavior rules (`rules/api_groups.toml`).
//!
//! The bundled file is compiled in; a replacement can be loaded at run time
//! ([`ApiRuleSet::parse`], CLI `--api-rules`). Rules are validated strictly:
//! unknown fields, bad enum values, duplicate or malformed IDs and malformed
//! API patterns are all load errors, never silently ignored.
//!
//! Rule IDs and ATT&CK IDs become `&'static str` (findings carry static IDs).
//! They are interned by leaking: a rule set is loaded once per process and is
//! bounded by [`MAX_RULES_FILE_SIZE`] / [`MAX_GROUPS`].

use std::collections::BTreeSet;
use std::sync::LazyLock;

use serde::Deserialize;

use crate::report::{Category, Confidence, Severity, StringKind};

/// The rules shipped with rtriage.
pub const BUNDLED_API_RULES: &str = include_str!("../../../rules/api_groups.toml");
/// Largest rules file accepted.
pub const MAX_RULES_FILE_SIZE: usize = 1 << 20;
/// Most groups accepted in one file.
pub const MAX_GROUPS: usize = 256;
/// Supported `schema_version`.
pub const SCHEMA_VERSION: u32 = 1;
/// Required prefix for group IDs (keeps them apart from built-in finding IDs).
pub const ID_PREFIX: &str = "PE-API-";

/// Why a rules file was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RulesError {
    /// The file exceeds [`MAX_RULES_FILE_SIZE`].
    #[error("rules file is {size} bytes, over the {limit}-byte limit")]
    TooLarge {
        /// File size.
        size: usize,
        /// Limit.
        limit: usize,
    },
    /// Not valid TOML, or does not match the schema.
    #[error("invalid rules file: {reason}")]
    Syntax {
        /// Parser message (includes line and column).
        reason: String,
    },
    /// `schema_version` is not supported.
    #[error("unsupported rules schema_version {found} (supported: {SCHEMA_VERSION})")]
    Schema {
        /// Version found in the file.
        found: u32,
    },
    /// More than [`MAX_GROUPS`] groups.
    #[error("too many groups: {count} (max {MAX_GROUPS})")]
    TooManyGroups {
        /// Number of groups found.
        count: usize,
    },
    /// A group is semantically invalid.
    #[error("group {id:?}: {reason}")]
    Invalid {
        /// Group ID (as written).
        id: String,
        /// What is wrong.
        reason: String,
    },
}

// ------------------------------------------------------------- raw schema

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFile {
    schema_version: u32,
    #[serde(default, rename = "group")]
    groups: Vec<RawGroup>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGroup {
    id: String,
    title: String,
    severity: Severity,
    confidence: Confidence,
    category: Category,
    #[serde(default)]
    attack: Vec<String>,
    rationale: String,
    #[serde(default)]
    false_positives: String,
    #[serde(default, rename = "when")]
    whens: Vec<RawWhen>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawWhen {
    #[serde(default)]
    slots: Vec<Vec<String>>,
    #[serde(default)]
    any_of: Vec<String>,
    #[serde(default = "one")]
    min: usize,
    strings: Option<RawStrings>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawStrings {
    #[serde(default)]
    kinds: Vec<StringKind>,
    #[serde(default)]
    contains: Vec<String>,
    #[serde(default = "one")]
    min_distinct: usize,
}

fn one() -> usize {
    1
}

// ------------------------------------------------------------- validated

/// A validated rule set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiRuleSet {
    /// Groups in file order.
    pub groups: Vec<ApiGroup>,
}

/// One behavior group; becomes one finding when any [`When`] matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiGroup {
    /// Finding ID, starts with [`ID_PREFIX`].
    pub id: &'static str,
    /// Finding title.
    pub title: String,
    /// Finding severity.
    pub severity: Severity,
    /// Finding confidence.
    pub confidence: Confidence,
    /// Finding category.
    pub category: Category,
    /// MITRE ATT&CK technique IDs.
    pub attack: Vec<&'static str>,
    /// Why the combination matters (finding detail).
    pub rationale: String,
    /// Known benign causes.
    pub false_positives: String,
    /// Alternatives; the first that matches is reported.
    pub whens: Vec<When>,
}

/// One alternative: all conditions must hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct When {
    /// Each slot needs at least one imported API.
    pub slots: Vec<Vec<ApiPattern>>,
    /// At least `min` different APIs from this list (if non-empty).
    pub any_of: Vec<ApiPattern>,
    /// See `any_of`.
    pub min: usize,
    /// Optional string condition.
    pub strings: Option<StringCondition>,
}

/// Extracted strings must show `min_distinct` different hits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringCondition {
    /// String classifications that count as a hit.
    pub kinds: Vec<StringKind>,
    /// Case-insensitive substrings that count as hits (stored lowercase).
    pub contains_lower: Vec<String>,
    /// Hits required.
    pub min_distinct: usize,
}

/// An API name pattern: exact, or prefix (trailing `*`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiPattern {
    /// Exact, case-sensitive name.
    Exact(String),
    /// Name must start with this (pattern was written `Prefix*`).
    Prefix(String),
}

impl ApiPattern {
    /// `true` if `name` matches.
    pub fn matches(&self, name: &str) -> bool {
        match self {
            ApiPattern::Exact(e) => name == e,
            ApiPattern::Prefix(p) => name.starts_with(p.as_str()),
        }
    }
}

impl ApiRuleSet {
    /// The bundled rules (parsed once).
    ///
    /// # Errors
    /// Only if the bundled file is broken, which the test suite prevents.
    pub fn bundled() -> Result<&'static ApiRuleSet, &'static RulesError> {
        static BUNDLED: LazyLock<Result<ApiRuleSet, RulesError>> =
            LazyLock::new(|| ApiRuleSet::parse(BUNDLED_API_RULES));
        BUNDLED.as_ref()
    }

    /// Parses and validates a rules file.
    ///
    /// # Errors
    /// See [`RulesError`].
    pub fn parse(text: &str) -> Result<Self, RulesError> {
        if text.len() > MAX_RULES_FILE_SIZE {
            return Err(RulesError::TooLarge {
                size: text.len(),
                limit: MAX_RULES_FILE_SIZE,
            });
        }
        let raw: RawFile = toml::from_str(text).map_err(|e| RulesError::Syntax {
            reason: e.to_string(),
        })?;
        if raw.schema_version != SCHEMA_VERSION {
            return Err(RulesError::Schema {
                found: raw.schema_version,
            });
        }
        if raw.groups.len() > MAX_GROUPS {
            return Err(RulesError::TooManyGroups {
                count: raw.groups.len(),
            });
        }
        let mut seen = BTreeSet::new();
        let mut groups = Vec::with_capacity(raw.groups.len());
        for g in raw.groups {
            if !seen.insert(g.id.clone()) {
                return Err(invalid(&g.id, "duplicate id"));
            }
            groups.push(validate_group(g)?);
        }
        Ok(Self { groups })
    }
}

fn validate_group(g: RawGroup) -> Result<ApiGroup, RulesError> {
    let id_ok = g.id.len() > ID_PREFIX.len()
        && g.id.starts_with(ID_PREFIX)
        && g.id
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-');
    if !id_ok {
        return Err(invalid(
            &g.id,
            "id must be PE-API-<UPPERCASE-ALNUM> (A-Z, 0-9, '-')",
        ));
    }
    if g.title.trim().is_empty() {
        return Err(invalid(&g.id, "title is empty"));
    }
    if g.whens.is_empty() {
        return Err(invalid(&g.id, "needs at least one [[group.when]]"));
    }
    for t in &g.attack {
        if !is_attack_id(t) {
            return Err(invalid(
                &g.id,
                &format!("bad ATT&CK id {t:?} (want T1234 or T1234.001)"),
            ));
        }
    }
    let whens = g
        .whens
        .into_iter()
        .map(|w| validate_when(&g.id, w))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ApiGroup {
        id: intern(g.id),
        title: g.title,
        severity: g.severity,
        confidence: g.confidence,
        category: g.category,
        attack: g.attack.into_iter().map(intern).collect(),
        rationale: g.rationale,
        false_positives: g.false_positives,
        whens,
    })
}

fn validate_when(id: &str, w: RawWhen) -> Result<When, RulesError> {
    if w.slots.is_empty() && w.any_of.is_empty() {
        return Err(invalid(id, "a when block needs `slots` or `any_of`"));
    }
    if w.slots.iter().any(Vec::is_empty) {
        return Err(invalid(id, "empty slot"));
    }
    if !w.any_of.is_empty() && (w.min == 0 || w.min > w.any_of.len()) {
        return Err(invalid(
            id,
            "`min` must be between 1 and the length of `any_of`",
        ));
    }
    let slots = w
        .slots
        .iter()
        .map(|slot| slot.iter().map(|p| pattern(id, p)).collect())
        .collect::<Result<Vec<Vec<_>>, _>>()?;
    let any_of = w
        .any_of
        .iter()
        .map(|p| pattern(id, p))
        .collect::<Result<Vec<_>, _>>()?;
    let strings = w.strings.map(|s| validate_strings(id, s)).transpose()?;
    Ok(When {
        slots,
        any_of,
        min: w.min,
        strings,
    })
}

fn validate_strings(id: &str, s: RawStrings) -> Result<StringCondition, RulesError> {
    let total = s.kinds.len() + s.contains.len();
    if total == 0 {
        return Err(invalid(id, "`strings` needs `kinds` or `contains`"));
    }
    if s.min_distinct == 0 || s.min_distinct > total {
        return Err(invalid(
            id,
            "`min_distinct` must be between 1 and the number of kinds + substrings",
        ));
    }
    if s.contains.iter().any(|c| c.is_empty()) {
        return Err(invalid(id, "empty substring in `contains`"));
    }
    Ok(StringCondition {
        kinds: s.kinds,
        contains_lower: s.contains.iter().map(|c| c.to_lowercase()).collect(),
        min_distinct: s.min_distinct,
    })
}

/// `Name` or `Prefix*`; names are identifier characters only.
fn pattern(id: &str, p: &str) -> Result<ApiPattern, RulesError> {
    let (body, prefix) = match p.strip_suffix('*') {
        Some(body) => (body, true),
        None => (p, false),
    };
    let ok = !body.is_empty() && body.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
    if !ok {
        return Err(invalid(
            id,
            &format!("bad API pattern {p:?} (letters, digits, '_', optional trailing '*')"),
        ));
    }
    Ok(if prefix {
        ApiPattern::Prefix(body.to_owned())
    } else {
        ApiPattern::Exact(body.to_owned())
    })
}

fn is_attack_id(t: &str) -> bool {
    let Some(rest) = t.strip_prefix('T') else {
        return false;
    };
    let (main, sub) = match rest.split_once('.') {
        Some((m, s)) => (m, Some(s)),
        None => (rest, None),
    };
    let digits = |s: &str, n: usize| s.len() == n && s.bytes().all(|b| b.is_ascii_digit());
    digits(main, 4) && sub.is_none_or(|s| digits(s, 3))
}

fn invalid(id: &str, reason: &str) -> RulesError {
    RulesError::Invalid {
        id: id.to_owned(),
        reason: reason.to_owned(),
    }
}

/// Gives a string a `'static` lifetime (see module docs for why this is bounded).
fn intern(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
schema_version = 1
[[group]]
id = "PE-API-TEST"
title = "t"
severity = "low"
confidence = "low"
category = "network"
rationale = "r"
[[group.when]]
slots = [["Foo", "Bar*"]]
"#;

    fn with(replace: &str, by: &str) -> Result<ApiRuleSet, RulesError> {
        ApiRuleSet::parse(&MINIMAL.replace(replace, by))
    }

    #[test]
    fn bundled_rules_are_valid() {
        let rules = ApiRuleSet::bundled().unwrap();
        let ids: Vec<_> = rules.groups.iter().map(|g| g.id).collect();
        assert_eq!(
            ids,
            [
                "PE-API-INJECTION",
                "PE-API-ANTIDEBUG",
                "PE-API-PERSISTENCE-REGISTRY",
                "PE-API-PERSISTENCE-SERVICE",
                "PE-API-NETWORK",
                "PE-API-RANSOM-CRYPTO",
                "PE-API-CREDENTIALS",
                "PE-API-KEYLOGGING",
            ]
        );
        assert!(rules.groups.iter().all(|g| !g.attack.is_empty()));
        assert!(rules.groups.iter().all(|g| !g.false_positives.is_empty()));
    }

    #[test]
    fn bundled_severities_match_agreed_table() {
        use Confidence as C;
        use Severity as S;
        let rules = ApiRuleSet::bundled().unwrap();
        let got: Vec<_> = rules
            .groups
            .iter()
            .map(|g| (g.id, g.severity, g.confidence))
            .collect();
        assert_eq!(
            got,
            [
                ("PE-API-INJECTION", S::High, C::High),
                ("PE-API-ANTIDEBUG", S::Low, C::Medium),
                ("PE-API-PERSISTENCE-REGISTRY", S::Medium, C::Medium),
                ("PE-API-PERSISTENCE-SERVICE", S::Medium, C::Low),
                ("PE-API-NETWORK", S::Low, C::Medium),
                ("PE-API-RANSOM-CRYPTO", S::High, C::Low),
                ("PE-API-CREDENTIALS", S::Medium, C::Medium),
                ("PE-API-KEYLOGGING", S::Medium, C::Low),
            ]
        );
    }

    #[test]
    fn minimal_file_parses() {
        let r = ApiRuleSet::parse(MINIMAL).unwrap();
        let slot = &r.groups[0].whens[0].slots[0];
        assert!(slot[0].matches("Foo") && !slot[0].matches("Foo2"));
        assert!(slot[1].matches("BarA") && slot[1].matches("Bar"));
    }

    #[test]
    fn rejects_bad_files() {
        assert!(matches!(
            with("severity = \"low\"", "severity = \"huge\""),
            Err(RulesError::Syntax { .. })
        ));
        assert!(matches!(
            with("rationale = \"r\"", "rationale = \"r\"\ncolour = 1"),
            Err(RulesError::Syntax { .. })
        ));
        assert!(matches!(
            with("schema_version = 1", "schema_version = 2"),
            Err(RulesError::Schema { found: 2 })
        ));
        assert!(matches!(
            with("PE-API-TEST", "PE-SECTION-RWX"),
            Err(RulesError::Invalid { .. })
        ));
        assert!(matches!(
            with("PE-API-TEST", "PE-API-lower"),
            Err(RulesError::Invalid { .. })
        ));
        assert!(matches!(
            with("\"Bar*\"", "\"B*r\""),
            Err(RulesError::Invalid { .. })
        ));
        assert!(matches!(
            with("\"Bar*\"", "\"*\""),
            Err(RulesError::Invalid { .. })
        ));
        assert!(matches!(
            with("[[\"Foo\", \"Bar*\"]]", "[[]]"),
            Err(RulesError::Invalid { .. })
        ));
        assert!(matches!(
            with("rationale = \"r\"", "rationale = \"r\"\nattack = [\"T10\"]"),
            Err(RulesError::Invalid { .. })
        ));
        assert!(ApiRuleSet::parse("not toml [[[").is_err());
    }

    #[test]
    fn rejects_duplicate_ids() {
        let twice = format!("{MINIMAL}{}", MINIMAL.replace("schema_version = 1", ""));
        assert!(matches!(
            ApiRuleSet::parse(&twice),
            Err(RulesError::Invalid { reason, .. }) if reason == "duplicate id"
        ));
    }

    #[test]
    fn rejects_bad_min_values() {
        let any = MINIMAL.replace(
            "slots = [[\"Foo\", \"Bar*\"]]",
            "any_of = [\"A\", \"B\"]\nmin = 3",
        );
        assert!(ApiRuleSet::parse(&any).is_err());
        let s = MINIMAL.replace(
            "slots = [[\"Foo\", \"Bar*\"]]",
            "slots = [[\"A\"]]\nstrings = { contains = [\"x\"], min_distinct = 2 }",
        );
        assert!(ApiRuleSet::parse(&s).is_err());
    }

    #[test]
    fn rejects_oversized_file() {
        let big = format!("{MINIMAL}\n#{}", "x".repeat(MAX_RULES_FILE_SIZE));
        assert!(matches!(
            ApiRuleSet::parse(&big),
            Err(RulesError::TooLarge { .. })
        ));
    }

    #[test]
    fn attack_id_format() {
        for ok in ["T1055", "T1547.001", "T1027.007"] {
            assert!(is_attack_id(ok), "{ok}");
        }
        for bad in ["T10", "1055", "T1055.1", "T1055.0001", "t1055", "T1O55"] {
            assert!(!is_attack_id(bad), "{bad}");
        }
    }
}

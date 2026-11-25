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

use crate::report::{Category, Confidence, IpScope, Severity, StringKind};

/// The rules shipped with rtriage.
pub const BUNDLED_API_RULES: &str = include_str!("../../../rules/api_groups.toml");
/// Largest rules file accepted.
pub const MAX_RULES_FILE_SIZE: usize = 1 << 20;
/// Most groups accepted in one file.
pub const MAX_GROUPS: usize = 256;
/// Supported `schema_version`.
pub const SCHEMA_VERSION: u32 = 1;
/// Required prefix for PE group IDs (keeps them apart from built-in finding IDs).
pub const ID_PREFIX: &str = "PE-API-";
/// Required prefix for ELF group IDs.
pub const ELF_ID_PREFIX: &str = "ELF-API-";
/// The ELF rules shipped with rtriage.
pub const BUNDLED_ELF_API_RULES: &str = include_str!("../../../rules/elf_api_groups.toml");

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
    #[serde(default)]
    include_defaults: bool,
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
    unless: Option<RawStrings>,
    #[serde(default)]
    exports: Vec<String>,
    max_imports: Option<u64>,
    severity: Option<Severity>,
    confidence: Option<Confidence>,
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
    #[serde(default)]
    ip_scopes: Option<Vec<IpScope>>,
}

fn one() -> usize {
    1
}

/// IP scopes a string condition accepts unless it lists `ip_scopes`.
pub const DEFAULT_IP_SCOPES: &[IpScope] = &[IpScope::Public];

// ------------------------------------------------------------- validated

/// A validated rule set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiRuleSet {
    /// Groups in file order.
    pub groups: Vec<ApiGroup>,
    /// `include_defaults = true` in the file: merge with the bundled rules
    /// (see [`ApiRuleSet::merged_over`]) instead of replacing them.
    pub include_defaults: bool,
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
    /// Strings that **veto** the match (e.g. markers of rootkit scanners,
    /// which contain the same paths as what they look for).
    pub unless: Option<StringCondition>,
    /// At least one *defined* (exported) dynamic symbol must match (ELF only).
    pub exports: Vec<ApiPattern>,
    /// The import table must have at most this many entries.
    pub max_imports: Option<u64>,
    /// Severity for this alternative instead of the group's.
    pub severity: Option<Severity>,
    /// Confidence for this alternative instead of the group's.
    pub confidence: Option<Confidence>,
}

/// Which binary format a rule file targets; decides the ID prefix and which
/// conditions are available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleTarget {
    /// PE: `PE-API-*`, imports only.
    Pe,
    /// ELF: `ELF-API-*`, imports and exports.
    Elf,
}

impl RuleTarget {
    /// Required ID prefix.
    pub fn prefix(self) -> &'static str {
        match self {
            RuleTarget::Pe => ID_PREFIX,
            RuleTarget::Elf => ELF_ID_PREFIX,
        }
    }
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
    /// IP scopes that count for `ipv4` / `ipv6` / IP-host `url` kinds.
    /// Default: only [`IpScope::Public`].
    pub ip_scopes: Vec<IpScope>,
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

    /// The bundled ELF rules (parsed once).
    ///
    /// # Errors
    /// Only if the bundled file is broken, which the test suite prevents.
    pub fn bundled_elf() -> Result<&'static ApiRuleSet, &'static RulesError> {
        static BUNDLED: LazyLock<Result<ApiRuleSet, RulesError>> =
            LazyLock::new(|| ApiRuleSet::parse_for(BUNDLED_ELF_API_RULES, RuleTarget::Elf));
        BUNDLED.as_ref()
    }

    /// Parses and validates a PE rules file (`PE-API-*`).
    ///
    /// # Errors
    /// See [`RulesError`].
    pub fn parse(text: &str) -> Result<Self, RulesError> {
        Self::parse_for(text, RuleTarget::Pe)
    }

    /// Parses and validates a rules file for `target`.
    ///
    /// # Errors
    /// See [`RulesError`].
    pub fn parse_for(text: &str, target: RuleTarget) -> Result<Self, RulesError> {
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
            groups.push(validate_group(g, target)?);
        }
        Ok(Self {
            groups,
            include_defaults: raw.include_defaults,
        })
    }

    /// `self` layered over `defaults`: a group with the same ID replaces the
    /// default one in place, new groups are appended. The merged set obeys the
    /// same [`MAX_GROUPS`] limit as a single file.
    ///
    /// # Errors
    /// [`RulesError::TooManyGroups`] if the merged set is too large.
    pub fn merged_over(self, defaults: &ApiRuleSet) -> Result<ApiRuleSet, RulesError> {
        let mut groups = defaults.groups.clone();
        for g in self.groups {
            match groups.iter_mut().find(|d| d.id == g.id) {
                Some(slot) => *slot = g,
                None => groups.push(g),
            }
        }
        if groups.len() > MAX_GROUPS {
            return Err(RulesError::TooManyGroups {
                count: groups.len(),
            });
        }
        Ok(ApiRuleSet {
            groups,
            include_defaults: false,
        })
    }
}

fn validate_group(g: RawGroup, target: RuleTarget) -> Result<ApiGroup, RulesError> {
    let prefix = target.prefix();
    let id_ok = g.id.len() > prefix.len()
        && g.id.starts_with(prefix)
        && g.id
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-');
    if !id_ok {
        return Err(invalid(
            &g.id,
            &format!("id must be {prefix}<UPPERCASE-ALNUM> (A-Z, 0-9, '-')"),
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
        .map(|w| validate_when(&g.id, w, target))
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

fn validate_when(id: &str, w: RawWhen, target: RuleTarget) -> Result<When, RulesError> {
    if w.slots.is_empty() && w.any_of.is_empty() && w.exports.is_empty() {
        return Err(invalid(
            id,
            "a when block needs `slots`, `any_of` or `exports`",
        ));
    }
    if !w.exports.is_empty() && target != RuleTarget::Elf {
        return Err(invalid(id, "`exports` is only available in ELF rules"));
    }
    if w.max_imports == Some(0) {
        return Err(invalid(id, "`max_imports` must be at least 1"));
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
    let unless = w.unless.map(|s| validate_strings(id, s)).transpose()?;
    let exports = w
        .exports
        .iter()
        .map(|p| pattern(id, p))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(When {
        slots,
        any_of,
        min: w.min,
        strings,
        unless,
        exports,
        max_imports: w.max_imports,
        severity: w.severity,
        confidence: w.confidence,
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
    let ip_scopes = match s.ip_scopes {
        None => DEFAULT_IP_SCOPES.to_vec(),
        Some(scopes) => {
            let ip_kind = s
                .kinds
                .iter()
                .any(|k| matches!(k, StringKind::Ipv4 | StringKind::Ipv6 | StringKind::Url));
            if !ip_kind {
                return Err(invalid(
                    id,
                    "`ip_scopes` only applies with an ipv4, ipv6 or url kind",
                ));
            }
            if scopes.is_empty() {
                return Err(invalid(id, "`ip_scopes` must not be empty"));
            }
            let mut v: Vec<IpScope> = Vec::new();
            for sc in scopes {
                if !v.contains(&sc) {
                    v.push(sc);
                }
            }
            v
        }
    };
    Ok(StringCondition {
        kinds: s.kinds,
        contains_lower: s.contains.iter().map(|c| c.to_lowercase()).collect(),
        min_distinct: s.min_distinct,
        ip_scopes,
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
    fn when_extensions_parse() {
        let text = MINIMAL.replace(
            "slots = [[\"Foo\", \"Bar*\"]]",
            "slots = [[\"Foo\"]]\nmax_imports = 5\nseverity = \"high\"\nconfidence = \"high\"\n\
             unless = { contains = [\"Scanner\"] }",
        );
        let w = &ApiRuleSet::parse(&text).unwrap().groups[0].whens[0];
        assert_eq!(w.max_imports, Some(5));
        assert_eq!(
            (w.severity, w.confidence),
            (Some(Severity::High), Some(Confidence::High))
        );
        assert_eq!(w.unless.as_ref().unwrap().contains_lower, ["scanner"]);
    }

    #[test]
    fn ip_scopes_default_to_public_and_are_validated() {
        let with = |strings: &str| {
            MINIMAL.replace(
                "slots = [[\"Foo\", \"Bar*\"]]",
                &format!("slots = [[\"Foo\"]]\nstrings = {strings}"),
            )
        };
        let w = |t: &str| ApiRuleSet::parse(t).map(|r| r.groups[0].whens[0].clone());
        let default = w(&with("{ kinds = [\"ipv4\"] }")).unwrap();
        assert_eq!(default.strings.unwrap().ip_scopes, [IpScope::Public]);
        let custom = w(&with(
            "{ kinds = [\"url\"], ip_scopes = [\"private\", \"loopback\", \"private\"] }",
        ))
        .unwrap();
        assert_eq!(
            custom.strings.unwrap().ip_scopes,
            [IpScope::Private, IpScope::Loopback]
        );
        // Only meaningful with IP-bearing kinds; never empty; names are checked.
        assert!(w(&with(
            "{ kinds = [\"file_path\"], ip_scopes = [\"private\"] }"
        ))
        .is_err());
        assert!(w(&with("{ kinds = [\"ipv4\"], ip_scopes = [] }")).is_err());
        assert!(w(&with("{ kinds = [\"ipv4\"], ip_scopes = [\"intranet\"] }")).is_err());
    }

    #[test]
    fn exports_are_elf_only() {
        let pe = MINIMAL.replace("slots = [[\"Foo\", \"Bar*\"]]", "exports = [\"readdir\"]");
        assert!(matches!(
            ApiRuleSet::parse(&pe),
            Err(RulesError::Invalid { .. })
        ));
        let elf = pe.replace("PE-API-TEST", "ELF-API-TEST");
        assert!(ApiRuleSet::parse_for(&elf, RuleTarget::Elf).is_ok());
    }

    #[test]
    fn prefixes_are_per_target() {
        assert!(ApiRuleSet::parse_for(MINIMAL, RuleTarget::Elf).is_err());
        assert!(
            ApiRuleSet::parse_for(&MINIMAL.replace("PE-API-", "ELF-API-"), RuleTarget::Pe).is_err()
        );
    }

    #[test]
    fn zero_max_imports_is_rejected() {
        let t = MINIMAL.replace(
            "slots = [[\"Foo\", \"Bar*\"]]",
            "slots = [[\"Foo\"]]\nmax_imports = 0",
        );
        assert!(ApiRuleSet::parse(&t).is_err());
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

// ======================================================= packer explanations

/// The packer and runtime explanations shipped with rtriage.
pub const BUNDLED_PACKER_RULES: &str = include_str!("../../../rules/packers.toml");

/// Finding IDs a **packer** may explain: structural findings only. API
/// behavior groups (`PE-API-*`, `ELF-API-*`) are deliberately absent and can
/// never be suppressed.
pub const EXPLAINABLE_IDS: &[&str] = &[
    "PE-SECTION-RWX",
    "PE-SECTION-VIRTUAL-ONLY",
    "PE-SECTION-HIGH-ENTROPY",
    "PE-SECTION-NAME-UNUSUAL",
    "PE-ENTRYPOINT-UNUSUAL",
    "PE-IMPORTS-DYNAMIC-RESOLUTION",
    "PE-IMPORTS-FEW",
    "PE-PACKED-LIKELY",
    "PE-RESOURCE-HIGH-ENTROPY",
    "ELF-SECTIONS-MISSING",
    "ELF-SEGMENT-RWX",
    "ELF-SEGMENT-HIGH-ENTROPY",
    "ELF-PACKED-LIKELY",
    "ELF-HARDENING-NO-PIE",
    "ELF-HARDENING-NO-RELRO",
];

/// Finding IDs a **runtime** may explain: only small hardening/import
/// findings that its toolchain produces by design.
pub const RUNTIME_EXPLAINABLE_IDS: &[&str] = &[
    "ELF-HARDENING-NO-PIE",
    "ELF-HARDENING-NO-RELRO",
    "PE-IMPORTS-FEW",
];

/// Minimum independent indicators required to confirm a packer or runtime.
pub const MIN_CONFIRM_INDICATORS: usize = 2;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPackerFile {
    schema_version: u32,
    #[serde(default)]
    include_defaults: bool,
    #[serde(default, rename = "packer")]
    packers: Vec<RawPacker>,
    #[serde(default, rename = "runtime")]
    runtimes: Vec<RawRuntime>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPacker {
    name: String,
    #[serde(default = "default_format")]
    format: String,
    confirm_with: Vec<String>,
    explains: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRuntime {
    name: String,
    confirm_min: usize,
    explains: Vec<String>,
}

fn default_format() -> String {
    "pe".into()
}

/// Binary format a packer rule applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackerFormat {
    /// Checked against `facts.pe.packers`; explained by `PE-PACKER-KNOWN`.
    Pe,
    /// Checked against `facts.elf.packers`; explained by `ELF-PACKER-KNOWN`.
    Elf,
}

impl PackerFormat {
    /// The finding that names a packer of this format.
    pub fn finding_id(self) -> &'static str {
        match self {
            PackerFormat::Pe => "PE-PACKER-KNOWN",
            PackerFormat::Elf => "ELF-PACKER-KNOWN",
        }
    }
}

/// Validated packer and runtime explanations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackerRuleSet {
    /// One entry per (packer, format).
    pub packers: Vec<PackerRule>,
    /// One entry per runtime.
    pub runtimes: Vec<RuntimeRule>,
    /// `include_defaults = true` in the file: merge with the bundled rules.
    pub include_defaults: bool,
}

/// What a confirmed packer explains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackerRule {
    /// Packer name as detected by the format's packers analyzer.
    pub name: &'static str,
    /// Format.
    pub format: PackerFormat,
    /// Indicators that must all be present.
    pub confirm_with: Vec<&'static str>,
    /// Finding IDs explained once confirmed (all from [`EXPLAINABLE_IDS`]).
    pub explains: Vec<&'static str>,
}

/// What a confirmed runtime explains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeRule {
    /// Runtime name as reported in `facts.runtime.language` (`go`, `rust`).
    pub name: &'static str,
    /// Independent indicators required (at least [`MIN_CONFIRM_INDICATORS`]).
    pub confirm_min: usize,
    /// Finding IDs explained (all from [`RUNTIME_EXPLAINABLE_IDS`]).
    pub explains: Vec<&'static str>,
}

impl PackerRule {
    /// `true` if every required indicator is in `found`.
    pub fn is_confirmed_by(&self, found: &[&str]) -> bool {
        self.confirm_with.iter().all(|i| found.contains(i))
    }
}

impl PackerRuleSet {
    /// An empty rule set (explains nothing).
    pub fn empty() -> Self {
        Self {
            packers: Vec::new(),
            runtimes: Vec::new(),
            include_defaults: false,
        }
    }

    /// The bundled explanations (parsed once).
    ///
    /// # Errors
    /// Only if the bundled file is broken, which the test suite prevents.
    pub fn bundled() -> Result<&'static PackerRuleSet, &'static RulesError> {
        static BUNDLED: LazyLock<Result<PackerRuleSet, RulesError>> =
            LazyLock::new(|| PackerRuleSet::parse(BUNDLED_PACKER_RULES));
        BUNDLED.as_ref()
    }

    /// Parses and validates a packer/runtime explanations file.
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
        let raw: RawPackerFile = toml::from_str(text).map_err(|e| RulesError::Syntax {
            reason: e.to_string(),
        })?;
        if raw.schema_version != SCHEMA_VERSION {
            return Err(RulesError::Schema {
                found: raw.schema_version,
            });
        }
        if raw.packers.len() + raw.runtimes.len() > MAX_GROUPS {
            return Err(RulesError::TooManyGroups {
                count: raw.packers.len() + raw.runtimes.len(),
            });
        }
        let mut seen = BTreeSet::new();
        let mut packers = Vec::with_capacity(raw.packers.len());
        for p in raw.packers {
            let format = match p.format.as_str() {
                "pe" => PackerFormat::Pe,
                "elf" => PackerFormat::Elf,
                other => {
                    return Err(invalid(
                        &p.name,
                        &format!("unknown format {other:?} (pe or elf)"),
                    ))
                }
            };
            let known: Vec<(&'static str, Vec<&'static str>)> = match format {
                PackerFormat::Pe => crate::analyzers::pe::packers::known_packers().collect(),
                PackerFormat::Elf => crate::analyzers::elf::packers::known_packers().collect(),
            };
            let Some((name, available)) = known.iter().find(|(n, _)| *n == p.name) else {
                return Err(invalid(&p.name, "unknown packer name for this format"));
            };
            if !seen.insert((*name, p.format.clone())) {
                return Err(invalid(&p.name, "duplicate packer"));
            }
            let mut confirm_with = Vec::new();
            for ind in &p.confirm_with {
                let Some(i) = available.iter().find(|a| **a == ind.as_str()) else {
                    return Err(invalid(
                        &p.name,
                        &format!("indicator {ind:?} is not available for this packer"),
                    ));
                };
                if !confirm_with.contains(i) {
                    confirm_with.push(*i);
                }
            }
            if confirm_with.len() < MIN_CONFIRM_INDICATORS {
                return Err(invalid(
                    &p.name,
                    "confirm_with needs at least two different indicators",
                ));
            }
            let explains = explained_ids(&p.name, &p.explains, EXPLAINABLE_IDS, "a packer")?;
            packers.push(PackerRule {
                name,
                format,
                confirm_with,
                explains,
            });
        }
        let mut runtimes = Vec::with_capacity(raw.runtimes.len());
        for r in raw.runtimes {
            let Some(name) = crate::analyzers::runtime::KNOWN_RUNTIMES
                .iter()
                .find(|n| **n == r.name.as_str())
            else {
                return Err(invalid(&r.name, "unknown runtime (go or rust)"));
            };
            if runtimes.iter().any(|x: &RuntimeRule| x.name == *name) {
                return Err(invalid(&r.name, "duplicate runtime"));
            }
            if r.confirm_min < MIN_CONFIRM_INDICATORS {
                return Err(invalid(&r.name, "confirm_min must be at least 2"));
            }
            let explains =
                explained_ids(&r.name, &r.explains, RUNTIME_EXPLAINABLE_IDS, "a runtime")?;
            runtimes.push(RuntimeRule {
                name,
                confirm_min: r.confirm_min,
                explains,
            });
        }
        Ok(Self {
            packers,
            runtimes,
            include_defaults: raw.include_defaults,
        })
    }

    /// `self` layered over `defaults`: a packer (same name and format) or
    /// runtime (same name) replaces the default entry, new ones are appended.
    ///
    /// # Errors
    /// [`RulesError::TooManyGroups`] if the merged set is too large.
    pub fn merged_over(self, defaults: &PackerRuleSet) -> Result<PackerRuleSet, RulesError> {
        let mut packers = defaults.packers.clone();
        for p in self.packers {
            match packers
                .iter_mut()
                .find(|d| d.name == p.name && d.format == p.format)
            {
                Some(slot) => *slot = p,
                None => packers.push(p),
            }
        }
        let mut runtimes = defaults.runtimes.clone();
        for rt in self.runtimes {
            match runtimes.iter_mut().find(|d| d.name == rt.name) {
                Some(slot) => *slot = rt,
                None => runtimes.push(rt),
            }
        }
        if packers.len() + runtimes.len() > MAX_GROUPS {
            return Err(RulesError::TooManyGroups {
                count: packers.len() + runtimes.len(),
            });
        }
        Ok(PackerRuleSet {
            packers,
            runtimes,
            include_defaults: false,
        })
    }
}

/// Validates `ids` against `allowed`, deduplicating.
fn explained_ids(
    owner: &str,
    ids: &[String],
    allowed: &[&'static str],
    what: &str,
) -> Result<Vec<&'static str>, RulesError> {
    let mut out = Vec::new();
    for id in ids {
        let Some(known) = allowed.iter().find(|k| **k == id.as_str()) else {
            return Err(invalid(
                owner,
                &format!("{id:?} cannot be explained by {what} (API groups never can)"),
            ));
        };
        if !out.contains(known) {
            out.push(*known);
        }
    }
    Ok(out)
}
#[cfg(test)]
mod packer_tests {
    use super::*;

    fn file(body: &str) -> String {
        format!("schema_version = 1\n[[packer]]\n{body}\n")
    }

    #[test]
    fn bundled_packer_rules_are_valid() {
        let r = PackerRuleSet::bundled().unwrap();
        assert_eq!(r.packers.len(), 2);
        assert_eq!(
            r.runtimes.iter().map(|r| r.name).collect::<Vec<_>>(),
            ["go", "rust"]
        );
        let upx = &r.packers[0];
        assert_eq!((upx.name, upx.format), ("UPX", PackerFormat::Pe));
        let elf = &r.packers[1];
        assert_eq!((elf.name, elf.format), ("UPX", PackerFormat::Elf));
        assert_eq!(
            elf.confirm_with,
            ["header_signature", "info_banner", "stub_structure"]
        );
        assert!(elf.explains.contains(&"ELF-PACKED-LIKELY"));
        assert_eq!(
            upx.confirm_with,
            ["section_names", "header_signature", "stub_structure"]
        );
        assert!(upx.explains.contains(&"PE-SECTION-RWX"));
        assert!(upx.explains.iter().all(|id| !id.starts_with("PE-API-")));
    }

    #[test]
    fn elf_packer_uses_elf_indicators() {
        let ok = file(
            "name = \"UPX\"\nformat = \"elf\"\nconfirm_with = [\"header_signature\", \"info_banner\"]\n\
             explains = [\"ELF-SEGMENT-RWX\"]",
        );
        assert!(PackerRuleSet::parse(&ok).is_ok());
        // section_names is a PE indicator.
        let bad = ok.replace("\"info_banner\"", "\"section_names\"");
        assert!(PackerRuleSet::parse(&bad).is_err());
        let fmt = ok.replace("\"elf\"", "\"macho\"");
        assert!(PackerRuleSet::parse(&fmt).is_err());
    }

    #[test]
    fn elf_api_groups_can_never_be_explained() {
        let f = file(
            "name = \"UPX\"\nformat = \"elf\"\nconfirm_with = [\"header_signature\", \"info_banner\"]\n\
             explains = [\"ELF-API-SHELL\"]",
        );
        assert!(PackerRuleSet::parse(&f).is_err());
    }

    fn runtime(body: &str) -> String {
        format!("schema_version = 1\n[[runtime]]\n{body}\n")
    }

    #[test]
    fn runtimes_explain_only_small_findings() {
        let ok = runtime("name = \"go\"\nconfirm_min = 2\nexplains = [\"ELF-HARDENING-NO-PIE\"]");
        assert!(PackerRuleSet::parse(&ok).is_ok());
        for id in [
            "ELF-PACKED-LIKELY",
            "PE-SECTION-RWX",
            "ELF-API-NETWORK",
            "ELF-HARDENING-EXEC-STACK",
        ] {
            let bad = ok.replace("ELF-HARDENING-NO-PIE", id);
            assert!(PackerRuleSet::parse(&bad).is_err(), "{id}");
        }
    }

    #[test]
    fn runtime_needs_two_indicators_and_a_known_name() {
        let one = runtime("name = \"go\"\nconfirm_min = 1\nexplains = []");
        assert!(PackerRuleSet::parse(&one).is_err());
        let unknown = runtime("name = \"zig\"\nconfirm_min = 2\nexplains = []");
        assert!(PackerRuleSet::parse(&unknown).is_err());
    }
    #[test]
    fn api_groups_can_never_be_explained() {
        let f = file(
            "name = \"UPX\"\nconfirm_with = [\"section_names\", \"header_signature\"]\n\
             explains = [\"PE-API-INJECTION\"]",
        );
        assert!(matches!(
            PackerRuleSet::parse(&f),
            Err(RulesError::Invalid { .. })
        ));
    }

    #[test]
    fn single_indicator_is_rejected() {
        let f = file(
            "name = \"UPX\"\nconfirm_with = [\"section_names\", \"section_names\"]\nexplains = []",
        );
        assert!(matches!(
            PackerRuleSet::parse(&f),
            Err(RulesError::Invalid { .. })
        ));
    }

    #[test]
    fn unavailable_indicator_is_rejected() {
        // ASPack has no header signature or stub check in rtriage.
        let f = file("name = \"ASPack\"\nconfirm_with = [\"section_names\", \"header_signature\"]\nexplains = []");
        assert!(matches!(
            PackerRuleSet::parse(&f),
            Err(RulesError::Invalid { .. })
        ));
    }

    #[test]
    fn unknown_packer_and_fields_are_rejected() {
        let f = file("name = \"Nope\"\nconfirm_with = []\nexplains = []");
        assert!(PackerRuleSet::parse(&f).is_err());
        let f = file("name = \"UPX\"\nconfirm_with = []\nexplains = []\nextra = 1");
        assert!(matches!(
            PackerRuleSet::parse(&f),
            Err(RulesError::Syntax { .. })
        ));
    }

    #[test]
    fn confirmation_needs_every_indicator() {
        let upx = &PackerRuleSet::bundled().unwrap().packers[0];
        assert!(upx.is_confirmed_by(&["section_names", "header_signature", "stub_structure"]));
        assert!(!upx.is_confirmed_by(&["section_names", "header_signature"]));
        assert!(!upx.is_confirmed_by(&["section_names"]));
    }
}

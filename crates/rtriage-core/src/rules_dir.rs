//! A user rules directory (`--rules-dir`): known file names, each optional,
//! layered over the bundled rules.
//!
//! | File | Effect |
//! |---|---|
//! | `api_groups.toml` | PE behavior groups: **replace** the bundled ones, or merge with `include_defaults = true` |
//! | `elf_api_groups.toml` | ELF behavior groups: same |
//! | `packers.toml` | packer / runtime explanations: same |
//! | `ioc_allowlist.toml` | IOC allowlist: always **added** to the bundled one |
//!
//! A missing file means "use the bundled one". Every file goes through the
//! same validation and size/count limits as the bundled data, and merged sets
//! obey the same limits. Other files are ignored and reported back.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::analyzers::iocs::IocAllowlist;
use crate::config::Config;
use crate::rules::{ApiRuleSet, PackerRuleSet, RuleTarget, RulesError, MAX_RULES_FILE_SIZE};
use crate::yara_sources::YaraSettings;

/// PE behavior groups.
pub const API_RULES_FILE: &str = "api_groups.toml";
/// ELF behavior groups.
pub const ELF_API_RULES_FILE: &str = "elf_api_groups.toml";
/// Packer and runtime explanations.
pub const PACKER_RULES_FILE: &str = "packers.toml";
/// IOC allowlist additions.
pub const IOC_ALLOWLIST_FILE: &str = "ioc_allowlist.toml";
/// YARA settings (bundled rules on/off, limits).
pub const YARA_SETTINGS_FILE: &str = "yara.toml";
/// Directory of user YARA rule files.
pub const YARA_DIR: &str = "yara";
/// Every file name a rules directory may contain.
pub const KNOWN_FILES: [&str; 5] = [
    API_RULES_FILE,
    ELF_API_RULES_FILE,
    PACKER_RULES_FILE,
    IOC_ALLOWLIST_FILE,
    YARA_SETTINGS_FILE,
];
/// Directory entries looked at when listing unknown files.
const MAX_DIR_ENTRIES: usize = 1024;

/// Why a rules directory could not be used.
#[derive(Debug, thiserror::Error)]
pub enum RulesDirError {
    /// The path is missing or not a directory.
    #[error("{path}: not a directory")]
    NotADirectory {
        /// Path as given.
        path: PathBuf,
    },
    /// A known file exists but cannot be read.
    #[error("{path}: {source}")]
    Io {
        /// File path.
        path: PathBuf,
        /// Underlying error.
        source: std::io::Error,
    },
    /// A known file exists but is not a regular file.
    #[error("{path}: not a regular file")]
    NotAFile {
        /// File path.
        path: PathBuf,
    },
    /// A known file is invalid, or merging it exceeded a limit.
    #[error("{path}: {source}")]
    Rules {
        /// File path.
        path: PathBuf,
        /// What is wrong.
        source: RulesError,
    },
}

/// Rules loaded from a directory, already merged with the bundled ones.
#[derive(Debug, Clone, Default)]
pub struct RulesDir {
    /// Effective PE rules (`None`: bundled).
    pub api_rules: Option<ApiRuleSet>,
    /// Effective ELF rules (`None`: bundled).
    pub elf_api_rules: Option<ApiRuleSet>,
    /// Effective packer rules (`None`: bundled).
    pub packer_rules: Option<PackerRuleSet>,
    /// Effective allowlist, bundled plus additions (`None`: bundled).
    pub ioc_allowlist: Option<IocAllowlist>,
    /// `yara.toml` settings (`None`: defaults).
    pub yara_settings: Option<YaraSettings>,
    /// `<dir>/yara/` if it exists (user rule files).
    pub yara_dir: Option<PathBuf>,
    /// Known files that were found, in [`KNOWN_FILES`] order.
    pub loaded: Vec<&'static str>,
    /// Other `.toml` files in the directory (likely typos), sorted.
    pub ignored: Vec<String>,
}

impl RulesDir {
    /// Loads every known file in `dir`.
    ///
    /// # Errors
    /// See [`RulesDirError`]; the first problem found is reported.
    pub fn load(dir: &Path) -> Result<Self, RulesDirError> {
        if !dir.is_dir() {
            return Err(RulesDirError::NotADirectory {
                path: dir.to_path_buf(),
            });
        }
        let mut out = RulesDir::default();
        let bundled_err = |path: &Path, e: &RulesError| RulesDirError::Rules {
            path: path.to_path_buf(),
            source: RulesError::Invalid {
                id: "(bundled)".into(),
                reason: e.to_string(),
            },
        };

        if let Some((path, text)) = read_known(dir, API_RULES_FILE)? {
            let rules = ApiRuleSet::parse_for(&text, RuleTarget::Pe).map_err(at(&path))?;
            out.api_rules = Some(if rules.include_defaults {
                let defaults = ApiRuleSet::bundled().map_err(|e| bundled_err(&path, e))?;
                rules.merged_over(defaults).map_err(at(&path))?
            } else {
                rules
            });
            out.loaded.push(API_RULES_FILE);
        }
        if let Some((path, text)) = read_known(dir, ELF_API_RULES_FILE)? {
            let rules = ApiRuleSet::parse_for(&text, RuleTarget::Elf).map_err(at(&path))?;
            out.elf_api_rules = Some(if rules.include_defaults {
                let defaults = ApiRuleSet::bundled_elf().map_err(|e| bundled_err(&path, e))?;
                rules.merged_over(defaults).map_err(at(&path))?
            } else {
                rules
            });
            out.loaded.push(ELF_API_RULES_FILE);
        }
        if let Some((path, text)) = read_known(dir, PACKER_RULES_FILE)? {
            let rules = PackerRuleSet::parse(&text).map_err(at(&path))?;
            out.packer_rules = Some(if rules.include_defaults {
                let defaults = PackerRuleSet::bundled().map_err(|e| bundled_err(&path, e))?;
                rules.merged_over(defaults).map_err(at(&path))?
            } else {
                rules
            });
            out.loaded.push(PACKER_RULES_FILE);
        }
        if let Some((path, text)) = read_known(dir, IOC_ALLOWLIST_FILE)? {
            let extra = IocAllowlist::parse(&text).map_err(at(&path))?;
            let defaults = IocAllowlist::bundled().map_err(|e| bundled_err(&path, e))?;
            out.ioc_allowlist = Some(extra.merged_over(defaults).map_err(at(&path))?);
            out.loaded.push(IOC_ALLOWLIST_FILE);
        }
        if let Some((path, text)) = read_known(dir, YARA_SETTINGS_FILE)? {
            out.yara_settings = Some(YaraSettings::parse(&text).map_err(at(&path))?);
            out.loaded.push(YARA_SETTINGS_FILE);
        }
        let yara_dir = dir.join(YARA_DIR);
        if yara_dir.is_dir() {
            out.yara_dir = Some(yara_dir);
        }
        out.ignored = unknown_toml_files(dir);
        Ok(out)
    }

    /// Puts the loaded rules into `config` (bundled ones stay where nothing
    /// was loaded).
    pub fn apply(self, config: &mut Config) {
        if let Some(r) = self.api_rules {
            config.api_rules = Some(Arc::new(r));
        }
        if let Some(r) = self.elf_api_rules {
            config.elf_api_rules = Some(Arc::new(r));
        }
        if let Some(r) = self.packer_rules {
            config.packer_rules = Some(Arc::new(r));
        }
        if let Some(a) = self.ioc_allowlist {
            config.ioc_allowlist = Some(Arc::new(a));
        }
        if let Some(s) = self.yara_settings {
            s.apply(&mut config.limits);
        }
    }
}

fn at(path: &Path) -> impl Fn(RulesError) -> RulesDirError + '_ {
    move |source| RulesDirError::Rules {
        path: path.to_path_buf(),
        source,
    }
}

/// `Some((path, text))` if `dir/name` exists. The size is checked before
/// reading, and the read itself is bounded too.
fn read_known(dir: &Path, name: &str) -> Result<Option<(PathBuf, String)>, RulesDirError> {
    let path = dir.join(name);
    let meta = match std::fs::metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(RulesDirError::Io { path, source }),
    };
    if !meta.is_file() {
        return Err(RulesDirError::NotAFile { path });
    }
    let too_large = |size: usize| RulesDirError::Rules {
        path: path.clone(),
        source: RulesError::TooLarge {
            size,
            limit: MAX_RULES_FILE_SIZE,
        },
    };
    if usize::try_from(meta.len()).map_or(true, |l| l > MAX_RULES_FILE_SIZE) {
        return Err(too_large(usize::try_from(meta.len()).unwrap_or(usize::MAX)));
    }
    let file = std::fs::File::open(&path).map_err(|source| RulesDirError::Io {
        path: path.clone(),
        source,
    })?;
    let mut text = String::new();
    let limit = u64::try_from(MAX_RULES_FILE_SIZE)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    file.take(limit)
        .read_to_string(&mut text)
        .map_err(|source| RulesDirError::Io {
            path: path.clone(),
            source,
        })?;
    if text.len() > MAX_RULES_FILE_SIZE {
        return Err(too_large(text.len()));
    }
    Ok(Some((path, text)))
}

/// `.toml` files in `dir` that are not [`KNOWN_FILES`] (best effort, bounded).
fn unknown_toml_files(dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<String> = entries
        .take(MAX_DIR_ENTRIES)
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.to_ascii_lowercase().ends_with(".toml") && !KNOWN_FILES.contains(&n.as_str()))
        .collect();
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str, files: &[(&str, &str)]) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rtriage-rules-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        for (f, text) in files {
            std::fs::write(d.join(f), text).unwrap();
        }
        d
    }

    const BEEP: &str = r#"schema_version = 1
[[group]]
id = "PE-API-BEEP"
title = "Beeps"
severity = "info"
confidence = "high"
category = "metadata"
rationale = "Imports Beep."
[[group.when]]
slots = [["Beep"]]
"#;

    #[test]
    fn empty_dir_uses_bundled_everything() {
        let d = dir("empty", &[]);
        let r = RulesDir::load(&d).unwrap();
        assert!(r.loaded.is_empty());
        assert!(r.api_rules.is_none() && r.ioc_allowlist.is_none());
    }

    #[test]
    fn api_rules_replace_by_default() {
        let d = dir("replace", &[(API_RULES_FILE, BEEP)]);
        let r = RulesDir::load(&d).unwrap();
        let ids: Vec<_> = r.api_rules.unwrap().groups.iter().map(|g| g.id).collect();
        assert_eq!(ids, ["PE-API-BEEP"]);
    }

    #[test]
    fn include_defaults_merges_and_overrides_by_id() {
        let text = format!(
            "include_defaults = true\n{}\n{}",
            BEEP,
            BEEP.replace("PE-API-BEEP", "PE-API-INJECTION")
                .replace("schema_version = 1\n", "")
                .replace("Beeps", "Overridden")
        );
        let d = dir("merge", &[(API_RULES_FILE, &text)]);
        let rules = RulesDir::load(&d).unwrap().api_rules.unwrap();
        let bundled = ApiRuleSet::bundled().unwrap();
        assert_eq!(rules.groups.len(), bundled.groups.len() + 1);
        let inj = rules
            .groups
            .iter()
            .find(|g| g.id == "PE-API-INJECTION")
            .unwrap();
        assert_eq!(inj.title, "Overridden");
        // Overrides keep the bundled position.
        assert_eq!(rules.groups[0].id, bundled.groups[0].id);
        assert_eq!(rules.groups.last().unwrap().id, "PE-API-BEEP");
    }

    #[test]
    fn allowlist_is_always_added() {
        let d = dir(
            "allow",
            &[(
                IOC_ALLOWLIST_FILE,
                "schema_version = 1\ndomains = [\"corp.example\"]",
            )],
        );
        let a = RulesDir::load(&d).unwrap().ioc_allowlist.unwrap();
        assert!(a.allows_domain("intranet.corp.example"));
        assert!(a.allows_domain("schemas.microsoft.com"));
    }

    #[test]
    fn elf_rules_need_elf_ids() {
        let d = dir("elf", &[(ELF_API_RULES_FILE, BEEP)]);
        assert!(matches!(
            RulesDir::load(&d),
            Err(RulesDirError::Rules { .. })
        ));
    }

    #[test]
    fn invalid_file_names_the_path() {
        let d = dir("bad", &[(PACKER_RULES_FILE, "schema_version = 2")]);
        let e = RulesDir::load(&d).unwrap_err().to_string();
        assert!(e.contains(PACKER_RULES_FILE), "{e}");
    }

    #[test]
    fn oversized_file_is_refused_before_parsing() {
        let big = "#".repeat(MAX_RULES_FILE_SIZE + 1);
        let d = dir("big", &[(API_RULES_FILE, &big)]);
        assert!(matches!(
            RulesDir::load(&d),
            Err(RulesDirError::Rules {
                source: RulesError::TooLarge { .. },
                ..
            })
        ));
    }

    #[test]
    fn merged_sets_keep_the_group_limit() {
        let mut text = String::from("schema_version = 1\ninclude_defaults = true\n");
        for i in 0..crate::rules::MAX_GROUPS {
            text.push_str(
                &BEEP
                    .replace("schema_version = 1\n", "")
                    .replace("PE-API-BEEP", &format!("PE-API-B{i}")),
            );
        }
        let d = dir("limit", &[(API_RULES_FILE, &text)]);
        assert!(matches!(
            RulesDir::load(&d),
            Err(RulesDirError::Rules {
                source: RulesError::TooManyGroups { .. },
                ..
            })
        ));
    }

    #[test]
    fn unknown_files_are_reported_and_missing_dir_is_an_error() {
        let d = dir("typo", &[("api-groups.toml", BEEP), ("notes.txt", "x")]);
        let r = RulesDir::load(&d).unwrap();
        assert_eq!(r.ignored, ["api-groups.toml"]);
        assert!(r.api_rules.is_none());
        assert!(matches!(
            RulesDir::load(&d.join("nope")),
            Err(RulesDirError::NotADirectory { .. })
        ));
    }
}

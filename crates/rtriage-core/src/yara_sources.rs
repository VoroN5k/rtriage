//! Where YARA rule text comes from, and the `yara.toml` settings. Plain file
//! handling: available without the `yara` feature, so a build without YARA
//! can still tell the user that rules were given but cannot be used.
//!
//! Sources, in order (each becomes its own namespace):
//! 1. the bundled first-party rules (`rules/yara/*.yar`, namespace `rtriage`),
//!    unless `yara.toml` says `include_bundled = false`;
//! 2. `<rules-dir>/yara/` and every `--yara <PATH>`: a file is taken as is,
//!    a directory is walked (sorted, symlinks not followed) for `*.yar` /
//!    `*.yara` files.
//!
//! Bounded by [`YaraLoadLimits`]: file count and total size are checked
//! from metadata before anything is read, and every read is capped too.

use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::limits::Limits;
use crate::walk::{self, WalkOptions};

/// One rule source to compile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YaraSource {
    /// Shown in errors (usually the file path).
    pub origin: String,
    /// Namespace of its rules (one per file keeps equal rule names apart).
    pub namespace: String,
    /// Rule text.
    pub text: String,
}

/// The bundled rule files.
const BUNDLED: &[(&str, &str)] = &[
    ("eicar.yar", include_str!("../../../rules/yara/eicar.yar")),
    (
        "embedded_pe.yar",
        include_str!("../../../rules/yara/embedded_pe.yar"),
    ),
];

/// Namespace of the bundled rules.
pub const BUNDLED_NAMESPACE: &str = "rtriage";

/// The bundled first-party rules, all in namespace [`BUNDLED_NAMESPACE`].
pub fn bundled_sources() -> Vec<YaraSource> {
    BUNDLED
        .iter()
        .map(|(name, text)| YaraSource {
            origin: format!("bundled rules/yara/{name}"),
            namespace: BUNDLED_NAMESPACE.to_owned(),
            text: (*text).to_owned(),
        })
        .collect()
}

/// Bounds on loading user rule files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct YaraLoadLimits {
    /// Rule files across all paths. Default: 1000.
    pub max_files: usize,
    /// Total bytes of rule text. Default: 16 MiB.
    pub max_total_size: u64,
}

impl Default for YaraLoadLimits {
    fn default() -> Self {
        Self {
            max_files: 1000,
            max_total_size: 16 << 20,
        }
    }
}

/// Why user rules could not be loaded.
#[derive(Debug, thiserror::Error)]
pub enum YaraLoadError {
    /// A path is missing or unreadable.
    #[error("{path}: {source}")]
    Io {
        /// The path.
        path: PathBuf,
        /// Underlying error.
        source: std::io::Error,
    },
    /// More rule files than `max_files`.
    #[error("more than {limit} YARA rule files (yara.toml limits.max_files)")]
    TooManyFiles {
        /// The limit.
        limit: usize,
    },
    /// More rule text than `max_total_size`.
    #[error("YARA rule files exceed {limit} bytes in total (yara.toml limits.max_total_size)")]
    TooLarge {
        /// The limit.
        limit: u64,
    },
    /// A rule file is not UTF-8.
    #[error("{path}: not valid UTF-8")]
    NotUtf8 {
        /// The path.
        path: PathBuf,
    },
    /// A path is neither a file nor a directory.
    #[error("{path}: not a file or directory")]
    NotAFile {
        /// The path.
        path: PathBuf,
    },
}

/// Reads every rule file under `paths` (see the module docs), in order.
///
/// # Errors
/// See [`YaraLoadError`]; the first problem stops loading.
pub fn load_sources(
    paths: &[PathBuf],
    limits: YaraLoadLimits,
) -> Result<Vec<YaraSource>, YaraLoadError> {
    let mut files: Vec<PathBuf> = Vec::new();
    for p in paths {
        let meta = std::fs::metadata(p).map_err(|source| YaraLoadError::Io {
            path: p.clone(),
            source,
        })?;
        if meta.is_file() {
            files.push(p.clone());
        } else if meta.is_dir() {
            let w = walk::collect(
                std::slice::from_ref(p),
                WalkOptions {
                    max_depth: 32,
                    max_files: limits.max_files.saturating_add(1).saturating_mul(4),
                },
            );
            if let Some(e) = w.errors.into_iter().next() {
                return Err(YaraLoadError::Io {
                    path: e.path,
                    source: e.error,
                });
            }
            files.extend(w.files.into_iter().filter(|f| is_rule_file(f)));
        } else {
            return Err(YaraLoadError::NotAFile { path: p.clone() });
        }
        if files.len() > limits.max_files {
            return Err(YaraLoadError::TooManyFiles {
                limit: limits.max_files,
            });
        }
    }
    // Sizes from metadata first: refuse before reading anything.
    let mut total = 0u64;
    for f in &files {
        let len = std::fs::metadata(f)
            .map_err(|source| YaraLoadError::Io {
                path: f.clone(),
                source,
            })?
            .len();
        total = total.saturating_add(len);
        if total > limits.max_total_size {
            return Err(YaraLoadError::TooLarge {
                limit: limits.max_total_size,
            });
        }
    }
    let mut namespaces: Vec<String> = Vec::new();
    let mut out = Vec::with_capacity(files.len());
    let mut read_total = 0u64;
    for f in files {
        let text = read_bounded(&f, limits.max_total_size.saturating_sub(read_total))?;
        read_total = read_total.saturating_add(text.len() as u64);
        out.push(YaraSource {
            origin: f.to_string_lossy().into_owned(),
            namespace: unique_namespace(&f, &mut namespaces),
            text,
        });
    }
    Ok(out)
}

fn is_rule_file(p: &Path) -> bool {
    p.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("yar") || e.eq_ignore_ascii_case("yara"))
}

/// The file stem, made unique among `taken` (`name`, `name#2`, ...).
fn unique_namespace(path: &Path, taken: &mut Vec<String>) -> String {
    let stem = path
        .file_stem()
        .map_or_else(|| "rules".to_owned(), |s| s.to_string_lossy().into_owned());
    let base = if stem == BUNDLED_NAMESPACE {
        format!("{stem}-user")
    } else {
        stem
    };
    let mut name = base.clone();
    let mut n = 2;
    while taken.contains(&name) {
        name = format!("{base}#{n}");
        n += 1;
    }
    taken.push(name.clone());
    name
}

/// Reads at most `budget` bytes; a file that turns out larger (it grew after
/// the metadata check) is an error, not a truncated rule.
fn read_bounded(path: &Path, budget: u64) -> Result<String, YaraLoadError> {
    let io = |source| YaraLoadError::Io {
        path: path.to_path_buf(),
        source,
    };
    let file = std::fs::File::open(path).map_err(io)?;
    let mut bytes = Vec::new();
    file.take(budget.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(io)?;
    if bytes.len() as u64 > budget {
        return Err(YaraLoadError::TooLarge { limit: budget });
    }
    String::from_utf8(bytes).map_err(|_| YaraLoadError::NotUtf8 {
        path: path.to_path_buf(),
    })
}

// ------------------------------------------------------------------ yara.toml

/// `<rules-dir>/yara.toml`: which rules to use and the YARA limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct YaraSettings {
    /// Compile the bundled rules too. Default: true.
    pub include_bundled: bool,
    /// Loading bounds.
    pub load: YaraLoadLimits,
    /// Matching rules reported per file (`Limits::max_yara_matches`).
    pub max_matches: usize,
    /// Matches recorded per pattern (`Limits::max_yara_pattern_matches`).
    pub max_pattern_matches: usize,
    /// Ranges kept per matching rule (`Limits::max_yara_strings_per_rule`).
    pub max_strings_per_rule: usize,
}

impl Default for YaraSettings {
    fn default() -> Self {
        let l = Limits::default();
        Self {
            include_bundled: true,
            load: YaraLoadLimits::default(),
            max_matches: l.max_yara_matches,
            max_pattern_matches: l.max_yara_pattern_matches,
            max_strings_per_rule: l.max_yara_strings_per_rule,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSettings {
    schema_version: u32,
    #[serde(default)]
    include_bundled: Option<bool>,
    #[serde(default)]
    limits: RawLimits,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLimits {
    max_files: Option<usize>,
    max_total_size: Option<u64>,
    max_matches: Option<usize>,
    max_pattern_matches: Option<usize>,
    max_strings_per_rule: Option<usize>,
}

/// Upper bounds a `yara.toml` may set (limits stay limits).
const MAX_FILES_CEILING: usize = 100_000;
const MAX_TOTAL_SIZE_CEILING: u64 = 256 << 20;
const MAX_MATCHES_CEILING: usize = 10_000;
const MAX_PATTERN_MATCHES_CEILING: usize = 1_000_000;
const MAX_STRINGS_CEILING: usize = 1024;

impl YaraSettings {
    /// Parses and validates a `yara.toml`.
    ///
    /// # Errors
    /// [`crate::rules::RulesError`] for syntax, schema or out-of-range values.
    pub fn parse(text: &str) -> Result<Self, crate::rules::RulesError> {
        use crate::rules::{RulesError, MAX_RULES_FILE_SIZE, SCHEMA_VERSION};
        if text.len() > MAX_RULES_FILE_SIZE {
            return Err(RulesError::TooLarge {
                size: text.len(),
                limit: MAX_RULES_FILE_SIZE,
            });
        }
        let raw: RawSettings = toml::from_str(text).map_err(|e| RulesError::Syntax {
            reason: e.to_string(),
        })?;
        if raw.schema_version != SCHEMA_VERSION {
            return Err(RulesError::Schema {
                found: raw.schema_version,
            });
        }
        let bad = |name: &str, max: u64| RulesError::Invalid {
            id: format!("limits.{name}"),
            reason: format!("must be between 1 and {max}"),
        };
        let mut s = YaraSettings::default();
        if let Some(b) = raw.include_bundled {
            s.include_bundled = b;
        }
        let l = raw.limits;
        if let Some(v) = l.max_files {
            if v == 0 || v > MAX_FILES_CEILING {
                return Err(bad("max_files", MAX_FILES_CEILING as u64));
            }
            s.load.max_files = v;
        }
        if let Some(v) = l.max_total_size {
            if v == 0 || v > MAX_TOTAL_SIZE_CEILING {
                return Err(bad("max_total_size", MAX_TOTAL_SIZE_CEILING));
            }
            s.load.max_total_size = v;
        }
        for (name, value, ceiling, slot) in [
            (
                "max_matches",
                l.max_matches,
                MAX_MATCHES_CEILING,
                &mut s.max_matches,
            ),
            (
                "max_pattern_matches",
                l.max_pattern_matches,
                MAX_PATTERN_MATCHES_CEILING,
                &mut s.max_pattern_matches,
            ),
            (
                "max_strings_per_rule",
                l.max_strings_per_rule,
                MAX_STRINGS_CEILING,
                &mut s.max_strings_per_rule,
            ),
        ] {
            if let Some(v) = value {
                if v == 0 || v > ceiling {
                    return Err(bad(name, ceiling as u64));
                }
                *slot = v;
            }
        }
        Ok(s)
    }

    /// Copies the scan limits into `limits`.
    pub fn apply(&self, limits: &mut Limits) {
        limits.max_yara_matches = self.max_matches;
        limits.max_yara_pattern_matches = self.max_pattern_matches;
        limits.max_yara_strings_per_rule = self.max_strings_per_rule;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(name: &str, files: &[(&str, &[u8])]) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("rtriage-yara-src-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for (f, bytes) in files {
            let p = root.join(f);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, bytes).unwrap();
        }
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn bundled_sources_exist_and_never_hold_the_full_eicar_string() {
        let b = bundled_sources();
        assert_eq!(b.len(), 2);
        assert!(b.iter().all(|s| s.namespace == BUNDLED_NAMESPACE));
        let eicar_tail = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE";
        assert!(b.iter().all(|s| !s.text.contains(eicar_tail)));
    }

    #[test]
    fn directories_give_sorted_rule_files_only() {
        let root = tree(
            "dir",
            &[
                ("b.yar", b"rule b { condition: true }"),
                ("a.YARA", b"x"),
                ("notes.txt", b"x"),
                ("sub/c.yar", b"x"),
            ],
        );
        let s = load_sources(std::slice::from_ref(&root), YaraLoadLimits::default()).unwrap();
        let ns: Vec<_> = s.iter().map(|s| s.namespace.as_str()).collect();
        assert_eq!(ns, ["a", "b", "c"]);
    }

    #[test]
    fn explicit_files_need_no_extension_and_namespaces_are_unique() {
        let root = tree(
            "ns",
            &[
                ("one/x.yar", b"r"),
                ("two/x.yar", b"r"),
                ("rtriage.yar", b"r"),
                ("plain", b"r"),
            ],
        );
        let paths = [
            root.join("one/x.yar"),
            root.join("two/x.yar"),
            root.join("rtriage.yar"),
            root.join("plain"),
        ];
        let s = load_sources(&paths, YaraLoadLimits::default()).unwrap();
        let ns: Vec<_> = s.iter().map(|s| s.namespace.as_str()).collect();
        assert_eq!(ns, ["x", "x#2", "rtriage-user", "plain"]);
    }

    #[test]
    fn limits_are_checked_before_reading() {
        let root = tree("limits", &[("a.yar", b"12345"), ("b.yar", b"67890")]);
        let one = YaraLoadLimits {
            max_files: 1,
            ..YaraLoadLimits::default()
        };
        assert!(matches!(
            load_sources(std::slice::from_ref(&root), one),
            Err(YaraLoadError::TooManyFiles { limit: 1 })
        ));
        let small = YaraLoadLimits {
            max_total_size: 9,
            ..YaraLoadLimits::default()
        };
        assert!(matches!(
            load_sources(std::slice::from_ref(&root), small),
            Err(YaraLoadError::TooLarge { .. })
        ));
    }

    #[test]
    fn bad_inputs_are_errors() {
        let root = tree("bad", &[("bad.yar", b"rule \xff {}")]);
        assert!(matches!(
            load_sources(&[root.join("bad.yar")], YaraLoadLimits::default()),
            Err(YaraLoadError::NotUtf8 { .. })
        ));
        assert!(matches!(
            load_sources(&[root.join("missing.yar")], YaraLoadLimits::default()),
            Err(YaraLoadError::Io { .. })
        ));
    }

    #[test]
    fn settings_parse_and_bound() {
        let s = YaraSettings::parse(
            "schema_version = 1\ninclude_bundled = false\n[limits]\nmax_files = 5\nmax_matches = 3\n",
        )
        .unwrap();
        assert!(!s.include_bundled);
        assert_eq!((s.load.max_files, s.max_matches), (5, 3));
        assert_eq!(
            s.max_pattern_matches,
            Limits::default().max_yara_pattern_matches
        );
        for bad in [
            "schema_version = 1\n[limits]\nmax_files = 0",
            "schema_version = 1\n[limits]\nmax_total_size = 999999999999",
            "schema_version = 1\n[limits]\nmax_strings_per_rule = 5000",
            "schema_version = 1\n[limits]\nbogus = 1",
            "schema_version = 2",
        ] {
            assert!(YaraSettings::parse(bad).is_err(), "{bad}");
        }
        let mut l = Limits::default();
        s.apply(&mut l);
        assert_eq!(l.max_yara_matches, 3);
    }
}

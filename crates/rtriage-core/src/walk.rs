//! Expands command-line paths into the list of files to analyze.
//!
//! - A path given explicitly is used as is (a symlink named on the command
//!   line is followed, like `find -H`).
//! - Directories are walked recursively, depth-first, entries sorted by name
//!   in every directory, so the order is deterministic.
//! - Inside directories **symlinks are never followed** (no cycles, no
//!   escaping the tree) and special files (FIFOs, sockets, devices) are
//!   skipped: reading a FIFO would block forever.
//! - Bounded: at most [`WalkOptions::max_depth`] directory levels below a
//!   root and [`WalkOptions::max_files`] files in total.
//! - The same file reached twice (two roots, or a root inside another) is
//!   listed once.
//!
//! Nothing here opens a file for reading; size and format checks happen
//! when each file is loaded.

use std::cmp::Ordering;
use std::collections::{BTreeSet, BinaryHeap};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

/// Traversal bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct WalkOptions {
    /// Directory levels below a root that are entered. Default: 32.
    pub max_depth: usize,
    /// Files collected across all roots. Default: 100 000.
    pub max_files: usize,
}

impl Default for WalkOptions {
    fn default() -> Self {
        Self {
            max_depth: 32,
            max_files: 100_000,
        }
    }
}

/// Why a path was not collected. Skips are not failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    /// A symlink inside a walked directory.
    Symlink,
    /// FIFO, socket, device or other non-regular file.
    SpecialFile,
    /// A directory deeper than `max_depth`.
    DepthLimit,
    /// Collection stopped at `max_files`; this directory was not finished.
    FileLimit,
}

/// A path that was skipped, with the reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Skipped {
    /// The path.
    pub path: PathBuf,
    /// Why.
    pub reason: SkipReason,
}

/// A path that could not be examined (missing root, unreadable directory).
#[derive(Debug)]
pub struct WalkError {
    /// The path.
    pub path: PathBuf,
    /// The I/O error.
    pub error: std::io::Error,
}

/// Result of expanding the command-line paths.
#[derive(Debug, Default)]
pub struct Walk {
    /// Files to analyze, in order: roots in command-line order, each
    /// directory's contents sorted by name, depth-first.
    pub files: Vec<PathBuf>,
    /// Paths skipped on purpose.
    pub skipped: Vec<Skipped>,
    /// Paths that could not be examined.
    pub errors: Vec<WalkError>,
    /// `true` if any root was (or contained) a directory.
    pub walked_directories: bool,
}

impl Walk {
    /// `true` once `max_files` has been reached.
    pub fn limit_reached(&self) -> bool {
        self.skipped
            .iter()
            .any(|s| s.reason == SkipReason::FileLimit)
    }
}

/// Expands `roots` into files.
pub fn collect(roots: &[PathBuf], opts: WalkOptions) -> Walk {
    let mut w = Walker {
        opts,
        out: Walk::default(),
        seen: BTreeSet::new(),
    };
    for root in roots {
        if w.full() {
            w.out.skipped.push(Skipped {
                path: root.clone(),
                reason: SkipReason::FileLimit,
            });
            continue;
        }
        // Explicit roots: follow symlinks.
        match fs::metadata(root) {
            Ok(m) if m.is_dir() => {
                w.out.walked_directories = true;
                w.dir(root, 0);
            }
            Ok(m) if m.is_file() => w.file(root),
            Ok(_) => w.out.skipped.push(Skipped {
                path: root.clone(),
                reason: SkipReason::SpecialFile,
            }),
            // Missing or unreadable: the loader reports it as a failure with
            // its usual message, so keep it in the list.
            Err(_) => w.out.files.push(root.clone()),
        }
    }
    w.out
}

/// Directory entries read from one directory before giving up on it
/// (reported as `file_limit`). Bounds time on pathological directories.
const MAX_SCANNED_PER_DIR: usize = 10_000_000;

/// A directory entry ordered by file name only.
struct ByName(OsString, fs::DirEntry);

impl PartialEq for ByName {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for ByName {}
impl PartialOrd for ByName {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for ByName {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

struct Walker {
    opts: WalkOptions,
    out: Walk,
    seen: BTreeSet<PathBuf>,
}

impl Walker {
    fn full(&self) -> bool {
        self.out.files.len() >= self.opts.max_files
    }

    fn file(&mut self, path: &Path) {
        // Dedup on the canonical path; fall back to the path as given.
        let key = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        if self.seen.insert(key) {
            self.out.files.push(path.to_path_buf());
        }
    }

    fn dir(&mut self, dir: &Path, depth: usize) {
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(error) => {
                self.out.errors.push(WalkError {
                    path: dir.to_path_buf(),
                    error,
                });
                return;
            }
        };
        // Bounded and deterministic: keep only the `room + 1` smallest names
        // (a max-heap evicts the largest), whatever order the OS returns.
        // Cutting the list *before* sorting would make the chosen subset
        // depend on the filesystem's order (ext4 is unsorted, NTFS sorted).
        let room = self.opts.max_files.saturating_sub(self.out.files.len());
        let keep = room.saturating_add(1);
        let mut heap: BinaryHeap<ByName> = BinaryHeap::new();
        let mut truncated = false;
        for (scanned, entry) in entries.enumerate() {
            if scanned >= MAX_SCANNED_PER_DIR {
                truncated = true;
                break;
            }
            match entry {
                Ok(e) => {
                    heap.push(ByName(e.file_name(), e));
                    if heap.len() > keep {
                        heap.pop();
                        truncated = true;
                    }
                }
                Err(error) => self.out.errors.push(WalkError {
                    path: dir.to_path_buf(),
                    error,
                }),
            }
        }
        let mut names: Vec<ByName> = heap.into_vec();
        names.sort();
        for ByName(_, entry) in names {
            if self.full() {
                truncated = true;
                break;
            }
            let path = entry.path();
            // `DirEntry::file_type` does not follow symlinks.
            let Ok(kind) = entry.file_type() else {
                self.out.errors.push(WalkError {
                    path,
                    error: std::io::Error::other("cannot determine file type"),
                });
                continue;
            };
            if kind.is_symlink() {
                self.out.skipped.push(Skipped {
                    path,
                    reason: SkipReason::Symlink,
                });
            } else if kind.is_dir() {
                if depth >= self.opts.max_depth {
                    self.out.skipped.push(Skipped {
                        path,
                        reason: SkipReason::DepthLimit,
                    });
                } else {
                    self.dir(&path, depth + 1);
                }
            } else if kind.is_file() {
                self.file(&path);
            } else {
                self.out.skipped.push(Skipped {
                    path,
                    reason: SkipReason::SpecialFile,
                });
            }
        }
        if truncated
            && !self
                .out
                .skipped
                .iter()
                .any(|s| s.reason == SkipReason::FileLimit)
        {
            self.out.skipped.push(Skipped {
                path: dir.to_path_buf(),
                reason: SkipReason::FileLimit,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh temp tree; `spec` entries ending in `/` are directories.
    fn tree(name: &str, spec: &[&str]) -> PathBuf {
        let root = std::env::temp_dir().join(format!("rtriage-walk-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        for s in spec {
            let p = root.join(s.trim_end_matches('/'));
            if s.ends_with('/') {
                fs::create_dir_all(&p).unwrap();
            } else {
                fs::create_dir_all(p.parent().unwrap()).unwrap();
                fs::write(&p, b"x").unwrap();
            }
        }
        root
    }

    fn rel(root: &Path, files: &[PathBuf]) -> Vec<String> {
        files
            .iter()
            .map(|f| {
                f.strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/")
            })
            .collect()
    }

    #[test]
    fn sorted_depth_first_order() {
        let root = tree("order", &["b.bin", "a/z.bin", "a/b/c.bin", "a/a.bin", "c/"]);
        let w = collect(std::slice::from_ref(&root), WalkOptions::default());
        assert_eq!(
            rel(&root, &w.files),
            ["a/a.bin", "a/b/c.bin", "a/z.bin", "b.bin"]
        );
        assert!(w.skipped.is_empty() && w.errors.is_empty());
        assert!(w.walked_directories);
    }

    #[test]
    fn depth_limit_skips_deeper_directories() {
        let root = tree("depth", &["top.bin", "d1/one.bin", "d1/d2/two.bin"]);
        let w = collect(
            std::slice::from_ref(&root),
            WalkOptions {
                max_depth: 1,
                ..WalkOptions::default()
            },
        );
        assert_eq!(rel(&root, &w.files), ["d1/one.bin", "top.bin"]);
        assert_eq!(w.skipped.len(), 1);
        assert_eq!(w.skipped[0].reason, SkipReason::DepthLimit);
    }

    #[test]
    fn file_limit_stops_collection() {
        let root = tree("limit", &["1.bin", "2.bin", "3.bin", "sub/4.bin"]);
        let w = collect(
            &[root.clone(), root.join("sub")],
            WalkOptions {
                max_files: 2,
                ..WalkOptions::default()
            },
        );
        assert_eq!(rel(&root, &w.files), ["1.bin", "2.bin"]);
        assert!(w.limit_reached());
        // The second root is reported as not collected.
        assert!(w.skipped.iter().any(|s| s.path == root.join("sub")));
    }

    #[test]
    fn duplicates_are_listed_once() {
        let root = tree("dedup", &["a.bin", "sub/b.bin"]);
        let w = collect(
            &[root.join("a.bin"), root.clone(), root.join("sub/b.bin")],
            WalkOptions::default(),
        );
        assert_eq!(rel(&root, &w.files), ["a.bin", "sub/b.bin"]);
    }

    #[test]
    fn missing_roots_are_kept_for_the_loader() {
        let w = collect(&[PathBuf::from("no-such-file.bin")], WalkOptions::default());
        assert_eq!(w.files, [PathBuf::from("no-such-file.bin")]);
        assert!(!w.walked_directories);
    }

    #[test]
    fn empty_directory_yields_nothing() {
        let root = tree("empty", &[]);
        let w = collect(std::slice::from_ref(&root), WalkOptions::default());
        assert!(w.files.is_empty() && w.skipped.is_empty() && w.errors.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_inside_directories_are_not_followed() {
        let root = tree("symlink", &["real/a.bin"]);
        std::os::unix::fs::symlink(root.join("real"), root.join("loop")).unwrap();
        std::os::unix::fs::symlink(root.join("real/a.bin"), root.join("link.bin")).unwrap();
        let w = collect(std::slice::from_ref(&root), WalkOptions::default());
        assert_eq!(rel(&root, &w.files), ["real/a.bin"]);
        let reasons: Vec<_> = w.skipped.iter().map(|s| s.reason).collect();
        assert_eq!(reasons, [SkipReason::Symlink, SkipReason::Symlink]);
        // But a symlink named explicitly is followed.
        let w = collect(&[root.join("link.bin")], WalkOptions::default());
        assert_eq!(w.files.len(), 1);
    }

    /// Windows symlinks need Developer Mode or admin rights; skip otherwise.
    #[cfg(windows)]
    #[test]
    fn windows_symlinks_are_not_followed() {
        let root = tree("winlink", &["real/a.bin"]);
        if std::os::windows::fs::symlink_dir(root.join("real"), root.join("loop")).is_err() {
            return;
        }
        let w = collect(std::slice::from_ref(&root), WalkOptions::default());
        assert_eq!(rel(&root, &w.files), ["real/a.bin"]);
        assert_eq!(w.skipped[0].reason, SkipReason::Symlink);
    }

    /// Junctions need no privileges; std reports them as symlinks.
    #[cfg(windows)]
    #[test]
    fn windows_junctions_are_not_followed() {
        let root = tree("junction", &["real/a.bin"]);
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(root.join("loop"))
            .arg(root.join("real"))
            .output()
            .is_ok_and(|o| o.status.success());
        if !made {
            return;
        }
        let w = collect(std::slice::from_ref(&root), WalkOptions::default());
        assert_eq!(rel(&root, &w.files), ["real/a.bin"]);
        assert_eq!(w.skipped[0].reason, SkipReason::Symlink);
        let _ = fs::remove_dir(root.join("loop"));
    }

    #[cfg(unix)]
    #[test]
    fn fifos_are_skipped_not_read() {
        let root = tree("fifo", &["a.bin"]);
        let fifo = root.join("pipe");
        let status = std::process::Command::new("mkfifo").arg(&fifo).status();
        if status.map(|s| s.success()).unwrap_or(false) {
            let w = collect(std::slice::from_ref(&root), WalkOptions::default());
            assert_eq!(rel(&root, &w.files), ["a.bin"]);
            assert_eq!(w.skipped[0].reason, SkipReason::SpecialFile);
        }
    }
}

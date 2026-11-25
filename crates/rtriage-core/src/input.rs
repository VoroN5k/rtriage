//! File loading and format sniffing.
//!
//! The file is read into memory only after its size has been checked against
//! [`Limits::max_file_size`]. The read itself is also bounded, so a file that
//! grows between the size check and the read still cannot exceed the limit.
//! The input is never executed or loaded as code.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::error::Error;
use crate::limits::Limits;
use crate::report::{FileInfo, Format};

/// ELF identification magic.
const ELF_MAGIC: &[u8] = b"\x7fELF";
/// DOS header magic (`MZ`).
const MZ_MAGIC: &[u8] = b"MZ";
/// PE signature that `e_lfanew` must point at.
const PE_SIGNATURE: &[u8] = b"PE\0\0";
/// Offset of `e_lfanew` in the DOS header.
const E_LFANEW_OFFSET: usize = 0x3c;

/// A loaded input file: raw bytes plus detected format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Input {
    /// Path the file was loaded from.
    pub path: PathBuf,
    /// Entire file contents (at most [`Limits::max_file_size`] bytes).
    pub data: Vec<u8>,
    /// Format detected from magic bytes.
    pub format: Format,
}

impl Input {
    /// Builds an input from bytes already in memory (tests, fuzzing, stdin).
    pub fn from_bytes(path: impl Into<PathBuf>, data: Vec<u8>) -> Self {
        let format = sniff_format(&data);
        Self {
            path: path.into(),
            data,
            format,
        }
    }

    /// File size in bytes.
    pub fn size(&self) -> u64 {
        // usize -> u64 never truncates on supported (<= 64-bit) targets.
        u64::try_from(self.data.len()).unwrap_or(u64::MAX)
    }

    /// Identity block for the report.
    pub fn file_info(&self) -> FileInfo {
        FileInfo {
            path: self.path.to_string_lossy().into_owned(),
            size: self.size(),
            format: self.format,
            hashes: None,
        }
    }
}

/// Reads `path` into memory, enforcing `limits.max_file_size`, and sniffs its format.
///
/// # Errors
/// - [`Error::Io`] if the file cannot be opened or read.
/// - [`Error::NotAFile`] for directories and other non-regular files.
/// - [`Error::FileTooLarge`] if the file exceeds the size limit.
pub fn load(path: &Path, limits: &Limits) -> Result<Input, Error> {
    let io_err = |source| Error::Io {
        path: path.to_path_buf(),
        source,
    };

    let meta = std::fs::metadata(path).map_err(io_err)?;
    if !meta.is_file() {
        return Err(Error::NotAFile {
            path: path.to_path_buf(),
        });
    }
    let limit = limits.max_file_size;
    if meta.len() > limit {
        return Err(Error::FileTooLarge {
            size: meta.len(),
            limit,
        });
    }

    // Bounded read: take one byte past the limit to detect growth after the check.
    let capacity = usize::try_from(meta.len()).unwrap_or(0);
    let mut data = Vec::with_capacity(capacity);
    File::open(path)
        .map_err(io_err)?
        .take(limit.saturating_add(1))
        .read_to_end(&mut data)
        .map_err(io_err)?;

    let input = Input::from_bytes(path, data);
    if input.size() > limit {
        return Err(Error::FileTooLarge {
            size: input.size(),
            limit,
        });
    }
    Ok(input)
}

/// Detects the container format from magic bytes. Never panics.
///
/// PE requires both `MZ` and a valid `PE\0\0` signature at `e_lfanew`;
/// a bare `MZ` (e.g. a DOS program) is reported as [`Format::Unknown`].
pub fn sniff_format(data: &[u8]) -> Format {
    if data.starts_with(ELF_MAGIC) {
        Format::Elf
    } else if data.starts_with(MZ_MAGIC) && has_pe_signature(data) {
        Format::Pe
    } else {
        Format::Unknown
    }
}

/// Checks that `e_lfanew` points at a `PE\0\0` signature inside `data`.
fn has_pe_signature(data: &[u8]) -> bool {
    let Some(raw) = data
        .get(E_LFANEW_OFFSET..E_LFANEW_OFFSET + 4)
        .and_then(|b| <[u8; 4]>::try_from(b).ok())
    else {
        return false;
    };
    let Ok(pe_offset) = usize::try_from(u32::from_le_bytes(raw)) else {
        return false;
    };
    pe_offset
        .checked_add(PE_SIGNATURE.len())
        .and_then(|end| data.get(pe_offset..end))
        .is_some_and(|sig| sig == PE_SIGNATURE)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal MZ header with `e_lfanew` set to `pe_offset` and `PE\0\0` placed there.
    fn mz_with_pe_at(pe_offset: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 0x40];
        buf[..2].copy_from_slice(MZ_MAGIC);
        buf[E_LFANEW_OFFSET..E_LFANEW_OFFSET + 4].copy_from_slice(&pe_offset.to_le_bytes());
        let off = pe_offset as usize;
        if buf.len() < off + 4 {
            buf.resize(off + 4, 0);
        }
        buf[off..off + 4].copy_from_slice(PE_SIGNATURE);
        buf
    }

    /// Unique scratch path under the system temp dir; removed by `TempFile::drop`.
    struct TempFile(PathBuf);

    impl TempFile {
        fn new(name: &str, contents: &[u8]) -> Self {
            let path =
                std::env::temp_dir().join(format!("rtriage-test-{}-{name}", std::process::id()));
            std::fs::write(&path, contents).unwrap();
            Self(path)
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn sniffs_elf() {
        assert_eq!(sniff_format(b"\x7fELF\x02\x01\x01"), Format::Elf);
    }

    #[test]
    fn sniffs_pe() {
        assert_eq!(sniff_format(&mz_with_pe_at(0x40)), Format::Pe);
    }

    #[test]
    fn bare_mz_without_pe_signature_is_unknown() {
        let mut buf = mz_with_pe_at(0x40);
        buf[0x40] = b'X';
        assert_eq!(sniff_format(&buf), Format::Unknown);
    }

    #[test]
    fn e_lfanew_past_end_is_unknown() {
        let mut buf = mz_with_pe_at(0x40);
        buf[E_LFANEW_OFFSET..E_LFANEW_OFFSET + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(sniff_format(&buf), Format::Unknown);
    }

    #[test]
    fn truncated_dos_header_is_unknown() {
        assert_eq!(sniff_format(b"MZ\x90\x00"), Format::Unknown);
    }

    #[test]
    fn empty_and_tiny_inputs_are_unknown() {
        assert_eq!(sniff_format(b""), Format::Unknown);
        assert_eq!(sniff_format(b"\x7f"), Format::Unknown);
        assert_eq!(sniff_format(b"M"), Format::Unknown);
    }

    #[test]
    fn load_reads_file_and_sniffs() {
        let f = TempFile::new("load.elf", b"\x7fELF rest");
        let input = load(&f.0, &Limits::default()).unwrap();
        assert_eq!(input.format, Format::Elf);
        assert_eq!(input.size(), 9);
        assert_eq!(input.file_info().size, 9);
    }

    #[test]
    fn load_accepts_empty_file() {
        let f = TempFile::new("empty.bin", b"");
        let input = load(&f.0, &Limits::default()).unwrap();
        assert_eq!(input.format, Format::Unknown);
        assert_eq!(input.size(), 0);
    }

    #[test]
    fn load_accepts_file_exactly_at_limit() {
        let f = TempFile::new("at-limit.bin", b"abcd");
        let limits = Limits {
            max_file_size: 4,
            ..Limits::default()
        };
        assert!(load(&f.0, &limits).is_ok());
    }

    #[test]
    fn load_rejects_file_over_limit() {
        let f = TempFile::new("big.bin", b"abcde");
        let limits = Limits {
            max_file_size: 4,
            ..Limits::default()
        };
        assert!(matches!(
            load(&f.0, &limits),
            Err(Error::FileTooLarge { size: 5, limit: 4 })
        ));
    }

    #[test]
    fn load_rejects_directory() {
        assert!(matches!(
            load(&std::env::temp_dir(), &Limits::default()),
            Err(Error::NotAFile { .. })
        ));
    }

    #[test]
    fn load_reports_missing_file() {
        let path = std::env::temp_dir().join("rtriage-test-definitely-missing.bin");
        assert!(matches!(
            load(&path, &Limits::default()),
            Err(Error::Io { .. })
        ));
    }
}

//! PE analysis.
//!
//! The file is parsed once per analysis into an owned [`PeImage`] (see
//! [`AnalysisContext::pe`](crate::analyzers::AnalysisContext::pe)). Only the
//! headers and the section table are parsed with goblin; their sizes are
//! validated against [`Limits`] *before* goblin runs, and every goblin call is
//! wrapped in [`guarded`] so a parser panic becomes an error instead of
//! taking down the whole analysis. Data directories (imports, TLS, debug)
//! get their own bounded parsers in later modules.

pub mod api_groups;
pub mod headers;
pub mod imports;
pub mod ordinals;
pub mod sections;

use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::analyzers::{AnalysisContext, Analyzer};
use crate::error::AnalysisError;
use crate::limits::Limits;
use crate::report::{Format, ReportBuilder};

/// Size of the COFF file header.
const COFF_HEADER_SIZE: usize = 20;
/// Size of one section table entry.
const SECTION_HEADER_SIZE: usize = 40;
/// Offset of `CheckSum` inside the optional header (same for PE32 and PE32+).
const CHECKSUM_OFFSET_IN_OPTIONAL: usize = 64;
/// Data directory index of the CLR runtime (COM descriptor) header.
const DIRECTORY_CLR: usize = 14;

/// Owned, validated view of a PE file's headers and section table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeImage {
    /// File offset of the `PE\0\0` signature.
    pub pe_offset: usize,
    /// COFF `Machine`.
    pub machine: u16,
    /// COFF `NumberOfSections`.
    pub number_of_sections: u16,
    /// COFF `TimeDateStamp`.
    pub timestamp: u32,
    /// COFF `Characteristics`.
    pub characteristics: u16,
    /// `true` for PE32+.
    pub is64: bool,
    /// `AddressOfEntryPoint`.
    pub entry_rva: u32,
    /// `ImageBase`.
    pub image_base: u64,
    /// `SizeOfImage`.
    pub size_of_image: u32,
    /// `SizeOfHeaders`.
    pub size_of_headers: u32,
    /// `CheckSum` as stored.
    pub checksum: u32,
    /// File offset of the `CheckSum` field.
    pub checksum_offset: usize,
    /// `Subsystem`.
    pub subsystem: u16,
    /// `DllCharacteristics`.
    pub dll_characteristics: u16,
    /// Data directories present in the header, indexed 0..16.
    pub data_directories: [Option<DataDirectory>; 16],
    /// Section table, in file order.
    pub sections: Vec<SectionHeader>,
}

/// One data directory entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataDirectory {
    /// RVA of the data.
    pub rva: u32,
    /// Size in bytes.
    pub size: u32,
}

/// One section table entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionHeader {
    /// Index in the section table.
    pub index: usize,
    /// Name with trailing NULs removed (lossy UTF-8, raw attacker data).
    pub name: String,
    /// `VirtualSize`.
    pub virtual_size: u32,
    /// `VirtualAddress`.
    pub virtual_address: u32,
    /// `SizeOfRawData`.
    pub raw_size: u32,
    /// `PointerToRawData`.
    pub raw_offset: u32,
    /// `Characteristics`.
    pub characteristics: u32,
}

/// `IMAGE_SCN_*` flags used by the analyzers.
pub mod scn {
    /// Contains code.
    pub const CNT_CODE: u32 = 0x0000_0020;
    /// Contains initialized data.
    pub const CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
    /// Contains uninitialized data.
    pub const CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
    /// Can be discarded after loading.
    pub const MEM_DISCARDABLE: u32 = 0x0200_0000;
    /// Shared between processes.
    pub const MEM_SHARED: u32 = 0x1000_0000;
    /// Executable.
    pub const MEM_EXECUTE: u32 = 0x2000_0000;
    /// Readable.
    pub const MEM_READ: u32 = 0x4000_0000;
    /// Writable.
    pub const MEM_WRITE: u32 = 0x8000_0000;
}

impl SectionHeader {
    /// `IMAGE_SCN_MEM_EXECUTE` is set.
    pub fn is_executable(&self) -> bool {
        self.characteristics & scn::MEM_EXECUTE != 0
    }

    /// `IMAGE_SCN_MEM_WRITE` is set.
    pub fn is_writable(&self) -> bool {
        self.characteristics & scn::MEM_WRITE != 0
    }

    /// `true` if `rva` falls inside this section's virtual range
    /// (`VirtualSize`, or `SizeOfRawData` when `VirtualSize` is 0).
    pub fn contains_rva(&self, rva: u32) -> bool {
        let size = if self.virtual_size == 0 {
            self.raw_size
        } else {
            self.virtual_size
        };
        let start = u64::from(self.virtual_address);
        let end = start.saturating_add(u64::from(size));
        (start..end).contains(&u64::from(rva))
    }
}

impl PeImage {
    /// The section containing `rva`, if any (first match in table order).
    pub fn section_for_rva(&self, rva: u32) -> Option<&SectionHeader> {
        self.sections.iter().find(|s| s.contains_rva(rva))
    }

    /// File offset of `rva`, if it maps to bytes present in the file.
    ///
    /// RVAs below `SizeOfHeaders` map 1:1 into the headers; otherwise the
    /// containing section's raw data is used. RVAs in a section's
    /// virtual-only tail, or past EOF, have no file offset.
    pub fn rva_to_offset(&self, rva: u32, file_len: usize) -> Option<usize> {
        let offset = if rva < self.size_of_headers {
            u64::from(rva)
        } else {
            let s = self.section_for_rva(rva)?;
            let delta = rva.checked_sub(s.virtual_address)?;
            if delta >= s.raw_size {
                return None;
            }
            u64::from(s.raw_offset).checked_add(u64::from(delta))?
        };
        usize::try_from(offset).ok().filter(|&o| o < file_len)
    }

    /// Data directory `index` if present and non-empty.
    pub fn directory(&self, index: usize) -> Option<DataDirectory> {
        self.data_directories
            .get(index)
            .copied()
            .flatten()
            .filter(|d| d.rva != 0 && d.size != 0)
    }

    /// `true` if the CLR header directory is present (managed .NET image).
    pub fn is_managed_dotnet(&self) -> bool {
        self.directory(DIRECTORY_CLR).is_some()
    }
}

/// Reports a failure to parse the PE headers exactly once.
///
/// Other PE analyzers call [`AnalysisContext::pe`] too, but stay silent when
/// it fails (see [`pe_or_skip`]), so a broken header yields one error entry,
/// not one per analyzer.
#[derive(Debug, Clone, Copy, Default)]
pub struct PeParseAnalyzer;

impl Analyzer for PeParseAnalyzer {
    fn name(&self) -> &'static str {
        "pe-parse"
    }

    fn applies_to(&self, format: Format) -> bool {
        format == Format::Pe
    }

    fn run(
        &self,
        ctx: &AnalysisContext<'_>,
        _out: &mut ReportBuilder,
    ) -> Result<(), AnalysisError> {
        ctx.pe().map(|_| ())
    }
}

/// The parsed PE, or `None` if parsing failed (already reported by
/// [`PeParseAnalyzer`]).
pub fn pe_or_skip<'c>(ctx: &'c AnalysisContext<'_>) -> Option<&'c PeImage> {
    ctx.pe().ok()
}

/// Runs a third-party parser call, converting a panic into
/// [`AnalysisError::Internal`].
///
/// `AssertUnwindSafe` is sound here: on panic, everything the closure touched
/// is discarded and only the error is kept.
pub fn guarded<T>(what: &'static str, f: impl FnOnce() -> T) -> Result<T, AnalysisError> {
    catch_unwind(AssertUnwindSafe(f)).map_err(|payload| {
        let msg = payload
            .downcast_ref::<&str>()
            .map(|s| (*s).to_owned())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "non-string panic payload".to_owned());
        AnalysisError::Internal {
            reason: format!("{what} parser panicked: {msg}"),
        }
    })
}

/// Parses and validates the headers and section table of a PE file.
///
/// # Errors
/// - [`AnalysisError::Truncated`] if a header or the section table runs past EOF.
/// - [`AnalysisError::LimitExceeded`] if `NumberOfSections > max_sections`.
/// - [`AnalysisError::Malformed`] if goblin rejects the headers.
/// - [`AnalysisError::Internal`] if goblin panics.
pub fn parse(data: &[u8], limits: &Limits) -> Result<PeImage, AnalysisError> {
    let len = data.len();
    let pe_offset = read_u32(data, 0x3c, "DOS header")? as usize;
    let coff = pe_offset
        .checked_add(4)
        .ok_or_else(|| overflow("PE signature"))?;
    // saturating_add: an overflowing offset simply fails the bounds check.
    let number_of_sections = read_u16(data, coff.saturating_add(2), "COFF header")?;
    let optional_size = read_u16(data, coff.saturating_add(16), "COFF header")?;

    // Validate counts and extents before goblin allocates anything.
    Limits::ensure(
        "max_sections",
        u64::from(number_of_sections),
        u64::try_from(limits.max_sections).unwrap_or(u64::MAX),
    )?;
    let optional_offset = coff.saturating_add(COFF_HEADER_SIZE);
    let table_offset = optional_offset
        .checked_add(usize::from(optional_size))
        .ok_or_else(|| overflow("section table"))?;
    let table_len = usize::from(number_of_sections) * SECTION_HEADER_SIZE;
    let table_end = table_offset
        .checked_add(table_len)
        .ok_or_else(|| overflow("section table"))?;
    if table_end > len {
        return Err(AnalysisError::Truncated {
            what: "PE section table",
            offset: to_u64(table_offset),
            needed: to_u64(table_len),
            available: to_u64(len.saturating_sub(table_offset)),
        });
    }

    let header =
        guarded("PE header", || goblin::pe::header::Header::parse(data))?.map_err(|e| {
            AnalysisError::Malformed {
                what: "PE header",
                reason: e.to_string(),
            }
        })?;
    let optional = header
        .optional_header
        .ok_or_else(|| AnalysisError::Malformed {
            what: "PE optional header",
            reason: "missing (SizeOfOptionalHeader is 0)".into(),
        })?;

    let mut offset = table_offset;
    let raw_sections = guarded("PE section table", || {
        header.coff_header.sections(data, &mut offset)
    })?
    .map_err(|e| AnalysisError::Malformed {
        what: "PE section table",
        reason: e.to_string(),
    })?;

    let sections = raw_sections
        .iter()
        .enumerate()
        .map(|(index, s)| SectionHeader {
            index,
            name: section_name(&s.name),
            virtual_size: s.virtual_size,
            virtual_address: s.virtual_address,
            raw_size: s.size_of_raw_data,
            raw_offset: s.pointer_to_raw_data,
            characteristics: s.characteristics,
        })
        .collect();

    let mut data_directories = [None; 16];
    for (slot, dir) in data_directories
        .iter_mut()
        .zip(optional.data_directories.data_directories.iter())
    {
        *slot = dir.map(|(_, d)| DataDirectory {
            rva: d.virtual_address,
            size: d.size,
        });
    }

    let w = &optional.windows_fields;
    Ok(PeImage {
        pe_offset,
        machine: header.coff_header.machine,
        number_of_sections,
        timestamp: header.coff_header.time_date_stamp,
        characteristics: header.coff_header.characteristics,
        is64: optional.standard_fields.magic == 0x20b,
        entry_rva: optional.standard_fields.address_of_entry_point,
        image_base: w.image_base,
        size_of_image: w.size_of_image,
        size_of_headers: w.size_of_headers,
        checksum: w.check_sum,
        checksum_offset: optional_offset.saturating_add(CHECKSUM_OFFSET_IN_OPTIONAL),
        subsystem: w.subsystem,
        dll_characteristics: w.dll_characteristics,
        data_directories,
        sections,
    })
}

/// Section name: raw 8 bytes up to the first NUL, lossy UTF-8.
fn section_name(raw: &[u8; 8]) -> String {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(raw.get(..end).unwrap_or_default()).into_owned()
}

fn read_u16(data: &[u8], offset: usize, what: &'static str) -> Result<u16, AnalysisError> {
    read_array::<2>(data, offset, what).map(u16::from_le_bytes)
}

fn read_u32(data: &[u8], offset: usize, what: &'static str) -> Result<u32, AnalysisError> {
    read_array::<4>(data, offset, what).map(u32::from_le_bytes)
}

fn read_array<const N: usize>(
    data: &[u8],
    offset: usize,
    what: &'static str,
) -> Result<[u8; N], AnalysisError> {
    offset
        .checked_add(N)
        .and_then(|end| data.get(offset..end))
        .and_then(|b| <[u8; N]>::try_from(b).ok())
        .ok_or(AnalysisError::Truncated {
            what,
            offset: to_u64(offset),
            needed: to_u64(N),
            available: to_u64(data.len().saturating_sub(offset)),
        })
}

fn overflow(what: &'static str) -> AnalysisError {
    AnalysisError::Malformed {
        what,
        reason: "offset overflows the address space".into(),
    }
}

/// `usize` -> `u64`; lossless on all supported (<= 64-bit) targets.
fn to_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtriage_fixtures::pe::{put_u16, put_u32, Arch, PeBuilder, Section};

    #[test]
    fn parses_minimal_pe32_and_pe32plus() {
        for (arch, is64) in [(Arch::X86, false), (Arch::X64, true)] {
            let built = PeBuilder::minimal(arch).build();
            let pe = parse(&built.bytes, &Limits::default()).unwrap();
            assert_eq!(pe.is64, is64);
            assert_eq!(pe.number_of_sections, 2);
            assert_eq!(pe.sections[0].name, ".text");
            assert_eq!(pe.checksum_offset, built.layout.checksum_offset);
            assert_eq!(pe.entry_rva, built.layout.sections[0].rva);
            assert!(!pe.is_managed_dotnet());
        }
    }

    #[test]
    fn huge_section_count_is_rejected_before_parsing() {
        let mut built = PeBuilder::minimal(Arch::X64).build();
        put_u16(
            &mut built.bytes,
            built.layout.number_of_sections_offset(),
            0xFFFF,
        );
        assert!(matches!(
            parse(&built.bytes, &Limits::default()),
            Err(AnalysisError::LimitExceeded {
                limit: "max_sections",
                value: 0xFFFF,
                ..
            })
        ));
    }

    #[test]
    fn section_count_past_eof_is_truncated() {
        let mut built = PeBuilder::minimal(Arch::X64).build();
        // 200 sections fit the limit but not the file.
        put_u16(
            &mut built.bytes,
            built.layout.number_of_sections_offset(),
            200,
        );
        built.bytes.truncate(0x400);
        assert!(matches!(
            parse(&built.bytes, &Limits::default()),
            Err(AnalysisError::Truncated {
                what: "PE section table",
                ..
            })
        ));
    }

    #[test]
    fn truncated_coff_header() {
        let built = PeBuilder::minimal(Arch::X86).build();
        let cut = &built.bytes[..built.layout.coff_offset + 4];
        assert!(matches!(
            parse(cut, &Limits::default()),
            Err(AnalysisError::Truncated { .. })
        ));
    }

    #[test]
    fn huge_e_lfanew_is_truncated_not_panic() {
        let mut built = PeBuilder::minimal(Arch::X86).build();
        put_u32(&mut built.bytes, 0x3c, u32::MAX);
        assert!(parse(&built.bytes, &Limits::default()).is_err());
    }

    #[test]
    fn huge_optional_header_size_is_truncated() {
        let mut built = PeBuilder::minimal(Arch::X64).build();
        put_u16(&mut built.bytes, built.layout.coff_offset + 16, 0xFFFF);
        assert!(parse(&built.bytes, &Limits::default()).is_err());
    }

    #[test]
    fn entry_section_lookup() {
        let built = PeBuilder::minimal(Arch::X64)
            .section(Section::code(".text2", vec![0xC3; 8]))
            .build();
        let pe = parse(&built.bytes, &Limits::default()).unwrap();
        let rva = built.layout.sections[2].rva + 4;
        assert_eq!(pe.section_for_rva(rva).unwrap().name, ".text2");
        assert!(pe.section_for_rva(0xdead_0000).is_none());
    }

    #[test]
    fn guarded_turns_panic_into_internal_error() {
        let r: Result<(), _> = guarded("test", || panic!("boom"));
        assert_eq!(
            r,
            Err(AnalysisError::Internal {
                reason: "test parser panicked: boom".into()
            })
        );
    }

    #[test]
    fn section_names_stop_at_nul_and_are_lossy() {
        assert_eq!(section_name(b".text\0\0\0"), ".text");
        assert_eq!(section_name(b"ABCDEFGH"), "ABCDEFGH");
        assert_eq!(section_name(b"\xff\xfe\0\0\0\0\0\0"), "\u{fffd}\u{fffd}");
    }
}

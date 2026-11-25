//! ELF analysis.
//!
//! The file is parsed once into an owned [`ElfImage`] (see
//! [`AnalysisContext::elf`]). **Program headers are the source of truth**:
//! they are what the loader uses, so a bad program header table is fatal,
//! while section header problems (wrong `e_shentsize`, table past EOF, bad
//! `e_shstrndx`, too many sections) are recorded in
//! [`ElfImage::section_problems`] and the analysis continues without sections.
//!
//! goblin parses only the ELF header and the two tables, after their counts,
//! entry sizes and extents were validated here, and always inside
//! [`guarded`]. Dynamic section, symbols and notes get own bounded parsers.

pub mod api_groups;
pub mod checksec;
pub mod dynamic;
pub mod headers;
pub mod notes;
pub mod packers;
pub mod segments;

use crate::analyzers::pe::guarded;
use crate::analyzers::{AnalysisContext, Analyzer};
use crate::error::AnalysisError;
use crate::limits::Limits;
use crate::report::{Format, ReportBuilder};

/// `PT_LOAD`.
pub const PT_LOAD: u32 = 1;
/// `PT_INTERP`.
pub const PT_INTERP: u32 = 3;
/// `PF_X`.
pub const PF_X: u32 = 1;
/// `PF_W`.
pub const PF_W: u32 = 2;
/// `PF_R`.
pub const PF_R: u32 = 4;
/// Longest interpreter path read (`PATH_MAX`).
const MAX_INTERP_LEN: usize = 4096;
/// Longest section name read.
const MAX_SECTION_NAME: usize = 256;
/// `e_phnum` value meaning "the real count is in section 0's `sh_info`".
const PN_XNUM: u16 = 0xffff;
/// `e_shstrndx` value meaning "the real index is in section 0's `sh_link`".
const SHN_XINDEX: u16 = 0xffff;

/// Owned, validated view of an ELF file's headers and tables.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfImage {
    /// ELF64 (`true`) or ELF32.
    pub is64: bool,
    /// Big-endian data encoding.
    pub big_endian: bool,
    /// `EI_OSABI`.
    pub os_abi: u8,
    /// `e_type`.
    pub elf_type: u16,
    /// `e_machine`.
    pub machine: u16,
    /// `e_entry`.
    pub entry: u64,
    /// `e_flags`.
    pub flags: u32,
    /// Program headers, in table order.
    pub segments: Vec<Segment>,
    /// Section headers (empty if absent or unusable), in table order.
    pub sections: Vec<ElfSection>,
    /// Why section headers were (partly) ignored; empty if they are fine.
    pub section_problems: Vec<String>,
    /// `PT_INTERP` path, if any (up to the first NUL, lossy UTF-8).
    pub interp: Option<String>,
}

/// One program header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    /// Index in the program header table.
    pub index: usize,
    /// `p_type`.
    pub kind: u32,
    /// `p_flags`.
    pub flags: u32,
    /// `p_offset`.
    pub offset: u64,
    /// `p_vaddr`.
    pub vaddr: u64,
    /// `p_filesz`.
    pub filesz: u64,
    /// `p_memsz`.
    pub memsz: u64,
    /// `p_align`.
    pub align: u64,
}

impl Segment {
    /// `PT_LOAD` with `PF_X`.
    pub fn is_exec_load(&self) -> bool {
        self.kind == PT_LOAD && self.flags & PF_X != 0
    }

    /// `true` if `vaddr` is inside `[p_vaddr, p_vaddr + p_memsz)`.
    pub fn contains_vaddr(&self, vaddr: u64) -> bool {
        vaddr >= self.vaddr && vaddr - self.vaddr < self.memsz
    }
}

/// One section header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfSection {
    /// Index in the section header table.
    pub index: usize,
    /// Name from the section name string table (lossy UTF-8, raw data).
    pub name: String,
    /// `sh_type`.
    pub kind: u32,
    /// `sh_flags`.
    pub flags: u64,
    /// `sh_addr`.
    pub addr: u64,
    /// `sh_offset`.
    pub offset: u64,
    /// `sh_size`.
    pub size: u64,
    /// `sh_link`.
    pub link: u32,
    /// `sh_info`.
    pub info: u32,
    /// `sh_entsize`.
    pub entsize: u64,
}

impl ElfImage {
    /// The `PT_LOAD` segment containing `vaddr`, if any.
    pub fn load_for_vaddr(&self, vaddr: u64) -> Option<&Segment> {
        self.segments
            .iter()
            .find(|s| s.kind == PT_LOAD && s.contains_vaddr(vaddr))
    }

    /// File offset of `vaddr` through the `PT_LOAD` segments, if it maps to
    /// bytes present in the file (not the zero-filled `p_memsz` tail).
    pub fn vaddr_to_offset(&self, vaddr: u64, file_len: usize) -> Option<usize> {
        let s = self.load_for_vaddr(vaddr)?;
        let delta = vaddr.checked_sub(s.vaddr)?;
        if delta >= s.filesz {
            return None;
        }
        let off = s.offset.checked_add(delta)?;
        usize::try_from(off).ok().filter(|&o| o < file_len)
    }
}

/// Reports a failure to parse the ELF headers exactly once (other ELF
/// analyzers stay silent, see [`elf_or_skip`]).
#[derive(Debug, Clone, Copy, Default)]
pub struct ElfParseAnalyzer;

impl Analyzer for ElfParseAnalyzer {
    fn name(&self) -> &'static str {
        "elf-parse"
    }

    fn applies_to(&self, format: Format) -> bool {
        format == Format::Elf
    }

    fn run(
        &self,
        ctx: &AnalysisContext<'_>,
        _out: &mut ReportBuilder,
    ) -> Result<(), AnalysisError> {
        ctx.elf().map(|_| ())
    }
}

/// The parsed ELF, or `None` if parsing failed (already reported by
/// [`ElfParseAnalyzer`]).
pub fn elf_or_skip<'c>(ctx: &'c AnalysisContext<'_>) -> Option<&'c ElfImage> {
    ctx.elf().ok()
}

/// Endian- and class-aware reader over the raw file.
#[derive(Debug, Clone, Copy)]
pub struct Reader<'a> {
    /// File contents.
    pub data: &'a [u8],
    /// ELF64.
    pub is64: bool,
    /// Big-endian.
    pub big: bool,
}

impl Reader<'_> {
    fn bytes<const N: usize>(
        &self,
        at: usize,
        what: &'static str,
    ) -> Result<[u8; N], AnalysisError> {
        at.checked_add(N)
            .and_then(|end| self.data.get(at..end))
            .and_then(|b| <[u8; N]>::try_from(b).ok())
            .ok_or(AnalysisError::Truncated {
                what,
                offset: to_u64(at),
                needed: to_u64(N),
                available: to_u64(self.data.len().saturating_sub(at)),
            })
    }

    /// `u16` at `at`.
    ///
    /// # Errors
    /// [`AnalysisError::Truncated`] past EOF.
    pub fn u16(&self, at: usize, what: &'static str) -> Result<u16, AnalysisError> {
        let b = self.bytes::<2>(at, what)?;
        Ok(if self.big {
            u16::from_be_bytes(b)
        } else {
            u16::from_le_bytes(b)
        })
    }

    /// `u32` at `at`.
    ///
    /// # Errors
    /// [`AnalysisError::Truncated`] past EOF.
    pub fn u32(&self, at: usize, what: &'static str) -> Result<u32, AnalysisError> {
        let b = self.bytes::<4>(at, what)?;
        Ok(if self.big {
            u32::from_be_bytes(b)
        } else {
            u32::from_le_bytes(b)
        })
    }

    /// `u64` at `at`.
    ///
    /// # Errors
    /// [`AnalysisError::Truncated`] past EOF.
    pub fn u64(&self, at: usize, what: &'static str) -> Result<u64, AnalysisError> {
        let b = self.bytes::<8>(at, what)?;
        Ok(if self.big {
            u64::from_be_bytes(b)
        } else {
            u64::from_le_bytes(b)
        })
    }

    /// Address-sized word (`u32` for ELF32, `u64` for ELF64).
    ///
    /// # Errors
    /// [`AnalysisError::Truncated`] past EOF.
    pub fn word(&self, at: usize, what: &'static str) -> Result<u64, AnalysisError> {
        if self.is64 {
            self.u64(at, what)
        } else {
            self.u32(at, what).map(u64::from)
        }
    }
}

/// Raw header fields read by hand for validation.
struct RawHeader {
    phoff: u64,
    shoff: u64,
    phentsize: u16,
    phnum: u16,
    shentsize: u16,
    shnum: u16,
    shstrndx: u16,
}

/// Parses and validates the ELF headers and tables.
///
/// # Errors
/// Bad identification, truncated header, unusable program header table,
/// `e_phnum > max_segments`, goblin failure or panic. Section header
/// problems are **not** errors (see [`ElfImage::section_problems`]).
pub fn parse(data: &[u8], limits: &Limits) -> Result<ElfImage, AnalysisError> {
    let ident = data.get(..16).ok_or(AnalysisError::Truncated {
        what: "ELF identification",
        offset: 0,
        needed: 16,
        available: to_u64(data.len()),
    })?;
    let is64 = match ident.get(4) {
        Some(1) => false,
        Some(2) => true,
        other => {
            return Err(malformed(
                "ELF header",
                format!("invalid EI_CLASS {other:?}"),
            ))
        }
    };
    let big = match ident.get(5) {
        Some(1) => false,
        Some(2) => true,
        other => {
            return Err(malformed(
                "ELF header",
                format!("invalid EI_DATA {other:?}"),
            ))
        }
    };
    let os_abi = ident.get(7).copied().unwrap_or(0);
    let r = Reader { data, is64, big };
    let w = if is64 { 8 } else { 4 };
    let raw = RawHeader {
        phoff: r.word(24 + w, "ELF header")?,
        shoff: r.word(24 + 2 * w, "ELF header")?,
        phentsize: r.u16(24 + 3 * w + 6, "ELF header")?,
        phnum: r.u16(24 + 3 * w + 8, "ELF header")?,
        shentsize: r.u16(24 + 3 * w + 10, "ELF header")?,
        shnum: r.u16(24 + 3 * w + 12, "ELF header")?,
        shstrndx: r.u16(24 + 3 * w + 14, "ELF header")?,
    };
    let (ph_size, sh_size) = if is64 { (56u16, 64u16) } else { (32, 40) };

    // ---- sections first: PN_XNUM / SHN_XINDEX live in section 0.
    let mut problems = Vec::new();
    let section_table = section_table(&r, &raw, sh_size, limits, &mut problems);

    // ---- program headers: mandatory and validated strictly.
    let phnum = if raw.phnum == PN_XNUM {
        match &section_table {
            Some((off, _, _)) => {
                r.u32(off + if is64 { 44 } else { 28 }, "section header 0")? as usize
            }
            None => {
                return Err(malformed(
                    "ELF header",
                    "e_phnum is PN_XNUM but section 0 is unreadable".into(),
                ))
            }
        }
    } else {
        usize::from(raw.phnum)
    };
    if phnum > 0 && raw.phentsize != ph_size {
        return Err(malformed(
            "ELF program header table",
            format!("e_phentsize is {}, expected {ph_size}", raw.phentsize),
        ));
    }
    Limits::ensure("max_segments", to_u64(phnum), to_u64(limits.max_segments))?;
    let ph_off = usize::try_from(raw.phoff).map_err(|_| overflow("ELF program header table"))?;
    let ph_len = phnum * usize::from(ph_size);
    if ph_off
        .checked_add(ph_len)
        .is_none_or(|end| end > data.len())
    {
        return Err(AnalysisError::Truncated {
            what: "ELF program header table",
            offset: raw.phoff,
            needed: to_u64(ph_len),
            available: to_u64(data.len().saturating_sub(ph_off)),
        });
    }

    let ctx = goblin::container::Ctx::new(
        if is64 {
            goblin::container::Container::Big
        } else {
            goblin::container::Container::Little
        },
        if big {
            goblin::container::Endian::Big
        } else {
            goblin::container::Endian::Little
        },
    );
    let header = guarded("ELF header", || goblin::elf::Elf::parse_header(data))?
        .map_err(|e| malformed("ELF header", e.to_string()))?;
    let phdrs = guarded("ELF program headers", || {
        goblin::elf::program_header::ProgramHeader::parse(data, ph_off, phnum, ctx)
    })?
    .map_err(|e| malformed("ELF program header table", e.to_string()))?;
    let segments: Vec<Segment> = phdrs
        .iter()
        .enumerate()
        .map(|(index, p)| Segment {
            index,
            kind: p.p_type,
            flags: p.p_flags,
            offset: p.p_offset,
            vaddr: p.p_vaddr,
            filesz: p.p_filesz,
            memsz: p.p_memsz,
            align: p.p_align,
        })
        .collect();

    let sections = match section_table {
        Some((off, count, strndx)) => {
            match guarded("ELF section headers", || {
                goblin::elf::section_header::SectionHeader::parse(data, off, count, ctx)
            })? {
                Ok(shdrs) => name_sections(data, &shdrs, strndx, &mut problems),
                Err(e) => {
                    problems.push(format!("section headers unreadable: {e}"));
                    Vec::new()
                }
            }
        }
        None => Vec::new(),
    };

    let interp = segments.iter().find(|s| s.kind == PT_INTERP).and_then(|s| {
        let start = usize::try_from(s.offset).ok()?;
        let len = usize::try_from(s.filesz).ok()?.min(MAX_INTERP_LEN);
        let bytes = data.get(start..start.checked_add(len)?.min(data.len()))?;
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        Some(String::from_utf8_lossy(bytes.get(..end)?).into_owned())
    });

    Ok(ElfImage {
        is64,
        big_endian: big,
        os_abi,
        elf_type: header.e_type,
        machine: header.e_machine,
        entry: header.e_entry,
        flags: header.e_flags,
        segments,
        sections,
        section_problems: problems,
        interp,
    })
}

/// Validates the section header table: `(offset, count, shstrndx)` if usable.
/// Every problem is recorded instead of failing.
fn section_table(
    r: &Reader<'_>,
    raw: &RawHeader,
    sh_size: u16,
    limits: &Limits,
    problems: &mut Vec<String>,
) -> Option<(usize, usize, usize)> {
    if raw.shoff == 0 {
        if raw.shnum != 0 {
            problems.push(format!("e_shnum is {} but e_shoff is 0", raw.shnum));
        }
        return None;
    }
    if raw.shentsize != sh_size {
        problems.push(format!(
            "e_shentsize is {}, expected {sh_size}",
            raw.shentsize
        ));
        return None;
    }
    let Ok(off) = usize::try_from(raw.shoff) else {
        problems.push("e_shoff overflows the address space".into());
        return None;
    };
    // Extended numbering: e_shnum == 0 -> count in section 0's sh_size.
    let (size_at, link_at) = if r.is64 { (32, 40) } else { (20, 24) };
    let count = if raw.shnum == 0 {
        match r.word(off.saturating_add(size_at), "section header 0") {
            Ok(n) => usize::try_from(n).unwrap_or(usize::MAX),
            Err(_) => {
                problems.push("e_shnum is 0 (extended numbering) but section 0 is past EOF".into());
                return None;
            }
        }
    } else {
        usize::from(raw.shnum)
    };
    if count > limits.max_sections {
        problems.push(format!(
            "{count} section headers exceed max_sections ({})",
            limits.max_sections
        ));
        return None;
    }
    let len = count * usize::from(sh_size);
    if off.checked_add(len).is_none_or(|end| end > r.data.len()) {
        problems.push(format!(
            "section header table (0x{off:x}, {count} entries) runs past end of file"
        ));
        return None;
    }
    let strndx = if raw.shstrndx == SHN_XINDEX {
        r.u32(off.saturating_add(link_at), "section header 0")
            .map(|v| v as usize)
            .unwrap_or(usize::MAX)
    } else {
        usize::from(raw.shstrndx)
    };
    Some((off, count, strndx))
}

/// Converts goblin's headers and resolves names via `shstrndx`.
fn name_sections(
    data: &[u8],
    shdrs: &[goblin::elf::SectionHeader],
    strndx: usize,
    problems: &mut Vec<String>,
) -> Vec<ElfSection> {
    let strtab = match shdrs.get(strndx) {
        Some(s) if strndx != 0 => usize::try_from(s.sh_offset)
            .ok()
            .zip(usize::try_from(s.sh_size).ok())
            .and_then(|(o, n)| data.get(o..o.checked_add(n)?)),
        _ => None,
    };
    if strtab.is_none() && !shdrs.is_empty() {
        problems.push(format!(
            "e_shstrndx {strndx} does not name a readable string table"
        ));
    }
    shdrs
        .iter()
        .enumerate()
        .map(|(index, s)| ElfSection {
            index,
            name: strtab
                .and_then(|t| cstr(t, s.sh_name, MAX_SECTION_NAME))
                .unwrap_or_default(),
            kind: s.sh_type,
            flags: s.sh_flags,
            addr: s.sh_addr,
            offset: s.sh_offset,
            size: s.sh_size,
            link: s.sh_link,
            info: s.sh_info,
            entsize: s.sh_entsize,
        })
        .collect()
}

/// NUL-terminated string at `at` within `table`, at most `max` bytes.
pub fn cstr(table: &[u8], at: usize, max: usize) -> Option<String> {
    let tail = table.get(at..)?;
    let tail = tail.get(..max.min(tail.len()))?;
    let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
    Some(String::from_utf8_lossy(tail.get(..end)?).into_owned())
}

fn malformed(what: &'static str, reason: String) -> AnalysisError {
    AnalysisError::Malformed { what, reason }
}

fn overflow(what: &'static str) -> AnalysisError {
    malformed(what, "offset overflows the address space".into())
}

/// `usize` -> `u64`; lossless on all supported (<= 64-bit) targets.
fn to_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtriage_fixtures::elf::{machine, profiles, Class, ElfBuilder, Endian};

    fn put16(b: &mut [u8], at: usize, v: u16, big: bool) {
        let bytes = if big {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        };
        b[at..at + 2].copy_from_slice(&bytes);
    }

    #[test]
    fn parses_every_class_and_byte_order() {
        for (class, endian, mach) in [
            (Class::Elf64, Endian::Little, machine::X86_64),
            (Class::Elf32, Endian::Little, machine::X86),
            (Class::Elf32, Endian::Big, machine::MIPS),
            (Class::Elf64, Endian::Big, machine::PPC64),
        ] {
            let built = ElfBuilder::new(class, endian, mach)
                .interp("/lib/ld.so.1")
                .build();
            let elf = parse(&built.bytes, &Limits::default()).unwrap();
            assert_eq!(elf.machine, mach);
            assert_eq!(elf.is64, class == Class::Elf64);
            assert_eq!(elf.big_endian, endian == Endian::Big);
            assert_eq!(elf.entry, built.layout.text_vaddr);
            assert_eq!(elf.interp.as_deref(), Some("/lib/ld.so.1"));
            assert!(elf.sections.iter().any(|s| s.name == ".text"));
            assert!(
                elf.section_problems.is_empty(),
                "{:?}",
                elf.section_problems
            );
        }
    }

    #[test]
    fn no_section_headers_is_fine() {
        let elf = parse(&profiles::upx_elf().build().bytes, &Limits::default()).unwrap();
        assert!(elf.sections.is_empty());
        assert!(elf.section_problems.is_empty());
        assert!(!elf.segments.is_empty());
    }

    #[test]
    fn wrong_shentsize_is_a_problem_not_an_error() {
        let mut built = ElfBuilder::x86_64().build();
        put16(&mut built.bytes, built.layout.shentsize_offset, 48, false);
        let elf = parse(&built.bytes, &Limits::default()).unwrap();
        assert!(elf.sections.is_empty());
        assert!(elf.section_problems[0].contains("e_shentsize"));
        assert!(!elf.segments.is_empty());
    }

    #[test]
    fn section_table_past_eof_is_a_problem() {
        let mut built = ElfBuilder::new(Class::Elf32, Endian::Big, machine::PPC).build();
        put16(&mut built.bytes, built.layout.shnum_offset, 4000, true);
        let elf = parse(&built.bytes, &Limits::default()).unwrap();
        assert!(elf.section_problems[0].contains("past end of file"));
    }

    #[test]
    fn bad_shstrndx_is_a_problem() {
        let mut built = ElfBuilder::x86_64().build();
        put16(&mut built.bytes, built.layout.shstrndx_offset, 999, false);
        let elf = parse(&built.bytes, &Limits::default()).unwrap();
        assert!(!elf.sections.is_empty());
        assert!(elf.sections.iter().all(|s| s.name.is_empty()));
        assert!(elf
            .section_problems
            .iter()
            .any(|p| p.contains("e_shstrndx")));
    }

    #[test]
    fn wrong_phentsize_is_fatal() {
        let mut built = ElfBuilder::x86_64().build();
        put16(&mut built.bytes, built.layout.phentsize_offset, 40, false);
        assert!(matches!(
            parse(&built.bytes, &Limits::default()),
            Err(AnalysisError::Malformed {
                what: "ELF program header table",
                ..
            })
        ));
    }

    #[test]
    fn huge_phnum_is_rejected_before_parsing() {
        let mut built = ElfBuilder::x86_64().build();
        put16(&mut built.bytes, built.layout.phnum_offset, 0xFFFE, false);
        assert!(matches!(
            parse(&built.bytes, &Limits::default()),
            Err(AnalysisError::LimitExceeded {
                limit: "max_segments",
                ..
            })
        ));
    }

    #[test]
    fn phdr_table_past_eof_is_truncated() {
        let mut built = ElfBuilder::x86_64().build();
        put16(&mut built.bytes, built.layout.phnum_offset, 200, false);
        built.bytes.truncate(0x400);
        assert!(matches!(
            parse(&built.bytes, &Limits::default()),
            Err(AnalysisError::Truncated { .. })
        ));
    }

    #[test]
    fn bad_identification() {
        assert!(parse(b"\x7fELF", &Limits::default()).is_err());
        let mut b = ElfBuilder::x86_64().build().bytes;
        b[4] = 7;
        assert!(parse(&b, &Limits::default()).is_err());
        let mut b = ElfBuilder::x86_64().build().bytes;
        b[5] = 0;
        assert!(parse(&b, &Limits::default()).is_err());
    }

    #[test]
    fn vaddr_mapping() {
        let built = ElfBuilder::x86_64().build();
        let elf = parse(&built.bytes, &Limits::default()).unwrap();
        assert_eq!(
            elf.vaddr_to_offset(built.layout.text_vaddr, built.bytes.len()),
            Some(built.layout.text_offset)
        );
        assert_eq!(
            elf.vaddr_to_offset(0xdead_beef_0000, built.bytes.len()),
            None
        );
    }
}

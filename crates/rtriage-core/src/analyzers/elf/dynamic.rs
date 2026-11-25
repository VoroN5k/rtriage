//! Bounded parser for `PT_DYNAMIC`, the dynamic symbol table and (if
//! present) the static `.symtab`.
//!
//! Everything is located through **segments** (`PT_DYNAMIC`, then virtual
//! addresses mapped via `PT_LOAD`), so it works on files without section
//! headers. The number of dynamic symbols is not stored anywhere directly; it
//! is derived, in order of trust, from:
//! 1. the `.dynsym` section header, if its address matches `DT_SYMTAB`;
//! 2. `DT_HASH` (`nchain`);
//! 3. `DT_GNU_HASH` (highest bucket, then walk its chain to the end bit);
//! 4. the gap between `DT_SYMTAB` and `DT_STRTAB` (common linker layout).
//!
//! The source used is reported, so an analyst can judge how far to trust it.

use super::{cstr, ElfImage, Reader};
use crate::deadline::{Budget, Deadline};
use crate::error::AnalysisError;
use crate::limits::Limits;

/// `PT_DYNAMIC`.
const PT_DYNAMIC: u32 = 2;
/// `SHT_SYMTAB`.
const SHT_SYMTAB: u32 = 2;
/// `SHT_DYNSYM`.
const SHT_DYNSYM: u32 = 11;
/// Longest library / path / symbol name read.
const MAX_NAME: usize = 4096;
/// Sanity cap for `DT_GNU_HASH` bucket and bloom counts.
const MAX_HASH_BUCKETS: u64 = 1 << 20;

const DT_NULL: u64 = 0;
const DT_NEEDED: u64 = 1;
const DT_HASH: u64 = 4;
const DT_STRTAB: u64 = 5;
const DT_SYMTAB: u64 = 6;
const DT_STRSZ: u64 = 10;
const DT_SYMENT: u64 = 11;
const DT_SONAME: u64 = 14;
const DT_RPATH: u64 = 15;
const DT_TEXTREL: u64 = 22;
const DT_BIND_NOW: u64 = 24;
const DT_RUNPATH: u64 = 29;
const DT_FLAGS: u64 = 30;
const DT_GNU_HASH: u64 = 0x6fff_fef5;
const DT_FLAGS_1: u64 = 0x6fff_fffb;

/// `DF_TEXTREL`.
pub const DF_TEXTREL: u64 = 0x4;
/// `DF_BIND_NOW`.
pub const DF_BIND_NOW: u64 = 0x8;
/// `DF_1_NOW`.
pub const DF_1_NOW: u64 = 0x1;
/// `DF_1_PIE`.
pub const DF_1_PIE: u64 = 0x0800_0000;

/// One ELF symbol (dynamic or static).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfSymbol {
    /// Name (lossy UTF-8, raw attacker data).
    pub name: String,
    /// `st_shndx != SHN_UNDEF`.
    pub defined: bool,
    /// `STT_*` (low nibble of `st_info`).
    pub kind: u8,
}

/// Parsed dynamic section plus symbols.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ElfDynamic {
    /// `true` if a `PT_DYNAMIC` segment exists.
    pub present: bool,
    /// `DT_NEEDED`.
    pub needed: Vec<String>,
    /// `DT_SONAME`.
    pub soname: Option<String>,
    /// `DT_RPATH`.
    pub rpath: Option<String>,
    /// `DT_RUNPATH`.
    pub runpath: Option<String>,
    /// `DT_FLAGS`.
    pub flags: u64,
    /// `DT_FLAGS_1`.
    pub flags_1: u64,
    /// `DT_BIND_NOW` present.
    pub bind_now_tag: bool,
    /// `DT_TEXTREL` present.
    pub textrel_tag: bool,
    /// Dynamic symbols (index 0, the null symbol, is skipped).
    pub dynamic_symbols: Vec<ElfSymbol>,
    /// How the dynamic symbol count was found.
    pub symbol_count_source: &'static str,
    /// Static `.symtab` symbols (empty if stripped or no sections).
    pub static_symbols: Vec<ElfSymbol>,
    /// `true` if a `.symtab` section exists.
    pub has_symtab: bool,
    /// A symbol table was cut at `max_symbols`.
    pub symbols_limit_reached: bool,
}

impl ElfDynamic {
    /// Immediate binding requested by any of the three mechanisms.
    pub fn bind_now(&self) -> bool {
        self.bind_now_tag || self.flags & DF_BIND_NOW != 0 || self.flags_1 & DF_1_NOW != 0
    }

    /// Imported (undefined, named) dynamic symbols.
    pub fn imports(&self) -> impl Iterator<Item = &str> {
        self.dynamic_symbols
            .iter()
            .filter(|s| !s.defined && !s.name.is_empty())
            .map(|s| s.name.as_str())
    }

    /// Every symbol name, dynamic and static.
    pub fn all_names(&self) -> impl Iterator<Item = &str> {
        self.dynamic_symbols
            .iter()
            .chain(&self.static_symbols)
            .map(|s| s.name.as_str())
            .filter(|n| !n.is_empty())
    }
}

/// Raw `d_tag`/`d_val` values collected from `PT_DYNAMIC`.
#[derive(Default)]
struct Tags {
    needed: Vec<u64>,
    soname: Option<u64>,
    rpath: Option<u64>,
    runpath: Option<u64>,
    strtab: Option<u64>,
    strsz: Option<u64>,
    symtab: Option<u64>,
    syment: Option<u64>,
    hash: Option<u64>,
    gnu_hash: Option<u64>,
}

/// Parses the dynamic section and symbols. Never fails on missing pieces;
/// errors only for budget exhaustion, the deadline, or an unreadable
/// `PT_DYNAMIC` that exists.
///
/// # Errors
/// [`AnalysisError::Truncated`] / [`AnalysisError::Malformed`] for a broken
/// `PT_DYNAMIC`, [`AnalysisError::LimitExceeded`] / [`AnalysisError::Timeout`]
/// from the budget.
pub fn parse(
    elf: &ElfImage,
    data: &[u8],
    limits: &Limits,
    deadline: &Deadline,
) -> Result<ElfDynamic, AnalysisError> {
    let r = Reader {
        data,
        is64: elf.is64,
        big: elf.big_endian,
    };
    let mut budget = deadline.budget(limits.max_parser_steps);
    let mut out = ElfDynamic {
        symbol_count_source: "none",
        ..ElfDynamic::default()
    };

    if let Some(seg) = elf.segments.iter().find(|s| s.kind == PT_DYNAMIC) {
        out.present = true;
        let tags = read_tags(&r, seg.offset, seg.filesz, limits, &mut budget, &mut out)?;
        let strtab = tags
            .strtab
            .and_then(|v| elf.vaddr_to_offset(v, data.len()))
            .and_then(|off| {
                let size = usize::try_from(tags.strsz.unwrap_or(0)).ok()?;
                data.get(off..off.saturating_add(size).min(data.len()))
            });
        let name = |o: u64| strtab.and_then(|t| cstr(t, usize::try_from(o).ok()?, MAX_NAME));
        out.needed = tags.needed.iter().filter_map(|&o| name(o)).collect();
        out.soname = tags.soname.and_then(name);
        out.rpath = tags.rpath.and_then(name);
        out.runpath = tags.runpath.and_then(name);
        if let (Some(symtab), Some(strtab)) = (tags.symtab, strtab) {
            let (count, source) = dynsym_count(elf, &r, &tags, symtab, &mut budget)?;
            out.symbol_count_source = source;
            if let Some(off) = elf.vaddr_to_offset(symtab, data.len()) {
                let syment = tags.syment.unwrap_or(if elf.is64 { 24 } else { 16 });
                out.dynamic_symbols = read_symbols(
                    &r,
                    off,
                    count,
                    syment,
                    strtab,
                    limits,
                    &mut budget,
                    &mut out.symbols_limit_reached,
                )?;
            }
        }
    }

    // Static symbols need section headers (.symtab + its linked .strtab).
    if let Some(sym) = elf.sections.iter().find(|s| s.kind == SHT_SYMTAB) {
        out.has_symtab = true;
        let strtab = elf
            .sections
            .get(sym.link as usize)
            .and_then(|s| {
                let o = usize::try_from(s.offset).ok()?;
                let n = usize::try_from(s.size).ok()?;
                data.get(o..o.saturating_add(n).min(data.len()))
            })
            .unwrap_or_default();
        let syment = if sym.entsize == 0 {
            if elf.is64 {
                24
            } else {
                16
            }
        } else {
            sym.entsize
        };
        let count = sym.size / syment.max(1);
        if let Ok(off) = usize::try_from(sym.offset) {
            out.static_symbols = read_symbols(
                &r,
                off,
                count,
                syment,
                strtab,
                limits,
                &mut budget,
                &mut out.symbols_limit_reached,
            )?;
        }
    }
    Ok(out)
}

fn read_tags(
    r: &Reader<'_>,
    offset: u64,
    size: u64,
    limits: &Limits,
    budget: &mut Budget,
    out: &mut ElfDynamic,
) -> Result<Tags, AnalysisError> {
    let entsize: u64 = if r.is64 { 16 } else { 8 };
    let word: usize = if r.is64 { 8 } else { 4 };
    let count = usize::try_from(size / entsize)
        .unwrap_or(usize::MAX)
        .min(limits.max_dynamic_entries);
    let base = usize::try_from(offset).map_err(|_| AnalysisError::Malformed {
        what: "ELF dynamic section",
        reason: "offset overflows the address space".into(),
    })?;
    let mut t = Tags::default();
    for i in 0..count {
        budget.step()?;
        let at = base.saturating_add(i * 2 * word);
        let tag = r.word(at, "ELF dynamic entry")?;
        let val = r.word(at.saturating_add(word), "ELF dynamic entry")?;
        match tag {
            DT_NULL => break,
            DT_NEEDED => t.needed.push(val),
            DT_HASH => t.hash = Some(val),
            DT_STRTAB => t.strtab = Some(val),
            DT_SYMTAB => t.symtab = Some(val),
            DT_STRSZ => t.strsz = Some(val),
            DT_SYMENT => t.syment = Some(val),
            DT_SONAME => t.soname = Some(val),
            DT_RPATH => t.rpath = Some(val),
            DT_RUNPATH => t.runpath = Some(val),
            DT_TEXTREL => out.textrel_tag = true,
            DT_BIND_NOW => out.bind_now_tag = true,
            DT_FLAGS => out.flags = val,
            DT_FLAGS_1 => out.flags_1 = val,
            DT_GNU_HASH => t.gnu_hash = Some(val),
            _ => {}
        }
    }
    Ok(t)
}

/// Number of dynamic symbols (including the null symbol) and its source.
fn dynsym_count(
    elf: &ElfImage,
    r: &Reader<'_>,
    tags: &Tags,
    symtab: u64,
    budget: &mut Budget,
) -> Result<(u64, &'static str), AnalysisError> {
    let syment = tags.syment.unwrap_or(if elf.is64 { 24 } else { 16 }).max(1);
    if let Some(s) = elf
        .sections
        .iter()
        .find(|s| s.kind == SHT_DYNSYM && s.addr == symtab && s.size > 0)
    {
        return Ok((s.size / syment, "section"));
    }
    if let Some(off) = tags.hash.and_then(|h| elf.vaddr_to_offset(h, r.data.len())) {
        if let Ok(nchain) = r.u32(off.saturating_add(4), "DT_HASH") {
            return Ok((u64::from(nchain), "dt_hash"));
        }
    }
    if let Some(off) = tags
        .gnu_hash
        .and_then(|h| elf.vaddr_to_offset(h, r.data.len()))
    {
        if let Some(n) = gnu_hash_count(r, off, budget)? {
            return Ok((n, "dt_gnu_hash"));
        }
    }
    if let Some(strtab) = tags.strtab.filter(|&s| s > symtab) {
        return Ok(((strtab - symtab) / syment, "strtab_gap"));
    }
    Ok((0, "none"))
}

/// Symbol count from a GNU hash table at file offset `off`: one past the
/// highest symbol index reachable from any bucket. `None` if unreadable.
pub fn gnu_hash_count(
    r: &Reader<'_>,
    off: usize,
    budget: &mut Budget,
) -> Result<Option<u64>, AnalysisError> {
    let (Ok(nbuckets), Ok(symoffset), Ok(bloom_size)) = (
        r.u32(off, "DT_GNU_HASH"),
        r.u32(off.saturating_add(4), "DT_GNU_HASH"),
        r.u32(off.saturating_add(8), "DT_GNU_HASH"),
    ) else {
        return Ok(None);
    };
    if u64::from(nbuckets) > MAX_HASH_BUCKETS || u64::from(bloom_size) > MAX_HASH_BUCKETS {
        return Ok(None);
    }
    let word = if r.is64 { 8 } else { 4 };
    let buckets = off.saturating_add(16 + bloom_size as usize * word);
    let mut max_sym = 0u32;
    for i in 0..nbuckets as usize {
        budget.step()?;
        let Ok(b) = r.u32(buckets.saturating_add(4 * i), "DT_GNU_HASH bucket") else {
            return Ok(None);
        };
        max_sym = max_sym.max(b);
    }
    if max_sym < symoffset {
        return Ok(Some(u64::from(symoffset)));
    }
    let chains = buckets.saturating_add(4 * nbuckets as usize);
    let mut idx = max_sym;
    loop {
        budget.step()?;
        let at = chains.saturating_add(4 * (idx - symoffset) as usize);
        let Ok(h) = r.u32(at, "DT_GNU_HASH chain") else {
            return Ok(None);
        };
        if h & 1 != 0 {
            return Ok(Some(u64::from(idx) + 1));
        }
        let Some(next) = idx.checked_add(1) else {
            return Ok(None);
        };
        idx = next;
    }
}

#[allow(clippy::too_many_arguments)]
fn read_symbols(
    r: &Reader<'_>,
    off: usize,
    count: u64,
    syment: u64,
    strtab: &[u8],
    limits: &Limits,
    budget: &mut Budget,
    limit_reached: &mut bool,
) -> Result<Vec<ElfSymbol>, AnalysisError> {
    let syment = usize::try_from(syment).unwrap_or(usize::MAX);
    if syment < if r.is64 { 24 } else { 16 } {
        return Ok(Vec::new()); // impossible entry size: ignore the table
    }
    let mut count = usize::try_from(count).unwrap_or(usize::MAX);
    if count > limits.max_symbols {
        *limit_reached = true;
        count = limits.max_symbols;
    }
    let mut syms = Vec::new();
    for i in 1..count {
        budget.step()?;
        let at = off.saturating_add(i.saturating_mul(syment));
        let Ok(name_off) = r.u32(at, "ELF symbol") else {
            break; // table runs past EOF: keep what was read
        };
        let (info_at, shndx_at) = if r.is64 { (4, 6) } else { (12, 14) };
        let (Some(&info), Ok(shndx)) = (
            r.data.get(at.saturating_add(info_at)),
            r.u16(at.saturating_add(shndx_at), "ELF symbol"),
        ) else {
            break;
        };
        syms.push(ElfSymbol {
            name: cstr(strtab, name_off as usize, MAX_NAME).unwrap_or_default(),
            defined: shndx != 0,
            kind: info & 0xf,
        });
    }
    Ok(syms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtriage_fixtures::elf::{df, machine, profiles, Class, ElfBuilder, Endian};

    fn parse_built(bytes: &[u8]) -> ElfDynamic {
        let elf = super::super::parse(bytes, &Limits::default()).unwrap();
        parse(&elf, bytes, &Limits::default(), &Deadline::never()).unwrap()
    }

    #[test]
    fn glibc_profile() {
        let d = parse_built(&profiles::glibc_pie().build().bytes);
        assert!(d.present);
        assert_eq!(d.needed, ["libc.so.6"]);
        assert!(d.bind_now());
        assert_ne!(d.flags_1 & DF_1_PIE, 0);
        assert_eq!(d.symbol_count_source, "section");
        assert!(d.imports().any(|n| n == "__stack_chk_fail"));
        assert_eq!(d.imports().count(), 10);
    }

    #[test]
    fn without_section_headers_uses_dt_hash() {
        let bytes = profiles::glibc_pie().section_headers(false).build().bytes;
        let d = parse_built(&bytes);
        assert_eq!(d.symbol_count_source, "dt_hash");
        assert_eq!(d.imports().count(), 10);
    }

    #[test]
    fn big_endian_32_bit() {
        let bytes = ElfBuilder::new(Class::Elf32, Endian::Big, machine::MIPS)
            .needed("libc.so.0")
            .imports(&["socket", "connect"])
            .rpath("/opt/lib")
            .build()
            .bytes;
        let d = parse_built(&bytes);
        assert_eq!(d.needed, ["libc.so.0"]);
        assert_eq!(d.rpath.as_deref(), Some("/opt/lib"));
        assert_eq!(d.imports().collect::<Vec<_>>(), ["socket", "connect"]);
    }

    #[test]
    fn static_symbols_from_symtab() {
        let d = parse_built(&profiles::go_static().build().bytes);
        assert!(!d.present);
        assert!(d.has_symtab);
        assert!(d.all_names().any(|n| n == "runtime.main"));
    }

    #[test]
    fn bind_now_mechanisms() {
        for b in [
            ElfBuilder::x86_64().needed("l").dt_flags(df::BIND_NOW),
            ElfBuilder::x86_64().needed("l").dt_flags_1(df::NOW_1),
        ] {
            assert!(parse_built(&b.build().bytes).bind_now());
        }
        assert!(!parse_built(&ElfBuilder::x86_64().needed("l").build().bytes).bind_now());
    }

    #[test]
    fn symbol_limit() {
        let names: Vec<String> = (0..50).map(|i| format!("f{i}")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let bytes = ElfBuilder::x86_64()
            .needed("l")
            .imports(&refs)
            .build()
            .bytes;
        let elf = super::super::parse(&bytes, &Limits::default()).unwrap();
        let limits = Limits {
            max_symbols: 10,
            ..Limits::default()
        };
        let d = parse(&elf, &bytes, &limits, &Deadline::never()).unwrap();
        assert!(d.symbols_limit_reached);
        assert_eq!(d.dynamic_symbols.len(), 9); // null symbol skipped
    }

    #[test]
    fn huge_dt_hash_nchain_is_capped() {
        // Overwrite nchain with u32::MAX and drop sections so DT_HASH is used.
        let built = profiles::glibc_pie().section_headers(false).build();
        let mut bytes = built.bytes.clone();
        let elf = super::super::parse(&bytes, &Limits::default()).unwrap();
        let r = Reader {
            data: &bytes,
            is64: true,
            big: false,
        };
        let dyn_seg = elf.segments.iter().find(|s| s.kind == PT_DYNAMIC).unwrap();
        let mut hash_vaddr = 0;
        for i in 0.. {
            let tag = r.u64(dyn_seg.offset as usize + i * 16, "t").unwrap();
            if tag == DT_HASH {
                hash_vaddr = r.u64(dyn_seg.offset as usize + i * 16 + 8, "t").unwrap();
                break;
            }
        }
        let off = elf.vaddr_to_offset(hash_vaddr, bytes.len()).unwrap();
        bytes[off + 4..off + 8].copy_from_slice(&u32::MAX.to_le_bytes());
        let d = parse(&elf, &bytes, &Limits::default(), &Deadline::never()).unwrap();
        assert!(d.symbols_limit_reached);
        // Reading stops at EOF long before the limit; no panic, no huge allocation.
        assert!(d.dynamic_symbols.len() < 200_000);
    }

    #[test]
    fn gnu_hash_counting() {
        // 2 buckets, symoffset 1, bloom 1 word (64-bit). Symbols 1..=3;
        // bucket[1] = 2, chain for sym 2 continues, sym 3 ends (bit 0 set).
        let mut t = Vec::new();
        for v in [2u32, 1, 1, 6] {
            t.extend_from_slice(&v.to_le_bytes());
        }
        t.extend_from_slice(&[0u8; 8]); // bloom
        for v in [1u32, 2] {
            t.extend_from_slice(&v.to_le_bytes()); // buckets
        }
        for v in [0x10u32, 0x20, 0x31] {
            t.extend_from_slice(&v.to_le_bytes()); // chains for syms 1, 2, 3
        }
        let r = Reader {
            data: &t,
            is64: true,
            big: false,
        };
        let mut b = Deadline::never().budget(1000);
        assert_eq!(gnu_hash_count(&r, 0, &mut b).unwrap(), Some(4));
    }

    #[test]
    fn gnu_hash_without_end_bit_hits_eof_or_budget() {
        let mut t = Vec::new();
        for v in [1u32, 0, 0, 6] {
            t.extend_from_slice(&v.to_le_bytes());
        }
        t.extend_from_slice(&0u32.to_le_bytes()); // bucket[0] = 0
        t.extend_from_slice(&[0u8; 400]); // chains never end
        let r = Reader {
            data: &t,
            is64: false,
            big: false,
        };
        // A small budget stops the walk...
        assert!(gnu_hash_count(&r, 0, &mut Deadline::never().budget(50)).is_err());
        // ...and with a large one it ends at EOF without a count.
        assert_eq!(
            gnu_hash_count(&r, 0, &mut Deadline::never().budget(10_000)).unwrap(),
            None
        );
    }
}

//! Synthetic ELF32 / ELF64, little- and big-endian builder.
//!
//! Layout produced by [`ElfBuilder::build`] (file offset == vaddr - base, so
//! every `PT_LOAD` satisfies `p_offset % p_align == p_vaddr % p_align`):
//!
//! ```text
//! ELF header, program headers, `after_phdrs` bytes
//! R   segment: .interp, .note.*, .dynsym, .dynstr, alloc extras, .rodata
//! R X segment: .text                                   (page aligned)
//! RW  segment: .dynamic, .data   (PT_GNU_RELRO covers .dynamic)
//! non-alloc sections (.symtab, .strtab, extras), .shstrtab, section headers
//! overlay
//! ```
//!
//! [`BuiltElf::layout`] exposes header field offsets so tests can corrupt them.

/// Page size used for segment alignment.
pub const PAGE: u64 = 0x1000;

/// ELF class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// 32-bit.
    Elf32,
    /// 64-bit.
    Elf64,
}

/// Byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endian {
    /// Little-endian.
    Little,
    /// Big-endian.
    Big,
}

/// `e_machine` values (subset).
pub mod machine {
    /// Intel 80386.
    pub const X86: u16 = 3;
    /// MIPS.
    pub const MIPS: u16 = 8;
    /// PowerPC.
    pub const PPC: u16 = 20;
    /// PowerPC64.
    pub const PPC64: u16 = 21;
    /// ARM (32-bit).
    pub const ARM: u16 = 40;
    /// AMD64.
    pub const X86_64: u16 = 62;
    /// AArch64.
    pub const AARCH64: u16 = 183;
    /// RISC-V.
    pub const RISCV: u16 = 243;
}

/// `e_type` values.
pub mod et {
    /// Relocatable object.
    pub const REL: u16 = 1;
    /// Executable.
    pub const EXEC: u16 = 2;
    /// Shared object / PIE.
    pub const DYN: u16 = 3;
    /// Core dump.
    pub const CORE: u16 = 4;
}

/// Program header types (subset).
pub mod pt {
    /// Loadable segment.
    pub const LOAD: u32 = 1;
    /// Dynamic linking info.
    pub const DYNAMIC: u32 = 2;
    /// Interpreter path.
    pub const INTERP: u32 = 3;
    /// Notes.
    pub const NOTE: u32 = 4;
    /// Program header table itself.
    pub const PHDR: u32 = 6;
    /// Stack permissions.
    pub const GNU_STACK: u32 = 0x6474_e551;
    /// Read-only after relocation.
    pub const GNU_RELRO: u32 = 0x6474_e552;
}

/// Segment permission flags.
pub mod pf {
    /// Execute.
    pub const X: u32 = 1;
    /// Write.
    pub const W: u32 = 2;
    /// Read.
    pub const R: u32 = 4;
}

/// Dynamic tags (subset).
pub mod dt {
    /// Needed library.
    pub const NEEDED: u64 = 1;
    /// String table address.
    pub const STRTAB: u64 = 5;
    /// SysV symbol hash table address.
    pub const HASH: u64 = 4;
    /// Symbol table address.
    pub const SYMTAB: u64 = 6;
    /// String table size.
    pub const STRSZ: u64 = 10;
    /// Symbol entry size.
    pub const SYMENT: u64 = 11;
    /// Library search path (deprecated).
    pub const RPATH: u64 = 15;
    /// Library search path.
    pub const RUNPATH: u64 = 29;
    /// Flags.
    pub const FLAGS: u64 = 30;
    /// Extended flags.
    pub const FLAGS_1: u64 = 0x6fff_fffb;
}

/// `DT_FLAGS` / `DT_FLAGS_1` bits.
pub mod df {
    /// `DF_BIND_NOW`.
    pub const BIND_NOW: u64 = 0x8;
    /// `DF_1_NOW`.
    pub const NOW_1: u64 = 0x1;
    /// `DF_1_PIE`.
    pub const PIE_1: u64 = 0x0800_0000;
}

/// Section types (subset).
pub mod sht {
    /// Program data.
    pub const PROGBITS: u32 = 1;
    /// Symbol table.
    pub const SYMTAB: u32 = 2;
    /// String table.
    pub const STRTAB: u32 = 3;
    /// Dynamic section.
    pub const DYNAMIC: u32 = 6;
    /// Notes.
    pub const NOTE: u32 = 7;
    /// SysV symbol hash table.
    pub const HASH: u32 = 5;
    /// Dynamic symbols.
    pub const DYNSYM: u32 = 11;
}

/// Section flags (subset).
pub mod shf {
    /// Writable.
    pub const WRITE: u64 = 1;
    /// Occupies memory.
    pub const ALLOC: u64 = 2;
    /// Executable.
    pub const EXECINSTR: u64 = 4;
}

/// Where `e_entry` points.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryPoint {
    /// Start of `.text`.
    Text,
    /// Raw address.
    Addr(u64),
}

/// An extra section with explicit contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtraSection {
    /// Name.
    pub name: String,
    /// `sh_type`.
    pub kind: u32,
    /// `sh_flags`; `SHF_ALLOC` places it in the read-only segment.
    pub flags: u64,
    /// Contents.
    pub data: Vec<u8>,
}

/// Builder for a synthetic ELF file.
#[derive(Debug, Clone)]
pub struct ElfBuilder {
    class: Class,
    endian: Endian,
    machine: u16,
    elf_type: u16,
    os_abi: u8,
    entry: EntryPoint,
    interp: Option<Vec<u8>>,
    text: Vec<u8>,
    text_flags: u32,
    rodata: Vec<u8>,
    data: Vec<u8>,
    gnu_stack: Option<u32>,
    relro: bool,
    needed: Vec<String>,
    rpath: Option<String>,
    runpath: Option<String>,
    flags: Option<u64>,
    flags_1: Option<u64>,
    imports: Vec<String>,
    symtab: Vec<String>,
    build_id: Option<Vec<u8>>,
    extra: Vec<ExtraSection>,
    section_headers: bool,
    after_phdrs: Vec<u8>,
    overlay: Vec<u8>,
}

impl ElfBuilder {
    /// Executable for `machine` with `.text` only, RW `PT_GNU_STACK`, section headers.
    pub fn new(class: Class, endian: Endian, machine: u16) -> Self {
        Self {
            class,
            endian,
            machine,
            elf_type: et::EXEC,
            os_abi: 0,
            entry: EntryPoint::Text,
            interp: None,
            text: vec![0xC3; 64],
            text_flags: pf::R | pf::X,
            rodata: Vec::new(),
            data: Vec::new(),
            gnu_stack: Some(pf::R | pf::W),
            relro: false,
            needed: Vec::new(),
            rpath: None,
            runpath: None,
            flags: None,
            flags_1: None,
            imports: Vec::new(),
            symtab: Vec::new(),
            build_id: None,
            extra: Vec::new(),
            section_headers: true,
            after_phdrs: Vec::new(),
            overlay: Vec::new(),
        }
    }

    /// x86-64 little-endian executable.
    pub fn x86_64() -> Self {
        Self::new(Class::Elf64, Endian::Little, machine::X86_64)
    }

    /// Sets `e_type`.
    #[must_use]
    pub fn elf_type(mut self, t: u16) -> Self {
        self.elf_type = t;
        self
    }
    /// Sets `EI_OSABI`.
    #[must_use]
    pub fn os_abi(mut self, abi: u8) -> Self {
        self.os_abi = abi;
        self
    }
    /// Sets the entry point.
    #[must_use]
    pub fn entry(mut self, e: EntryPoint) -> Self {
        self.entry = e;
        self
    }
    /// Adds `PT_INTERP` with this path.
    #[must_use]
    pub fn interp(mut self, path: &str) -> Self {
        self.interp = Some(path.as_bytes().to_vec());
        self
    }
    /// Replaces `.text` contents.
    #[must_use]
    pub fn text(mut self, bytes: Vec<u8>) -> Self {
        self.text = bytes;
        self
    }
    /// Permission flags of the code `PT_LOAD` (default `R|X`).
    #[must_use]
    pub fn text_flags(mut self, flags: u32) -> Self {
        self.text_flags = flags;
        self
    }
    /// Sets `.rodata` contents.
    #[must_use]
    pub fn rodata(mut self, bytes: Vec<u8>) -> Self {
        self.rodata = bytes;
        self
    }
    /// Sets `.data` contents.
    #[must_use]
    pub fn data(mut self, bytes: Vec<u8>) -> Self {
        self.data = bytes;
        self
    }
    /// `PT_GNU_STACK` flags, or `None` for no such header.
    #[must_use]
    pub fn gnu_stack(mut self, flags: Option<u32>) -> Self {
        self.gnu_stack = flags;
        self
    }
    /// Adds `PT_GNU_RELRO` covering `.dynamic`.
    #[must_use]
    pub fn relro(mut self, on: bool) -> Self {
        self.relro = on;
        self
    }
    /// Adds a `DT_NEEDED` entry.
    #[must_use]
    pub fn needed(mut self, lib: &str) -> Self {
        self.needed.push(lib.to_owned());
        self
    }
    /// Sets `DT_RPATH`.
    #[must_use]
    pub fn rpath(mut self, path: &str) -> Self {
        self.rpath = Some(path.to_owned());
        self
    }
    /// Sets `DT_RUNPATH`.
    #[must_use]
    pub fn runpath(mut self, path: &str) -> Self {
        self.runpath = Some(path.to_owned());
        self
    }
    /// Sets `DT_FLAGS`.
    #[must_use]
    pub fn dt_flags(mut self, flags: u64) -> Self {
        self.flags = Some(flags);
        self
    }
    /// Sets `DT_FLAGS_1`.
    #[must_use]
    pub fn dt_flags_1(mut self, flags: u64) -> Self {
        self.flags_1 = Some(flags);
        self
    }
    /// Undefined dynamic function symbols (imports).
    #[must_use]
    pub fn imports(mut self, names: &[&str]) -> Self {
        self.imports.extend(names.iter().map(|n| (*n).to_owned()));
        self
    }
    /// Defined function symbols in a static `.symtab` (all at `.text`).
    #[must_use]
    pub fn symtab(mut self, names: &[&str]) -> Self {
        self.symtab.extend(names.iter().map(|n| (*n).to_owned()));
        self
    }
    /// Adds a `.note.gnu.build-id` note.
    #[must_use]
    pub fn build_id(mut self, id: &[u8]) -> Self {
        self.build_id = Some(id.to_vec());
        self
    }
    /// Adds an extra section.
    #[must_use]
    pub fn section(mut self, name: &str, kind: u32, flags: u64, data: Vec<u8>) -> Self {
        self.extra.push(ExtraSection {
            name: name.to_owned(),
            kind,
            flags,
            data,
        });
        self
    }
    /// `false` writes no section header table (`e_shoff = e_shnum = 0`).
    #[must_use]
    pub fn section_headers(mut self, on: bool) -> Self {
        self.section_headers = on;
        self
    }
    /// Bytes placed right after the program headers (UPX's `l_info`).
    #[must_use]
    pub fn after_phdrs(mut self, bytes: Vec<u8>) -> Self {
        self.after_phdrs = bytes;
        self
    }
    /// Bytes appended after everything else.
    #[must_use]
    pub fn overlay(mut self, bytes: Vec<u8>) -> Self {
        self.overlay = bytes;
        self
    }

    fn is64(&self) -> bool {
        self.class == Class::Elf64
    }

    fn has_dynamic(&self) -> bool {
        !self.needed.is_empty()
            || !self.imports.is_empty()
            || self.rpath.is_some()
            || self.runpath.is_some()
            || self.flags.is_some()
            || self.flags_1.is_some()
    }

    fn base(&self) -> u64 {
        match (self.elf_type, self.class) {
            (et::DYN, _) => 0,
            (_, Class::Elf64) => 0x40_0000,
            (_, Class::Elf32) => 0x0804_8000,
        }
    }

    /// Assembles the file.
    pub fn build(&self) -> BuiltElf {
        let w = W {
            is64: self.is64(),
            big: self.endian == Endian::Big,
        };
        let (ehsize, phentsize, shentsize) = if w.is64 { (64, 56, 64) } else { (52, 32, 40) };
        let dynamic = self.has_dynamic();
        let base = self.base();

        let phnum = 3 // three PT_LOADs
            + usize::from(self.interp.is_some()) * 2 // PT_PHDR + PT_INTERP
            + usize::from(dynamic)
            + usize::from(self.build_id.is_some())
            + usize::from(self.gnu_stack.is_some())
            + usize::from(self.relro && dynamic);

        let mut f: Vec<u8> = vec![0; ehsize + phnum * phentsize];
        f.extend_from_slice(&self.after_phdrs);
        let mut secs: Vec<Sec> = Vec::new();

        // ---- read-only segment contents
        let interp_off = self.interp.as_ref().map(|p| {
            let mut z = p.clone();
            z.push(0);
            push_sec(
                &mut f,
                &mut secs,
                ".interp",
                sht::PROGBITS,
                shf::ALLOC,
                &z,
                1,
            )
        });
        let note = self.build_id.as_ref().map(|id| {
            let n = w.note(b"GNU\0", 3, id);
            let off = push_sec(
                &mut f,
                &mut secs,
                ".note.gnu.build-id",
                sht::NOTE,
                shf::ALLOC,
                &n,
                4,
            );
            (off, n.len())
        });

        // .dynstr and .dynsym
        let mut dynstr = vec![0u8];
        let str_off = |s: &str, tab: &mut Vec<u8>| -> u64 {
            let o = tab.len() as u64;
            tab.extend_from_slice(s.as_bytes());
            tab.push(0);
            o
        };
        let needed_offs: Vec<u64> = self
            .needed
            .iter()
            .map(|n| str_off(n, &mut dynstr))
            .collect();
        let rpath_off = self.rpath.as_ref().map(|s| str_off(s, &mut dynstr));
        let runpath_off = self.runpath.as_ref().map(|s| str_off(s, &mut dynstr));
        let import_offs: Vec<u64> = self
            .imports
            .iter()
            .map(|n| str_off(n, &mut dynstr))
            .collect();
        let sym_size = if w.is64 { 24 } else { 16 };
        let (dynsym_off, dynstr_off, hash_off) = if dynamic {
            let mut syms = vec![0u8; sym_size]; // null symbol
            for &name in &import_offs {
                syms.extend(w.sym(name as u32, 0x12, 0, 0)); // GLOBAL FUNC, UND
            }
            let s = push_sec(
                &mut f,
                &mut secs,
                ".dynsym",
                sht::DYNSYM,
                shf::ALLOC,
                &syms,
                8,
            );
            let d = push_sec(
                &mut f,
                &mut secs,
                ".dynstr",
                sht::STRTAB,
                shf::ALLOC,
                &dynstr,
                1,
            );
            // SysV hash with one bucket: loaders (and goblin) size .dynsym from nchain.
            let nsyms = (import_offs.len() + 1) as u32;
            let mut hash = Vec::new();
            hash.extend(w.u32(1)); // nbucket
            hash.extend(w.u32(nsyms)); // nchain
            hash.extend(w.u32(nsyms - 1)); // bucket[0] -> last symbol
            for i in 0..nsyms {
                hash.extend(w.u32(i.saturating_sub(1))); // chain[i] -> previous
            }
            let h = push_sec(&mut f, &mut secs, ".hash", sht::HASH, shf::ALLOC, &hash, 8);
            (Some(s), Some(d), Some(h))
        } else {
            (None, None, None)
        };
        for x in self
            .extra
            .iter()
            .filter(|x| x.flags & shf::ALLOC != 0 && x.flags & shf::WRITE == 0)
        {
            push_sec(&mut f, &mut secs, &x.name, x.kind, x.flags, &x.data, 8);
        }
        if !self.rodata.is_empty() {
            push_sec(
                &mut f,
                &mut secs,
                ".rodata",
                sht::PROGBITS,
                shf::ALLOC,
                &self.rodata,
                8,
            );
        }
        let ro_end = f.len();

        // ---- code segment
        align_to(&mut f, PAGE as usize);
        let text_off = push_sec(
            &mut f,
            &mut secs,
            ".text",
            sht::PROGBITS,
            shf::ALLOC | shf::EXECINSTR,
            &self.text,
            16,
        );
        let text_end = f.len();

        // ---- data segment: .dynamic first (RELRO), then writable extras and .data
        align_to(&mut f, PAGE as usize);
        let rw_start = f.len();
        let addr = |off: usize| base + off as u64;
        let dyn_range = dynamic.then(|| {
            let mut entries: Vec<(u64, u64)> =
                needed_offs.iter().map(|&o| (dt::NEEDED, o)).collect();
            if let Some(o) = rpath_off {
                entries.push((dt::RPATH, o));
            }
            if let Some(o) = runpath_off {
                entries.push((dt::RUNPATH, o));
            }
            entries.push((dt::STRTAB, addr(dynstr_off.unwrap_or(0))));
            entries.push((dt::SYMTAB, addr(dynsym_off.unwrap_or(0))));
            entries.push((dt::HASH, addr(hash_off.unwrap_or(0))));
            entries.push((dt::STRSZ, dynstr.len() as u64));
            entries.push((dt::SYMENT, sym_size as u64));
            if let Some(v) = self.flags {
                entries.push((dt::FLAGS, v));
            }
            if let Some(v) = self.flags_1 {
                entries.push((dt::FLAGS_1, v));
            }
            entries.push((0, 0)); // DT_NULL
            let mut bytes = Vec::new();
            for (tag, val) in entries {
                bytes.extend(w.word(tag));
                bytes.extend(w.word(val));
            }
            let off = push_sec(
                &mut f,
                &mut secs,
                ".dynamic",
                sht::DYNAMIC,
                shf::ALLOC | shf::WRITE,
                &bytes,
                8,
            );
            (off, bytes.len())
        });
        for x in self
            .extra
            .iter()
            .filter(|x| x.flags & shf::ALLOC != 0 && x.flags & shf::WRITE != 0)
        {
            push_sec(&mut f, &mut secs, &x.name, x.kind, x.flags, &x.data, 8);
        }
        push_sec(
            &mut f,
            &mut secs,
            ".data",
            sht::PROGBITS,
            shf::ALLOC | shf::WRITE,
            &self.data,
            8,
        );
        let rw_end = f.len();

        // ---- non-alloc sections
        for x in self.extra.iter().filter(|x| x.flags & shf::ALLOC == 0) {
            push_sec(&mut f, &mut secs, &x.name, x.kind, x.flags, &x.data, 1);
        }
        if !self.symtab.is_empty() {
            let mut strtab = vec![0u8];
            let mut syms = vec![0u8; sym_size];
            let text_index = 1 + secs.iter().position(|s| s.name == ".text").unwrap_or(0);
            for name in &self.symtab {
                let o = strtab.len() as u32;
                strtab.extend_from_slice(name.as_bytes());
                strtab.push(0);
                syms.extend(w.sym(o, 0x12, text_index as u16, addr(text_off)));
            }
            push_sec(&mut f, &mut secs, ".symtab", sht::SYMTAB, 0, &syms, 8);
            push_sec(&mut f, &mut secs, ".strtab", sht::STRTAB, 0, &strtab, 1);
        }

        // Fill in links/entsizes now that indices are known (index 0 is the null section).
        let index_of = |name: &str| {
            secs.iter()
                .position(|s| s.name == name)
                .map(|i| i as u32 + 1)
        };
        let dynstr_idx = index_of(".dynstr");
        let strtab_idx = index_of(".strtab");
        let dynsym_idx = index_of(".dynsym");
        for s in &mut secs {
            match s.kind {
                sht::HASH => {
                    s.link = dynsym_idx.unwrap_or(0);
                    s.entsize = 4;
                }
                sht::DYNSYM => {
                    s.link = dynstr_idx.unwrap_or(0);
                    s.info = 1;
                    s.entsize = sym_size;
                }
                sht::SYMTAB => {
                    s.link = strtab_idx.unwrap_or(0);
                    s.info = 1;
                    s.entsize = sym_size;
                }
                sht::DYNAMIC => {
                    s.link = dynstr_idx.unwrap_or(0);
                    s.entsize = if w.is64 { 16 } else { 8 };
                }
                _ => {}
            }
        }

        // ---- section header table
        let (shoff, shnum, shstrndx) = if self.section_headers {
            let mut shstrtab = vec![0u8];
            let mut names = Vec::new();
            for s in &secs {
                names.push(shstrtab.len() as u32);
                shstrtab.extend_from_slice(s.name.as_bytes());
                shstrtab.push(0);
            }
            let shstr_name = shstrtab.len() as u32;
            shstrtab.extend_from_slice(b".shstrtab\0");
            let shstr_off = f.len();
            f.extend_from_slice(&shstrtab);
            align_to(&mut f, 8);
            let shoff = f.len();
            f.extend(vec![0u8; shentsize]); // null section
            for (s, &name) in secs.iter().zip(&names) {
                let a = if s.flags & shf::ALLOC != 0 {
                    addr(s.offset)
                } else {
                    0
                };
                f.extend(w.shdr(
                    name,
                    s.kind,
                    s.flags,
                    a,
                    s.offset as u64,
                    s.size as u64,
                    s.link,
                    s.info,
                    s.entsize as u64,
                ));
            }
            f.extend(w.shdr(
                shstr_name,
                sht::STRTAB,
                0,
                0,
                shstr_off as u64,
                shstrtab.len() as u64,
                0,
                0,
                0,
            ));
            (shoff, secs.len() + 2, secs.len() + 1)
        } else {
            (0, 0, 0)
        };
        let image_end = f.len();
        f.extend_from_slice(&self.overlay);

        // ---- program headers
        let mut phdrs: Vec<Seg> = Vec::new();
        let phoff = ehsize;
        if self.interp.is_some() {
            phdrs.push(Seg::new(pt::PHDR, pf::R, phoff, phnum * phentsize, 8));
            if let (Some(off), Some(p)) = (interp_off, &self.interp) {
                phdrs.push(Seg::new(pt::INTERP, pf::R, off, p.len() + 1, 1));
            }
        }
        phdrs.push(Seg::new(pt::LOAD, pf::R, 0, ro_end, PAGE as usize));
        phdrs.push(Seg::new(
            pt::LOAD,
            self.text_flags,
            text_off,
            text_end - text_off,
            PAGE as usize,
        ));
        phdrs.push(Seg::new(
            pt::LOAD,
            pf::R | pf::W,
            rw_start,
            rw_end - rw_start,
            PAGE as usize,
        ));
        if let Some((off, len)) = dyn_range {
            phdrs.push(Seg::new(pt::DYNAMIC, pf::R | pf::W, off, len, 8));
            if self.relro {
                phdrs.push(Seg::new(pt::GNU_RELRO, pf::R, off, len, 1));
            }
        }
        if let Some((off, len)) = note {
            phdrs.push(Seg::new(pt::NOTE, pf::R, off, len, 4));
        }
        if let Some(flags) = self.gnu_stack {
            let mut s = Seg::new(pt::GNU_STACK, flags, 0, 0, 16);
            s.vaddr_zero = true;
            phdrs.push(s);
        }
        assert_eq!(phdrs.len(), phnum, "program header count");
        let mut seg_layout = Vec::new();
        for (i, s) in phdrs.iter().enumerate() {
            let at = phoff + i * phentsize;
            let vaddr = if s.vaddr_zero { 0 } else { addr(s.offset) };
            let bytes = w.phdr(
                s.kind,
                s.flags,
                s.offset as u64,
                vaddr,
                s.size as u64,
                s.align as u64,
            );
            f[at..at + phentsize].copy_from_slice(&bytes);
            seg_layout.push(SegLayout {
                kind: s.kind,
                flags: s.flags,
                offset: s.offset,
                vaddr,
                size: s.size,
                header_offset: at,
            });
        }

        // ---- ELF header
        let entry = match self.entry {
            EntryPoint::Text => addr(text_off),
            EntryPoint::Addr(a) => a,
        };
        f[..4].copy_from_slice(b"\x7fELF");
        f[4] = if w.is64 { 2 } else { 1 };
        f[5] = if w.big { 2 } else { 1 };
        f[6] = 1;
        f[7] = self.os_abi;
        let mut h = Vec::new();
        h.extend(w.u16(self.elf_type));
        h.extend(w.u16(self.machine));
        h.extend(w.u32(1));
        h.extend(w.word(entry));
        h.extend(w.word(phoff as u64));
        h.extend(w.word(shoff as u64));
        h.extend(w.u32(0)); // e_flags
        h.extend(w.u16(ehsize as u16));
        h.extend(w.u16(phentsize as u16));
        h.extend(w.u16(phnum as u16));
        h.extend(w.u16(shentsize as u16));
        h.extend(w.u16(shnum as u16));
        h.extend(w.u16(shstrndx as u16));
        f[16..16 + h.len()].copy_from_slice(&h);

        let word = if w.is64 { 8 } else { 4 };
        BuiltElf {
            bytes: f,
            layout: ElfLayout {
                entry_offset: 24,
                phoff_offset: 24 + word,
                shoff_offset: 24 + 2 * word,
                phentsize_offset: ehsize - 10,
                phnum_offset: ehsize - 8,
                shentsize_offset: ehsize - 6,
                shnum_offset: ehsize - 4,
                shstrndx_offset: ehsize - 2,
                phoff,
                shoff,
                segments: seg_layout,
                text_offset: text_off,
                text_vaddr: addr(text_off),
                image_end,
            },
        }
    }
}

/// A built ELF file plus where everything landed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltElf {
    /// File contents.
    pub bytes: Vec<u8>,
    /// Offsets of headers and segments.
    pub layout: ElfLayout,
}

/// File offsets inside a [`BuiltElf`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfLayout {
    /// `e_entry` field.
    pub entry_offset: usize,
    /// `e_phoff` field.
    pub phoff_offset: usize,
    /// `e_shoff` field.
    pub shoff_offset: usize,
    /// `e_phentsize` field.
    pub phentsize_offset: usize,
    /// `e_phnum` field.
    pub phnum_offset: usize,
    /// `e_shentsize` field.
    pub shentsize_offset: usize,
    /// `e_shnum` field.
    pub shnum_offset: usize,
    /// `e_shstrndx` field.
    pub shstrndx_offset: usize,
    /// Program header table offset.
    pub phoff: usize,
    /// Section header table offset (0 if none).
    pub shoff: usize,
    /// Every program header, in table order.
    pub segments: Vec<SegLayout>,
    /// `.text` file offset.
    pub text_offset: usize,
    /// `.text` virtual address.
    pub text_vaddr: u64,
    /// End of the image (start of the overlay).
    pub image_end: usize,
}

/// Where one program header points.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegLayout {
    /// `p_type`.
    pub kind: u32,
    /// `p_flags`.
    pub flags: u32,
    /// `p_offset`.
    pub offset: usize,
    /// `p_vaddr`.
    pub vaddr: u64,
    /// `p_filesz` (== `p_memsz`).
    pub size: usize,
    /// File offset of this program header entry.
    pub header_offset: usize,
}

struct Sec {
    name: String,
    kind: u32,
    flags: u64,
    offset: usize,
    size: usize,
    link: u32,
    info: u32,
    entsize: usize,
}

struct Seg {
    kind: u32,
    flags: u32,
    offset: usize,
    size: usize,
    align: usize,
    vaddr_zero: bool,
}

impl Seg {
    fn new(kind: u32, flags: u32, offset: usize, size: usize, align: usize) -> Self {
        Self {
            kind,
            flags,
            offset,
            size,
            align,
            vaddr_zero: false,
        }
    }
}

/// Endian- and class-aware field writer.
#[derive(Clone, Copy)]
struct W {
    is64: bool,
    big: bool,
}

impl W {
    fn u16(self, v: u16) -> Vec<u8> {
        if self.big {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        }
        .to_vec()
    }
    fn u32(self, v: u32) -> Vec<u8> {
        if self.big {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        }
        .to_vec()
    }
    fn u64(self, v: u64) -> Vec<u8> {
        if self.big {
            v.to_be_bytes()
        } else {
            v.to_le_bytes()
        }
        .to_vec()
    }
    /// Address-sized word.
    fn word(self, v: u64) -> Vec<u8> {
        if self.is64 {
            self.u64(v)
        } else {
            self.u32(v as u32)
        }
    }
    fn phdr(self, kind: u32, flags: u32, off: u64, vaddr: u64, size: u64, align: u64) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend(self.u32(kind));
        if self.is64 {
            b.extend(self.u32(flags));
            for v in [off, vaddr, vaddr, size, size, align] {
                b.extend(self.u64(v));
            }
        } else {
            for v in [off, vaddr, vaddr, size, size] {
                b.extend(self.u32(v as u32));
            }
            b.extend(self.u32(flags));
            b.extend(self.u32(align as u32));
        }
        b
    }
    #[allow(clippy::too_many_arguments)]
    fn shdr(
        self,
        name: u32,
        kind: u32,
        flags: u64,
        addr: u64,
        off: u64,
        size: u64,
        link: u32,
        info: u32,
        entsize: u64,
    ) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend(self.u32(name));
        b.extend(self.u32(kind));
        b.extend(self.word(flags));
        b.extend(self.word(addr));
        b.extend(self.word(off));
        b.extend(self.word(size));
        b.extend(self.u32(link));
        b.extend(self.u32(info));
        b.extend(self.word(8)); // sh_addralign
        b.extend(self.word(entsize));
        b
    }
    fn sym(self, name: u32, info: u8, shndx: u16, value: u64) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend(self.u32(name));
        if self.is64 {
            b.push(info);
            b.push(0);
            b.extend(self.u16(shndx));
            b.extend(self.u64(value));
            b.extend(self.u64(0));
        } else {
            b.extend(self.u32(value as u32));
            b.extend(self.u32(0));
            b.push(info);
            b.push(0);
            b.extend(self.u16(shndx));
        }
        b
    }
    /// `Elf_Nhdr` + name + desc, each padded to 4 bytes.
    fn note(self, name: &[u8], kind: u32, desc: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend(self.u32(name.len() as u32));
        b.extend(self.u32(desc.len() as u32));
        b.extend(self.u32(kind));
        b.extend_from_slice(name);
        while !b.len().is_multiple_of(4) {
            b.push(0);
        }
        b.extend_from_slice(desc);
        while !b.len().is_multiple_of(4) {
            b.push(0);
        }
        b
    }
}

/// Appends `data` at the next `align` boundary and records it as a section.
#[allow(clippy::too_many_arguments)]
fn push_sec(
    f: &mut Vec<u8>,
    secs: &mut Vec<Sec>,
    name: &str,
    kind: u32,
    flags: u64,
    data: &[u8],
    align: usize,
) -> usize {
    align_to(f, align);
    let off = f.len();
    f.extend_from_slice(data);
    secs.push(Sec {
        name: name.to_owned(),
        kind,
        flags,
        offset: off,
        size: data.len(),
        link: 0,
        info: 0,
        entsize: 0,
    });
    off
}

fn align_to(f: &mut Vec<u8>, a: usize) {
    while !f.len().is_multiple_of(a) {
        f.push(0);
    }
}

/// Benign look-alike ELF profiles (negative tests), plus a synthetic UPX
/// layout. None contains real compiled or packed code.
pub mod profiles {
    use super::{df, et, machine, pf, shf, sht, Class, ElfBuilder, Endian};

    /// Typical glibc dynamic PIE with full hardening.
    pub fn glibc_pie() -> ElfBuilder {
        ElfBuilder::x86_64()
            .elf_type(et::DYN)
            .interp("/lib64/ld-linux-x86-64.so.2")
            .needed("libc.so.6")
            .imports(&[
                "__libc_start_main",
                "__cxa_finalize",
                "__stack_chk_fail",
                "__printf_chk",
                "puts",
                "malloc",
                "free",
                "strlen",
                "memcpy",
                "exit",
            ])
            .dt_flags(df::BIND_NOW)
            .dt_flags_1(df::NOW_1 | df::PIE_1)
            .relro(true)
            .build_id(&[0xAB; 20])
            .rodata(b"usage: tool [options]\0hello, world\0".to_vec())
            .data(vec![0; 32])
    }

    /// Statically linked Go executable: no interpreter, no dynamic section,
    /// no PIE, no RELRO, `.go.buildinfo`, `.gopclntab`, Go symbols.
    pub fn go_static() -> ElfBuilder {
        let mut buildinfo = b"\xff Go buildinf:".to_vec();
        buildinfo.extend_from_slice(&[8, 2]);
        buildinfo.resize(32, 0);
        buildinfo.extend_from_slice(b"\x08go1.22.5");
        ElfBuilder::x86_64()
            .text(vec![0xCC; 1024])
            .rodata(b"runtime: unexpected return pc\0go1.22.5\0".to_vec())
            .section(
                ".go.buildinfo",
                sht::PROGBITS,
                shf::ALLOC | shf::WRITE,
                buildinfo,
            )
            .section(
                ".gopclntab",
                sht::PROGBITS,
                shf::ALLOC,
                vec![0xF1, 0xFF, 0xFF, 0xFF, 0, 0, 1, 8],
            )
            .section(
                ".note.go.buildid",
                sht::NOTE,
                shf::ALLOC,
                b"\x04\0\0\0\x10\0\0\0\x04\0\0\0Go\0\0abcdefghijklmnop".to_vec(),
            )
            .symtab(&[
                "runtime.main",
                "runtime.goexit",
                "main.main",
                "runtime.rt0_go",
            ])
            .data(vec![0; 64])
    }

    /// Rust binary as dynamic PIE: libgcc_s for unwinding, mangled `_ZN...17h...E`
    /// symbols, `/rustc/<hash>` paths in panics.
    pub fn rust_pie() -> ElfBuilder {
        ElfBuilder::x86_64()
            .elf_type(et::DYN)
            .interp("/lib64/ld-linux-x86-64.so.2")
            .needed("libgcc_s.so.1")
            .needed("libc.so.6")
            .imports(&[
                "_Unwind_Resume",
                "__libc_start_main",
                "__cxa_thread_atexit_impl",
                "malloc",
                "free",
                "write",
                "pthread_key_create",
                "dl_iterate_phdr",
                "getauxval",
                "memcpy",
            ])
            .dt_flags(df::BIND_NOW)
            .dt_flags_1(df::NOW_1 | df::PIE_1)
            .relro(true)
            .build_id(&[0xCD; 20])
            .rodata(
                b"/rustc/82e1608dfa6e0b5569232559e3d385fea5a93112/library/core/src/panicking.rs\0\
                  called `Option::unwrap()` on a `None` value\0"
                    .to_vec(),
            )
            .symtab(&[
                "_ZN4core9panicking5panic17h1a2b3c4d5e6f7081E",
                "_ZN3std2rt10lang_start17h0123456789abcdefE",
                "rust_begin_unwind",
                "main",
            ])
            .data(vec![0; 32])
    }

    /// Static BusyBox-like multi-call binary: no symbols, many applet strings
    /// (including shell and networking ones) but no dynamic imports.
    pub fn busybox_static() -> ElfBuilder {
        ElfBuilder::new(Class::Elf32, Endian::Little, machine::ARM)
            .text([0x1E, 0xFF, 0x2F, 0xE1].repeat(256))
            .rodata(
                b"BusyBox v1.36.1 (2024-01-01) multi-call binary.\0/bin/sh\0telnetd\0nc\0\
                  wget\0crontab\0/etc/init.d/rcS\0"
                    .to_vec(),
            )
            .data(vec![0; 64])
    }

    /// Synthetic UPX-style ELF: `l_info` with `UPX!` after the program
    /// headers, the `$Info` banner, one RWX high-entropy load segment, no
    /// section headers, static.
    pub fn upx_elf() -> ElfBuilder {
        let mut l_info = vec![0u8; 4]; // checksum
        l_info.extend_from_slice(b"UPX!");
        l_info.extend_from_slice(&[0x0d, 0x0e, 0x18, 0x16]);
        let mut payload: Vec<u8> = (0..8192u32).map(|i| (i % 256) as u8).collect();
        payload.extend_from_slice(
            b"$Info: This file is packed with the UPX executable packer http://upx.sf.net $\n",
        );
        ElfBuilder::x86_64()
            .after_phdrs(l_info)
            .text(payload)
            .text_flags(pf::R | pf::W | pf::X)
            .section_headers(false)
    }
}

/// One named fixture per ELF feature combination: every profile plus every
/// class / byte order. Shared by property tests and the fuzz seed corpus.
pub fn corpus() -> Vec<(&'static str, Vec<u8>)> {
    let mut v = vec![
        ("glibc_pie", profiles::glibc_pie().build().bytes),
        ("go_static", profiles::go_static().build().bytes),
        ("rust_pie", profiles::rust_pie().build().bytes),
        ("busybox_static", profiles::busybox_static().build().bytes),
        ("upx_elf", profiles::upx_elf().build().bytes),
    ];
    for (name, class, endian, mach) in [
        ("x86_32", Class::Elf32, Endian::Little, machine::X86),
        ("mips_be32", Class::Elf32, Endian::Big, machine::MIPS),
        ("ppc64_be", Class::Elf64, Endian::Big, machine::PPC64),
        ("aarch64", Class::Elf64, Endian::Little, machine::AARCH64),
    ] {
        v.push((
            name,
            ElfBuilder::new(class, endian, mach)
                .interp("/lib/ld.so.1")
                .needed("libc.so.6")
                .rpath("$ORIGIN/lib:/tmp")
                .imports(&["socket", "connect", "dup2", "execve"])
                .rodata(b"/bin/sh\0http://example.invalid/x\0".to_vec())
                .build_id(&[7; 20])
                .text_flags(pf::R | pf::W | pf::X)
                .gnu_stack(None)
                .symtab(&["main"])
                .overlay(vec![0xEE; 64])
                .build()
                .bytes,
        ));
    }
    v
}

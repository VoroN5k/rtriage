//! Synthetic PE32 / PE32+ builder.
//!
//! Layout produced by [`PeBuilder::build`]:
//!
//! ```text
//! 0x00   DOS header ("MZ", e_lfanew = 0x80), zero-filled stub
//! 0x80   "PE\0\0", COFF header, optional header, section table
//! ...    user sections (file-aligned 0x200, section-aligned 0x1000)
//! ...    auto ".rdata" section with imports / TLS / debug, if any requested
//! ...    overlay bytes, if any
//! ```
//!
//! [`BuiltPe::layout`] exposes every important offset so tests can corrupt
//! specific fields to produce malformed variants.

/// File offset of the `PE\0\0` signature (`e_lfanew`).
pub const PE_OFFSET: usize = 0x80;
/// `FileAlignment` used by the builder.
pub const FILE_ALIGN: u32 = 0x200;
/// `SectionAlignment` used by the builder.
pub const SECTION_ALIGN: u32 = 0x1000;

/// Section characteristic flags (subset of `IMAGE_SCN_*`).
pub mod scn {
    /// Contains executable code.
    pub const CNT_CODE: u32 = 0x0000_0020;
    /// Contains initialized data.
    pub const CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
    /// Contains uninitialized data.
    pub const CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
    /// Executable.
    pub const MEM_EXECUTE: u32 = 0x2000_0000;
    /// Readable.
    pub const MEM_READ: u32 = 0x4000_0000;
    /// Writable.
    pub const MEM_WRITE: u32 = 0x8000_0000;
}

/// COFF `Characteristics` flags (subset).
pub mod coff {
    /// Image is executable.
    pub const EXECUTABLE_IMAGE: u16 = 0x0002;
    /// Image is 32-bit.
    pub const MACHINE_32BIT: u16 = 0x0100;
    /// Image is a DLL.
    pub const DLL: u16 = 0x2000;
    /// Supports addresses > 2 GiB.
    pub const LARGE_ADDRESS_AWARE: u16 = 0x0020;
}

/// `Subsystem` values (subset).
pub mod subsystem {
    /// Kernel-mode driver / native.
    pub const NATIVE: u16 = 1;
    /// GUI application.
    pub const WINDOWS_GUI: u16 = 2;
    /// Console application.
    pub const WINDOWS_CUI: u16 = 3;
}

/// Target architecture; decides PE32 vs PE32+.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    /// i386, PE32.
    X86,
    /// AMD64, PE32+.
    X64,
}

impl Arch {
    fn machine(self) -> u16 {
        match self {
            Arch::X86 => 0x014c,
            Arch::X64 => 0x8664,
        }
    }
    fn is64(self) -> bool {
        self == Arch::X64
    }
    fn optional_header_size(self) -> usize {
        if self.is64() {
            240
        } else {
            224
        }
    }
    fn thunk_size(self) -> usize {
        if self.is64() {
            8
        } else {
            4
        }
    }
    fn default_image_base(self) -> u64 {
        if self.is64() {
            0x1_4000_0000
        } else {
            0x40_0000
        }
    }
}

/// A user-defined section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// Name; at most 8 bytes are stored.
    pub name: Vec<u8>,
    /// `IMAGE_SCN_*` flags.
    pub characteristics: u32,
    /// Raw contents.
    pub data: Vec<u8>,
    /// `VirtualSize`; defaults to `max(data.len(), 1)`.
    pub virtual_size: Option<u32>,
    /// `SizeOfRawData`; defaults to `data.len()` rounded up to [`FILE_ALIGN`].
    /// `Some(0)` yields a virtual-only section.
    pub raw_size: Option<u32>,
}

impl Section {
    /// Section with explicit flags.
    pub fn new(name: &str, characteristics: u32, data: Vec<u8>) -> Self {
        Self {
            name: name.as_bytes().to_vec(),
            characteristics,
            data,
            virtual_size: None,
            raw_size: None,
        }
    }
    /// Readable + executable code section.
    pub fn code(name: &str, data: Vec<u8>) -> Self {
        Self::new(name, scn::CNT_CODE | scn::MEM_EXECUTE | scn::MEM_READ, data)
    }
    /// Readable + writable data section.
    pub fn data(name: &str, data: Vec<u8>) -> Self {
        Self::new(
            name,
            scn::CNT_INITIALIZED_DATA | scn::MEM_READ | scn::MEM_WRITE,
            data,
        )
    }
    /// Read-only data section.
    pub fn rdata(name: &str, data: Vec<u8>) -> Self {
        Self::new(name, scn::CNT_INITIALIZED_DATA | scn::MEM_READ, data)
    }
    /// Readable + writable + executable section.
    pub fn rwx(name: &str, data: Vec<u8>) -> Self {
        Self::new(
            name,
            scn::CNT_CODE | scn::MEM_EXECUTE | scn::MEM_READ | scn::MEM_WRITE,
            data,
        )
    }
    /// Overrides `VirtualSize`.
    #[must_use]
    pub fn virtual_size(mut self, size: u32) -> Self {
        self.virtual_size = Some(size);
        self
    }
    /// Overrides `SizeOfRawData` (e.g. `0` for a virtual-only section).
    #[must_use]
    pub fn raw_size(mut self, size: u32) -> Self {
        self.raw_size = Some(size);
        self
    }
}

/// One imported symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportEntry {
    /// Import by name (hint 0).
    Name(String),
    /// Import by ordinal only.
    Ordinal(u16),
}

/// Where `AddressOfEntryPoint` points.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Entry {
    /// Start of the first executable user section (or RVA 0 if none).
    FirstExecutable,
    /// `offset` bytes into user section `index`.
    Section {
        /// User section index.
        index: usize,
        /// Offset inside it.
        offset: u32,
    },
    /// Raw RVA, may point anywhere (including outside all sections).
    Rva(u32),
}

/// How the optional header `CheckSum` is filled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Checksum {
    /// Leave it 0 (typical for user-mode executables).
    Zero,
    /// Compute the correct PE checksum.
    Correct,
    /// Store this exact value.
    Value(u32),
}

/// Builder for a synthetic PE file.
#[derive(Debug, Clone)]
pub struct PeBuilder {
    arch: Arch,
    dll: bool,
    subsystem: u16,
    timestamp: u32,
    checksum: Checksum,
    image_base: u64,
    entry: Entry,
    sections: Vec<Section>,
    imports: Vec<(String, Vec<ImportEntry>)>,
    tls_callbacks: usize,
    pdb_path: Option<Vec<u8>>,
    clr: bool,
    auto_section_name: Vec<u8>,
    overlay: Vec<u8>,
}

impl PeBuilder {
    /// Console EXE with no sections, timestamp `0x5f5e1000`, checksum 0.
    pub fn new(arch: Arch) -> Self {
        Self {
            arch,
            dll: false,
            subsystem: subsystem::WINDOWS_CUI,
            timestamp: 0x5f5e_1000,
            checksum: Checksum::Zero,
            image_base: arch.default_image_base(),
            entry: Entry::FirstExecutable,
            sections: Vec::new(),
            imports: Vec::new(),
            tls_callbacks: 0,
            pdb_path: None,
            clr: false,
            auto_section_name: b".rdata".to_vec(),
            overlay: Vec::new(),
        }
    }

    /// Minimal realistic EXE: `.text` (ret instructions) + `.data`.
    pub fn minimal(arch: Arch) -> Self {
        Self::new(arch)
            .section(Section::code(".text", vec![0xC3; 64]))
            .section(Section::data(".data", vec![0; 32]))
    }

    /// Marks the image as a DLL.
    #[must_use]
    pub fn dll(mut self, dll: bool) -> Self {
        self.dll = dll;
        self
    }
    /// Sets `Subsystem`.
    #[must_use]
    pub fn subsystem(mut self, subsystem: u16) -> Self {
        self.subsystem = subsystem;
        self
    }
    /// Sets COFF `TimeDateStamp`.
    #[must_use]
    pub fn timestamp(mut self, timestamp: u32) -> Self {
        self.timestamp = timestamp;
        self
    }
    /// Sets the checksum policy.
    #[must_use]
    pub fn checksum(mut self, checksum: Checksum) -> Self {
        self.checksum = checksum;
        self
    }
    /// Sets `ImageBase`.
    #[must_use]
    pub fn image_base(mut self, base: u64) -> Self {
        self.image_base = base;
        self
    }
    /// Sets the entry point.
    #[must_use]
    pub fn entry(mut self, entry: Entry) -> Self {
        self.entry = entry;
        self
    }
    /// Appends a user section.
    #[must_use]
    pub fn section(mut self, section: Section) -> Self {
        self.sections.push(section);
        self
    }
    /// Imports `names` from `dll` by name.
    #[must_use]
    pub fn import(self, dll: &str, names: &[&str]) -> Self {
        let entries = names
            .iter()
            .map(|n| ImportEntry::Name((*n).to_owned()))
            .collect();
        self.import_entries(dll, entries)
    }
    /// Imports `ordinals` from `dll` by ordinal only.
    #[must_use]
    pub fn import_ordinals(self, dll: &str, ordinals: &[u16]) -> Self {
        let entries = ordinals.iter().map(|&o| ImportEntry::Ordinal(o)).collect();
        self.import_entries(dll, entries)
    }
    /// Imports arbitrary entries from `dll`.
    #[must_use]
    pub fn import_entries(mut self, dll: &str, entries: Vec<ImportEntry>) -> Self {
        self.imports.push((dll.to_owned(), entries));
        self
    }
    /// Adds `count` TLS callbacks, all pointing at the start of the first
    /// executable user section.
    #[must_use]
    pub fn tls_callbacks(mut self, count: usize) -> Self {
        self.tls_callbacks = count;
        self
    }
    /// Adds a CodeView (RSDS) debug entry with this PDB path.
    #[must_use]
    pub fn pdb_path(mut self, path: &str) -> Self {
        self.pdb_path = Some(path.as_bytes().to_vec());
        self
    }
    /// Adds a minimal CLR (COR20) header, making the image a managed .NET assembly.
    #[must_use]
    pub fn clr_header(mut self) -> Self {
        self.clr = true;
        self
    }
    /// Renames the auto-generated section holding imports/TLS/debug/CLR data
    /// (default `.rdata`).
    #[must_use]
    pub fn auto_section_name(mut self, name: &str) -> Self {
        self.auto_section_name = name.as_bytes().to_vec();
        self
    }
    /// Appends bytes after the last section (overlay).
    #[must_use]
    pub fn overlay(mut self, bytes: Vec<u8>) -> Self {
        self.overlay = bytes;
        self
    }

    /// Assembles the file.
    pub fn build(&self) -> BuiltPe {
        let arch = self.arch;
        let has_auto = !self.imports.is_empty()
            || self.tls_callbacks > 0
            || self.pdb_path.is_some()
            || self.clr;
        let n_sections = self.sections.len() + usize::from(has_auto);

        let coff_offset = PE_OFFSET + 4;
        let optional_offset = coff_offset + 20;
        let section_table_offset = optional_offset + arch.optional_header_size();
        let headers_end = section_table_offset + 40 * n_sections;
        let size_of_headers = align(headers_end as u32, FILE_ALIGN);

        // Place user sections.
        let mut layouts = Vec::with_capacity(n_sections);
        let mut next_rva = SECTION_ALIGN;
        let mut next_raw = size_of_headers;
        for s in &self.sections {
            let vsize = s
                .virtual_size
                .unwrap_or_else(|| (s.data.len() as u32).max(1));
            let raw_size = s
                .raw_size
                .unwrap_or_else(|| align(s.data.len() as u32, FILE_ALIGN));
            let raw_ptr = if raw_size == 0 { 0 } else { next_raw };
            layouts.push(SectionLayout {
                rva: next_rva,
                vsize,
                raw_ptr,
                raw_size,
            });
            next_rva += align(vsize.max(raw_size).max(1), SECTION_ALIGN);
            next_raw += raw_size;
        }

        // Auto section (imports / TLS / debug) goes last.
        let auto = has_auto.then(|| {
            let rva = next_rva;
            let raw_ptr = next_raw;
            let entry_rva = self.first_exec_rva(&layouts);
            let content = self.auto_content(rva, raw_ptr, entry_rva);
            let raw_size = align(content.bytes.len() as u32, FILE_ALIGN);
            let vsize = (content.bytes.len() as u32).max(1);
            layouts.push(SectionLayout {
                rva,
                vsize,
                raw_ptr,
                raw_size,
            });
            next_rva += align(vsize.max(raw_size), SECTION_ALIGN);
            next_raw += raw_size;
            content
        });
        let size_of_image = next_rva;
        let image_end = next_raw as usize;

        let mut f = vec![0u8; image_end];

        // DOS header.
        f[0..2].copy_from_slice(b"MZ");
        put_u32(&mut f, 0x3c, PE_OFFSET as u32);

        // PE signature + COFF header.
        f[PE_OFFSET..PE_OFFSET + 4].copy_from_slice(b"PE\0\0");
        let mut characteristics = coff::EXECUTABLE_IMAGE;
        characteristics |= if arch.is64() {
            coff::LARGE_ADDRESS_AWARE
        } else {
            coff::MACHINE_32BIT
        };
        if self.dll {
            characteristics |= coff::DLL;
        }
        put_u16(&mut f, coff_offset, arch.machine());
        put_u16(&mut f, coff_offset + 2, n_sections as u16);
        put_u32(&mut f, coff_offset + 4, self.timestamp);
        put_u16(&mut f, coff_offset + 16, arch.optional_header_size() as u16);
        put_u16(&mut f, coff_offset + 18, characteristics);

        // Optional header.
        let o = optional_offset;
        let code_size: u32 = self
            .sections
            .iter()
            .zip(&layouts)
            .filter(|(s, _)| s.characteristics & scn::CNT_CODE != 0)
            .map(|(_, l)| l.raw_size)
            .sum();
        let entry_rva = self.entry_rva(&layouts);
        put_u16(&mut f, o, if arch.is64() { 0x20b } else { 0x10b });
        f[o + 2] = 14; // MajorLinkerVersion
        put_u32(&mut f, o + 4, code_size);
        put_u32(&mut f, o + 16, entry_rva);
        put_u32(&mut f, o + 20, self.first_exec_rva(&layouts));
        let (dd_offset, checksum_offset);
        if arch.is64() {
            put_u64(&mut f, o + 24, self.image_base);
            put_u32(&mut f, o + 32, SECTION_ALIGN);
            put_u32(&mut f, o + 36, FILE_ALIGN);
            put_u16(&mut f, o + 40, 6); // MajorOperatingSystemVersion
            put_u16(&mut f, o + 48, 6); // MajorSubsystemVersion
            put_u32(&mut f, o + 56, size_of_image);
            put_u32(&mut f, o + 60, size_of_headers);
            checksum_offset = o + 64;
            put_u16(&mut f, o + 68, self.subsystem);
            put_u16(&mut f, o + 70, 0x8160); // DllCharacteristics: NX, DYNAMIC_BASE, HIGH_ENTROPY_VA, TS_AWARE
            put_u64(&mut f, o + 72, 0x10_0000);
            put_u64(&mut f, o + 80, 0x1000);
            put_u64(&mut f, o + 88, 0x10_0000);
            put_u64(&mut f, o + 96, 0x1000);
            put_u32(&mut f, o + 108, 16);
            dd_offset = o + 112;
        } else {
            put_u32(&mut f, o + 28, self.image_base as u32);
            put_u32(&mut f, o + 32, SECTION_ALIGN);
            put_u32(&mut f, o + 36, FILE_ALIGN);
            put_u16(&mut f, o + 40, 6);
            put_u16(&mut f, o + 48, 6);
            put_u32(&mut f, o + 56, size_of_image);
            put_u32(&mut f, o + 60, size_of_headers);
            checksum_offset = o + 64;
            put_u16(&mut f, o + 68, self.subsystem);
            put_u16(&mut f, o + 70, 0x8140); // NX, DYNAMIC_BASE, TS_AWARE
            put_u32(&mut f, o + 72, 0x10_0000);
            put_u32(&mut f, o + 76, 0x1000);
            put_u32(&mut f, o + 80, 0x10_0000);
            put_u32(&mut f, o + 84, 0x1000);
            put_u32(&mut f, o + 92, 16);
            dd_offset = o + 96;
        }
        if let Some(a) = &auto {
            for &(index, rva, size) in &a.directories {
                put_u32(&mut f, dd_offset + index * 8, rva);
                put_u32(&mut f, dd_offset + index * 8 + 4, size);
            }
        }

        // Section table + contents.
        let auto_section = auto.as_ref().map(|a| Section {
            name: self.auto_section_name.clone(),
            characteristics: scn::CNT_INITIALIZED_DATA | scn::MEM_READ,
            data: a.bytes.clone(),
            virtual_size: None,
            raw_size: None,
        });
        let all_sections = self.sections.iter().chain(auto_section.as_ref());
        for (i, (s, l)) in all_sections.zip(&layouts).enumerate() {
            let h = section_table_offset + 40 * i;
            let name_len = s.name.len().min(8);
            f[h..h + name_len].copy_from_slice(&s.name[..name_len]);
            put_u32(&mut f, h + 8, l.vsize);
            put_u32(&mut f, h + 12, l.rva);
            put_u32(&mut f, h + 16, l.raw_size);
            put_u32(&mut f, h + 20, l.raw_ptr);
            put_u32(&mut f, h + 36, s.characteristics);
            if l.raw_size > 0 {
                let start = l.raw_ptr as usize;
                let n = s.data.len().min(l.raw_size as usize);
                f[start..start + n].copy_from_slice(&s.data[..n]);
            }
        }

        f.extend_from_slice(&self.overlay);

        match self.checksum {
            Checksum::Zero => {}
            Checksum::Value(v) => put_u32(&mut f, checksum_offset, v),
            Checksum::Correct => {
                let sum = pe_checksum(&f, checksum_offset);
                put_u32(&mut f, checksum_offset, sum);
            }
        }

        BuiltPe {
            bytes: f,
            layout: Layout {
                pe_offset: PE_OFFSET,
                coff_offset,
                optional_offset,
                data_directories_offset: dd_offset,
                checksum_offset,
                section_table_offset,
                sections: layouts,
                image_end,
            },
        }
    }

    fn first_exec_rva(&self, layouts: &[SectionLayout]) -> u32 {
        self.sections
            .iter()
            .zip(layouts)
            .find(|(s, _)| s.characteristics & scn::MEM_EXECUTE != 0)
            .map_or(0, |(_, l)| l.rva)
    }

    fn entry_rva(&self, layouts: &[SectionLayout]) -> u32 {
        match self.entry {
            Entry::FirstExecutable => self.first_exec_rva(layouts),
            Entry::Section { index, offset } => layouts[index].rva + offset,
            Entry::Rva(rva) => rva,
        }
    }

    /// Builds the auto section's bytes given its RVA and file offset.
    fn auto_content(&self, base_rva: u32, base_raw: u32, callback_rva: u32) -> AutoContent {
        let arch = self.arch;
        let ts = arch.thunk_size();
        let mut b: Vec<u8> = Vec::new();
        let mut dirs = Vec::new();

        if !self.imports.is_empty() {
            let desc_off = 0usize;
            let desc_size = (self.imports.len() + 1) * 20;
            b.resize(desc_size, 0);
            for (i, (dll, entries)) in self.imports.iter().enumerate() {
                // ILT and IAT, both null-terminated.
                let ilt = b.len();
                b.resize(ilt + (entries.len() + 1) * ts, 0);
                let iat = b.len();
                b.resize(iat + (entries.len() + 1) * ts, 0);
                for (k, e) in entries.iter().enumerate() {
                    let thunk: u64 = match e {
                        ImportEntry::Ordinal(o) => {
                            let flag = if arch.is64() { 1u64 << 63 } else { 1u64 << 31 };
                            flag | u64::from(*o)
                        }
                        ImportEntry::Name(name) => {
                            pad2(&mut b);
                            let hn = b.len();
                            b.extend_from_slice(&[0, 0]); // hint
                            b.extend_from_slice(name.as_bytes());
                            b.push(0);
                            u64::from(base_rva + hn as u32)
                        }
                    };
                    put_thunk(&mut b, ilt + k * ts, thunk, ts);
                    put_thunk(&mut b, iat + k * ts, thunk, ts);
                }
                let name_off = b.len();
                b.extend_from_slice(dll.as_bytes());
                b.push(0);
                let d = desc_off + i * 20;
                put_u32(&mut b, d, base_rva + ilt as u32);
                put_u32(&mut b, d + 12, base_rva + name_off as u32);
                put_u32(&mut b, d + 16, base_rva + iat as u32);
            }
            dirs.push((1, base_rva, desc_size as u32)); // IMPORT
        }

        if self.tls_callbacks > 0 {
            align8(&mut b);
            let va = |rva: u32| self.image_base + u64::from(rva);
            let index_slot = b.len();
            b.extend_from_slice(&[0; 8]);
            let callbacks = b.len();
            for _ in 0..self.tls_callbacks {
                let at = b.len();
                b.resize(at + ts, 0);
                put_thunk(&mut b, at, va(callback_rva), ts);
            }
            b.resize(b.len() + ts, 0); // terminator
            let dir = b.len();
            let dir_size = if arch.is64() { 40 } else { 24 };
            b.resize(dir + dir_size, 0);
            let raw_va = va(base_rva + index_slot as u32);
            let fields = [
                raw_va,                          // StartAddressOfRawData
                raw_va + 4,                      // EndAddressOfRawData
                raw_va,                          // AddressOfIndex
                va(base_rva + callbacks as u32), // AddressOfCallBacks
            ];
            for (k, v) in fields.iter().enumerate() {
                put_thunk(&mut b, dir + k * ts, *v, ts);
            }
            dirs.push((9, base_rva + dir as u32, dir_size as u32)); // TLS
        }

        if let Some(path) = &self.pdb_path {
            align8(&mut b);
            let entry = b.len();
            b.resize(entry + 28, 0);
            let rsds = b.len();
            b.extend_from_slice(b"RSDS");
            b.extend_from_slice(&[0x11; 16]); // GUID
            b.extend_from_slice(&1u32.to_le_bytes()); // Age
            b.extend_from_slice(path);
            b.push(0);
            let size = (b.len() - rsds) as u32;
            put_u32(&mut b, entry + 4, self.timestamp);
            put_u32(&mut b, entry + 12, 2); // IMAGE_DEBUG_TYPE_CODEVIEW
            put_u32(&mut b, entry + 16, size);
            put_u32(&mut b, entry + 20, base_rva + rsds as u32);
            put_u32(&mut b, entry + 24, base_raw + rsds as u32);
            dirs.push((6, base_rva + entry as u32, 28)); // DEBUG
        }

        if self.clr {
            align8(&mut b);
            // Tiny fake metadata root ("BSJB" signature) for the MetaData directory.
            let metadata = b.len();
            b.extend_from_slice(b"BSJB");
            b.extend_from_slice(&[0; 12]);
            let cor20 = b.len();
            b.resize(cor20 + 72, 0);
            put_u32(&mut b, cor20, 72); // cb
            put_u16(&mut b, cor20 + 4, 2); // MajorRuntimeVersion
            put_u16(&mut b, cor20 + 6, 5); // MinorRuntimeVersion
            put_u32(&mut b, cor20 + 8, base_rva + metadata as u32); // MetaData.rva
            put_u32(&mut b, cor20 + 12, 16); // MetaData.size
            put_u32(&mut b, cor20 + 16, 1); // Flags: ILONLY
            put_u32(&mut b, cor20 + 20, 0x0600_0001); // EntryPointToken
            dirs.push((14, base_rva + cor20 as u32, 72)); // CLR runtime header
        }

        AutoContent {
            bytes: b,
            directories: dirs,
        }
    }
}

/// Bytes of the auto section plus `(directory index, rva, size)` entries.
struct AutoContent {
    bytes: Vec<u8>,
    directories: Vec<(usize, u32, u32)>,
}

/// A built PE file plus where everything landed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltPe {
    /// The file contents.
    pub bytes: Vec<u8>,
    /// Offsets of headers and sections.
    pub layout: Layout,
}

/// File offsets inside a [`BuiltPe`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    /// `PE\0\0` signature.
    pub pe_offset: usize,
    /// COFF header (`Machine` field).
    pub coff_offset: usize,
    /// Optional header (`Magic` field).
    pub optional_offset: usize,
    /// First data directory entry.
    pub data_directories_offset: usize,
    /// Optional header `CheckSum` field.
    pub checksum_offset: usize,
    /// First section header.
    pub section_table_offset: usize,
    /// Placement of every section, user sections first, then the auto `.rdata`.
    pub sections: Vec<SectionLayout>,
    /// End of the last section's raw data = start of the overlay.
    pub image_end: usize,
}

impl Layout {
    /// Offset of COFF `NumberOfSections`.
    pub fn number_of_sections_offset(&self) -> usize {
        self.coff_offset + 2
    }
    /// Offset of COFF `TimeDateStamp`.
    pub fn timestamp_offset(&self) -> usize {
        self.coff_offset + 4
    }
    /// Offset of `AddressOfEntryPoint`.
    pub fn entry_offset(&self) -> usize {
        self.optional_offset + 16
    }
    /// Offset of data directory `index` (RVA field; size follows at +4).
    pub fn data_directory_offset(&self, index: usize) -> usize {
        self.data_directories_offset + index * 8
    }
}

/// Where one section landed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionLayout {
    /// `VirtualAddress`.
    pub rva: u32,
    /// `VirtualSize`.
    pub vsize: u32,
    /// `PointerToRawData`.
    pub raw_ptr: u32,
    /// `SizeOfRawData`.
    pub raw_size: u32,
}

/// Standard PE image checksum, skipping the 4-byte `CheckSum` field.
pub fn pe_checksum(data: &[u8], checksum_offset: usize) -> u32 {
    let mut sum: u64 = 0;
    let mut i = 0;
    while i < data.len() {
        if i == checksum_offset {
            i += 4;
            continue;
        }
        let lo = u64::from(data[i]);
        let hi = data.get(i + 1).map_or(0, |&b| u64::from(b));
        sum += lo | (hi << 8);
        sum = (sum & 0xffff) + (sum >> 16);
        i += 2;
    }
    sum = (sum & 0xffff) + (sum >> 16);
    (sum as u32).wrapping_add(data.len() as u32)
}

/// Writes a little-endian `u16` at `off`.
pub fn put_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

/// Writes a little-endian `u32` at `off`.
pub fn put_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// Writes a little-endian `u64` at `off`.
pub fn put_u64(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

fn put_thunk(buf: &mut [u8], off: usize, v: u64, size: usize) {
    if size == 8 {
        put_u64(buf, off, v);
    } else {
        put_u32(buf, off, v as u32);
    }
}

fn align(v: u32, a: u32) -> u32 {
    v.div_ceil(a) * a
}

fn pad2(b: &mut Vec<u8>) {
    if !b.len().is_multiple_of(2) {
        b.push(0);
    }
}

fn align8(b: &mut Vec<u8>) {
    while !b.len().is_multiple_of(8) {
        b.push(0);
    }
}

/// Benign look-alike profiles of common toolchains, used as negative tests:
/// heuristics must not fire on them just because they look unusual.
pub mod profiles {
    use super::{Arch, PeBuilder, Section};

    /// Managed .NET assembly: CLR header, a single import
    /// (`mscoree.dll!_CorExeMain`), `.text` / `.rsrc` / `.reloc`.
    pub fn dotnet_like(arch: Arch) -> PeBuilder {
        // x86 entry stub: jmp dword ptr [IAT] (address irrelevant here).
        let mut text = vec![0xFF, 0x25, 0x00, 0x20, 0x40, 0x00];
        text.extend_from_slice(&[0u8; 250]);
        PeBuilder::new(arch)
            .subsystem(super::subsystem::WINDOWS_GUI)
            .section(Section::code(".text", text))
            .section(Section::rdata(".rsrc", vec![0u8; 128]))
            .section(Section::rdata(".reloc", vec![0u8; 12]))
            .import("mscoree.dll", &["_CorExeMain"])
            .clr_header()
    }

    /// Kernel32 functions imported by the Go runtime on Windows. Includes
    /// thread-context and memory APIs that look like injection/hollowing in
    /// isolation.
    pub const GO_KERNEL32_IMPORTS: &[&str] = &[
        "AddVectoredExceptionHandler",
        "CloseHandle",
        "CreateEventA",
        "CreateFileA",
        "CreateIoCompletionPort",
        "CreateThread",
        "CreateWaitableTimerExW",
        "DuplicateHandle",
        "ExitProcess",
        "FreeEnvironmentStringsW",
        "GetConsoleMode",
        "GetEnvironmentStringsW",
        "GetProcAddress",
        "GetProcessAffinityMask",
        "GetQueuedCompletionStatusEx",
        "GetStdHandle",
        "GetSystemDirectoryA",
        "GetSystemInfo",
        "GetThreadContext",
        "LoadLibraryExW",
        "LoadLibraryW",
        "PostQueuedCompletionStatus",
        "ResumeThread",
        "SetConsoleCtrlHandler",
        "SetErrorMode",
        "SetEvent",
        "SetProcessPriorityBoost",
        "SetThreadContext",
        "SetUnhandledExceptionFilter",
        "SetWaitableTimer",
        "SuspendThread",
        "SwitchToThread",
        "TlsAlloc",
        "VirtualAlloc",
        "VirtualFree",
        "VirtualQuery",
        "WaitForMultipleObjects",
        "WaitForSingleObject",
        "WriteConsoleW",
        "WriteFile",
    ];

    /// Statically linked Go executable: zero timestamp, `.symtab` section,
    /// Go build ID, many runtime imports from kernel32 only.
    pub fn go_like(arch: Arch) -> PeBuilder {
        let mut text =
            b"\xff Go build ID: \"Xb1aB2cD3eF4gH5iJ6kL/abcdefghij/klmnopqrst/uvwxyz0123\"\n \xff"
                .to_vec();
        text.extend_from_slice(&[0xCC; 512]);
        let mut rdata = b"go1.22.5\0runtime.main\0runtime/internal/sys\0".to_vec();
        rdata.extend_from_slice(&[0u8; 256]);
        PeBuilder::new(arch)
            .timestamp(0)
            .section(Section::code(".text", text))
            .section(Section::rdata(".rdata", rdata))
            .section(Section::data(".data", vec![0u8; 256]))
            .section(Section::rdata(".pdata", vec![0u8; 64]))
            .section(Section::rdata(".xdata", vec![0u8; 64]))
            .section(Section::rdata(".symtab", vec![0u8; 4]))
            .import("kernel32.dll", GO_KERNEL32_IMPORTS)
            .auto_section_name(".idata")
    }
}

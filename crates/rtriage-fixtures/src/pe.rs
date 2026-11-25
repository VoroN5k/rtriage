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

/// One Rich header record: `(product id, build number, use count)`.
pub type RichEntry = (u16, u16, u32);

/// One exported function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportSpec {
    /// Export name; `None` = exported by ordinal only.
    pub name: Option<String>,
    /// Forwarder string (`"DLL.Function"`); `None` = code in this image.
    pub forwarder: Option<String>,
}

impl ExportSpec {
    /// Named export pointing at code.
    pub fn named(name: &str) -> Self {
        Self {
            name: Some(name.to_owned()),
            forwarder: None,
        }
    }
    /// Ordinal-only export pointing at code.
    pub fn ordinal_only() -> Self {
        Self {
            name: None,
            forwarder: None,
        }
    }
    /// Named export forwarded to `target` (`"KERNEL32.CreateFileW"`).
    pub fn forward(name: &str, target: &str) -> Self {
        Self {
            name: Some(name.to_owned()),
            forwarder: Some(target.to_owned()),
        }
    }
}

/// Resource type or name: numeric ID or string.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResId {
    /// String name (sorted before IDs, as the loader expects).
    Name(String),
    /// Numeric ID.
    Id(u16),
}

/// One resource leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceSpec {
    /// Type (e.g. `ResId::Id(10)` = `RT_RCDATA`).
    pub type_id: ResId,
    /// Name.
    pub name: ResId,
    /// Language ID.
    pub lang: u16,
    /// Data.
    pub data: Vec<u8>,
}

impl ResourceSpec {
    /// Resource with numeric type and name, language 1033 (en-US).
    pub fn new(type_id: u16, name: u16, data: Vec<u8>) -> Self {
        Self {
            type_id: ResId::Id(type_id),
            name: ResId::Id(name),
            lang: 1033,
            data,
        }
    }
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
    linker_version: u8,
    checksum: Checksum,
    image_base: u64,
    entry: Entry,
    sections: Vec<Section>,
    imports: Vec<(String, Vec<ImportEntry>)>,
    tls_callbacks: usize,
    pdb_path: Option<Vec<u8>>,
    clr: bool,
    auto_section_name: Vec<u8>,
    header_extra: Vec<u8>,
    rich: Option<Vec<RichEntry>>,
    exports: Option<(String, Vec<ExportSpec>)>,
    resources: Vec<ResourceSpec>,
    certificate: Option<Vec<u8>>,
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
            linker_version: 14,
            checksum: Checksum::Zero,
            image_base: arch.default_image_base(),
            entry: Entry::FirstExecutable,
            sections: Vec::new(),
            imports: Vec::new(),
            tls_callbacks: 0,
            pdb_path: None,
            clr: false,
            auto_section_name: b".rdata".to_vec(),
            header_extra: Vec::new(),
            rich: None,
            exports: None,
            resources: Vec::new(),
            certificate: None,
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
    /// Sets `MajorLinkerVersion` (default 14, MSVC 2015 and later).
    #[must_use]
    pub fn linker_version(mut self, major: u8) -> Self {
        self.linker_version = major;
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
    /// Adds a Rich header (at most 5 entries) at offset 0x40 with a correct
    /// checksum. `Layout::rich_offset` points at its `DanS` marker.
    #[must_use]
    pub fn rich_header(mut self, entries: &[RichEntry]) -> Self {
        assert!(
            entries.len() <= 5,
            "fixture Rich header holds at most 5 entries"
        );
        self.rich = Some(entries.to_vec());
        self
    }
    /// Adds an export directory naming the DLL `dll_name`.
    #[must_use]
    pub fn exports(mut self, dll_name: &str, entries: Vec<ExportSpec>) -> Self {
        self.exports = Some((dll_name.to_owned(), entries));
        self
    }
    /// Adds one resource (type / name / language / data).
    #[must_use]
    pub fn resource(mut self, spec: ResourceSpec) -> Self {
        self.resources.push(spec);
        self
    }
    /// Bytes placed in the headers right after the section table (where UPX
    /// stores its `UPX!` block); `SizeOfHeaders` grows to fit.
    #[must_use]
    pub fn header_extra(mut self, bytes: Vec<u8>) -> Self {
        self.header_extra = bytes;
        self
    }
    /// Appends an Authenticode-style certificate table (`WIN_CERTIFICATE`
    /// wrapping `blob`) after the last section and before any overlay, and
    /// points the SECURITY data directory (a *file offset*) at it.
    #[must_use]
    pub fn certificate(mut self, blob: Vec<u8>) -> Self {
        self.certificate = Some(blob);
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
            || self.clr
            || self.exports.is_some()
            || !self.resources.is_empty();
        let n_sections = self.sections.len() + usize::from(has_auto);

        let coff_offset = PE_OFFSET + 4;
        let optional_offset = coff_offset + 20;
        let section_table_offset = optional_offset + arch.optional_header_size();
        let section_table_end = section_table_offset + 40 * n_sections;
        let headers_end = section_table_end + self.header_extra.len();
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
        let rich_offset = self.rich.as_ref().map(|entries| {
            write_rich(&mut f, entries);
            RICH_OFFSET
        });

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
        f[o + 2] = self.linker_version; // MajorLinkerVersion
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

        f[section_table_end..headers_end].copy_from_slice(&self.header_extra);

        let certificate_offset = self.certificate.as_ref().map(|blob| {
            while !f.len().is_multiple_of(8) {
                f.push(0);
            }
            let at = f.len();
            let len = 8 + blob.len();
            f.extend_from_slice(&(len as u32).to_le_bytes()); // dwLength
            f.extend_from_slice(&0x0200u16.to_le_bytes()); // WIN_CERT_REVISION_2_0
            f.extend_from_slice(&0x0002u16.to_le_bytes()); // WIN_CERT_TYPE_PKCS_SIGNED_DATA
            f.extend_from_slice(blob);
            while !f.len().is_multiple_of(8) {
                f.push(0);
            }
            // SECURITY directory holds a file offset, not an RVA.
            put_u32(&mut f, dd_offset + 4 * 8, at as u32);
            let table_len = (f.len() - at) as u32;
            put_u32(&mut f, dd_offset + 4 * 8 + 4, table_len);
            at
        });

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
                certificate_offset,
                rich_offset,
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

        if let Some((dll, entries)) = &self.exports {
            align8(&mut b);
            let dir = b.len();
            b.resize(dir + 40, 0);
            let name_off = b.len();
            b.extend_from_slice(dll.as_bytes());
            b.push(0);
            align8(&mut b);
            let funcs = b.len();
            b.resize(funcs + 4 * entries.len(), 0);
            // Names sorted, as the loader's binary search expects.
            let mut named: Vec<(usize, &str)> = entries
                .iter()
                .enumerate()
                .filter_map(|(i, e)| e.name.as_deref().map(|n| (i, n)))
                .collect();
            named.sort_by(|a, b| a.1.cmp(b.1));
            let names = b.len();
            b.resize(names + 4 * named.len(), 0);
            let ords = b.len();
            b.resize(ords + 2 * named.len(), 0);
            for (j, (i, n)) in named.iter().enumerate() {
                let at = b.len();
                b.extend_from_slice(n.as_bytes());
                b.push(0);
                put_u32(&mut b, names + 4 * j, base_rva + at as u32);
                put_u16(&mut b, ords + 2 * j, *i as u16);
            }
            for (i, e) in entries.iter().enumerate() {
                let rva = match &e.forwarder {
                    Some(target) => {
                        let at = b.len();
                        b.extend_from_slice(target.as_bytes());
                        b.push(0);
                        base_rva + at as u32
                    }
                    None => callback_rva + 16 * i as u32,
                };
                put_u32(&mut b, funcs + 4 * i, rva);
            }
            put_u32(&mut b, dir + 4, self.timestamp);
            put_u32(&mut b, dir + 12, base_rva + name_off as u32);
            put_u32(&mut b, dir + 16, 1); // Base
            put_u32(&mut b, dir + 20, entries.len() as u32);
            put_u32(&mut b, dir + 24, named.len() as u32);
            put_u32(&mut b, dir + 28, base_rva + funcs as u32);
            put_u32(&mut b, dir + 32, base_rva + names as u32);
            put_u32(&mut b, dir + 36, base_rva + ords as u32);
            // Directory size covers everything, so forwarder strings fall inside it.
            dirs.push((0, base_rva + dir as u32, (b.len() - dir) as u32)); // EXPORT
        }

        if !self.resources.is_empty() {
            align8(&mut b);
            let root = b.len();
            write_resources(&mut b, root, base_rva, &self.resources);
            dirs.push((2, base_rva + root as u32, (b.len() - root) as u32)); // RESOURCE
        }

        AutoContent {
            bytes: b,
            directories: dirs,
        }
    }
}

/// type -> name -> [(language, spec index)]; BTreeMap order puts named entries first.
type ResourceTree<'a> =
    std::collections::BTreeMap<&'a ResId, std::collections::BTreeMap<&'a ResId, Vec<(u16, usize)>>>;

/// Writes a three-level resource tree (type / name / language) at `root`.
/// All directory offsets are relative to `root`; data RVAs use `base_rva`.
fn write_resources(b: &mut Vec<u8>, root: usize, base_rva: u32, specs: &[ResourceSpec]) {
    use std::collections::BTreeMap;
    // type -> name -> [(lang, spec index)], BTreeMap order = named first, then IDs.
    let mut tree: ResourceTree<'_> = BTreeMap::new();
    for (i, s) in specs.iter().enumerate() {
        tree.entry(&s.type_id)
            .or_default()
            .entry(&s.name)
            .or_default()
            .push((s.lang, i));
    }
    let mut names_to_write: Vec<(usize, String)> = Vec::new(); // (entry offset, name)
    let mut data_entries: Vec<(usize, usize)> = Vec::new(); // (data entry offset, spec index)

    let dir = |b: &mut Vec<u8>, ids: Vec<&ResId>| -> usize {
        let at = b.len();
        b.resize(at + 16 + 8 * ids.len(), 0);
        let named = ids.iter().filter(|i| matches!(i, ResId::Name(_))).count();
        put_u16(b, at + 12, named as u16);
        put_u16(b, at + 14, (ids.len() - named) as u16);
        at
    };
    let set_id =
        |b: &mut Vec<u8>, entry: usize, id: &ResId, names: &mut Vec<(usize, String)>| match id {
            ResId::Id(n) => put_u32(b, entry, u32::from(*n)),
            ResId::Name(s) => names.push((entry, s.clone())),
        };

    let root_dir = dir(b, tree.keys().copied().collect());
    for (ti, (type_id, names)) in tree.iter().enumerate() {
        let type_entry = root_dir + 16 + 8 * ti;
        set_id(b, type_entry, type_id, &mut names_to_write);
        let type_dir = dir(b, names.keys().copied().collect());
        put_u32(b, type_entry + 4, 0x8000_0000 | (type_dir - root) as u32);
        for (ni, (name, langs)) in names.iter().enumerate() {
            let name_entry = type_dir + 16 + 8 * ni;
            set_id(b, name_entry, name, &mut names_to_write);
            let lang_ids: Vec<ResId> = langs.iter().map(|(l, _)| ResId::Id(*l)).collect();
            let lang_dir = dir(b, lang_ids.iter().collect());
            put_u32(b, name_entry + 4, 0x8000_0000 | (lang_dir - root) as u32);
            for (li, (lang, spec)) in langs.iter().enumerate() {
                let lang_entry = lang_dir + 16 + 8 * li;
                put_u32(b, lang_entry, u32::from(*lang));
                let data_entry = b.len();
                b.resize(data_entry + 16, 0);
                put_u32(b, lang_entry + 4, (data_entry - root) as u32); // leaf: no high bit
                data_entries.push((data_entry, *spec));
            }
        }
    }
    for (entry, name) in names_to_write {
        pad2(b);
        let at = b.len();
        let units: Vec<u16> = name.encode_utf16().collect();
        b.extend_from_slice(&(units.len() as u16).to_le_bytes());
        for u in units {
            b.extend_from_slice(&u.to_le_bytes());
        }
        put_u32(b, entry, 0x8000_0000 | (at - root) as u32);
    }
    for (entry, spec) in data_entries {
        align8(b);
        let at = b.len();
        b.extend_from_slice(&specs[spec].data);
        put_u32(b, entry, base_rva + at as u32);
        put_u32(b, entry + 4, specs[spec].data.len() as u32);
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
    /// End of the last section's raw data (start of the overlay, unless a
    /// certificate table follows).
    pub image_end: usize,
    /// File offset of the certificate table, if one was added.
    pub certificate_offset: Option<usize>,
    /// File offset of the Rich header's `DanS` marker, if one was added.
    pub rich_offset: Option<usize>,
}

/// Offset of the fixture Rich header (right after the 64-byte DOS header).
pub const RICH_OFFSET: usize = 0x40;
/// `"DanS"` as a little-endian dword.
pub const DANS: u32 = 0x536E_6144;
/// `"Rich"` as bytes.
pub const RICH: &[u8; 4] = b"Rich";

/// Rich header checksum: sum of the bytes before `DanS` rotated by their
/// offset (skipping `e_lfanew`), plus each `comp_id` rotated by its count.
pub fn rich_checksum(dos: &[u8], dans_offset: usize, entries: &[RichEntry]) -> u32 {
    let mut sum = dans_offset as u32;
    for (i, &b) in dos[..dans_offset].iter().enumerate() {
        if (0x3c..0x40).contains(&i) {
            continue;
        }
        sum = sum.wrapping_add(u32::from(b).rotate_left(i as u32 & 0x1f));
    }
    for &(product, build, count) in entries {
        let comp_id = (u32::from(product) << 16) | u32::from(build);
        sum = sum.wrapping_add(comp_id.rotate_left(count & 0x1f));
    }
    sum
}

fn write_rich(f: &mut [u8], entries: &[RichEntry]) {
    let key = rich_checksum(f, RICH_OFFSET, entries);
    let mut at = RICH_OFFSET;
    for v in [DANS, 0, 0, 0] {
        put_u32(f, at, v ^ key);
        at += 4;
    }
    for &(product, build, count) in entries {
        put_u32(f, at, ((u32::from(product) << 16) | u32::from(build)) ^ key);
        put_u32(f, at + 4, count ^ key);
        at += 8;
    }
    f[at..at + 4].copy_from_slice(RICH);
    put_u32(f, at + 4, key);
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
    use super::{Arch, Entry, PeBuilder, Section};

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
            .linker_version(3) // Go's internal linker writes 3.0
            .section(Section::code(".text", text))
            .section(Section::rdata(".rdata", rdata))
            .section(Section::data(".data", vec![0u8; 256]))
            .section(Section::rdata(".pdata", vec![0u8; 64]))
            .section(Section::rdata(".xdata", vec![0u8; 64]))
            .section(Section::rdata(".symtab", vec![0u8; 4]))
            .import("kernel32.dll", GO_KERNEL32_IMPORTS)
            .auto_section_name(".idata")
    }

    /// UPX-style packed executable (synthetic): virtual-only `UPX0`, high-entropy
    /// RWX `UPX1` holding the entry point, `UPX!` block in the headers and the
    /// classic minimal import set. Contains no real packed code.
    pub fn upx_like(arch: Arch) -> PeBuilder {
        // Every byte value equally often: entropy 8.0, like compressed data.
        let payload: Vec<u8> = (0..8192u32).map(|i| (i % 256) as u8).collect();
        let mut upx_block = b"3.96\0UPX!".to_vec();
        upx_block.extend_from_slice(&[0x0d, 0x09, 0x08, 0x07]);
        PeBuilder::new(arch)
            .header_extra(upx_block)
            .section(
                Section::rwx("UPX0", Vec::new())
                    .raw_size(0)
                    .virtual_size(0x2_0000),
            )
            .section(Section::rwx("UPX1", payload))
            .section(Section::data(".rsrc", vec![0u8; 64]))
            .entry(Entry::Section {
                index: 1,
                offset: 0x100,
            })
            .import(
                "KERNEL32.DLL",
                &[
                    "LoadLibraryA",
                    "GetProcAddress",
                    "VirtualProtect",
                    "VirtualAlloc",
                    "VirtualFree",
                    "ExitProcess",
                ],
            )
    }
}

/// Fixed import layouts used to cross-check imphash against pefile.
/// The expected hashes live next to the rtriage test that consumes them.
pub mod imphash_vectors {
    use super::{profiles, Arch, ImportEntry, PeBuilder};

    /// `(name, builder)` pairs. Never change existing entries: their
    /// expected hashes were computed with pefile.
    pub fn cases() -> Vec<(&'static str, PeBuilder)> {
        vec![
            (
                "named_x86",
                PeBuilder::minimal(Arch::X86)
                    .import(
                        "KERNEL32.dll",
                        &["LoadLibraryA", "GetProcAddress", "ExitProcess"],
                    )
                    .import("USER32.dll", &["MessageBoxA"]),
            ),
            (
                "ordinals_x64",
                PeBuilder::minimal(Arch::X64)
                    .import_ordinals("WS2_32.dll", &[1, 4, 115, 9999])
                    .import_ordinals("OLEAUT32.dll", &[2, 9])
                    .import_ordinals("custom.ocx", &[7])
                    .import("odd.drv", &["Foo"]),
            ),
            (
                "mixed_case_x64",
                PeBuilder::minimal(Arch::X64)
                    .import_entries(
                        "Kernel32.DLL",
                        vec![
                            ImportEntry::Name("CreateFileW".into()),
                            ImportEntry::Ordinal(42),
                        ],
                    )
                    .import_ordinals("wsock32.dll", &[3]),
            ),
            ("go_like_x64", profiles::go_like(Arch::X64)),
            ("dotnet_like_x86", profiles::dotnet_like(Arch::X86)),
        ]
    }
}

/// One named fixture per PE feature combination. Shared by the property
/// tests and the fuzzing seed corpus so both exercise the same structures.
pub fn corpus() -> Vec<(&'static str, Vec<u8>)> {
    let mut pkcs7 = vec![0x30, 0x82, 0x02, 0x00, 0x06, 0x09];
    pkcs7.extend_from_slice(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02]);
    pkcs7.resize(300, 0x41);
    let inner = PeBuilder::minimal(Arch::X86).build().bytes;
    let mut v = Vec::new();
    for (arch, tag) in [(Arch::X86, "x86"), (Arch::X64, "x64")] {
        let named = |n: &str| -> &'static str { Box::leak(format!("{n}_{tag}").into_boxed_str()) };
        v.push((named("minimal"), PeBuilder::minimal(arch).build().bytes));
        v.push((named("dotnet"), profiles::dotnet_like(arch).build().bytes));
        v.push((named("go"), profiles::go_like(arch).build().bytes));
        v.push((
            named("upx"),
            profiles::upx_like(arch).tls_callbacks(2).build().bytes,
        ));
        v.push((
            named("everything"),
            PeBuilder::minimal(arch)
                .dll(true)
                .rich_header(&[(0x0104, 30_795, 12), (0x0105, 30_795, 3)])
                .import(
                    "KERNEL32.dll",
                    &["LoadLibraryA", "GetProcAddress", "ExitProcess"],
                )
                .import_ordinals("WS2_32.dll", &[4, 115])
                .exports(
                    "x.dll",
                    vec![
                        ExportSpec::named("ReflectiveLoader"),
                        ExportSpec::ordinal_only(),
                        ExportSpec::forward("F", "KERNEL32.CreateFileW"),
                    ],
                )
                .resource(ResourceSpec::new(10, 1, inner.clone()))
                .resource(ResourceSpec {
                    type_id: ResId::Name("CFG".into()),
                    name: ResId::Name("main".into()),
                    lang: 0,
                    data: b"k=v".to_vec(),
                })
                .tls_callbacks(1)
                .pdb_path(r"C:\Users\x\a.pdb")
                .certificate(pkcs7.clone())
                .overlay(inner.clone())
                .build()
                .bytes,
        ));
        v.push((
            named("virtual_rwx"),
            PeBuilder::new(arch)
                .section(
                    Section::rwx(".a", Vec::new())
                        .raw_size(0)
                        .virtual_size(0x10_0000),
                )
                .section(Section::rwx(".b", (0..4096u32).map(|i| i as u8).collect()))
                .build()
                .bytes,
        ));
    }
    v
}

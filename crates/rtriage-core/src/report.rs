//! Report model: what analyzers produce and renderers consume.
//!
//! - **Facts** are neutral extracted data (sections, imports, ...).
//! - **Findings** are judgments, each backed by concrete [`Evidence`].
//!
//! Keeping them separate lets output be re-scored without re-parsing.

use serde::{Deserialize, Serialize};

use crate::error::AnalysisError;

/// Detected container format of the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Format {
    /// Windows Portable Executable (`MZ` + `PE\0\0`).
    Pe,
    /// Executable and Linkable Format (`\x7fELF`).
    Elf,
    /// Anything else. Format-independent analyzers still run.
    Unknown,
}

/// Basic identity of the analysed file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileInfo {
    /// Path as given by the user, lossily converted to UTF-8.
    pub path: String,
    /// Size in bytes.
    pub size: u64,
    /// Detected format.
    pub format: Format,
    /// Cryptographic hashes; `None` until the hashes analyzer has run.
    pub hashes: Option<Hashes>,
}

/// Cryptographic hashes of the whole file, as lowercase hex.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Hashes {
    /// MD5 (32 hex chars). Weak, kept for compatibility with threat-intel feeds.
    pub md5: String,
    /// SHA-1 (40 hex chars). Weak, kept for compatibility with threat-intel feeds.
    pub sha1: String,
    /// SHA-256 (64 hex chars).
    pub sha256: String,
}

/// Neutral data extracted from the file. Analyzers add fields as they land.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Facts {
    /// Entropy profile; `None` until the entropy analyzer has run.
    pub entropy: Option<EntropyFacts>,
    /// Extracted strings; `None` until the strings analyzer has run.
    pub strings: Option<StringsFacts>,
    /// PE-specific facts; `None` for non-PE input.
    pub pe: Option<PeFacts>,
    /// ELF-specific facts; `None` for non-ELF input.
    pub elf: Option<ElfFacts>,
}

/// ELF facts; each part is filled by its own analyzer.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct ElfFacts {
    /// ELF header summary.
    pub headers: Option<ElfHeaderFacts>,
}

/// Summary of the ELF header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ElfHeaderFacts {
    /// 32 or 64.
    pub bits: u8,
    /// `little` or `big`.
    pub endianness: &'static str,
    /// OS/ABI name (`sysv`, `linux`, `freebsd`, ... or `unknown_N`).
    pub os_abi: String,
    /// Raw `EI_OSABI`.
    pub os_abi_raw: u8,
    /// `e_type` name: `rel`, `exec`, `dyn`, `core` or `unknown_N`.
    pub elf_type: String,
    /// What the file is: `executable`, `pie`, `shared_library`,
    /// `relocatable`, `core` or `unknown`. PIE vs. shared library is decided
    /// by the presence of an interpreter (refined with `DF_1_PIE` later).
    pub kind: &'static str,
    /// Machine name (`x86_64`, `aarch64`, `mips`, ... or `unknown_N`).
    pub machine: String,
    /// Raw `e_machine`.
    pub machine_raw: u16,
    /// Entry point; `None` when `e_entry` is 0.
    pub entry_point: Option<ElfEntryPoint>,
    /// `PT_INTERP` path (raw attacker data: sanitize before display).
    pub interpreter: Option<String>,
    /// Number of program headers.
    pub number_of_segments: usize,
    /// Number of usable section headers (0 if absent or ignored).
    pub number_of_sections: usize,
    /// Raw `e_flags`.
    pub flags: u32,
}

/// Where the ELF entry point is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ElfEntryPoint {
    /// `e_entry`.
    pub vaddr: u64,
    /// Index of the `PT_LOAD` segment containing it, if any.
    pub segment: Option<usize>,
}

/// PE facts. Each part is filled by its own analyzer and is `None` if that
/// analyzer did not run or failed.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct PeFacts {
    /// COFF / optional header summary.
    pub headers: Option<PeHeaderFacts>,
    /// Section table with per-section entropy.
    pub sections: Option<Vec<PeSectionFacts>>,
    /// Import table and imphash.
    pub imports: Option<PeImportsFacts>,
    /// Data appended after the image; `None` if there is none.
    pub overlay: Option<PeOverlayFacts>,
    /// TLS callbacks; `None` if the file has no TLS directory.
    pub tls: Option<PeTlsFacts>,
    /// CodeView debug information; `None` if the file has none.
    pub debug: Option<PeDebugFacts>,
    /// Known packers/protectors detected (empty if none).
    pub packers: Option<Vec<PePackerFacts>>,
    /// Rich header; `None` if absent.
    pub rich: Option<PeRichFacts>,
    /// Export table; `None` if the file has none.
    pub exports: Option<PeExportsFacts>,
    /// Resources; `None` if the file has no resource directory.
    pub resources: Option<PeResourcesFacts>,
    /// Authenticode certificate table structure; `None` if unsigned.
    pub signature: Option<PeSignatureFacts>,
}

/// Rich header: build tool records left by the Microsoft linker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeRichFacts {
    /// File offset of the `DanS` marker.
    pub offset: u64,
    /// XOR key stored after `Rich` (it doubles as the checksum).
    pub key: u32,
    /// Checksum recomputed from the DOS header and the records.
    pub computed_checksum: u32,
    /// `key == computed_checksum`; `false` means the header or records were edited.
    pub checksum_valid: bool,
    /// Records in stored order.
    pub entries: Vec<PeRichEntry>,
}

/// One Rich record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PeRichEntry {
    /// Tool/product ID (`@comp.id` high word).
    pub product_id: u16,
    /// Tool build number.
    pub build: u16,
    /// How many objects this tool produced.
    pub count: u32,
}

/// Export table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeExportsFacts {
    /// DLL name stored in the export directory (raw attacker data).
    pub dll_name: Option<String>,
    /// Export directory `TimeDateStamp`.
    pub timestamp: u32,
    /// Ordinal `Base`.
    pub ordinal_base: u32,
    /// Exports in ordinal order (empty slots omitted).
    pub exports: Vec<PeExport>,
    /// `true` if the table was cut at `max_exports`.
    pub limit_reached: bool,
}

/// One exported function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeExport {
    /// Ordinal (`Base` + index).
    pub ordinal: u32,
    /// Name, if exported by name (raw attacker data).
    pub name: Option<String>,
    /// RVA of the code, or of the forwarder string.
    pub rva: u32,
    /// Forwarder target (`DLL.Function`), if forwarded.
    pub forwarder: Option<String>,
}

/// Resource directory contents.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PeResourcesFacts {
    /// Leaves in tree order.
    pub entries: Vec<PeResource>,
    /// `true` if the walk stopped at `max_resources`.
    pub limit_reached: bool,
}

/// One resource leaf.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PeResource {
    /// Type: `RT_ICON`, `RT_RCDATA`, ..., `#<id>` or a custom name.
    pub type_name: String,
    /// Name: `#<id>` or a string.
    pub name: String,
    /// Language ID.
    pub lang: u32,
    /// Data RVA.
    pub rva: u32,
    /// Data size as declared.
    pub size: u32,
    /// Entropy of the data present in the file; `None` under 512 bytes.
    pub entropy: Option<f64>,
    /// Content format from magic bytes (`pe`, `zip`, `png`, ...).
    pub kind: Option<&'static str>,
}

/// Authenticode certificate table structure. The signature is **not**
/// verified (no certificate chain or hash check).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeSignatureFacts {
    /// File offset of the table.
    pub offset: u64,
    /// Declared size.
    pub size: u64,
    /// `signed_unverified` if the structure is sound, else `malformed`.
    pub status: SignatureStatus,
    /// `WIN_CERTIFICATE` entries.
    pub certificates: Vec<PeCertificate>,
    /// Structural problems found (empty when `signed_unverified`).
    pub problems: Vec<String>,
}

/// Outcome of the structural check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureStatus {
    /// Well-formed table holding a PKCS#7 SignedData blob; not verified.
    SignedUnverified,
    /// Present but structurally broken.
    Malformed,
}

/// One `WIN_CERTIFICATE` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeCertificate {
    /// File offset.
    pub offset: u64,
    /// `dwLength`.
    pub length: u32,
    /// `wRevision`.
    pub revision: u16,
    /// `wCertificateType` name: `x509`, `pkcs_signed_data`, `reserved`,
    /// `ts_stack_signed`, or `unknown`.
    pub kind: &'static str,
    /// Blob starts like a DER PKCS#7 SignedData (`1.2.840.113549.1.7.2`).
    pub pkcs7_signed_data: bool,
}

/// A detected packer and which independent indicators were seen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PePackerFacts {
    /// Packer name, e.g. `UPX`.
    pub name: &'static str,
    /// Indicators found, in fixed order: `section_names`,
    /// `header_signature`, `stub_structure`.
    pub indicators: Vec<&'static str>,
}

/// Data after the end of the image (and after the certificate table, which
/// is excluded: it is expected trailing data).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PeOverlayFacts {
    /// File offset where the overlay starts.
    pub offset: u64,
    /// Overlay size in bytes.
    pub size: u64,
    /// Shannon entropy; `None` if smaller than `section_entropy_min_size`.
    pub entropy: Option<f64>,
    /// Format recognised from the first bytes: `pe`, `zip`, `7z`, `rar`,
    /// `cab`, `gzip`, `pdf`, `nsis`; `None` if unknown.
    pub kind: Option<&'static str>,
}

/// TLS directory summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeTlsFacts {
    /// Callbacks in array order.
    pub callbacks: Vec<PeTlsCallback>,
    /// `true` if the array was cut at `max_tls_callbacks`.
    pub limit_reached: bool,
}

/// One TLS callback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeTlsCallback {
    /// Virtual address as stored.
    pub va: u64,
    /// Section containing it, if the address maps into one.
    pub section: Option<SectionRef>,
}

/// CodeView debug record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeDebugFacts {
    /// `RSDS` (PDB 7.0) or `NB10` (PDB 2.0).
    pub codeview: &'static str,
    /// PDB path as stored (raw attacker data: sanitize before display).
    pub pdb_path: String,
    /// PDB GUID (`RSDS` only), `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX`.
    pub pdb_guid: Option<String>,
    /// PDB age.
    pub pdb_age: u32,
}

/// Import table summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeImportsFacts {
    /// Imported libraries in import-directory order.
    pub libraries: Vec<PeImportLibrary>,
    /// Number of imported functions across all libraries.
    pub total_functions: u64,
    /// `true` if parsing stopped at `max_imports` / `max_import_libraries`.
    pub limit_reached: bool,
    /// pefile-compatible import hash (lowercase hex MD5); `None` if there are
    /// no imported functions.
    pub imphash: Option<String>,
}

/// One imported library (DLL) and its functions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeImportLibrary {
    /// DLL name as stored (raw attacker data: sanitize before display).
    pub name: String,
    /// Imported functions in thunk order.
    pub functions: Vec<PeImportedFunction>,
}

/// One imported function: by name, or by ordinal only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeImportedFunction {
    /// Function name; `None` for ordinal-only imports.
    pub name: Option<String>,
    /// Ordinal; `Some` only for ordinal-only imports.
    pub ordinal: Option<u16>,
}

/// One PE section.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PeSectionFacts {
    /// Index in the section table.
    pub index: usize,
    /// Name (raw attacker data: sanitize before display).
    pub name: String,
    /// `VirtualAddress`.
    pub virtual_address: u32,
    /// `VirtualSize`.
    pub virtual_size: u32,
    /// `PointerToRawData`.
    pub raw_offset: u32,
    /// `SizeOfRawData`.
    pub raw_size: u32,
    /// Raw `Characteristics`.
    pub characteristics_raw: u32,
    /// Memory permissions as `rwx` with `-` for unset bits, e.g. `r-x`.
    pub permissions: String,
    /// Names of notable flags: `code`, `initialized_data`,
    /// `uninitialized_data`, `discardable`, `shared`.
    pub flags: Vec<&'static str>,
    /// Shannon entropy of the raw data; `None` if fewer than
    /// `section_entropy_min_size` bytes are available.
    pub entropy: Option<f64>,
    /// `true` if `PointerToRawData + SizeOfRawData` runs past the end of the file.
    pub raw_truncated: bool,
}

/// Kind of PE image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PeKind {
    /// Executable.
    Exe,
    /// Dynamic-link library (`IMAGE_FILE_DLL`).
    Dll,
    /// Subsystem `NATIVE`: kernel driver, or a native-mode image such as `smss.exe`.
    Driver,
}

/// Summary of the PE headers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeHeaderFacts {
    /// Machine name (`i386`, `amd64`, `arm64`, ... or `unknown_0x....`).
    pub machine: String,
    /// Raw COFF `Machine` value.
    pub machine_raw: u16,
    /// 32 (PE32) or 64 (PE32+), from the optional header magic.
    pub bits: u8,
    /// EXE, DLL or driver.
    pub kind: PeKind,
    /// Subsystem name (`windows_gui`, `windows_cui`, `native`, ...).
    pub subsystem: String,
    /// Raw `Subsystem` value.
    pub subsystem_raw: u16,
    /// Names of set COFF `Characteristics` flags, in bit order.
    pub characteristics: Vec<&'static str>,
    /// Names of set `DllCharacteristics` flags, in bit order.
    pub dll_characteristics: Vec<&'static str>,
    /// Entry point; `None` when `AddressOfEntryPoint` is 0 (e.g. resource-only DLLs).
    pub entry_point: Option<PeEntryPoint>,
    /// Preferred load address.
    pub image_base: u64,
    /// `SizeOfImage`.
    pub size_of_image: u32,
    /// COFF `NumberOfSections`.
    pub number_of_sections: u16,
    /// Link timestamp.
    pub timestamp: PeTimestamp,
    /// Stored vs. computed image checksum.
    pub checksum: PeChecksum,
    /// `true` if a CLR (COM descriptor) data directory is present: a managed
    /// .NET assembly. Native-code heuristics (few imports, entry stub) do not
    /// apply to such files.
    pub managed_dotnet: bool,
}

/// Where the entry point is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeEntryPoint {
    /// `AddressOfEntryPoint`.
    pub rva: u32,
    /// Section containing it, if any.
    pub section: Option<SectionRef>,
}

/// Reference to a section by index and name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SectionRef {
    /// Index in the section table.
    pub index: usize,
    /// Section name (raw attacker data: sanitize before display).
    pub name: String,
}

/// COFF `TimeDateStamp`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeTimestamp {
    /// Raw seconds since the Unix epoch.
    pub raw: u32,
    /// ISO 8601 UTC rendering, e.g. `2020-09-13T12:26:40Z`; `None` when `raw` is 0.
    pub utc: Option<String>,
}

/// Optional header `CheckSum`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeChecksum {
    /// Value stored in the header (0 = not set).
    pub stored: u32,
    /// Value computed over the file.
    pub computed: u32,
}

/// Result of string extraction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StringsFacts {
    /// Minimum length used, in characters.
    pub min_len: u64,
    /// Number of strings found, including any beyond `max_strings`.
    pub total: u64,
    /// `true` if `total` exceeded `max_strings` and `items` was capped.
    pub limit_reached: bool,
    /// Which strings `items` contains.
    pub items_included: StringsIncluded,
    /// Extracted strings sorted by offset (at most `max_strings`).
    pub items: Vec<ExtractedString>,
}

impl StringsFacts {
    /// Drops strings without any [`StringKind`] and marks the list as classified-only.
    pub fn retain_classified(&mut self) {
        self.items.retain(|s| !s.kinds.is_empty());
        self.items_included = StringsIncluded::Classified;
    }
}

/// Which extracted strings a [`StringsFacts::items`] list holds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StringsIncluded {
    /// Every extracted string (up to `max_strings`).
    #[default]
    All,
    /// Only strings with at least one [`StringKind`].
    Classified,
}

/// One string found in the file. `value` is raw attacker data: sanitize before display.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExtractedString {
    /// File offset of the first byte.
    pub offset: u64,
    /// Encoding it was found in.
    pub encoding: StringEncoding,
    /// Full length in characters (before truncation).
    pub len: u64,
    /// Decoded value, cut to `max_string_len` characters.
    pub value: String,
    /// `true` if `value` was cut short.
    pub truncated: bool,
    /// What the string looks like (URL, IP, path, ...); sorted, may be empty.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub kinds: Vec<StringKind>,
}

/// Classification of an extracted string. A string can have several kinds
/// (a URL also contains a domain). Pattern-based, so treat as hints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum StringKind {
    /// `http(s)://`, `ftp://`, `ws(s)://` URL.
    Url,
    /// Dotted-quad IPv4 address.
    Ipv4,
    /// IPv6 address.
    Ipv6,
    /// Domain name with a known TLD.
    Domain,
    /// Email address.
    Email,
    /// Windows, UNC, environment-variable or Unix system path.
    FilePath,
    /// Windows registry key.
    RegistryKey,
    /// Long base64-looking blob.
    Base64,
    /// Shell command often abused by malware (e.g. `vssadmin delete shadows`).
    SuspiciousCommand,
    /// Bitcoin / Ethereum / Monero-like address.
    CryptoWallet,
    /// HTTP user-agent string.
    UserAgent,
}

/// Shannon entropy summary of the whole file.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EntropyFacts {
    /// Entropy of the entire file, in bits per byte (0.0вЂ“8.0).
    pub whole_file: f64,
    /// Window size used for region detection, in bytes.
    pub window: u64,
    /// Threshold a window had to reach to count as high-entropy.
    pub high_threshold: f64,
    /// Maximal runs of consecutive high-entropy windows, in file order.
    pub high_regions: Vec<EntropyRegion>,
}

/// A contiguous byte range whose windows all reached the high-entropy threshold.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EntropyRegion {
    /// Start offset in the file.
    pub offset: u64,
    /// Length in bytes (a multiple of the window size).
    pub len: u64,
    /// Entropy of the whole region, in bits per byte.
    pub entropy: f64,
}

/// How serious a finding is if it is meaningful. Ordered `Info < Low < Medium < High`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Context for the analyst; does not raise suspicion on its own.
    Info,
    /// Weak signal.
    Low,
    /// Notable signal.
    Medium,
    /// Strong signal.
    High,
}

/// How likely the finding is to be meaningful rather than a false positive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// Heuristic with known false positives.
    Low,
    /// Usually meaningful.
    Medium,
    /// Strong, specific indicator.
    High,
}

/// Behavioral area a finding belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Category {
    /// Packing, compression, encryption of code.
    Packing,
    /// Obfuscation such as dynamic API resolution.
    Obfuscation,
    /// Anti-debugging / anti-analysis tricks.
    AntiAnalysis,
    /// Code injection into other processes.
    Injection,
    /// Surviving reboots (run keys, services, cron, ...).
    Persistence,
    /// Network communication / C2.
    Network,
    /// Credential theft.
    CredentialAccess,
    /// Input capture, keylogging.
    Collection,
    /// Destructive or ransomware-like behaviour.
    Impact,
    /// Missing exploit mitigations (NX, RELRO, PIE, ...).
    Hardening,
    /// Structural oddities in the file format.
    Anomaly,
    /// Neutral metadata (compiler, build paths, signatures).
    Metadata,
}

/// Text encoding of an extracted string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StringEncoding {
    /// 7-bit printable ASCII.
    Ascii,
    /// UTF-16 little-endian.
    Utf16Le,
}

/// One concrete piece of data that supports a finding.
///
/// String fields hold raw, attacker-controlled data; renderers must sanitize them.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Evidence {
    /// A byte range in the file.
    Range {
        /// Start offset.
        offset: u64,
        /// Length in bytes.
        len: u64,
    },
    /// A section (PE) or section header (ELF).
    Section {
        /// Section index in the header table.
        index: usize,
        /// Section name.
        name: String,
    },
    /// An imported symbol.
    Import {
        /// Providing library (DLL for PE, `DT_NEEDED` is not per-symbol for ELF so may be `None`).
        library: Option<String>,
        /// Symbol name, or `#<ordinal>` for ordinal-only imports.
        symbol: String,
    },
    /// An extracted string.
    String {
        /// File offset of the string.
        offset: u64,
        /// Encoding it was found in.
        encoding: StringEncoding,
        /// Decoded value.
        value: String,
    },
    /// A numeric measurement, e.g. `entropy = 7.93`.
    Metric {
        /// What was measured.
        name: &'static str,
        /// Measured value.
        value: f64,
    },
    /// A named field and its value, e.g. `TimeDateStamp = 0`.
    Field {
        /// Field name.
        name: &'static str,
        /// Field value as text.
        value: String,
    },
}

/// A judgment about the file, always backed by evidence.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Finding {
    /// Stable identifier, e.g. `"PE-SECTION-RWX"`. Documented in `docs/heuristics.md`.
    pub id: &'static str,
    /// Severity if meaningful.
    pub severity: Severity,
    /// Likelihood of being meaningful.
    pub confidence: Confidence,
    /// Behavioral area.
    pub category: Category,
    /// One-line summary.
    pub title: String,
    /// Longer explanation for the analyst.
    pub detail: String,
    /// Concrete data that triggered the finding.
    pub evidence: Vec<Evidence>,
    /// MITRE ATT&CK technique IDs, e.g. `"T1055"`.
    pub attack: Vec<&'static str>,
    /// Set when the finding is explained by a confirmed packer: it stays in
    /// the report for the analyst but contributes no points and consumes no
    /// category cap.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suppressed: Option<Suppression>,
}

/// Why a finding does not count towards the score.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Suppression {
    /// ID of the finding that explains this one (e.g. `PE-PACKER-KNOWN`).
    pub by: &'static str,
    /// Packer whose confirmed presence explains it (e.g. `UPX`).
    pub packer: &'static str,
}

impl Finding {
    /// Starts a finding with medium confidence and no detail, evidence or ATT&CK IDs.
    pub fn new(
        id: &'static str,
        severity: Severity,
        category: Category,
        title: impl Into<String>,
    ) -> Self {
        Self {
            id,
            severity,
            confidence: Confidence::Medium,
            category,
            title: title.into(),
            detail: String::new(),
            evidence: Vec::new(),
            attack: Vec::new(),
            suppressed: None,
        }
    }

    /// Sets the confidence.
    #[must_use]
    pub fn confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self
    }

    /// Sets the detail text.
    #[must_use]
    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }

    /// Appends one piece of evidence.
    #[must_use]
    pub fn evidence(mut self, evidence: Evidence) -> Self {
        self.evidence.push(evidence);
        self
    }

    /// Appends an ATT&CK technique ID.
    #[must_use]
    pub fn attack(mut self, technique: &'static str) -> Self {
        self.attack.push(technique);
        self
    }
}

/// Aggregate risk level. Ordered `CleanLooking < Low < Medium < High`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    /// Nothing notable found. Not a guarantee the file is benign.
    #[default]
    CleanLooking,
    /// Weak signals only.
    Low,
    /// Notable signals.
    Medium,
    /// Strong signals.
    High,
}

/// Aggregate risk: a numeric score for sorting, its level, and exactly how it
/// was computed (see `docs/heuristics.md`, "Scoring v1").
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Risk {
    /// Score used to sort files in batch mode.
    pub score: u32,
    /// Level derived from the score.
    pub level: RiskLevel,
    /// One entry per finding, in scoring order.
    pub breakdown: Vec<ScoreEntry>,
}

/// How one finding contributed to the score.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScoreEntry {
    /// Finding ID.
    pub id: &'static str,
    /// Finding category (the cap it counts against).
    pub category: Category,
    /// Points from the severity × confidence table.
    pub table_points: u32,
    /// Points actually added to the score.
    pub points: u32,
    /// Why `points` is lower than `table_points`, if it is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reduced_by: Option<Reduction>,
}

/// Reason a finding contributed fewer points than its table value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Reduction {
    /// Explained by a confirmed packer (see [`Finding::suppressed`]).
    Suppressed {
        /// Explaining finding ID.
        by: &'static str,
        /// Packer name.
        packer: &'static str,
    },
    /// Another finding with the same ID already counted.
    Duplicate,
    /// The category cap was (partly) used up.
    CategoryCap {
        /// The cap.
        cap: u32,
    },
    /// The global cap on low-severity points was (partly) used up.
    LowSeverityCap {
        /// The cap.
        cap: u32,
    },
}

/// Why static analysis of this file is less complete than usual.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AnalysisLimit {
    /// Code is packed or protected: imports, strings and code-based findings
    /// describe the unpacking stub, not the real program.
    Packed,
}

/// An analyzer that failed, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AnalyzerFailure {
    /// Name of the analyzer.
    pub analyzer: &'static str,
    /// What went wrong.
    pub error: AnalysisError,
}

/// Complete result of triaging one file.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Report {
    /// File identity.
    pub file: FileInfo,
    /// Neutral extracted data.
    pub facts: Facts,
    /// Judgments, sorted most severe first.
    pub findings: Vec<Finding>,
    /// Aggregate risk.
    pub risk: Risk,
    /// Reasons the analysis is limited (empty when it is not).
    pub analysis_limited: Vec<AnalysisLimit>,
    /// Analyzers that failed partially or completely.
    pub errors: Vec<AnalyzerFailure>,
}

/// Collects analyzer output and assembles a deterministic [`Report`].
#[derive(Debug)]
pub struct ReportBuilder {
    file: FileInfo,
    /// Facts, filled in directly by analyzers.
    pub facts: Facts,
    findings: Vec<Finding>,
    errors: Vec<AnalyzerFailure>,
}

impl ReportBuilder {
    /// Starts an empty report for `file`.
    pub fn new(file: FileInfo) -> Self {
        Self {
            file,
            facts: Facts::default(),
            findings: Vec::new(),
            errors: Vec::new(),
        }
    }

    /// Adds a finding.
    pub fn push_finding(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    /// Records a failed analyzer.
    pub fn push_error(&mut self, analyzer: &'static str, error: AnalysisError) {
        self.errors.push(AnalyzerFailure { analyzer, error });
    }

    /// Read-only view of findings collected so far (used by scoring).
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// Records the file hashes.
    pub fn set_hashes(&mut self, hashes: Hashes) {
        self.file.hashes = Some(hashes);
    }

    /// Finishes the report with the given risk.
    ///
    /// Findings are sorted by severity (desc), confidence (desc), then id, so
    /// output is deterministic regardless of analyzer order.
    pub fn finish(mut self, risk: Risk) -> Report {
        self.findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then(b.confidence.cmp(&a.confidence))
                .then(a.id.cmp(b.id))
        });
        self.errors.sort_by(|a, b| a.analyzer.cmp(b.analyzer));
        Report {
            file: self.file,
            facts: self.facts,
            findings: self.findings,
            risk,
            analysis_limited: Vec::new(),
            errors: self.errors,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file() -> FileInfo {
        FileInfo {
            path: "sample.bin".into(),
            size: 0,
            format: Format::Unknown,
            hashes: None,
        }
    }

    #[test]
    fn severity_orders_info_to_high() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
    }

    #[test]
    fn finish_sorts_findings_deterministically() {
        let mut b = ReportBuilder::new(file());
        b.push_finding(Finding::new("B-LOW", Severity::Low, Category::Anomaly, "b"));
        b.push_finding(Finding::new(
            "Z-HIGH",
            Severity::High,
            Category::Packing,
            "z",
        ));
        b.push_finding(Finding::new("A-LOW", Severity::Low, Category::Anomaly, "a"));
        b.push_finding(
            Finding::new("C-HIGH", Severity::High, Category::Packing, "c")
                .confidence(Confidence::Low),
        );

        let ids: Vec<_> = b
            .finish(Risk::default())
            .findings
            .iter()
            .map(|f| f.id)
            .collect();
        assert_eq!(ids, ["Z-HIGH", "C-HIGH", "A-LOW", "B-LOW"]);
    }

    #[test]
    fn finish_keeps_errors() {
        let mut b = ReportBuilder::new(file());
        b.push_error(
            "pe",
            AnalysisError::Malformed {
                what: "PE header",
                reason: "bad magic".into(),
            },
        );
        assert_eq!(b.finish(Risk::default()).errors.len(), 1);
    }

    #[test]
    fn finding_serializes_with_tagged_evidence() {
        let f = Finding::new(
            "PE-SECTION-RWX",
            Severity::High,
            Category::Anomaly,
            "RWX section",
        )
        .evidence(Evidence::Section {
            index: 1,
            name: ".text".into(),
        })
        .attack("T1055");

        let json = serde_json::to_value(&f).unwrap();
        assert_eq!(json["severity"], "high");
        assert_eq!(json["evidence"][0]["type"], "section");
        assert_eq!(json["evidence"][0]["name"], ".text");
        assert_eq!(json["attack"][0], "T1055");
    }
}

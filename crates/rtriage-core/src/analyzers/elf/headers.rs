//! ELF header facts plus entry-point and interpreter findings.
//!
//! Findings (see `docs/heuristics.md`):
//! - `ELF-ENTRY-UNUSUAL`: `e_entry` is not inside an executable `PT_LOAD`.
//! - `ELF-INTERP-UNUSUAL`: `PT_INTERP` names a non-standard loader
//!   (Medium/Medium), or one in a world-writable / relative location
//!   (Medium/High). Nix and Guix store paths are standard.

use super::{ElfImage, PT_INTERP};
use crate::analyzers::{AnalysisContext, Analyzer};
use crate::error::AnalysisError;
use crate::report::{
    Category, Confidence, ElfEntryPoint, ElfFacts, ElfHeaderFacts, Evidence, Finding, Format,
    ReportBuilder, Severity,
};

const ET_REL: u16 = 1;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const ET_CORE: u16 = 4;

/// Directories that hold system loaders.
const LOADER_DIRS: &[&str] = &[
    "/lib/",
    "/lib32/",
    "/lib64/",
    "/libx32/",
    "/usr/lib/",
    "/usr/lib32/",
    "/usr/lib64/",
];
/// File name prefixes of system loaders (glibc, musl, uClibc, PowerPC/s390 ld64).
const LOADER_NAMES: &[&str] = &["ld-linux", "ld64.so.", "ld.so.", "ld-musl-", "ld-uClibc"];
/// Exact loader paths of other systems.
const LOADER_PATHS: &[&str] = &[
    "/system/bin/linker",     // Android
    "/system/bin/linker64",   // Android
    "/libexec/ld-elf.so.1",   // FreeBSD
    "/libexec/ld-elf32.so.1", // FreeBSD (32-bit compat)
    "/usr/libexec/ld.so",     // OpenBSD
    "/usr/libexec/ld.elf_so", // NetBSD
    "/lib/ld.so",             // generic
];
/// Content-addressed package stores whose loaders live at hashed paths.
const STORE_PREFIXES: &[&str] = &["/nix/store/", "/gnu/store/"];
/// World-writable or volatile locations no loader should live in.
const UNSAFE_PREFIXES: &[&str] = &["/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/"];

/// Fills [`ElfHeaderFacts`] and emits entry-point / interpreter findings.
#[derive(Debug, Clone, Copy, Default)]
pub struct ElfHeadersAnalyzer;

impl Analyzer for ElfHeadersAnalyzer {
    fn name(&self) -> &'static str {
        "elf-headers"
    }

    fn applies_to(&self, format: Format) -> bool {
        format == Format::Elf
    }

    fn run(&self, ctx: &AnalysisContext<'_>, out: &mut ReportBuilder) -> Result<(), AnalysisError> {
        let Some(elf) = super::elf_or_skip(ctx) else {
            return Ok(());
        };
        entry_finding(elf, out);
        if let Some(path) = &elf.interp {
            interp_finding(path, out);
        }
        out.facts.elf.get_or_insert_with(ElfFacts::default).headers = Some(header_facts(elf));
        Ok(())
    }
}

fn header_facts(elf: &ElfImage) -> ElfHeaderFacts {
    let has_interp = elf.segments.iter().any(|s| s.kind == PT_INTERP);
    let kind = match elf.elf_type {
        ET_EXEC => "executable",
        ET_DYN if has_interp => "pie",
        ET_DYN => "shared_library",
        ET_REL => "relocatable",
        ET_CORE => "core",
        _ => "unknown",
    };
    ElfHeaderFacts {
        bits: if elf.is64 { 64 } else { 32 },
        endianness: if elf.big_endian { "big" } else { "little" },
        os_abi: os_abi_name(elf.os_abi),
        os_abi_raw: elf.os_abi,
        elf_type: match elf.elf_type {
            ET_REL => "rel".into(),
            ET_EXEC => "exec".into(),
            ET_DYN => "dyn".into(),
            ET_CORE => "core".into(),
            t => format!("unknown_{t}"),
        },
        kind,
        machine: machine_name(elf.machine),
        machine_raw: elf.machine,
        entry_point: (elf.entry != 0).then(|| ElfEntryPoint {
            vaddr: elf.entry,
            segment: elf.load_for_vaddr(elf.entry).map(|s| s.index),
        }),
        interpreter: elf.interp.clone(),
        number_of_segments: elf.segments.len(),
        number_of_sections: elf.sections.len(),
        flags: elf.flags,
    }
}

fn entry_finding(elf: &ElfImage, out: &mut ReportBuilder) {
    // Relocatable objects and cores have no meaningful entry; 0 means "none".
    if !matches!(elf.elf_type, ET_EXEC | ET_DYN) || elf.entry == 0 {
        return;
    }
    let reason = match elf.load_for_vaddr(elf.entry) {
        Some(s) if s.is_exec_load() => return,
        Some(_) => "the entry point is in a loadable segment without execute permission",
        None => "the entry point is outside every loadable segment",
    };
    let mut f = Finding::new(
        "ELF-ENTRY-UNUSUAL",
        Severity::Medium,
        Category::Anomaly,
        "Entry point outside executable code",
    )
    .confidence(Confidence::High)
    .detail(format!(
        "{}. The loader would jump to data or unmapped memory: a corrupted or \
         deliberately crafted file (anti-analysis, or code made executable at run time).",
        capitalize(reason)
    ))
    .evidence(Evidence::Field {
        name: "e_entry",
        value: format!("0x{:x}", elf.entry),
    });
    if let Some(s) = elf.load_for_vaddr(elf.entry) {
        f = f.evidence(Evidence::Field {
            name: "segment",
            value: format!("#{} {}", s.index, perms(s.flags)),
        });
    }
    out.push_finding(f);
}

/// How unusual an interpreter path is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterpClass {
    /// A known system or package-store loader.
    Standard,
    /// Absolute path that is not a known loader.
    Nonstandard,
    /// Relative, `..`, or in a world-writable location.
    Unsafe,
}

/// Classifies a `PT_INTERP` path.
pub fn classify_interp(path: &str) -> InterpClass {
    if !path.starts_with('/')
        || path.split('/').any(|c| c == "..")
        || UNSAFE_PREFIXES.iter().any(|p| path.starts_with(p))
    {
        return InterpClass::Unsafe;
    }
    let file = path.rsplit('/').next().unwrap_or(path);
    let loader_name = LOADER_NAMES.iter().any(|n| file.starts_with(n));
    let in_system_dir = LOADER_DIRS
        .iter()
        .any(|d| path.strip_prefix(d).is_some_and(|rest| !rest.contains('/')));
    let in_store = STORE_PREFIXES.iter().any(|p| path.starts_with(p)) && loader_name;
    if LOADER_PATHS.contains(&path) || (loader_name && in_system_dir) || in_store {
        InterpClass::Standard
    } else {
        InterpClass::Nonstandard
    }
}

fn interp_finding(path: &str, out: &mut ReportBuilder) {
    let (confidence, detail) = match classify_interp(path) {
        InterpClass::Standard => return,
        InterpClass::Nonstandard => (
            Confidence::Medium,
            "The program asks for a dynamic loader that is not a standard system \
             loader. A custom loader runs before any program code and can do anything; \
             unusual toolchains and embedded systems also ship their own.",
        ),
        InterpClass::Unsafe => (
            Confidence::High,
            "The requested dynamic loader is a relative path or lives in a \
             world-writable location (/tmp, /dev/shm, ...): whoever controls that path \
             controls the process before main runs.",
        ),
    };
    out.push_finding(
        Finding::new(
            "ELF-INTERP-UNUSUAL",
            Severity::Medium,
            Category::Anomaly,
            "Unusual program interpreter",
        )
        .confidence(confidence)
        .detail(detail)
        .evidence(Evidence::Field {
            name: "PT_INTERP",
            value: path.to_owned(),
        }),
    );
}

fn perms(flags: u32) -> String {
    [(super::PF_R, 'r'), (super::PF_W, 'w'), (super::PF_X, 'x')]
        .iter()
        .map(|&(bit, c)| if flags & bit != 0 { c } else { '-' })
        .collect()
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    c.next()
        .map(|f| f.to_uppercase().chain(c).collect())
        .unwrap_or_default()
}

/// Machine name for `e_machine`.
pub fn machine_name(m: u16) -> String {
    let name = match m {
        2 => "sparc",
        3 => "i386",
        8 => "mips",
        20 => "ppc",
        21 => "ppc64",
        22 => "s390",
        40 => "arm",
        43 => "sparcv9",
        50 => "ia64",
        62 => "x86_64",
        183 => "aarch64",
        243 => "riscv",
        258 => "loongarch",
        _ => return format!("unknown_{m}"),
    };
    name.to_owned()
}

fn os_abi_name(abi: u8) -> String {
    let name = match abi {
        0 => "sysv",
        1 => "hpux",
        2 => "netbsd",
        3 => "linux",
        6 => "solaris",
        7 => "aix",
        8 => "irix",
        9 => "freebsd",
        12 => "openbsd",
        97 => "arm",
        255 => "standalone",
        _ => return format!("unknown_{abi}"),
    };
    name.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::input::Input;
    use crate::report::Report;
    use crate::Registry;
    use rtriage_fixtures::elf::{et, machine, pf, profiles, Class, ElfBuilder, Endian, EntryPoint};

    fn analyze(bytes: Vec<u8>) -> Report {
        let input = Input::from_bytes("t", bytes);
        assert_eq!(input.format, Format::Elf);
        let r = Registry::default().analyze(&input, &Config::default());
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        r
    }

    fn headers(r: &Report) -> &ElfHeaderFacts {
        r.facts.elf.as_ref().unwrap().headers.as_ref().unwrap()
    }

    fn ids(r: &Report) -> Vec<&'static str> {
        r.findings
            .iter()
            .map(|f| f.id)
            .filter(|id| id.starts_with("ELF-ENTRY") || id.starts_with("ELF-INTERP"))
            .collect()
    }

    #[test]
    fn header_facts_for_profiles() {
        let r = analyze(profiles::glibc_pie().build().bytes);
        let h = headers(&r);
        assert_eq!(
            (h.bits, h.endianness, h.machine.as_str()),
            (64, "little", "x86_64")
        );
        assert_eq!((h.elf_type.as_str(), h.kind), ("dyn", "pie"));
        assert_eq!(
            h.interpreter.as_deref(),
            Some("/lib64/ld-linux-x86-64.so.2")
        );
        assert!(h.entry_point.as_ref().unwrap().segment.is_some());

        let r = analyze(profiles::go_static().build().bytes);
        assert_eq!(headers(&r).kind, "executable");
        assert_eq!(headers(&r).interpreter, None);

        let r = analyze(profiles::busybox_static().build().bytes);
        let h = headers(&r);
        assert_eq!((h.bits, h.machine.as_str()), (32, "arm"));

        let r = analyze(
            ElfBuilder::new(Class::Elf32, Endian::Big, machine::MIPS)
                .build()
                .bytes,
        );
        assert_eq!(headers(&r).endianness, "big");
    }

    #[test]
    fn shared_library_without_interpreter() {
        let r = analyze(ElfBuilder::x86_64().elf_type(et::DYN).build().bytes);
        assert_eq!(headers(&r).kind, "shared_library");
    }

    #[test]
    fn profiles_have_no_header_findings() {
        for b in [
            profiles::glibc_pie(),
            profiles::go_static(),
            profiles::rust_pie(),
            profiles::busybox_static(),
            profiles::upx_elf(),
        ] {
            let r = analyze(b.build().bytes);
            assert!(ids(&r).is_empty(), "{:?}", ids(&r));
        }
    }

    // ---- entry point

    #[test]
    fn entry_outside_all_segments() {
        let r = analyze(
            ElfBuilder::x86_64()
                .entry(EntryPoint::Addr(0xdead_0000))
                .build()
                .bytes,
        );
        assert_eq!(ids(&r), ["ELF-ENTRY-UNUSUAL"]);
        let f = &r
            .findings
            .iter()
            .find(|f| f.id == "ELF-ENTRY-UNUSUAL")
            .unwrap();
        assert_eq!(
            (f.severity, f.confidence),
            (Severity::Medium, Confidence::High)
        );
    }

    #[test]
    fn entry_in_non_executable_segment() {
        // Base of the read-only first PT_LOAD (the ELF header itself).
        let r = analyze(
            ElfBuilder::x86_64()
                .entry(EntryPoint::Addr(0x40_0000))
                .build()
                .bytes,
        );
        assert_eq!(ids(&r), ["ELF-ENTRY-UNUSUAL"]);
    }

    #[test]
    fn zero_entry_and_relocatables_are_not_judged() {
        let lib = ElfBuilder::x86_64()
            .elf_type(et::DYN)
            .entry(EntryPoint::Addr(0))
            .build();
        assert!(ids(&analyze(lib.bytes)).is_empty());
        let obj = ElfBuilder::x86_64()
            .elf_type(et::REL)
            .entry(EntryPoint::Addr(0xdead))
            .build();
        assert!(ids(&analyze(obj.bytes)).is_empty());
    }

    #[test]
    fn rwx_text_entry_is_not_an_entry_finding() {
        let r = analyze(
            ElfBuilder::x86_64()
                .text_flags(pf::R | pf::W | pf::X)
                .build()
                .bytes,
        );
        assert!(ids(&r).is_empty());
    }

    // ---- interpreter

    #[test]
    fn interpreter_classification() {
        use InterpClass::*;
        for (path, want) in [
            ("/lib64/ld-linux-x86-64.so.2", Standard),
            ("/lib/ld-linux-aarch64.so.1", Standard),
            ("/lib/ld-linux-armhf.so.3", Standard),
            ("/lib/ld-linux.so.2", Standard),
            ("/lib/ld-musl-x86_64.so.1", Standard),
            ("/lib/ld.so.1", Standard),
            ("/lib64/ld64.so.2", Standard),
            ("/lib/ld-uClibc.so.0", Standard),
            ("/system/bin/linker64", Standard),
            ("/libexec/ld-elf.so.1", Standard),
            ("/usr/libexec/ld.so", Standard),
            (
                "/nix/store/abc123-glibc-2.39/lib/ld-linux-x86-64.so.2",
                Standard,
            ),
            (
                "/gnu/store/xyz-glibc-2.38/lib/ld-linux-x86-64.so.2",
                Standard,
            ),
            ("/opt/vendor/lib/ld-linux-x86-64.so.2", Nonstandard),
            ("/lib/x86_64-linux-gnu/evil.so", Nonstandard),
            ("/nix/store/abc-evil/bin/loader", Nonstandard),
            ("/tmp/ld-linux-x86-64.so.2", Unsafe),
            ("/dev/shm/l", Unsafe),
            ("ld-linux.so.2", Unsafe),
            ("/lib/../tmp/ld.so", Unsafe),
        ] {
            assert_eq!(classify_interp(path), want, "{path}");
        }
    }

    #[test]
    fn nonstandard_interpreter_is_medium_medium() {
        let r = analyze(
            ElfBuilder::x86_64()
                .interp("/opt/ld/custom-ld.so")
                .needed("libc.so.6")
                .build()
                .bytes,
        );
        let f = r
            .findings
            .iter()
            .find(|f| f.id == "ELF-INTERP-UNUSUAL")
            .unwrap();
        assert_eq!(
            (f.severity, f.confidence),
            (Severity::Medium, Confidence::Medium)
        );
    }

    #[test]
    fn unsafe_interpreter_is_medium_high() {
        for path in ["/tmp/ld.so", "./ld.so"] {
            let r = analyze(
                ElfBuilder::x86_64()
                    .interp(path)
                    .needed("libc.so.6")
                    .build()
                    .bytes,
            );
            let f = r
                .findings
                .iter()
                .find(|f| f.id == "ELF-INTERP-UNUSUAL")
                .unwrap();
            assert_eq!(
                (f.severity, f.confidence),
                (Severity::Medium, Confidence::High),
                "{path}"
            );
        }
    }

    #[test]
    fn nix_store_loader_is_fine() {
        let r = analyze(
            ElfBuilder::x86_64()
                .interp("/nix/store/0c3wds3iw7c8qqy7r8y9q2a3dfjp9a8x-glibc-2.39-52/lib/ld-linux-x86-64.so.2")
                .needed("libc.so.6")
                .build()
                .bytes,
        );
        assert!(ids(&r).is_empty());
    }

    // ---- malformed

    #[test]
    fn broken_phdrs_record_one_error_from_elf_parse() {
        let mut built = ElfBuilder::x86_64().build();
        let at = built.layout.phentsize_offset;
        built.bytes[at..at + 2].copy_from_slice(&40u16.to_le_bytes());
        let r =
            Registry::default().analyze(&Input::from_bytes("t", built.bytes), &Config::default());
        assert_eq!(r.errors.len(), 1);
        assert_eq!(r.errors[0].analyzer, "elf-parse");
        assert!(r.file.hashes.is_some());
        assert!(r.facts.elf.is_none());
    }
}

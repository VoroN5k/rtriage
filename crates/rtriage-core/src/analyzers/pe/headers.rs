//! PE header facts plus timestamp and checksum findings.
//!
//! Findings (see `docs/heuristics.md`):
//! - `PE-TIMESTAMP-ZERO`: `TimeDateStamp` is 0.
//! - `PE-TIMESTAMP-FUTURE`: `TimeDateStamp` more than one day after analysis time.
//! - `PE-CHECKSUM-MISMATCH`: stored checksum wrong (non-zero for normal images;
//!   zero or wrong for drivers, which the kernel requires to be correct).

use std::time::{SystemTime, UNIX_EPOCH};

use super::PeImage;
use crate::analyzers::{AnalysisContext, Analyzer};
use crate::deadline::Deadline;
use crate::error::AnalysisError;
use crate::report::{
    Category, Confidence, Evidence, Finding, Format, PeChecksum, PeEntryPoint, PeFacts,
    PeHeaderFacts, PeKind, PeTimestamp, ReportBuilder, SectionRef, Severity,
};

/// Slack before a timestamp counts as "in the future" (clock skew, time zones).
const FUTURE_SLACK_SECS: u64 = 24 * 60 * 60;
/// Bytes summed between deadline checks while computing the checksum. Even.
const CHECKSUM_CHUNK: usize = 1 << 20;

/// `IMAGE_SUBSYSTEM_NATIVE`.
const SUBSYSTEM_NATIVE: u16 = 1;
/// `IMAGE_FILE_DLL`.
const FILE_DLL: u16 = 0x2000;

/// Fills [`PeHeaderFacts`] and emits timestamp/checksum findings.
#[derive(Debug, Clone, Copy, Default)]
pub struct PeHeadersAnalyzer;

impl Analyzer for PeHeadersAnalyzer {
    fn name(&self) -> &'static str {
        "pe-headers"
    }

    fn applies_to(&self, format: Format) -> bool {
        format == Format::Pe
    }

    fn run(&self, ctx: &AnalysisContext<'_>, out: &mut ReportBuilder) -> Result<(), AnalysisError> {
        let Some(pe) = super::pe_or_skip(ctx) else {
            return Ok(());
        };
        let computed = checksum(&ctx.input.data, pe.checksum_offset, &ctx.deadline)?;
        let facts = header_facts(pe, computed);

        timestamp_findings(pe.timestamp, ctx.now, out);
        checksum_findings(&facts, out);

        out.facts.pe.get_or_insert_with(PeFacts::default).headers = Some(facts);
        Ok(())
    }
}

fn header_facts(pe: &PeImage, computed_checksum: u32) -> PeHeaderFacts {
    let kind = if pe.subsystem == SUBSYSTEM_NATIVE {
        PeKind::Driver
    } else if pe.characteristics & FILE_DLL != 0 {
        PeKind::Dll
    } else {
        PeKind::Exe
    };
    let entry_point = (pe.entry_rva != 0).then(|| PeEntryPoint {
        rva: pe.entry_rva,
        section: pe.section_for_rva(pe.entry_rva).map(|s| SectionRef {
            index: s.index,
            name: s.name.clone(),
        }),
    });
    PeHeaderFacts {
        machine: machine_name(pe.machine),
        machine_raw: pe.machine,
        bits: if pe.is64 { 64 } else { 32 },
        kind,
        subsystem: subsystem_name(pe.subsystem),
        subsystem_raw: pe.subsystem,
        characteristics: flag_names(u32::from(pe.characteristics), COFF_FLAGS),
        dll_characteristics: flag_names(u32::from(pe.dll_characteristics), DLL_FLAGS),
        entry_point,
        image_base: pe.image_base,
        size_of_image: pe.size_of_image,
        number_of_sections: pe.number_of_sections,
        timestamp: PeTimestamp {
            raw: pe.timestamp,
            utc: (pe.timestamp != 0).then(|| unix_to_iso8601(pe.timestamp)),
        },
        checksum: PeChecksum {
            stored: pe.checksum,
            computed: computed_checksum,
        },
        managed_dotnet: pe.is_managed_dotnet(),
    }
}

fn timestamp_findings(timestamp: u32, now: SystemTime, out: &mut ReportBuilder) {
    let field = |value: String| Evidence::Field {
        name: "TimeDateStamp",
        value,
    };
    if timestamp == 0 {
        out.push_finding(
            Finding::new(
                "PE-TIMESTAMP-ZERO",
                Severity::Info,
                Category::Anomaly,
                "Link timestamp is zero",
            )
            .detail(
                "TimeDateStamp was cleared. Common for Go binaries and some \
                 reproducible-build toolchains; also used to hide the build date.",
            )
            .evidence(field("0".into())),
        );
        return;
    }
    let now_secs = now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    if u64::from(timestamp) > now_secs.saturating_add(FUTURE_SLACK_SECS) {
        out.push_finding(
            Finding::new(
                "PE-TIMESTAMP-FUTURE",
                Severity::Low,
                Category::Anomaly,
                "Link timestamp is in the future",
            )
            .confidence(Confidence::Low)
            .detail(
                "TimeDateStamp lies after the analysis time: forged, or a \
                 reproducible build (/Brepro) that stores a hash instead of a time.",
            )
            .evidence(field(format!(
                "0x{timestamp:08x} ({})",
                unix_to_iso8601(timestamp)
            ))),
        );
    }
}

fn checksum_findings(facts: &PeHeaderFacts, out: &mut ReportBuilder) {
    let PeChecksum { stored, computed } = facts.checksum;
    let is_driver = facts.kind == PeKind::Driver;
    let (severity, confidence, detail) = if is_driver && (stored == 0 || stored != computed) {
        (
            Severity::Low,
            Confidence::High,
            "Driver images must carry a correct checksum; a missing or wrong \
             one suggests the file was modified after linking.",
        )
    } else if !is_driver && stored != 0 && stored != computed {
        (
            Severity::Info,
            Confidence::Medium,
            "The stored checksum does not match the file. Windows ignores it \
             for user-mode images, but it shows the file changed after linking \
             (patching, appended data, resigning).",
        )
    } else {
        return;
    };
    out.push_finding(
        Finding::new(
            "PE-CHECKSUM-MISMATCH",
            severity,
            Category::Anomaly,
            "Image checksum does not match",
        )
        .confidence(confidence)
        .detail(detail)
        .evidence(Evidence::Field {
            name: "CheckSum",
            value: format!("0x{stored:08x}"),
        })
        .evidence(Evidence::Field {
            name: "computed",
            value: format!("0x{computed:08x}"),
        }),
    );
}

/// Standard PE image checksum (as `CheckSumMappedFile`): 16-bit one's-complement
/// style sum of the file with the 4-byte `CheckSum` field treated as zero,
/// plus the file length.
///
/// # Errors
/// [`AnalysisError::Timeout`] if `deadline` passes.
pub fn checksum(
    data: &[u8],
    checksum_offset: usize,
    deadline: &Deadline,
) -> Result<u32, AnalysisError> {
    let field = checksum_offset..checksum_offset.saturating_add(4);
    let byte_at = |off: usize, b: u8| {
        if field.contains(&off) {
            0
        } else {
            u64::from(b)
        }
    };
    let mut sum: u64 = 0;
    let mut base = 0usize;
    for chunk in data.chunks(CHECKSUM_CHUNK) {
        deadline.check()?;
        for (k, word) in chunk.chunks(2).enumerate() {
            let off = base + 2 * k;
            let lo = word.first().map_or(0, |&b| byte_at(off, b));
            let hi = word.get(1).map_or(0, |&b| byte_at(off + 1, b));
            sum += lo | (hi << 8);
            sum = (sum & 0xffff) + (sum >> 16);
        }
        base += chunk.len();
    }
    sum = (sum & 0xffff) + (sum >> 16);
    // File length is bounded by max_file_size; wrap like the Windows implementation.
    let len = u32::try_from(data.len()).unwrap_or(u32::MAX);
    Ok((sum as u32 & 0xffff).wrapping_add(len))
}

/// Seconds since the Unix epoch as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn unix_to_iso8601(secs: u32) -> String {
    let secs = i64::from(secs);
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Days since 1970-01-01 to (year, month, day). Howard Hinnant's algorithm;
/// inputs here come from a `u32`, so no overflow is possible in `i64`.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

fn machine_name(machine: u16) -> String {
    let name = match machine {
        0x014c => "i386",
        0x8664 => "amd64",
        0xaa64 => "arm64",
        0x01c0 => "arm",
        0x01c4 => "armnt",
        0x0200 => "ia64",
        0x5064 => "riscv64",
        0x0ebc => "ebc",
        _ => return format!("unknown_0x{machine:04x}"),
    };
    name.to_owned()
}

fn subsystem_name(subsystem: u16) -> String {
    let name = match subsystem {
        0 => "unknown",
        1 => "native",
        2 => "windows_gui",
        3 => "windows_cui",
        5 => "os2_cui",
        7 => "posix_cui",
        8 => "native_windows",
        9 => "windows_ce_gui",
        10 => "efi_application",
        11 => "efi_boot_service_driver",
        12 => "efi_runtime_driver",
        13 => "efi_rom",
        14 => "xbox",
        16 => "windows_boot_application",
        _ => return format!("unknown_{subsystem}"),
    };
    name.to_owned()
}

const COFF_FLAGS: &[(u32, &str)] = &[
    (0x0001, "relocs_stripped"),
    (0x0002, "executable_image"),
    (0x0004, "line_nums_stripped"),
    (0x0008, "local_syms_stripped"),
    (0x0010, "aggressive_ws_trim"),
    (0x0020, "large_address_aware"),
    (0x0080, "bytes_reversed_lo"),
    (0x0100, "machine_32bit"),
    (0x0200, "debug_stripped"),
    (0x0400, "removable_run_from_swap"),
    (0x0800, "net_run_from_swap"),
    (0x1000, "system"),
    (0x2000, "dll"),
    (0x4000, "up_system_only"),
    (0x8000, "bytes_reversed_hi"),
];

const DLL_FLAGS: &[(u32, &str)] = &[
    (0x0020, "high_entropy_va"),
    (0x0040, "dynamic_base"),
    (0x0080, "force_integrity"),
    (0x0100, "nx_compat"),
    (0x0200, "no_isolation"),
    (0x0400, "no_seh"),
    (0x0800, "no_bind"),
    (0x1000, "appcontainer"),
    (0x2000, "wdm_driver"),
    (0x4000, "guard_cf"),
    (0x8000, "terminal_server_aware"),
];

fn flag_names(value: u32, table: &[(u32, &'static str)]) -> Vec<&'static str> {
    table
        .iter()
        .filter(|(bit, _)| value & bit != 0)
        .map(|&(_, name)| name)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::input::Input;
    use crate::report::Report;
    use crate::Registry;
    use rtriage_fixtures::pe::{pe_checksum, profiles, subsystem, Arch, Checksum, PeBuilder};

    fn analyze(bytes: Vec<u8>) -> Report {
        let input = Input::from_bytes("t.exe", bytes);
        assert_eq!(input.format, Format::Pe);
        Registry::default().analyze(&input, &Config::default())
    }

    fn headers(r: &Report) -> &PeHeaderFacts {
        r.facts.pe.as_ref().unwrap().headers.as_ref().unwrap()
    }

    fn ids(r: &Report) -> Vec<&'static str> {
        r.findings.iter().map(|f| f.id).collect()
    }

    // ---- facts

    #[test]
    fn header_facts_for_x64_exe() {
        let built = PeBuilder::minimal(Arch::X64).build();
        let r = analyze(built.bytes.clone());
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        let h = headers(&r);
        assert_eq!(h.machine, "amd64");
        assert_eq!(h.bits, 64);
        assert_eq!(h.kind, PeKind::Exe);
        assert_eq!(h.subsystem, "windows_cui");
        assert_eq!(h.number_of_sections, 2);
        assert_eq!(h.image_base, 0x1_4000_0000);
        assert!(h.dll_characteristics.contains(&"nx_compat"));
        let ep = h.entry_point.as_ref().unwrap();
        assert_eq!(ep.rva, built.layout.sections[0].rva);
        assert_eq!(ep.section.as_ref().unwrap().name, ".text");
        assert_eq!(h.timestamp.utc.as_deref(), Some("2020-09-13T12:26:40Z"));
        assert!(!h.managed_dotnet);
    }

    #[test]
    fn header_facts_for_x86_dll() {
        let r = analyze(PeBuilder::minimal(Arch::X86).dll(true).build().bytes);
        let h = headers(&r);
        assert_eq!(
            (h.machine.as_str(), h.bits, h.kind),
            ("i386", 32, PeKind::Dll)
        );
        assert!(h.characteristics.contains(&"dll"));
    }

    #[test]
    fn entry_point_zero_is_none() {
        let r = analyze(
            PeBuilder::minimal(Arch::X64)
                .dll(true)
                .entry(rtriage_fixtures::pe::Entry::Rva(0))
                .build()
                .bytes,
        );
        assert!(headers(&r).entry_point.is_none());
    }

    #[test]
    fn checksum_matches_independent_implementation() {
        for arch in [Arch::X86, Arch::X64] {
            let built = PeBuilder::minimal(arch)
                .overlay(vec![0xAB; 1001]) // odd length exercises the tail byte
                .checksum(Checksum::Correct)
                .build();
            let ours = checksum(
                &built.bytes,
                built.layout.checksum_offset,
                &Deadline::never(),
            );
            let stored = pe_checksum(&built.bytes, built.layout.checksum_offset);
            assert_eq!(ours.unwrap(), stored);
        }
    }

    #[test]
    fn checksum_respects_deadline() {
        assert!(matches!(
            checksum(&[0; 10], 0, &Deadline::expired()),
            Err(AnalysisError::Timeout { .. })
        ));
    }

    #[test]
    fn iso8601_dates() {
        assert_eq!(unix_to_iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(unix_to_iso8601(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(unix_to_iso8601(1_600_000_000), "2020-09-13T12:26:40Z");
        assert_eq!(unix_to_iso8601(u32::MAX), "2106-02-07T06:28:15Z");
    }

    // ---- timestamp findings

    #[test]
    fn zero_timestamp_is_info() {
        let r = analyze(PeBuilder::minimal(Arch::X64).timestamp(0).build().bytes);
        assert_eq!(ids(&r), ["PE-TIMESTAMP-ZERO"]);
        assert_eq!(r.findings[0].severity, Severity::Info);
        assert!(headers(&r).timestamp.utc.is_none());
    }

    #[test]
    fn future_timestamp_is_flagged() {
        // 2106: far beyond any plausible analysis date.
        let r = analyze(
            PeBuilder::minimal(Arch::X64)
                .timestamp(u32::MAX)
                .build()
                .bytes,
        );
        assert_eq!(ids(&r), ["PE-TIMESTAMP-FUTURE"]);
        let f = &r.findings[0];
        assert_eq!((f.severity, f.confidence), (Severity::Low, Confidence::Low));
    }

    #[test]
    fn past_timestamp_is_clean() {
        let r = analyze(PeBuilder::minimal(Arch::X64).build().bytes);
        assert!(r.findings.is_empty());
    }

    #[test]
    fn old_delphi_timestamp_is_not_flagged() {
        // Borland Delphi's constant 1992-06-19 stamp: plausible-but-old is fine.
        let r = analyze(
            PeBuilder::minimal(Arch::X86)
                .timestamp(0x2A42_5E19)
                .build()
                .bytes,
        );
        assert!(r.findings.is_empty());
    }

    // ---- checksum findings

    #[test]
    fn zero_checksum_on_exe_is_not_a_mismatch() {
        let r = analyze(
            PeBuilder::minimal(Arch::X64)
                .checksum(Checksum::Zero)
                .build()
                .bytes,
        );
        assert!(!ids(&r).contains(&"PE-CHECKSUM-MISMATCH"));
    }

    #[test]
    fn correct_checksum_on_exe_is_clean() {
        let r = analyze(
            PeBuilder::minimal(Arch::X64)
                .checksum(Checksum::Correct)
                .build()
                .bytes,
        );
        assert!(r.findings.is_empty());
    }

    #[test]
    fn wrong_checksum_on_exe_is_info() {
        let r = analyze(
            PeBuilder::minimal(Arch::X64)
                .checksum(Checksum::Value(0x1234))
                .build()
                .bytes,
        );
        assert_eq!(ids(&r), ["PE-CHECKSUM-MISMATCH"]);
        let f = &r.findings[0];
        assert_eq!(
            (f.severity, f.confidence),
            (Severity::Info, Confidence::Medium)
        );
    }

    #[test]
    fn driver_with_zero_checksum_is_flagged() {
        let r = analyze(
            PeBuilder::minimal(Arch::X64)
                .subsystem(subsystem::NATIVE)
                .build()
                .bytes,
        );
        assert_eq!(headers(&r).kind, PeKind::Driver);
        assert_eq!(ids(&r), ["PE-CHECKSUM-MISMATCH"]);
        let f = &r.findings[0];
        assert_eq!(
            (f.severity, f.confidence),
            (Severity::Low, Confidence::High)
        );
    }

    #[test]
    fn driver_with_correct_checksum_is_clean() {
        let r = analyze(
            PeBuilder::minimal(Arch::X64)
                .subsystem(subsystem::NATIVE)
                .checksum(Checksum::Correct)
                .build()
                .bytes,
        );
        assert!(r.findings.is_empty());
    }

    // ---- profiles (negative tests)

    #[test]
    fn dotnet_profile_is_managed_and_clean() {
        for arch in [Arch::X86, Arch::X64] {
            let r = analyze(profiles::dotnet_like(arch).build().bytes);
            assert!(r.errors.is_empty(), "{:?}", r.errors);
            assert!(headers(&r).managed_dotnet);
            assert!(r.findings.is_empty(), "{:?}", ids(&r));
        }
    }

    #[test]
    fn go_profile_only_has_informational_timestamp() {
        for arch in [Arch::X86, Arch::X64] {
            let r = analyze(profiles::go_like(arch).build().bytes);
            assert!(r.errors.is_empty(), "{:?}", r.errors);
            assert!(!headers(&r).managed_dotnet);
            assert_eq!(ids(&r), ["PE-TIMESTAMP-ZERO"]);
            assert!(r.findings.iter().all(|f| f.severity == Severity::Info));
        }
    }

    // ---- malformed input

    #[test]
    fn malformed_pe_records_error_but_other_analyzers_run() {
        let mut built = PeBuilder::minimal(Arch::X64).build();
        rtriage_fixtures::pe::put_u16(
            &mut built.bytes,
            built.layout.number_of_sections_offset(),
            0xFFFF,
        );
        let r = analyze(built.bytes);
        assert_eq!(r.errors.len(), 1);
        // Reported once, by pe-parse; other PE analyzers skip silently.
        assert_eq!(r.errors[0].analyzer, "pe-parse");
        assert!(matches!(
            r.errors[0].error,
            AnalysisError::LimitExceeded {
                limit: "max_sections",
                ..
            }
        ));
        assert!(r.file.hashes.is_some());
        assert!(r.facts.pe.is_none());
    }
}

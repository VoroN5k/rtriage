//! Rich header: XOR-encoded build-tool records the Microsoft linker writes
//! between the DOS stub and the PE header.
//!
//! Layout (all dwords XORed with `key` except `Rich` and `key` itself):
//! `DanS`, 3 zero dwords, `(comp_id, count)` pairs, `"Rich"`, `key`.
//! The key is a checksum over the DOS header and the records; editing either
//! (e.g. forging the toolchain, as in the Olympic Destroyer false flag) breaks
//! it unless the forger recomputes it.
//!
//! Findings: `PE-RICH-CHECKSUM-MISMATCH`, `PE-RICH-ABSENT` (see `docs/heuristics.md`).

use super::read_u32;
use crate::analyzers::{AnalysisContext, Analyzer};
use crate::error::AnalysisError;
use crate::report::{
    Category, Confidence, Evidence, Finding, Format, PeFacts, PeRichEntry, PeRichFacts,
    ReportBuilder, Severity,
};

/// `MajorLinkerVersion` values written by the Microsoft linker (VC 6.0 to
/// VS 2015+); all of them emit a Rich header.
const MSVC_LINKER_VERSIONS: std::ops::RangeInclusive<u8> = 6..=14;

/// `"DanS"` as a little-endian dword.
const DANS: u32 = 0x536E_6144;
/// The DOS header is 64 bytes; the Rich header can only follow it.
const SEARCH_START: usize = 0x40;
/// Never search further than this, whatever `e_lfanew` claims.
const SEARCH_LIMIT: usize = 0x1000;

/// Parses and verifies the Rich header.
#[derive(Debug, Clone, Copy, Default)]
pub struct PeRichAnalyzer;

impl Analyzer for PeRichAnalyzer {
    fn name(&self) -> &'static str {
        "pe-rich"
    }

    fn applies_to(&self, format: Format) -> bool {
        format == Format::Pe
    }

    fn run(&self, ctx: &AnalysisContext<'_>, out: &mut ReportBuilder) -> Result<(), AnalysisError> {
        let Some(pe) = super::pe_or_skip(ctx) else {
            return Ok(());
        };
        match parse(&ctx.input.data, pe.pe_offset)? {
            Some(rich) => {
                if !rich.checksum_valid {
                    out.push_finding(
                        Finding::new(
                            "PE-RICH-CHECKSUM-MISMATCH",
                            Severity::Low,
                            Category::Anomaly,
                            "Rich header was edited",
                        )
                        .detail(
                            "The Rich header's checksum does not match its build-tool \
                             records: they were altered after linking. Used to forge a \
                             toolchain fingerprint (false flags) or left by sloppy patching.",
                        )
                        .evidence(Evidence::Field {
                            name: "stored key",
                            value: format!("0x{:08x}", rich.key),
                        })
                        .evidence(Evidence::Field {
                            name: "computed",
                            value: format!("0x{:08x}", rich.computed_checksum),
                        }),
                    );
                }
                out.facts.pe.get_or_insert_with(PeFacts::default).rich = Some(rich);
            }
            None if MSVC_LINKER_VERSIONS.contains(&pe.major_linker_version)
                && !pe.is_managed_dotnet() =>
            {
                out.push_finding(
                    Finding::new(
                        "PE-RICH-ABSENT",
                        Severity::Info,
                        Category::Metadata,
                        "No Rich header despite an MSVC-style linker version",
                    )
                    .confidence(Confidence::Low)
                    .detail(
                        "Microsoft's linker writes a Rich header; this file claims an MSVC \
                         linker version but has none, so it was stripped or built by another \
                         linker (lld-link writes version 14 without one).",
                    )
                    .evidence(Evidence::Field {
                        name: "MajorLinkerVersion",
                        value: pe.major_linker_version.to_string(),
                    }),
                );
            }
            None => {}
        }
        Ok(())
    }
}

/// Finds and decodes the Rich header in `data[0x40..pe_offset]`.
/// `Ok(None)` if there is none.
///
/// # Errors
/// [`AnalysisError::Malformed`] if a `Rich` marker exists but the record
/// block is inconsistent (no `DanS`, odd length).
pub fn parse(data: &[u8], pe_offset: usize) -> Result<Option<PeRichFacts>, AnalysisError> {
    let end = pe_offset.min(SEARCH_LIMIT).min(data.len());
    let Some(rich_at) = (SEARCH_START..end.saturating_sub(7))
        .step_by(4)
        .find(|&i| data.get(i..i + 4) == Some(b"Rich"))
    else {
        return Ok(None);
    };
    let key = read_u32(data, rich_at + 4, "Rich header")?;
    let dans_at = (SEARCH_START..rich_at)
        .step_by(4)
        .rev()
        .find(|&i| read_u32(data, i, "Rich header").is_ok_and(|v| v ^ key == DANS))
        .ok_or_else(|| malformed("Rich marker without a DanS start marker"))?;

    let records_start = dans_at + 16; // DanS + 3 padding dwords
    if records_start > rich_at || (rich_at - records_start) % 8 != 0 {
        return Err(malformed("record block is not a whole number of records"));
    }
    let mut entries = Vec::with_capacity((rich_at - records_start) / 8);
    let mut at = records_start;
    while at < rich_at {
        let comp_id = read_u32(data, at, "Rich header")? ^ key;
        let count = read_u32(data, at + 4, "Rich header")? ^ key;
        entries.push(PeRichEntry {
            product_id: (comp_id >> 16) as u16,
            build: (comp_id & 0xffff) as u16,
            count,
        });
        at += 8;
    }
    let computed = checksum(data.get(..dans_at).unwrap_or_default(), &entries);
    Ok(Some(PeRichFacts {
        offset: dans_at as u64,
        key,
        computed_checksum: computed,
        checksum_valid: computed == key,
        entries,
    }))
}

/// Rich checksum: `dans_offset` + every byte before `DanS` rotated left by
/// its offset (skipping `e_lfanew` at 0x3c..0x40) + every `comp_id` rotated
/// left by its count.
pub fn checksum(before_dans: &[u8], entries: &[PeRichEntry]) -> u32 {
    let mut sum = u32::try_from(before_dans.len()).unwrap_or(u32::MAX);
    for (i, &b) in before_dans.iter().enumerate() {
        if (0x3c..0x40).contains(&i) {
            continue;
        }
        sum = sum.wrapping_add(u32::from(b).rotate_left((i & 0x1f) as u32));
    }
    for e in entries {
        let comp_id = (u32::from(e.product_id) << 16) | u32::from(e.build);
        sum = sum.wrapping_add(comp_id.rotate_left(e.count & 0x1f));
    }
    sum
}

fn malformed(reason: &str) -> AnalysisError {
    AnalysisError::Malformed {
        what: "Rich header",
        reason: reason.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::input::Input;
    use crate::report::Report;
    use crate::Registry;
    use rtriage_fixtures::pe::{put_u32, Arch, PeBuilder, PE_OFFSET, RICH_OFFSET};

    const ENTRIES: [(u16, u16, u32); 3] = [
        (0x0104, 30_795, 12),
        (0x0105, 30_795, 3),
        (0x0093, 30_729, 1),
    ];

    fn analyze(bytes: Vec<u8>) -> Report {
        let r = Registry::default().analyze(&Input::from_bytes("t.exe", bytes), &Config::default());
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        r
    }

    fn rich(r: &Report) -> Option<&PeRichFacts> {
        r.facts.pe.as_ref().unwrap().rich.as_ref()
    }

    #[test]
    fn valid_rich_header() {
        let r = analyze(
            PeBuilder::minimal(Arch::X64)
                .rich_header(&ENTRIES)
                .build()
                .bytes,
        );
        let rich = rich(&r).unwrap();
        assert_eq!(rich.offset, RICH_OFFSET as u64);
        assert!(rich.checksum_valid);
        let got: Vec<_> = rich
            .entries
            .iter()
            .map(|e| (e.product_id, e.build, e.count))
            .collect();
        assert_eq!(got, ENTRIES);
    }

    #[test]
    fn checksum_matches_fixture_implementation() {
        let built = PeBuilder::minimal(Arch::X86).rich_header(&ENTRIES).build();
        let entries: Vec<_> = ENTRIES
            .iter()
            .map(|&(product_id, build, count)| PeRichEntry {
                product_id,
                build,
                count,
            })
            .collect();
        assert_eq!(
            checksum(&built.bytes[..RICH_OFFSET], &entries),
            rtriage_fixtures::pe::rich_checksum(&built.bytes, RICH_OFFSET, &ENTRIES)
        );
    }

    #[test]
    fn edited_record_breaks_checksum() {
        let mut built = PeBuilder::minimal(Arch::X64).rich_header(&ENTRIES).build();
        let key = u32::from_le_bytes(
            built.bytes[RICH_OFFSET + 4..RICH_OFFSET + 8]
                .try_into()
                .unwrap(),
        );
        // Rewrite the first record's count to 99 (forging the toolchain).
        put_u32(&mut built.bytes, RICH_OFFSET + 16 + 4, 99 ^ key);
        let r = analyze(built.bytes);
        let rich = rich(&r).unwrap();
        assert!(!rich.checksum_valid);
        assert_eq!(rich.entries[0].count, 99);
    }

    #[test]
    fn no_rich_header() {
        let r = analyze(PeBuilder::minimal(Arch::X64).build().bytes);
        assert!(rich(&r).is_none());
    }

    fn ids(r: &Report) -> Vec<&'static str> {
        r.findings
            .iter()
            .map(|f| f.id)
            .filter(|id| id.starts_with("PE-RICH"))
            .collect()
    }

    #[test]
    fn valid_rich_has_no_finding() {
        let r = analyze(
            PeBuilder::minimal(Arch::X64)
                .rich_header(&ENTRIES)
                .build()
                .bytes,
        );
        assert!(ids(&r).is_empty());
    }

    #[test]
    fn edited_rich_is_flagged() {
        let mut built = PeBuilder::minimal(Arch::X64).rich_header(&ENTRIES).build();
        let key = u32::from_le_bytes(
            built.bytes[RICH_OFFSET + 4..RICH_OFFSET + 8]
                .try_into()
                .unwrap(),
        );
        put_u32(&mut built.bytes, RICH_OFFSET + 16, 0x00FF_0001 ^ key);
        let r = analyze(built.bytes);
        assert_eq!(ids(&r), ["PE-RICH-CHECKSUM-MISMATCH"]);
        let f = r
            .findings
            .iter()
            .find(|f| f.id == "PE-RICH-CHECKSUM-MISMATCH")
            .unwrap();
        assert_eq!(
            (f.severity, f.confidence),
            (Severity::Low, Confidence::Medium)
        );
    }

    #[test]
    fn msvc_linker_without_rich_is_info() {
        let r = analyze(PeBuilder::minimal(Arch::X64).build().bytes);
        assert_eq!(ids(&r), ["PE-RICH-ABSENT"]);
        assert_eq!(
            r.findings
                .iter()
                .find(|f| f.id == "PE-RICH-ABSENT")
                .unwrap()
                .severity,
            Severity::Info
        );
    }

    #[test]
    fn other_linkers_and_dotnet_without_rich_are_fine() {
        use rtriage_fixtures::pe::profiles;
        for bytes in [
            profiles::go_like(Arch::X64).build().bytes, // linker 3
            PeBuilder::minimal(Arch::X86)
                .linker_version(2)
                .build()
                .bytes, // MinGW-style
            profiles::dotnet_like(Arch::X86).build().bytes, // managed
        ] {
            assert!(ids(&analyze(bytes)).is_empty());
        }
    }

    #[test]
    fn rich_without_dans_is_malformed_not_panic() {
        let mut data = vec![0u8; PE_OFFSET];
        data[0x50..0x54].copy_from_slice(b"Rich");
        assert!(parse(&data, PE_OFFSET).is_err());
    }

    #[test]
    fn huge_e_lfanew_bounds_the_search() {
        assert_eq!(parse(&[0u8; 64], usize::MAX).unwrap(), None);
    }
}

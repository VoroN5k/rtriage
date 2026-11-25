//! ELF notes from `PT_NOTE` segments: GNU build-id, GNU ABI tag, Go build ID.
//!
//! Bounded: at most `max_notes` notes, one budget step each, every size
//! checked against the segment. Facts only.

use super::{ElfImage, Reader};
use crate::analyzers::{AnalysisContext, Analyzer};
use crate::deadline::Deadline;
use crate::error::AnalysisError;
use crate::limits::Limits;
use crate::report::{ElfFacts, ElfNotes, Format, ReportBuilder};

/// `PT_NOTE`.
const PT_NOTE: u32 = 4;
/// `NT_GNU_ABI_TAG`.
const NT_GNU_ABI_TAG: u32 = 1;
/// `NT_GNU_BUILD_ID`.
const NT_GNU_BUILD_ID: u32 = 3;
/// Go's build ID note type (owner `Go`).
const NT_GO_BUILD_ID: u32 = 4;
/// Longest note descriptor kept.
const MAX_DESC: usize = 1024;

/// Reads notes.
#[derive(Debug, Clone, Copy, Default)]
pub struct ElfNotesAnalyzer;

impl Analyzer for ElfNotesAnalyzer {
    fn name(&self) -> &'static str {
        "elf-notes"
    }

    fn applies_to(&self, format: Format) -> bool {
        format == Format::Elf
    }

    fn run(&self, ctx: &AnalysisContext<'_>, out: &mut ReportBuilder) -> Result<(), AnalysisError> {
        let Some(elf) = super::elf_or_skip(ctx) else {
            return Ok(());
        };
        let notes = parse(elf, &ctx.input.data, &ctx.config.limits, &ctx.deadline)?;
        if notes.count > 0 {
            out.facts.elf.get_or_insert_with(ElfFacts::default).notes = Some(notes);
        }
        Ok(())
    }
}

/// Parses every `PT_NOTE` segment.
///
/// # Errors
/// Budget exhaustion or deadline.
pub fn parse(
    elf: &ElfImage,
    data: &[u8],
    limits: &Limits,
    deadline: &Deadline,
) -> Result<ElfNotes, AnalysisError> {
    let r = Reader {
        data,
        is64: elf.is64,
        big: elf.big_endian,
    };
    let mut budget = deadline.budget(limits.max_parser_steps);
    let mut out = ElfNotes::default();
    for seg in elf.segments.iter().filter(|s| s.kind == PT_NOTE) {
        let (Ok(start), Ok(size)) = (usize::try_from(seg.offset), usize::try_from(seg.filesz))
        else {
            continue;
        };
        let end = start.saturating_add(size).min(data.len());
        let align = if seg.align == 8 { 8 } else { 4 };
        let mut at = start;
        while at.saturating_add(12) <= end {
            budget.step()?;
            if out.count >= limits.max_notes {
                out.limit_reached = true;
                return Ok(out);
            }
            let (Ok(namesz), Ok(descsz), Ok(kind)) = (
                r.u32(at, "ELF note"),
                r.u32(at.saturating_add(4), "ELF note"),
                r.u32(at.saturating_add(8), "ELF note"),
            ) else {
                break;
            };
            let name_at = at.saturating_add(12);
            let desc_at = name_at.saturating_add(pad(namesz as usize, align));
            let next = desc_at.saturating_add(pad(descsz as usize, align));
            if next > end || next <= at {
                break; // sizes run past the segment: stop, keep what was read
            }
            out.count += 1;
            let name = data
                .get(name_at..name_at.saturating_add(namesz as usize))
                .unwrap_or_default();
            let desc = data
                .get(desc_at..desc_at.saturating_add((descsz as usize).min(MAX_DESC)))
                .unwrap_or_default();
            match (name, kind) {
                (b"GNU\0", NT_GNU_BUILD_ID) => {
                    out.build_id = Some(desc.iter().map(|b| format!("{b:02x}")).collect());
                }
                (b"GNU\0", NT_GNU_ABI_TAG) if desc.len() >= 16 => {
                    let w = |i: usize| r.u32(desc_at.saturating_add(4 * i), "ABI tag").unwrap_or(0);
                    let os = match w(0) {
                        0 => "linux",
                        1 => "gnu",
                        2 => "solaris",
                        3 => "freebsd",
                        _ => "unknown",
                    };
                    out.abi_tag = Some(format!("{os} {}.{}.{}", w(1), w(2), w(3)));
                }
                (b"Go\0\0" | b"Go\0", NT_GO_BUILD_ID) => {
                    let end = desc.iter().position(|&b| b == 0).unwrap_or(desc.len());
                    out.go_build_id = Some(
                        String::from_utf8_lossy(desc.get(..end).unwrap_or_default()).into_owned(),
                    );
                }
                _ => {}
            }
            at = next;
        }
    }
    Ok(out)
}

fn pad(n: usize, align: usize) -> usize {
    n.div_ceil(align).saturating_mul(align)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtriage_fixtures::elf::{machine, profiles, Class, ElfBuilder, Endian};

    fn notes(bytes: &[u8]) -> ElfNotes {
        let elf = super::super::parse(bytes, &Limits::default()).unwrap();
        parse(&elf, bytes, &Limits::default(), &Deadline::never()).unwrap()
    }

    #[test]
    fn build_id_little_and_big_endian() {
        let n = notes(&profiles::glibc_pie().build().bytes);
        assert_eq!(n.build_id.as_deref(), Some("ab".repeat(20).as_str()));
        let be = ElfBuilder::new(Class::Elf32, Endian::Big, machine::MIPS)
            .build_id(&[0x12, 0x34])
            .build()
            .bytes;
        assert_eq!(notes(&be).build_id.as_deref(), Some("1234"));
    }

    #[test]
    fn no_notes() {
        let n = notes(&ElfBuilder::x86_64().build().bytes);
        assert_eq!(n.count, 0);
    }

    /// glibc fixture whose `PT_NOTE` is pointed at `count` empty notes in the overlay.
    fn many_notes(count: usize) -> (Vec<u8>, ElfImage) {
        let mut blob = Vec::new();
        for _ in 0..count {
            blob.extend_from_slice(&[0u8; 12]); // namesz 0, descsz 0, type 0
        }
        let bytes = profiles::glibc_pie().overlay(blob.clone()).build().bytes;
        let mut elf = super::super::parse(&bytes, &Limits::default()).unwrap();
        let seg = elf.segments.iter_mut().find(|s| s.kind == PT_NOTE).unwrap();
        seg.offset = (bytes.len() - blob.len()) as u64;
        seg.filesz = blob.len() as u64;
        (bytes, elf)
    }

    #[test]
    fn max_notes_is_enforced() {
        let (bytes, elf) = many_notes(5000);
        let n = parse(&elf, &bytes, &Limits::default(), &Deadline::never()).unwrap();
        assert_eq!(n.count, Limits::default().max_notes);
        assert!(n.limit_reached);
    }

    #[test]
    fn budget_bounds_note_walking() {
        let (bytes, elf) = many_notes(100);
        let limits = Limits {
            max_parser_steps: 10,
            ..Limits::default()
        };
        assert!(matches!(
            parse(&elf, &bytes, &limits, &Deadline::never()),
            Err(AnalysisError::LimitExceeded { .. })
        ));
        // The budget re-checks the clock every `Budget::CHECK_EVERY` steps, so
        // a long walk (here: max_notes raised) stops at the deadline.
        let (bytes, elf) = many_notes(5000);
        let long = Limits {
            max_notes: 10_000,
            ..Limits::default()
        };
        assert!(matches!(
            parse(&elf, &bytes, &long, &Deadline::expired()),
            Err(AnalysisError::Timeout { .. })
        ));
    }

    #[test]
    fn oversized_note_does_not_loop_or_panic() {
        let built = profiles::glibc_pie().build();
        let mut bytes = built.bytes.clone();
        let note = built
            .layout
            .segments
            .iter()
            .find(|s| s.kind == PT_NOTE)
            .unwrap();
        // descsz = u32::MAX
        bytes[note.offset + 4..note.offset + 8].copy_from_slice(&u32::MAX.to_le_bytes());
        let n = notes(&bytes);
        assert_eq!(n.count, 0);
    }
}

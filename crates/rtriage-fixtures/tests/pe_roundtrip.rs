//! Cross-checks the PE builder against an independent parser (goblin), so
//! fixtures used by rtriage tests are known to be structurally valid.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use goblin::pe::PE;
use rtriage_fixtures::pe::{pe_checksum, scn, Arch, Checksum, Entry, PeBuilder, Section};

fn section_names(pe: &PE<'_>) -> Vec<String> {
    pe.sections
        .iter()
        .map(|s| s.name().unwrap().to_owned())
        .collect()
}

#[test]
fn minimal_pe32_and_pe32plus_parse() {
    for (arch, is64) in [(Arch::X86, false), (Arch::X64, true)] {
        let built = PeBuilder::minimal(arch).build();
        let pe = PE::parse(&built.bytes).unwrap();
        assert_eq!(pe.is_64, is64);
        assert!(!pe.is_lib);
        assert_eq!(section_names(&pe), [".text", ".data"]);
        assert_eq!(pe.entry, built.layout.sections[0].rva);
        assert_eq!(pe.header.coff_header.time_date_stamp, 0x5f5e_1000);
    }
}

#[test]
fn dll_flag_and_section_flags() {
    let built = PeBuilder::new(Arch::X64)
        .dll(true)
        .section(Section::rwx(".rwx", vec![0x90; 16]))
        .build();
    let pe = PE::parse(&built.bytes).unwrap();
    assert!(pe.is_lib);
    let c = pe.sections[0].characteristics;
    assert_ne!(c & scn::MEM_EXECUTE, 0);
    assert_ne!(c & scn::MEM_WRITE, 0);
}

#[test]
fn virtual_only_section() {
    let built = PeBuilder::minimal(Arch::X86)
        .section(
            Section::rwx("UPX0", Vec::new())
                .raw_size(0)
                .virtual_size(0x10_0000),
        )
        .build();
    let pe = PE::parse(&built.bytes).unwrap();
    let s = &pe.sections[2];
    assert_eq!(s.size_of_raw_data, 0);
    assert_eq!(s.virtual_size, 0x10_0000);
}

#[test]
fn imports_by_name_and_ordinal() {
    for arch in [Arch::X86, Arch::X64] {
        let built = PeBuilder::minimal(arch)
            .import("KERNEL32.dll", &["LoadLibraryA", "GetProcAddress"])
            .import_ordinals("WS2_32.dll", &[23, 115])
            .build();
        let pe = PE::parse(&built.bytes).unwrap();
        assert_eq!(pe.libraries, ["KERNEL32.dll", "WS2_32.dll"]);
        let mut named: Vec<_> = pe
            .imports
            .iter()
            .filter(|i| i.dll == "KERNEL32.dll")
            .map(|i| i.name.to_string())
            .collect();
        named.sort();
        assert_eq!(named, ["GetProcAddress", "LoadLibraryA"]);
        let mut ords: Vec<_> = pe
            .imports
            .iter()
            .filter(|i| i.dll == "WS2_32.dll")
            .map(|i| i.ordinal)
            .collect();
        ords.sort();
        assert_eq!(ords, [23, 115]);
    }
}

#[test]
fn tls_callbacks() {
    for arch in [Arch::X86, Arch::X64] {
        let built = PeBuilder::minimal(arch).tls_callbacks(2).build();
        let pe = PE::parse(&built.bytes).unwrap();
        let tls = pe.tls_data.unwrap();
        assert_eq!(tls.callbacks.len(), 2);
    }
}

#[test]
fn pdb_path() {
    let path = r"C:\Users\builder\src\tool\Release\tool.pdb";
    let built = PeBuilder::minimal(Arch::X64).pdb_path(path).build();
    let pe = PE::parse(&built.bytes).unwrap();
    let cv = pe.debug_data.unwrap().codeview_pdb70_debug_info.unwrap();
    let name = cv.filename.split(|&b| b == 0).next().unwrap();
    assert_eq!(name, path.as_bytes());
}

#[test]
fn everything_together() {
    let built = PeBuilder::minimal(Arch::X64)
        .import("KERNEL32.dll", &["ExitProcess"])
        .tls_callbacks(1)
        .pdb_path(r"C:\x.pdb")
        .build();
    let pe = PE::parse(&built.bytes).unwrap();
    assert_eq!(section_names(&pe), [".text", ".data", ".rdata"]);
    assert_eq!(pe.imports.len(), 1);
    assert!(pe.tls_data.is_some());
    assert!(pe.debug_data.is_some());
}

#[test]
fn overlay_is_appended_after_image() {
    let built = PeBuilder::minimal(Arch::X86)
        .overlay(b"OVERLAY-DATA".to_vec())
        .build();
    assert_eq!(&built.bytes[built.layout.image_end..], b"OVERLAY-DATA");
    // goblin still parses; the overlay is outside every section.
    let pe = PE::parse(&built.bytes).unwrap();
    let last = pe.sections.last().unwrap();
    assert_eq!(
        (last.pointer_to_raw_data + last.size_of_raw_data) as usize,
        built.layout.image_end
    );
}

#[test]
fn entry_point_variants() {
    let built = PeBuilder::minimal(Arch::X86)
        .entry(Entry::Section {
            index: 1,
            offset: 4,
        })
        .build();
    let pe = PE::parse(&built.bytes).unwrap();
    assert_eq!(pe.entry, built.layout.sections[1].rva + 4);

    let built = PeBuilder::minimal(Arch::X86)
        .entry(Entry::Rva(0xdead_0000))
        .build();
    let pe = PE::parse(&built.bytes).unwrap();
    assert_eq!(pe.entry, 0xdead_0000);
}

#[test]
fn checksum_policies() {
    let zero = PeBuilder::minimal(Arch::X64).build();
    let pe = PE::parse(&zero.bytes).unwrap();
    assert_eq!(
        pe.header.optional_header.unwrap().windows_fields.check_sum,
        0
    );

    let ok = PeBuilder::minimal(Arch::X64)
        .checksum(Checksum::Correct)
        .build();
    let stored = u32::from_le_bytes(
        ok.bytes[ok.layout.checksum_offset..ok.layout.checksum_offset + 4]
            .try_into()
            .unwrap(),
    );
    assert_ne!(stored, 0);
    assert_eq!(stored, pe_checksum(&ok.bytes, ok.layout.checksum_offset));

    let bad = PeBuilder::minimal(Arch::X64)
        .checksum(Checksum::Value(0x1234))
        .build();
    let pe = PE::parse(&bad.bytes).unwrap();
    assert_eq!(
        pe.header.optional_header.unwrap().windows_fields.check_sum,
        0x1234
    );
}

#[test]
fn layout_offsets_point_at_real_fields() {
    let built = PeBuilder::minimal(Arch::X86).timestamp(0xAABB_CCDD).build();
    let l = &built.layout;
    assert_eq!(&built.bytes[l.pe_offset..l.pe_offset + 4], b"PE\0\0");
    assert_eq!(
        &built.bytes[l.timestamp_offset()..l.timestamp_offset() + 4],
        &0xAABB_CCDDu32.to_le_bytes()
    );
    assert_eq!(
        u16::from_le_bytes(
            built.bytes[l.number_of_sections_offset()..l.number_of_sections_offset() + 2]
                .try_into()
                .unwrap()
        ),
        2
    );
    assert_eq!(
        &built.bytes[l.section_table_offset..l.section_table_offset + 5],
        b".text"
    );
}

#[test]
fn dotnet_profile_has_clr_header() {
    use rtriage_fixtures::pe::profiles;
    for arch in [Arch::X86, Arch::X64] {
        let built = profiles::dotnet_like(arch).build();
        let pe = PE::parse(&built.bytes).unwrap();
        let clr = pe
            .header
            .optional_header
            .unwrap()
            .data_directories
            .get_clr_runtime_header()
            .copied()
            .unwrap();
        assert_eq!(clr.size, 72);
        assert_eq!(pe.libraries, ["mscoree.dll"]);
    }
}

#[test]
fn go_profile_parses() {
    use rtriage_fixtures::pe::profiles;
    for arch in [Arch::X86, Arch::X64] {
        let built = profiles::go_like(arch).build();
        let pe = PE::parse(&built.bytes).unwrap();
        assert_eq!(pe.header.coff_header.time_date_stamp, 0);
        assert!(section_names(&pe).contains(&".symtab".to_owned()));
        assert_eq!(pe.imports.len(), profiles::GO_KERNEL32_IMPORTS.len());
    }
}

/// Writes the imphash vectors to `$RTRIAGE_DUMP_DIR/<name>.bin` so they can
/// be hashed with pefile. Run manually:
/// `RTRIAGE_DUMP_DIR=... cargo test -p rtriage-fixtures -- --ignored dump_imphash_vectors`
#[test]
#[ignore = "manual: dumps fixtures for cross-checking with pefile"]
fn dump_imphash_vectors() {
    let dir = std::env::var("RTRIAGE_DUMP_DIR").expect("set RTRIAGE_DUMP_DIR");
    for (name, b) in rtriage_fixtures::pe::imphash_vectors::cases() {
        std::fs::write(format!("{dir}/{name}.bin"), b.build().bytes).unwrap();
    }
}

#[test]
fn rich_header_parses_with_goblin() {
    let entries = [
        (0x0104, 30_795, 12),
        (0x0105, 30_795, 3),
        (0x0093, 30_729, 1),
    ];
    let built = PeBuilder::minimal(Arch::X64).rich_header(&entries).build();
    let pe = PE::parse(&built.bytes).unwrap();
    let rich = pe.header.rich_header.unwrap();
    let got: Vec<(u16, u16, u32)> = rich
        .metadatas()
        .map(|m| {
            let m = m.unwrap();
            (m.product, m.build, m.use_count)
        })
        .collect();
    assert_eq!(got, entries);
    assert_eq!(
        rich.key,
        rtriage_fixtures::pe::rich_checksum(&built.bytes, 0x40, &entries)
    );
}

#[test]
fn exports_and_forwarders_parse_with_goblin() {
    use rtriage_fixtures::pe::ExportSpec;
    for arch in [Arch::X86, Arch::X64] {
        let built = PeBuilder::minimal(arch)
            .dll(true)
            .exports(
                "helper.dll",
                vec![
                    ExportSpec::named("Zeta"),
                    ExportSpec::named("Alpha"),
                    ExportSpec::ordinal_only(),
                    ExportSpec::forward("OpenFile", "KERNEL32.CreateFileW"),
                ],
            )
            .build();
        let pe = PE::parse(&built.bytes).unwrap();
        assert_eq!(pe.name, Some("helper.dll"));
        let mut names: Vec<_> = pe.exports.iter().filter_map(|e| e.name).collect();
        names.sort_unstable();
        assert_eq!(names, ["Alpha", "OpenFile", "Zeta"]);
        let fwd = pe
            .exports
            .iter()
            .find(|e| e.name == Some("OpenFile"))
            .unwrap();
        assert!(fwd.reexport.is_some());
    }
}

#[test]
fn resources_parse_with_goblin() {
    use rtriage_fixtures::pe::{ResId, ResourceSpec};
    let built = PeBuilder::minimal(Arch::X64)
        .resource(ResourceSpec::new(10, 101, b"payload".to_vec()))
        .resource(ResourceSpec::new(10, 102, b"second".to_vec()))
        .resource(ResourceSpec::new(24, 1, b"<assembly/>".to_vec()))
        .resource(ResourceSpec {
            type_id: ResId::Name("CONFIG".into()),
            name: ResId::Id(1),
            lang: 0,
            data: b"k=v".to_vec(),
        })
        .build();
    let pe = PE::parse(&built.bytes).unwrap();
    let res = pe.resource_data.unwrap();
    // Three types at the root: "CONFIG", RT_RCDATA (10), RT_MANIFEST (24).
    assert_eq!(res.count(), 3);
}

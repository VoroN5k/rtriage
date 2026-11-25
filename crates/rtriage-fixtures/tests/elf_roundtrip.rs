//! Cross-checks the ELF builder against goblin, so ELF fixtures are known to
//! be structurally valid in every class / byte order combination.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use goblin::elf::program_header::{PT_GNU_RELRO, PT_GNU_STACK, PT_INTERP, PT_LOAD};
use goblin::elf::Elf;
use rtriage_fixtures::elf::{df, et, machine, pf, profiles, Class, ElfBuilder, Endian};

fn section_names(elf: &Elf<'_>) -> Vec<String> {
    elf.section_headers
        .iter()
        .filter_map(|s| elf.shdr_strtab.get_at(s.sh_name).map(str::to_owned))
        .collect()
}

fn dyn_imports(elf: &Elf<'_>) -> Vec<String> {
    elf.dynsyms
        .iter()
        .filter(|s| s.is_import())
        .filter_map(|s| elf.dynstrtab.get_at(s.st_name).map(str::to_owned))
        .collect()
}

#[test]
fn every_class_and_byte_order_parses() {
    for (class, endian, mach, is64, little) in [
        (Class::Elf64, Endian::Little, machine::X86_64, true, true),
        (Class::Elf32, Endian::Little, machine::X86, false, true),
        (Class::Elf32, Endian::Big, machine::MIPS, false, false),
        (Class::Elf32, Endian::Big, machine::PPC, false, false),
        (Class::Elf64, Endian::Big, machine::PPC64, true, false),
        (Class::Elf64, Endian::Little, machine::AARCH64, true, true),
    ] {
        let built = ElfBuilder::new(class, endian, mach)
            .interp("/lib/ld.so.1")
            .needed("libc.so.6")
            .imports(&["puts", "exit"])
            .build_id(&[1; 20])
            .build();
        let elf = Elf::parse(&built.bytes).unwrap();
        assert_eq!(elf.is_64, is64, "{mach}");
        assert_eq!(elf.little_endian, little, "{mach}");
        assert_eq!(elf.header.e_machine, mach);
        assert_eq!(elf.entry, built.layout.text_vaddr);
        assert_eq!(elf.interpreter, Some("/lib/ld.so.1"));
        assert_eq!(elf.libraries, ["libc.so.6"]);
        assert_eq!(dyn_imports(&elf), ["puts", "exit"]);
        assert!(section_names(&elf).contains(&".text".to_owned()));
    }
}

#[test]
fn load_segments_have_requested_permissions() {
    let built = ElfBuilder::x86_64()
        .text_flags(pf::R | pf::W | pf::X)
        .gnu_stack(Some(pf::R | pf::W | pf::X))
        .build();
    let elf = Elf::parse(&built.bytes).unwrap();
    let loads: Vec<u32> = elf
        .program_headers
        .iter()
        .filter(|p| p.p_type == PT_LOAD)
        .map(|p| p.p_flags)
        .collect();
    assert_eq!(loads, [pf::R, pf::R | pf::W | pf::X, pf::R | pf::W]);
    let stack = elf
        .program_headers
        .iter()
        .find(|p| p.p_type == PT_GNU_STACK)
        .unwrap();
    assert_eq!(stack.p_flags, pf::R | pf::W | pf::X);
    for p in elf.program_headers.iter().filter(|p| p.p_type == PT_LOAD) {
        assert_eq!(p.p_offset % 0x1000, p.p_vaddr % 0x1000);
    }
}

#[test]
fn glibc_pie_profile() {
    let built = profiles::glibc_pie().build();
    let elf = Elf::parse(&built.bytes).unwrap();
    assert_eq!(elf.header.e_type, et::DYN);
    assert_eq!(elf.interpreter, Some("/lib64/ld-linux-x86-64.so.2"));
    let info = &elf.dynamic.as_ref().unwrap().info;
    assert_ne!(info.flags & df::BIND_NOW, 0);
    assert_ne!(info.flags_1 & df::PIE_1, 0);
    assert!(elf.program_headers.iter().any(|p| p.p_type == PT_GNU_RELRO));
    assert!(dyn_imports(&elf).contains(&"__stack_chk_fail".to_owned()));
    let notes: Vec<_> = elf
        .iter_note_headers(&built.bytes)
        .unwrap()
        .map(|n| n.unwrap())
        .collect();
    assert_eq!(notes[0].n_type, 3); // NT_GNU_BUILD_ID
    assert_eq!(notes[0].desc, &[0xAB; 20]);
}

#[test]
fn rpath_and_runpath() {
    let built = ElfBuilder::x86_64()
        .needed("libfoo.so")
        .rpath("$ORIGIN/../lib")
        .runpath("/tmp/lib")
        .build();
    let elf = Elf::parse(&built.bytes).unwrap();
    assert_eq!(elf.rpaths, ["$ORIGIN/../lib"]);
    assert_eq!(elf.runpaths, ["/tmp/lib"]);
}

#[test]
fn static_profiles_have_no_interpreter_or_dynamic() {
    for b in [profiles::go_static(), profiles::busybox_static()] {
        let built = b.build();
        let elf = Elf::parse(&built.bytes).unwrap();
        assert_eq!(elf.interpreter, None);
        assert!(elf.dynamic.is_none());
        assert!(!elf.program_headers.iter().any(|p| p.p_type == PT_INTERP));
    }
}

#[test]
fn go_profile_has_buildinfo_and_symbols() {
    let built = profiles::go_static().build();
    let elf = Elf::parse(&built.bytes).unwrap();
    let names = section_names(&elf);
    assert!(names.contains(&".go.buildinfo".to_owned()));
    assert!(names.contains(&".gopclntab".to_owned()));
    let syms: Vec<_> = elf
        .syms
        .iter()
        .filter_map(|s| elf.strtab.get_at(s.st_name))
        .collect();
    assert!(syms.contains(&"runtime.main"));
}

#[test]
fn rust_profile_has_mangled_symbols() {
    let elf_bytes = profiles::rust_pie().build().bytes;
    let elf = Elf::parse(&elf_bytes).unwrap();
    let syms: Vec<_> = elf
        .syms
        .iter()
        .filter_map(|s| elf.strtab.get_at(s.st_name))
        .collect();
    assert!(syms
        .iter()
        .any(|s| s.starts_with("_ZN") && s.contains("17h")));
    assert_eq!(elf.libraries, ["libgcc_s.so.1", "libc.so.6"]);
}

#[test]
fn upx_profile_has_no_section_headers() {
    let built = profiles::upx_elf().build();
    assert_eq!(built.layout.shoff, 0);
    let elf = Elf::parse(&built.bytes).unwrap();
    assert!(elf.section_headers.is_empty());
    let after = &built.bytes[built.layout.phoff + elf.program_headers.len() * 56..][..8];
    assert_eq!(&after[4..8], b"UPX!");
    assert!(elf
        .program_headers
        .iter()
        .any(|p| p.p_type == PT_LOAD && p.p_flags == pf::R | pf::W | pf::X));
}

#[test]
fn layout_offsets_point_at_header_fields() {
    let built = ElfBuilder::new(Class::Elf32, Endian::Big, machine::MIPS).build();
    let l = &built.layout;
    let be16 = |o: usize| u16::from_be_bytes(built.bytes[o..o + 2].try_into().unwrap());
    assert_eq!(be16(l.phentsize_offset), 32);
    assert_eq!(usize::from(be16(l.phnum_offset)), l.segments.len());
    assert_eq!(be16(l.shentsize_offset), 40);
    let elf = Elf::parse(&built.bytes).unwrap();
    assert_eq!(usize::from(be16(l.shnum_offset)), elf.section_headers.len());
    assert_eq!(
        usize::from(be16(l.shstrndx_offset)),
        elf.header.e_shstrndx as usize
    );
}

#[test]
fn overlay_is_after_the_image() {
    let built = ElfBuilder::x86_64().overlay(b"APPENDED".to_vec()).build();
    assert_eq!(&built.bytes[built.layout.image_end..], b"APPENDED");
    Elf::parse(&built.bytes).unwrap();
}

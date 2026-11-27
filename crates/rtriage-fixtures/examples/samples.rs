//! Writes the synthetic sample files used by the release smoke test
//! (`scripts/smoke.sh`), the README screenshots and anyone trying rtriage.
//!
//! `cargo run -p rtriage-fixtures --example samples --locked -- <dir> [copies]`
//!
//! Every file is built by this crate's fixture builders: synthetic and
//! benign, never a real sample, and never the EICAR test string. With
//! `copies` > 1, `<name>-<n>` copies are written too (for benchmarks).

use std::path::Path;
use std::process::ExitCode;

/// Sample file name and the corpus entry it is built from (`pe:`/`elf:`).
const SAMPLES: [(&str, &str); 6] = [
    ("pe-clean.exe", "pe:minimal_x64"),
    ("pe-upx.exe", "pe:upx_x64"),
    ("pe-medium.exe", "pe:virtual_rwx_x64"),
    ("pe-high.exe", "pe:everything_x64"),
    ("elf-clean", "elf:glibc_pie"),
    ("elf-upx", "elf:upx_elf"),
];

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let (Some(dir), copies) = (args.next(), args.next()) else {
        eprintln!("usage: samples <dir> [copies]");
        return ExitCode::from(2);
    };
    let copies = match copies.as_deref().map(str::parse::<usize>) {
        None => 1,
        Some(Ok(n)) if n >= 1 => n,
        Some(_) => {
            eprintln!("copies must be a number >= 1");
            return ExitCode::from(2);
        }
    };
    match write_samples(Path::new(&dir), copies) {
        Ok(n) => {
            println!("wrote {n} synthetic samples to {dir}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(if e.kind() == std::io::ErrorKind::NotFound {
                2
            } else {
                1
            })
        }
    }
}

fn write_samples(dir: &Path, copies: usize) -> std::io::Result<usize> {
    let pe = rtriage_fixtures::pe::corpus();
    let elf = rtriage_fixtures::elf::corpus();
    std::fs::create_dir_all(dir)?;
    let mut written = 0;
    for (file, source) in SAMPLES {
        let found = match source.split_once(':') {
            Some(("pe", n)) => pe.iter().find(|(c, _)| *c == n),
            Some(("elf", n)) => elf.iter().find(|(c, _)| *c == n),
            _ => None,
        };
        let Some((_, bytes)) = found else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no corpus entry {source} (fixture renamed?)"),
            ));
        };
        std::fs::write(dir.join(file), bytes)?;
        written += 1;
        for n in 2..=copies {
            std::fs::write(dir.join(format!("{file}-{n}")), bytes)?;
            written += 1;
        }
    }
    Ok(written)
}

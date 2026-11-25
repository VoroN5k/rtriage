//! Writes the synthetic corpus as fuzzing seeds.
//!
//! `cargo run -p rtriage-fixtures --example fuzz_corpus -- <dir> [pe|elf|all]`
//! (default `pe`). Synthetic fixtures only: never real samples.

fn main() -> std::io::Result<()> {
    let mut args = std::env::args().skip(1);
    let dir = args.next().unwrap_or_else(|| "fuzz/corpus/pe_parse".into());
    let kind = args.next().unwrap_or_else(|| "pe".into());
    let seeds: Vec<(String, Vec<u8>)> = match kind.as_str() {
        "pe" => prefixed("pe", rtriage_fixtures::pe::corpus()),
        "elf" => prefixed("elf", rtriage_fixtures::elf::corpus()),
        "all" => {
            let mut v = prefixed("pe", rtriage_fixtures::pe::corpus());
            v.extend(prefixed("elf", rtriage_fixtures::elf::corpus()));
            v
        }
        other => {
            eprintln!("unknown corpus {other:?}: expected pe, elf or all");
            std::process::exit(2);
        }
    };
    std::fs::create_dir_all(&dir)?;
    for (name, bytes) in &seeds {
        std::fs::write(format!("{dir}/{name}.bin"), bytes)?;
    }
    println!("wrote {} {kind} seeds to {dir}", seeds.len());
    Ok(())
}

fn prefixed(prefix: &str, corpus: Vec<(&'static str, Vec<u8>)>) -> Vec<(String, Vec<u8>)> {
    corpus
        .into_iter()
        .map(|(name, bytes)| (format!("{prefix}_{name}"), bytes))
        .collect()
}

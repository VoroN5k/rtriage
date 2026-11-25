//! Writes the synthetic PE corpus as fuzzing seeds.
//!
//! `cargo run -p rtriage-fixtures --example fuzz_corpus -- fuzz/corpus/pe_parse`

fn main() -> std::io::Result<()> {
    let dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "fuzz/corpus/pe_parse".into());
    std::fs::create_dir_all(&dir)?;
    for (name, bytes) in rtriage_fixtures::pe::corpus() {
        std::fs::write(format!("{dir}/{name}.bin"), bytes)?;
    }
    println!(
        "wrote {} seeds to {dir}",
        rtriage_fixtures::pe::corpus().len()
    );
    Ok(())
}

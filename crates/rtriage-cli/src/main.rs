//! `rtriage` binary: thin CLI layer over `rtriage-core`.
#![forbid(unsafe_code)]

fn main() {
    println!("rtriage {}", rtriage_core::VERSION);
}

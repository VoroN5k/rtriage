//! String extraction and classification on arbitrary bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rtriage_core::analyzers::strings::{classify, extract, Options};
use rtriage_core::Deadline;

fuzz_target!(|data: &[u8]| {
    let opts = Options {
        min_len: 4,
        max_len: 4096,
        max_items: 10_000,
    };
    let Ok(facts) = extract(data, opts, &Deadline::never()) else {
        return;
    };
    assert!(facts.items.len() <= opts.max_items);
    assert!(facts.items.windows(2).all(|w| w[0].offset <= w[1].offset));
    if let Ok(c) = classify::classifier() {
        for s in &facts.items {
            let _ = c.classify(&s.value);
        }
    }
});

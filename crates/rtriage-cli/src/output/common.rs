//! Formatting helpers shared by the text and Markdown renderers. None of
//! them touches file-derived text: callers sanitize or code-span values.

use rtriage_core::report::ExplainerKind;
use rtriage_core::Format;
use serde::Serialize;

/// Display name of a format.
pub(crate) fn format_name(f: Format) -> &'static str {
    match f {
        Format::Pe => "PE",
        Format::Elf => "ELF",
        _ => "unknown",
    }
}

/// Same snake_case name as in the JSON output, so text and JSON agree.
pub(crate) fn enum_name<T: Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| "?".to_owned())
}

/// `48128` -> `"48 128 bytes (47.0 KiB)"`.
pub(crate) fn human_size(n: u64) -> String {
    if n < 1024 {
        format!("{} bytes", group_digits(n))
    } else {
        format!("{} bytes ({})", group_digits(n), short_size(n))
    }
}

/// `16384` -> `"16.0 KiB"`.
pub(crate) fn short_size(n: u64) -> String {
    const UNITS: [&str; 4] = ["KiB", "MiB", "GiB", "TiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut value = n as f64 / 1024.0;
    let mut unit = "KiB";
    for next in UNITS.iter().skip(1) {
        if value < 1024.0 {
            break;
        }
        value /= 1024.0;
        unit = next;
    }
    format!("{value:.1} {unit}")
}

/// `1204` -> `"1 204"`.
pub(crate) fn group_digits(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(' ');
        }
        out.push(c);
    }
    out
}

/// `UPX (PE-PACKER-KNOWN)` for packers, `the Go runtime` for runtimes.
pub(crate) fn explainer_label(kind: ExplainerKind, name: &str, by: Option<&str>) -> String {
    match (kind, by) {
        (ExplainerKind::Runtime, _) => format!("the {} runtime", runtime_display(name)),
        (_, Some(by)) => format!("{name} ({by})"),
        (_, None) => name.to_owned(),
    }
}

/// Display name of a runtime (`go` -> `Go`).
pub(crate) fn runtime_display(name: &str) -> &str {
    match name {
        "go" => "Go",
        "rust" => "Rust",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn number_formatting() {
        assert_eq!(group_digits(0), "0");
        assert_eq!(group_digits(999), "999");
        assert_eq!(group_digits(1204), "1 204");
        assert_eq!(group_digits(1_234_567), "1 234 567");
        assert_eq!(human_size(570), "570 bytes");
        assert_eq!(human_size(48_128), "48 128 bytes (47.0 KiB)");
        assert_eq!(short_size(3 * 1024 * 1024), "3.0 MiB");
    }

    #[test]
    fn explainers_and_formats() {
        assert_eq!(
            explainer_label(ExplainerKind::Packer, "UPX", Some("PE-PACKER-KNOWN")),
            "UPX (PE-PACKER-KNOWN)"
        );
        assert_eq!(
            explainer_label(ExplainerKind::Runtime, "go", None),
            "the Go runtime"
        );
        assert_eq!(format_name(Format::Elf), "ELF");
        assert_eq!(
            enum_name(&rtriage_core::RiskLevel::CleanLooking),
            "clean_looking"
        );
    }
}

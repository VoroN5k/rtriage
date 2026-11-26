//! Row models of the Sections, Imports and Strings panes. Jumps and views
//! both use these functions, so "row N" means the same thing everywhere.

use std::borrow::Cow;

use rtriage_core::Report;

/// Rows of the Sections pane: PE sections, or ELF section headers.
pub fn section_count(report: &Report) -> usize {
    if let Some(s) = report.facts.pe.as_ref().and_then(|p| p.sections.as_ref()) {
        s.len()
    } else if let Some(s) = report.facts.elf.as_ref().and_then(|e| e.sections.as_ref()) {
        s.len()
    } else {
        0
    }
}

/// Row of the section with header-table index `index`.
pub fn section_row(report: &Report, index: usize) -> Option<usize> {
    if let Some(s) = report.facts.pe.as_ref().and_then(|p| p.sections.as_ref()) {
        s.iter().position(|s| s.index == index)
    } else {
        let s = report.facts.elf.as_ref()?.sections.as_ref()?;
        s.iter().position(|s| s.index == index)
    }
}

/// Name of the section whose file bytes contain `offset` (raw, unsanitized).
pub fn section_containing(report: &Report, offset: u64) -> Option<&str> {
    if let Some(s) = report.facts.pe.as_ref().and_then(|p| p.sections.as_ref()) {
        s.iter()
            .find(|s| {
                let start = u64::from(s.raw_offset);
                (start..start.saturating_add(u64::from(s.raw_size))).contains(&offset)
            })
            .map(|s| s.name.as_str())
    } else {
        let s = report.facts.elf.as_ref()?.sections.as_ref()?;
        s.iter()
            .filter(|s| s.kind != "NOBITS")
            .find(|s| (s.offset..s.offset.saturating_add(s.size)).contains(&offset))
            .map(|s| s.name.as_str())
    }
}

/// One row of the Imports pane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportRow<'a> {
    /// Providing library (PE); `None` for ELF symbols.
    pub library: Option<&'a str>,
    /// Symbol name, or `#<ordinal>` for ordinal-only PE imports.
    pub symbol: Cow<'a, str>,
}

/// Rows of the Imports pane: PE functions grouped by DLL in import order,
/// or ELF imported symbols in table order.
pub fn import_rows(report: &Report) -> Vec<ImportRow<'_>> {
    if let Some(imports) = report.facts.pe.as_ref().and_then(|p| p.imports.as_ref()) {
        imports
            .libraries
            .iter()
            .flat_map(|lib| {
                lib.functions.iter().map(move |f| ImportRow {
                    library: Some(lib.name.as_str()),
                    symbol: match (&f.name, f.ordinal) {
                        (Some(name), _) => Cow::Borrowed(name.as_str()),
                        (None, Some(ord)) => Cow::Owned(format!("#{ord}")),
                        (None, None) => Cow::Borrowed("?"),
                    },
                })
            })
            .collect()
    } else if let Some(d) = report.facts.elf.as_ref().and_then(|e| e.dynamic.as_ref()) {
        d.imports
            .iter()
            .map(|s| ImportRow {
                library: None,
                symbol: Cow::Borrowed(s.as_str()),
            })
            .collect()
    } else {
        Vec::new()
    }
}

/// Row of an import. DLL names compare case-insensitively (Windows does).
pub fn import_row(report: &Report, library: Option<&str>, symbol: &str) -> Option<usize> {
    // A library on only one side (ELF symbols, evidence without a DLL) matches.
    import_rows(report).iter().position(|r| {
        r.symbol == symbol
            && r.library
                .zip(library)
                .is_none_or(|(a, b)| a.eq_ignore_ascii_case(b))
    })
}

/// Rows of the Strings pane.
pub fn string_count(report: &Report) -> usize {
    report.facts.strings.as_ref().map_or(0, |s| s.items.len())
}

/// Row of the string starting at `offset` (items are sorted by offset).
pub fn string_row(report: &Report, offset: u64) -> Option<usize> {
    let items = &report.facts.strings.as_ref()?.items;
    items.binary_search_by_key(&offset, |s| s.offset).ok()
}

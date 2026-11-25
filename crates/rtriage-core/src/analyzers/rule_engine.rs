//! Evaluation of data-driven API behavior rules ([`crate::rules`]) against a
//! format-neutral view of a binary's symbols, plus lazily fetched strings.
//! Used by the PE and ELF API-group analyzers.

use std::collections::BTreeSet;

use crate::analyzers::iocs::{effective_scope, ioc_kind_for};
use crate::deadline::Deadline;
use crate::error::AnalysisError;
use crate::report::{Confidence, Evidence, ExtractedString, Finding, IocFacts, StringsFacts};
use crate::rules::{ApiGroup, ApiPattern, ApiRuleSet, StringCondition, When};

/// String evidence items attached per finding.
const MAX_STRING_EVIDENCE: usize = 5;

/// The text a rule's `strings` condition can see.
#[derive(Debug, Clone, Copy)]
pub struct TextView<'s> {
    /// All extracted strings.
    pub strings: &'s StringsFacts,
    /// IOCs from those strings (network kinds are judged on these).
    pub iocs: &'s IocFacts,
}

/// The symbols a rule can see.
#[derive(Debug, Clone, Default)]
pub struct SymbolView<'a> {
    /// Imported APIs as `(library, name)`; library is `None` for ELF.
    pub imports: Vec<(Option<&'a str>, &'a str)>,
    /// Defined (exported) symbols.
    pub exports: Vec<&'a str>,
    /// Size of the import table, for `max_imports`.
    pub import_count: u64,
}

/// Evaluates every group of `rules`.
///
/// `primary` is what the binary actually imports. `extended`, if given, adds
/// symbols that are present but not necessarily used (an ELF's static
/// `.symtab`): an alternative that only matches with them is reported with
/// **low** confidence. `strings` is called at most once, and only if some
/// alternative needs strings.
///
/// # Errors
/// [`AnalysisError::Timeout`] from `deadline`. A failure to obtain strings is
/// returned alongside the findings (rules needing strings then don't match).
pub fn evaluate<'s>(
    rules: &ApiRuleSet,
    primary: &SymbolView<'_>,
    extended: Option<&SymbolView<'_>>,
    deadline: &Deadline,
    strings: &mut dyn FnMut() -> Result<TextView<'s>, AnalysisError>,
) -> Result<(Vec<Finding>, Option<AnalysisError>), AnalysisError> {
    let mut cache: Option<Result<TextView<'s>, AnalysisError>> = None;
    let mut fetch = |cache: &mut Option<Result<TextView<'s>, AnalysisError>>| {
        cache.get_or_insert_with(&mut *strings).clone()
    };
    let mut findings = Vec::new();
    let mut strings_error = None;

    for group in &rules.groups {
        deadline.check()?;
        'whens: for when in &group.whens {
            for (view, via_static) in [(Some(primary), false), (extended, true)] {
                let Some(view) = view else {
                    continue;
                };
                let Some(api_ev) = match_symbols(when, view) else {
                    continue;
                };
                // Strings are only fetched once symbols already match.
                let needs_strings = when.strings.is_some() || when.unless.is_some();
                let text = if needs_strings {
                    match fetch(&mut cache) {
                        Ok(s) => Some(s),
                        Err(e) => {
                            strings_error.get_or_insert(e);
                            continue 'whens;
                        }
                    }
                } else {
                    None
                };
                let string_ev = match (&when.strings, text) {
                    (Some(cond), Some(s)) => match match_strings(cond, s) {
                        Some(ev) => ev,
                        None => continue,
                    },
                    _ => Vec::new(),
                };
                if let (Some(veto), Some(s)) = (&when.unless, text) {
                    if match_strings(veto, s).is_some() {
                        continue;
                    }
                }
                findings.push(finding(group, when, api_ev, string_ev, via_static));
                break 'whens; // first matching alternative wins
            }
        }
    }
    Ok((findings, strings_error))
}

/// Symbol evidence if every slot, `any_of`, `exports` and `max_imports` hold.
fn match_symbols(when: &When, view: &SymbolView<'_>) -> Option<Vec<Evidence>> {
    if when.max_imports.is_some_and(|max| view.import_count > max) {
        return None;
    }
    let find = |p: &ApiPattern| view.imports.iter().find(|(_, n)| p.matches(n));
    let mut ev = Vec::new();
    for slot in &when.slots {
        let &(lib, name) = slot.iter().find_map(find)?;
        ev.push(import_ev(lib, name));
    }
    if !when.any_of.is_empty() {
        let hits: Vec<_> = when.any_of.iter().filter_map(find).collect();
        let distinct: BTreeSet<&str> = hits.iter().map(|(_, n)| *n).collect();
        if distinct.len() < when.min {
            return None;
        }
        ev.extend(hits.iter().map(|&&(lib, name)| import_ev(lib, name)));
    }
    if !when.exports.is_empty() {
        let name = view
            .exports
            .iter()
            .find(|n| when.exports.iter().any(|p| p.matches(n)))?;
        ev.push(Evidence::Field {
            name: "export",
            value: (*name).to_owned(),
        });
    }
    dedup(&mut ev);
    Some(ev)
}

/// String evidence if at least `min_distinct` different kinds/substrings hit.
///
/// Network kinds (URL, domain, IP, email) count only through IOCs that are
/// not allowlisted and, for IPs and IP-host URLs, in `cond.ip_scopes`.
pub fn match_strings(cond: &StringCondition, text: TextView<'_>) -> Option<Vec<Evidence>> {
    let strings = text.strings;
    let mut hits: Vec<&ExtractedString> = Vec::new();
    let mut distinct = 0usize;
    for kind in &cond.kinds {
        let hit = match ioc_kind_for(*kind) {
            Some(ik) => text
                .iocs
                .items
                .iter()
                .filter(|i| i.kind == ik && !i.allowlisted)
                .filter(|i| effective_scope(i).is_none_or(|s| cond.ip_scopes.contains(&s)))
                .find_map(|i| {
                    let at = *i.offsets.first()?;
                    strings.items.iter().find(|s| s.offset == at)
                }),
            None => strings.items.iter().find(|s| s.kinds.contains(kind)),
        };
        if let Some(s) = hit {
            distinct += 1;
            hits.push(s);
        }
    }
    for needle in &cond.contains_lower {
        if let Some(s) = strings
            .items
            .iter()
            .find(|s| s.value.to_lowercase().contains(needle.as_str()))
        {
            distinct += 1;
            hits.push(s);
        }
    }
    if distinct < cond.min_distinct {
        return None;
    }
    let mut ev: Vec<Evidence> = hits
        .into_iter()
        .map(|s| Evidence::String {
            offset: s.offset,
            encoding: s.encoding,
            value: s.value.clone(),
        })
        .collect();
    dedup(&mut ev);
    ev.truncate(MAX_STRING_EVIDENCE);
    Some(ev)
}

fn finding(
    group: &ApiGroup,
    when: &When,
    api_ev: Vec<Evidence>,
    string_ev: Vec<Evidence>,
    via_static: bool,
) -> Finding {
    let confidence = if via_static {
        Confidence::Low
    } else {
        when.confidence.unwrap_or(group.confidence)
    };
    let mut detail = group.rationale.clone();
    if via_static {
        detail.push_str(
            " Matched only with symbols from the static symbol table: the code is \
             linked in, but not necessarily used.",
        );
    }
    let mut f = Finding::new(
        group.id,
        when.severity.unwrap_or(group.severity),
        group.category,
        group.title.clone(),
    )
    .confidence(confidence)
    .detail(detail);
    for e in api_ev.into_iter().chain(string_ev) {
        f = f.evidence(e);
    }
    for t in &group.attack {
        f = f.attack(t);
    }
    f
}

/// Import evidence; `lib` is the providing library when the format knows it.
pub fn import_ev(lib: Option<&str>, name: &str) -> Evidence {
    Evidence::Import {
        library: lib.map(str::to_owned),
        symbol: name.to_owned(),
    }
}

/// Removes repeated evidence, keeping first occurrences in order.
fn dedup(ev: &mut Vec<Evidence>) {
    let mut out: Vec<Evidence> = Vec::with_capacity(ev.len());
    for e in ev.drain(..) {
        if !out.contains(&e) {
            out.push(e);
        }
    }
    *ev = out;
}

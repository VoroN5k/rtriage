//! API behavior groups: data-driven combinations of imported APIs (and
//! optionally strings) from [`crate::rules`].
//!
//! Imports and strings come from [`AnalysisContext`], computed once and shared,
//! so this analyzer does not depend on the imports or strings analyzers.
//! Strings are only extracted if some rule actually needs them.

use std::collections::BTreeSet;

use crate::analyzers::{AnalysisContext, Analyzer};
use crate::error::AnalysisError;
use crate::report::{Evidence, ExtractedString, Finding, Format, ReportBuilder, StringsFacts};
use crate::rules::{ApiGroup, ApiPattern, ApiRuleSet, StringCondition, When};

/// String evidence items attached per finding.
const MAX_STRING_EVIDENCE: usize = 5;

/// Evaluates the configured (or bundled) API behavior rules.
#[derive(Debug, Clone, Copy, Default)]
pub struct PeApiGroupsAnalyzer;

impl Analyzer for PeApiGroupsAnalyzer {
    fn name(&self) -> &'static str {
        "pe-api-groups"
    }

    fn applies_to(&self, format: Format) -> bool {
        format == Format::Pe
    }

    fn run(&self, ctx: &AnalysisContext<'_>, out: &mut ReportBuilder) -> Result<(), AnalysisError> {
        let Some(imports) = ctx.pe_imports() else {
            return Ok(());
        };
        let rules: &ApiRuleSet = match &ctx.config.api_rules {
            Some(custom) => custom,
            None => ApiRuleSet::bundled().map_err(|e| AnalysisError::Internal {
                reason: format!("bundled API rules are invalid: {e}"),
            })?,
        };
        let apis: Vec<(&str, &str)> = imports.api_names().collect();

        // Strings are expensive; fetch them lazily, once, and remember failures.
        let mut strings: Option<Result<&StringsFacts, AnalysisError>> = None;
        let mut first_error = None;

        for group in &rules.groups {
            ctx.deadline.check()?;
            for when in &group.whens {
                let Some(api_ev) = match_apis(when, &apis) else {
                    continue;
                };
                let string_ev = match &when.strings {
                    None => Some(Vec::new()),
                    Some(cond) => match strings.get_or_insert_with(|| ctx.strings()) {
                        Ok(s) => match_strings(cond, s),
                        Err(e) => {
                            first_error.get_or_insert_with(|| e.clone());
                            None
                        }
                    },
                };
                if let Some(string_ev) = string_ev {
                    out.push_finding(finding(group, api_ev, string_ev));
                    break; // first matching alternative wins
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

/// Import evidence if every slot and the `any_of` condition are satisfied.
fn match_apis(when: &When, apis: &[(&str, &str)]) -> Option<Vec<Evidence>> {
    let find = |pattern: &ApiPattern| apis.iter().find(|(_, name)| pattern.matches(name));
    let mut ev = Vec::new();
    for slot in &when.slots {
        let &(lib, name) = slot.iter().find_map(find)?;
        ev.push(import(lib, name));
    }
    if !when.any_of.is_empty() {
        let hits: Vec<_> = when.any_of.iter().filter_map(find).collect();
        let distinct: BTreeSet<&str> = hits.iter().map(|(_, n)| *n).collect();
        if distinct.len() < when.min {
            return None;
        }
        ev.extend(hits.iter().map(|&&(lib, name)| import(lib, name)));
    }
    dedup(&mut ev);
    Some(ev)
}

/// String evidence if at least `min_distinct` different kinds/substrings hit.
fn match_strings(cond: &StringCondition, strings: &StringsFacts) -> Option<Vec<Evidence>> {
    let mut hits: Vec<&ExtractedString> = Vec::new();
    let mut distinct = 0usize;
    for kind in &cond.kinds {
        if let Some(s) = strings.items.iter().find(|s| s.kinds.contains(kind)) {
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

fn finding(group: &ApiGroup, api_ev: Vec<Evidence>, string_ev: Vec<Evidence>) -> Finding {
    let mut f = Finding::new(
        group.id,
        group.severity,
        group.category,
        group.title.clone(),
    )
    .confidence(group.confidence)
    .detail(group.rationale.clone());
    for e in api_ev.into_iter().chain(string_ev) {
        f = f.evidence(e);
    }
    for t in &group.attack {
        f = f.attack(t);
    }
    f
}

fn import(lib: &str, name: &str) -> Evidence {
    Evidence::Import {
        library: Some(lib.to_owned()),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::input::Input;
    use crate::report::{Report, Severity};
    use crate::Registry;
    use rtriage_fixtures::pe::{profiles, Arch, PeBuilder, Section};
    use std::sync::Arc;

    /// Builds a PE importing `imports` (`(dll, names)`) whose `.data` holds
    /// `strings` as NUL-separated ASCII and UTF-16LE text.
    fn pe(imports: &[(&str, &[&str])], strings: &[&str]) -> Vec<u8> {
        let mut data = vec![0xffu8];
        for s in strings {
            data.extend_from_slice(s.as_bytes());
            data.push(0);
            data.extend(s.bytes().flat_map(|b| [b, 0]));
            data.extend_from_slice(&[0xff, 0xff]);
        }
        let mut b = PeBuilder::new(Arch::X64)
            .section(Section::code(".text", vec![0xC3; 64]))
            .section(Section::data(".data", data));
        for (dll, names) in imports {
            b = b.import(dll, names);
        }
        b.build().bytes
    }

    fn run(bytes: Vec<u8>) -> Report {
        run_with(bytes, &Config::default())
    }

    fn run_with(bytes: Vec<u8>, config: &Config) -> Report {
        let r = Registry::default().analyze(&Input::from_bytes("t.exe", bytes), config);
        assert!(
            r.errors.iter().all(|e| e.analyzer != "pe-api-groups"),
            "{:?}",
            r.errors
        );
        r
    }

    fn api_ids(r: &Report) -> Vec<&'static str> {
        r.findings
            .iter()
            .map(|f| f.id)
            .filter(|id| id.starts_with("PE-API-"))
            .collect()
    }

    fn has(r: &Report, id: &str) -> bool {
        api_ids(r).contains(&id)
    }

    const K32: &str = "KERNEL32.dll";

    // ---- injection

    #[test]
    fn injection_full_chain() {
        let r = run(pe(
            &[(
                K32,
                &[
                    "OpenProcess",
                    "VirtualAllocEx",
                    "WriteProcessMemory",
                    "CreateRemoteThread",
                ],
            )],
            &[],
        ));
        assert_eq!(api_ids(&r), ["PE-API-INJECTION"]);
        let f = &r.findings[0];
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.attack, ["T1055"]);
        assert!(f.evidence.contains(&import(K32, "CreateRemoteThread")));
    }

    #[test]
    fn injection_via_apc_and_native_api() {
        let r = run(pe(
            &[
                (K32, &["OpenProcess", "QueueUserAPC"]),
                (
                    "ntdll.dll",
                    &["NtAllocateVirtualMemory", "NtWriteVirtualMemory"],
                ),
            ],
            &[],
        ));
        assert!(has(&r, "PE-API-INJECTION"));
    }

    #[test]
    fn partial_chain_is_not_injection() {
        // No OpenProcess: e.g. allocating in a child it created itself.
        let r = run(pe(
            &[(
                K32,
                &["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
            )],
            &[],
        ));
        assert!(!has(&r, "PE-API-INJECTION"));
    }

    #[test]
    fn go_runtime_triggers_no_api_group() {
        // SuspendThread/Get/SetThreadContext/VirtualAlloc/CreateThread/LoadLibraryW/GetProcAddress.
        for arch in [Arch::X86, Arch::X64] {
            let r = run(profiles::go_like(arch).build().bytes);
            assert!(api_ids(&r).is_empty(), "{:?}", api_ids(&r));
        }
    }

    // ---- anti-debug

    #[test]
    fn two_debugger_checks_are_antidebug() {
        let r = run(pe(
            &[(K32, &["IsDebuggerPresent", "CheckRemoteDebuggerPresent"])],
            &[],
        ));
        assert_eq!(api_ids(&r), ["PE-API-ANTIDEBUG"]);
    }

    #[test]
    fn crt_isdebuggerpresent_alone_is_not_antidebug() {
        let r = run(pe(&[(K32, &["IsDebuggerPresent", "ExitProcess"])], &[]));
        assert!(!has(&r, "PE-API-ANTIDEBUG"));
    }

    // ---- registry persistence

    #[test]
    fn run_key_write_is_persistence() {
        let r = run(pe(
            &[("ADVAPI32.dll", &["RegOpenKeyExW", "RegSetValueExW"])],
            &[r"Software\Microsoft\Windows\CurrentVersion\Run"],
        ));
        assert!(has(&r, "PE-API-PERSISTENCE-REGISTRY"));
        let f = r
            .findings
            .iter()
            .find(|f| f.id == "PE-API-PERSISTENCE-REGISTRY")
            .unwrap();
        assert!(f
            .evidence
            .iter()
            .any(|e| matches!(e, Evidence::String { .. })));
    }

    #[test]
    fn registry_write_elsewhere_is_not_persistence() {
        let r = run(pe(
            &[("ADVAPI32.dll", &["RegSetValueExW"])],
            &[r"Software\Vendor\App\Settings"],
        ));
        assert!(!has(&r, "PE-API-PERSISTENCE-REGISTRY"));
    }

    // ---- service persistence

    #[test]
    fn create_and_start_service() {
        let r = run(pe(
            &[(
                "ADVAPI32.dll",
                &["OpenSCManagerW", "CreateServiceW", "StartServiceW"],
            )],
            &[],
        ));
        assert!(has(&r, "PE-API-PERSISTENCE-SERVICE"));
    }

    #[test]
    fn service_controller_without_create_is_not_persistence() {
        let r = run(pe(
            &[(
                "ADVAPI32.dll",
                &["OpenSCManagerW", "OpenServiceW", "StartServiceW"],
            )],
            &[],
        ));
        assert!(!has(&r, "PE-API-PERSISTENCE-SERVICE"));
    }

    // ---- network

    #[test]
    fn winhttp_with_url_is_network() {
        let r = run(pe(
            &[("WINHTTP.dll", &["WinHttpOpen", "WinHttpConnect"])],
            &["http://c2.example.ru/gate"],
        ));
        assert!(has(&r, "PE-API-NETWORK"));
    }

    #[test]
    fn winhttp_without_endpoint_is_not_network() {
        let r = run(pe(&[("WINHTTP.dll", &["WinHttpOpen"])], &["User settings"]));
        assert!(!has(&r, "PE-API-NETWORK"));
    }

    #[test]
    fn ws2_32_by_ordinal_with_ip_is_network() {
        // ws2_32 #115 = WSAStartup, #4 = connect (resolved via pefile's table).
        let bytes = PeBuilder::new(Arch::X86)
            .section(Section::code(".text", vec![0xC3; 64]))
            .section(Section::data(".data", b"\xff45.13.227.8\0".to_vec()))
            .import_ordinals("WS2_32.dll", &[115, 4])
            .build()
            .bytes;
        let r = run(bytes);
        assert!(has(&r, "PE-API-NETWORK"), "{:?}", api_ids(&r));
    }

    // ---- ransomware

    const EXTENSIONS: &str = ".docx.xlsx.pptx.pdf.jpg.png.zip.rar.sql.bak";

    #[test]
    fn encrypt_enumerate_and_extensions_is_ransom() {
        let r = run(pe(
            &[
                (K32, &["FindFirstFileW", "FindNextFileW"]),
                ("ADVAPI32.dll", &["CryptEncrypt"]),
            ],
            &[EXTENSIONS],
        ));
        assert!(has(&r, "PE-API-RANSOM-CRYPTO"));
    }

    #[test]
    fn backup_tool_lookalike_is_not_ransom() {
        let r = run(pe(
            &[
                (K32, &["FindFirstFileW", "FindNextFileW"]),
                ("bcrypt.dll", &["BCryptEncrypt"]),
            ],
            &["backup.zip", "settings.bak"],
        ));
        assert!(!has(&r, "PE-API-RANSOM-CRYPTO"));
    }

    // ---- credentials

    #[test]
    fn credential_enumeration() {
        let r = run(pe(&[("ADVAPI32.dll", &["CredEnumerateW"])], &[]));
        assert!(has(&r, "PE-API-CREDENTIALS"));
    }

    #[test]
    fn dpapi_with_several_browser_stores_is_credentials() {
        let r = run(pe(
            &[("CRYPT32.dll", &["CryptUnprotectData"])],
            &[
                r"\Google\Chrome\User Data",
                r"\Mozilla\Firefox\Profiles",
                "logins.json",
            ],
        ));
        assert!(has(&r, "PE-API-CREDENTIALS"));
    }

    #[test]
    fn chromium_like_own_store_is_not_credentials() {
        // A browser decrypting its own "Login Data" with DPAPI.
        let r = run(pe(
            &[("CRYPT32.dll", &["CryptUnprotectData"])],
            &["Login Data", "Local State"],
        ));
        assert!(!has(&r, "PE-API-CREDENTIALS"));
    }

    // ---- keylogging

    #[test]
    fn hook_and_key_translation_is_keylogging() {
        let r = run(pe(
            &[(
                "USER32.dll",
                &["SetWindowsHookExW", "CallNextHookEx", "GetKeyNameTextW"],
            )],
            &[],
        ));
        assert!(has(&r, "PE-API-KEYLOGGING"));
    }

    #[test]
    fn hotkey_hook_alone_is_not_keylogging() {
        let r = run(pe(
            &[(
                "USER32.dll",
                &["SetWindowsHookExW", "CallNextHookEx", "UnhookWindowsHookEx"],
            )],
            &[],
        ));
        assert!(!has(&r, "PE-API-KEYLOGGING"));
    }

    #[test]
    fn polling_keylogger() {
        let r = run(pe(
            &[(
                "USER32.dll",
                &["GetAsyncKeyState", "GetForegroundWindow", "GetWindowTextW"],
            )],
            &[],
        ));
        assert!(has(&r, "PE-API-KEYLOGGING"));
    }

    // ---- engine

    #[test]
    fn profiles_and_plain_programs_are_clean() {
        for bytes in [
            profiles::dotnet_like(Arch::X86).build().bytes,
            pe(
                &[(
                    K32,
                    &[
                        "ExitProcess",
                        "GetStdHandle",
                        "WriteFile",
                        "IsDebuggerPresent",
                    ],
                )],
                &[],
            ),
        ] {
            let r = run(bytes);
            assert!(api_ids(&r).is_empty(), "{:?}", api_ids(&r));
        }
    }

    #[test]
    fn custom_rules_replace_bundled() {
        let rules = ApiRuleSet::parse(
            r#"
schema_version = 1
[[group]]
id = "PE-API-CUSTOM-BEEP"
title = "Beeps"
severity = "info"
confidence = "high"
category = "metadata"
rationale = "Imports Beep."
[[group.when]]
slots = [["Beep"]]
"#,
        )
        .unwrap();
        let config = Config {
            api_rules: Some(Arc::new(rules)),
            ..Config::default()
        };
        let bytes = pe(
            &[(
                K32,
                &[
                    "Beep",
                    "OpenProcess",
                    "VirtualAllocEx",
                    "WriteProcessMemory",
                    "CreateRemoteThread",
                ],
            )],
            &[],
        );
        let r = run_with(bytes, &config);
        assert_eq!(api_ids(&r), ["PE-API-CUSTOM-BEEP"]);
    }
}

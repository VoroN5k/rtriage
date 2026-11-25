//! ELF API behavior groups (`rules/elf_api_groups.toml`).
//!
//! The primary view is what the binary imports: undefined named `.dynsym`
//! symbols, with defined dynamic symbols as exports. If the file also has a
//! static `.symtab`, an extended view adds its defined functions: a rule that
//! only matches with those (code linked in, not necessarily used, typical of
//! non-stripped static binaries) is reported with low confidence. Static
//! functions never count as exports or as an import table: a statically linked
//! libc defines `readdir`, `dlopen` and `dlsym` in every static glibc binary.

use super::dynamic::ElfDynamic;
use crate::analyzers::rule_engine::{self, SymbolView, TextView};
use crate::analyzers::{AnalysisContext, Analyzer};
use crate::error::AnalysisError;
use crate::report::{Format, ReportBuilder};
use crate::rules::ApiRuleSet;

/// `STT_FUNC`.
const STT_FUNC: u8 = 2;

/// Evaluates the configured (or bundled) ELF API behavior rules.
#[derive(Debug, Clone, Copy, Default)]
pub struct ElfApiGroupsAnalyzer;

impl Analyzer for ElfApiGroupsAnalyzer {
    fn name(&self) -> &'static str {
        "elf-api-groups"
    }

    fn applies_to(&self, format: Format) -> bool {
        format == Format::Elf
    }

    fn run(&self, ctx: &AnalysisContext<'_>, out: &mut ReportBuilder) -> Result<(), AnalysisError> {
        // A broken dynamic section is reported by elf-dynamic; skip silently.
        let Some(Ok(dynamic)) = ctx.elf_dynamic() else {
            return Ok(());
        };
        let rules: &ApiRuleSet = match &ctx.config.elf_api_rules {
            Some(custom) => custom,
            None => ApiRuleSet::bundled_elf().map_err(|e| AnalysisError::Internal {
                reason: format!("bundled ELF API rules are invalid: {e}"),
            })?,
        };
        let primary = primary_view(dynamic);
        let extended = extended_view(dynamic, &primary);
        let (findings, strings_error) = rule_engine::evaluate(
            rules,
            &primary,
            extended.as_ref(),
            &ctx.deadline,
            &mut || {
                Ok(TextView {
                    strings: ctx.strings()?,
                    iocs: ctx.iocs()?,
                })
            },
        )?;
        for f in findings {
            out.push_finding(f);
        }
        strings_error.map_or(Ok(()), Err)
    }
}

fn primary_view(d: &ElfDynamic) -> SymbolView<'_> {
    let imports: Vec<_> = d.imports().map(|n| (None, n)).collect();
    SymbolView {
        import_count: Some(imports.len() as u64),
        imports,
        exports: d
            .dynamic_symbols
            .iter()
            .filter(|s| s.defined && !s.name.is_empty())
            .map(|s| s.name.as_str())
            .collect(),
    }
}

/// Primary view plus defined static functions, or `None` without a `.symtab`.
fn extended_view<'a>(d: &'a ElfDynamic, primary: &SymbolView<'a>) -> Option<SymbolView<'a>> {
    let statics: Vec<&str> = d
        .static_symbols
        .iter()
        .filter(|s| s.defined && s.kind == STT_FUNC && !s.name.is_empty())
        .map(|s| s.name.as_str())
        .collect();
    if statics.is_empty() {
        return None;
    }
    // Static functions widen only what code is present. They are never
    // exports (interposition works through .dynsym only) and they are not an
    // import table, so `exports` and `max_imports` cannot match through them.
    let mut v = primary.clone();
    v.imports.extend(statics.iter().map(|n| (None, *n)));
    v.import_count = None;
    Some(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::input::Input;
    use crate::report::{Confidence, Report, Severity};
    use crate::Registry;
    use rtriage_fixtures::elf::{et, profiles, ElfBuilder};

    fn run(bytes: Vec<u8>) -> Report {
        let r = Registry::default().analyze(&Input::from_bytes("t", bytes), &Config::default());
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        r
    }

    fn api(r: &Report) -> Vec<&'static str> {
        r.findings
            .iter()
            .map(|f| f.id)
            .filter(|id| id.starts_with("ELF-API-"))
            .collect()
    }

    fn get<'a>(r: &'a Report, id: &str) -> &'a crate::report::Finding {
        r.findings.iter().find(|f| f.id == id).unwrap()
    }

    /// Dynamic executable importing `imports` with `strings` in `.rodata`.
    fn elf(imports: &[&str], strings: &[&str]) -> Vec<u8> {
        let mut ro = Vec::new();
        for s in strings {
            ro.extend_from_slice(s.as_bytes());
            ro.push(0);
        }
        ElfBuilder::x86_64()
            .needed("libc.so.6")
            .imports(imports)
            .rodata(ro)
            .build()
            .bytes
    }

    const SHELL: &[&str] = &["socket", "connect", "dup2", "execve"];

    #[test]
    fn bundled_elf_rules_are_valid() {
        let ids: Vec<_> = ApiRuleSet::bundled_elf()
            .unwrap()
            .groups
            .iter()
            .map(|g| g.id)
            .collect();
        assert_eq!(
            ids,
            [
                "ELF-API-SHELL",
                "ELF-API-FILELESS",
                "ELF-API-PRELOAD-ROOTKIT",
                "ELF-API-PERSISTENCE",
                "ELF-API-ANTIDEBUG",
                "ELF-API-NETWORK",
                "ELF-API-DYNAMIC-LOADING",
                "ELF-API-RANSOM-CRYPTO",
            ]
        );
    }

    #[test]
    fn benign_profiles_match_no_group() {
        for b in [
            profiles::glibc_pie(),
            profiles::go_static(),
            profiles::rust_pie(),
            profiles::busybox_static(),
        ] {
            let r = run(b.build().bytes);
            assert!(api(&r).is_empty(), "{:?}", api(&r));
        }
    }

    // ---- shell

    #[test]
    fn shell_with_shell_string_is_high_medium() {
        let r = run(elf(SHELL, &["/bin/sh", "-i"]));
        let f = get(&r, "ELF-API-SHELL");
        assert_eq!(
            (f.severity, f.confidence),
            (Severity::High, Confidence::Medium)
        );
        assert_eq!(f.attack, ["T1059.004"]);
    }

    #[test]
    fn shell_without_shell_string_is_medium_low() {
        let r = run(elf(SHELL, &["usage: relay host port"]));
        let f = get(&r, "ELF-API-SHELL");
        assert_eq!(
            (f.severity, f.confidence),
            (Severity::Medium, Confidence::Low)
        );
    }

    #[test]
    fn shell_string_without_api_chain_is_nothing() {
        // BusyBox-like: shell paths everywhere, no socket/dup2 imports.
        let r = run(elf(&["printf", "execve"], &["/bin/sh"]));
        assert!(!api(&r).contains(&"ELF-API-SHELL"));
    }

    #[test]
    fn non_stripped_static_chain_is_low_confidence() {
        // Static binary whose .symtab defines the chain (linked in, maybe unused).
        let bytes = ElfBuilder::x86_64()
            .symtab(&["main", "socket", "connect", "dup2", "execve"])
            .rodata(b"/bin/sh\0".to_vec())
            .build()
            .bytes;
        let r = run(bytes);
        let f = get(&r, "ELF-API-SHELL");
        assert_eq!(
            (f.severity, f.confidence),
            (Severity::High, Confidence::Low)
        );
        assert!(f.detail.contains("static symbol table"));
    }

    // ---- fileless

    #[test]
    fn memfd_exec_is_fileless_medium_low() {
        let r = run(elf(&["memfd_create", "write", "fexecve"], &[]));
        let f = get(&r, "ELF-API-FILELESS");
        assert_eq!(
            (f.severity, f.confidence),
            (Severity::Medium, Confidence::Low)
        );
    }

    #[test]
    fn memfd_alone_is_not_fileless() {
        assert!(api(&run(elf(&["memfd_create", "mmap"], &[]))).is_empty());
    }

    // ---- LD_PRELOAD rootkit

    #[test]
    fn preload_writer_is_rootkit() {
        let r = run(elf(
            &["fopen", "fputs", "fclose"],
            &["/etc/ld.so.preload", "/usr/lib/libx.so"],
        ));
        assert!(api(&r).contains(&"ELF-API-PRELOAD-ROOTKIT"));
    }

    #[test]
    fn rootkit_scanners_are_not_rootkits() {
        for marker in [
            "chkrootkit version 0.58b",
            "Rootkit Hunter version 1.4.6",
            "rkhunter",
            "Checking `ld.so.preload'... not infected",
            "unhide-linux",
        ] {
            let r = run(elf(
                &["fopen", "fprintf", "fgets", "opendir", "readdir"],
                &["/etc/ld.so.preload", marker],
            ));
            assert!(!api(&r).contains(&"ELF-API-PRELOAD-ROOTKIT"), "{marker}");
        }
    }

    #[test]
    fn readdir_hooking_library_is_rootkit() {
        // libprocesshider-style: exports readdir, resolves the real one with dlsym.
        let bytes = ElfBuilder::x86_64()
            .elf_type(et::DYN)
            .needed("libdl.so.2")
            .imports(&["dlsym", "strcmp", "snprintf"])
            .dyn_exports(&["readdir"])
            .rodata(b"/proc/self/fd/%d\0".to_vec())
            .build()
            .bytes;
        let r = run(bytes);
        let f = get(&r, "ELF-API-PRELOAD-ROOTKIT");
        assert_eq!(
            (f.severity, f.confidence),
            (Severity::Medium, Confidence::Medium)
        );
        assert!(f.evidence.iter().any(|e| matches!(
            e,
            crate::report::Evidence::Field { name: "export", value } if value == "readdir"
        )));
    }

    /// Regression: a real `gcc -static` hello world (glibc) defines `readdir`,
    /// `dlopen`, `dlsym`, `open`, `write` in `.symtab` and contains
    /// `/proc/self/...` strings. It used to get PRELOAD-ROOTKIT and
    /// DYNAMIC-LOADING through the static view.
    #[test]
    fn static_glibc_hello_matches_no_group() {
        let bytes = ElfBuilder::x86_64()
            .symtab(&[
                "main",
                "__libc_start_main",
                "_dl_non_dynamic_init",
                "readdir",
                "readdir64",
                "opendir",
                "dlopen",
                "__libc_dlopen_mode",
                "dlsym",
                "open",
                "write",
                "puts",
            ])
            .rodata(b"/proc/self/maps\0/proc/sys/kernel/osrelease\0hi\0".to_vec())
            .build()
            .bytes;
        let r = run(bytes);
        assert!(api(&r).is_empty(), "{:?}", api(&r));
    }

    #[test]
    fn libc_like_library_exporting_readdir_is_not_rootkit() {
        // A libc *defines* readdir and dlsym; it does not import dlsym.
        let bytes = ElfBuilder::x86_64()
            .elf_type(et::DYN)
            .needed("ld-linux-x86-64.so.2")
            .imports(&["__tls_get_addr"])
            .dyn_exports(&["readdir", "readdir64", "dlsym", "opendir"])
            .rodata(b"/proc/self/maps\0".to_vec())
            .build()
            .bytes;
        assert!(!api(&run(bytes)).contains(&"ELF-API-PRELOAD-ROOTKIT"));
    }

    #[test]
    fn readdir_hook_inside_a_scanner_is_vetoed() {
        let bytes = ElfBuilder::x86_64()
            .elf_type(et::DYN)
            .needed("libdl.so.2")
            .imports(&["dlsym"])
            .dyn_exports(&["readdir"])
            .rodata(b"/proc\0unhide: hidden process scanner\0".to_vec())
            .build()
            .bytes;
        assert!(!api(&run(bytes)).contains(&"ELF-API-PRELOAD-ROOTKIT"));
    }
    // ---- persistence

    #[test]
    fn cron_writer_is_persistence() {
        let r = run(elf(
            &["fopen", "fprintf"],
            &["* * * * * /tmp/.x\n", "/var/spool/cron/crontabs/root"],
        ));
        assert!(api(&r).contains(&"ELF-API-PERSISTENCE"));
    }

    #[test]
    fn startup_paths_without_write_apis_are_nothing() {
        let r = run(elf(
            &["printf", "getenv"],
            &["/etc/systemd/system", ".bashrc"],
        ));
        assert!(!api(&r).contains(&"ELF-API-PERSISTENCE"));
    }

    // ---- anti-debug

    #[test]
    fn ptrace_and_prctl_is_antidebug() {
        assert!(api(&run(elf(&["ptrace", "prctl"], &[]))).contains(&"ELF-API-ANTIDEBUG"));
    }

    #[test]
    fn tracerpid_check_is_antidebug() {
        assert!(api(&run(elf(&["fopen", "fgets"], &["TracerPid:"]))).contains(&"ELF-API-ANTIDEBUG"));
    }

    #[test]
    fn debugger_like_ptrace_alone_is_not_antidebug() {
        assert!(api(&run(elf(&["ptrace", "waitpid", "fork"], &[]))).is_empty());
    }

    // ---- network

    #[test]
    fn socket_client_with_ip_is_network() {
        let r = run(elf(&["socket", "connect", "send"], &["45.13.227.8"]));
        assert_eq!(api(&r), ["ELF-API-NETWORK"]);
    }

    #[test]
    fn local_and_allowlisted_endpoints_are_not_network() {
        for s in [
            "127.0.0.1",
            "http://localhost:8080/health",
            "http://api.localhost/v1",
            "172.16.0.10",
            "169.254.169.254",
            "100.64.0.1",
            "203.0.113.9",
            "fe80::1:2:3",
            "http://10.0.0.1:9000/metrics",
            "https://www.openssl.org/docs/",
        ] {
            let r = run(elf(&["socket", "connect", "send"], &[s]));
            assert!(!api(&r).contains(&"ELF-API-NETWORK"), "{s}");
        }
    }

    #[test]
    fn version_strings_are_not_endpoints() {
        for s in [
            "10.0.19041.1",
            "6.1.7601.17514",
            "version 1.2.3.4",
            "libfoo.so.1.2.3.4",
        ] {
            let r = run(elf(&["socket", "connect"], &[s]));
            assert!(!api(&r).contains(&"ELF-API-NETWORK"), "{s}");
        }
    }

    #[test]
    fn socket_client_without_endpoint_is_not_network() {
        assert!(api(&run(elf(&["socket", "connect"], &["usage: client"]))).is_empty());
    }

    // ---- dynamic loading

    #[test]
    fn tiny_table_with_dlopen_dlsym_is_dynamic_loading() {
        let r = run(elf(&["dlopen", "dlsym", "exit"], &[]));
        let f = get(&r, "ELF-API-DYNAMIC-LOADING");
        assert_eq!(f.attack, ["T1027.007"]);
    }

    #[test]
    fn normal_table_with_dlopen_is_not_dynamic_loading() {
        let names: Vec<String> = (0..30).map(|i| format!("f{i}")).collect();
        let mut refs: Vec<&str> = names.iter().map(String::as_str).collect();
        refs.extend(["dlopen", "dlsym"]);
        assert!(api(&run(elf(&refs, &[]))).is_empty());
    }

    // ---- ransomware

    #[test]
    fn crypto_walk_and_extensions_is_ransom() {
        let r = run(elf(
            &["EVP_EncryptInit_ex", "opendir", "readdir"],
            &[".docx.xlsx.pptx.pdf.jpg.png.zip.rar.sql.bak"],
        ));
        assert!(api(&r).contains(&"ELF-API-RANSOM-CRYPTO"));
    }

    #[test]
    fn backup_tool_is_not_ransom() {
        let r = run(elf(
            &["EVP_EncryptInit_ex", "opendir", "readdir"],
            &["backup.tar", "notes.txt"],
        ));
        assert!(!api(&r).contains(&"ELF-API-RANSOM-CRYPTO"));
    }
}

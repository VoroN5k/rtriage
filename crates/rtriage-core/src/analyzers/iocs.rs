//! IOC extraction: URLs, domains, IPs, emails and wallet addresses found in
//! the shared strings, deduplicated and normalized, with IP scope,
//! allowlisting (`rules/ioc_allowlist.toml`) and a defanged form.
//!
//! Facts only: IOCs never produce findings or points by themselves (behavior
//! groups may use string kinds). `defang` / `defang_text` are pure helpers
//! for renderers.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::LazyLock;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::analyzers::strings::classify::classifier;
use crate::analyzers::{AnalysisContext, Analyzer};
use crate::deadline::Deadline;
use crate::error::AnalysisError;
use crate::report::{
    Format, Ioc, IocFacts, IocKind, IpScope, ReportBuilder, StringKind, StringsFacts,
};
use crate::rules::{RulesError, MAX_RULES_FILE_SIZE, SCHEMA_VERSION};

/// The allowlist shipped with rtriage.
pub const BUNDLED_IOC_ALLOWLIST: &str = include_str!("../../../../rules/ioc_allowlist.toml");
/// Offsets kept per IOC.
pub const MAX_OFFSETS_PER_IOC: usize = 8;
/// Most allowlist entries accepted.
const MAX_ALLOWLIST_ENTRIES: usize = 10_000;
/// Strings processed between deadline checks.
const DEADLINE_STRIDE: usize = 256;

// ------------------------------------------------------------- allowlist

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAllowlist {
    schema_version: u32,
    #[serde(default)]
    domains: Vec<String>,
}

/// Validated IOC allowlist.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IocAllowlist {
    /// Lowercase domains; each covers its subdomains.
    pub domains: Vec<String>,
}

impl IocAllowlist {
    /// The bundled allowlist (parsed once).
    ///
    /// # Errors
    /// Only if the bundled file is broken, which the test suite prevents.
    pub fn bundled() -> Result<&'static IocAllowlist, &'static RulesError> {
        static BUNDLED: LazyLock<Result<IocAllowlist, RulesError>> =
            LazyLock::new(|| IocAllowlist::parse(BUNDLED_IOC_ALLOWLIST));
        BUNDLED.as_ref()
    }

    /// Parses and validates an allowlist file.
    ///
    /// # Errors
    /// See [`RulesError`].
    pub fn parse(text: &str) -> Result<Self, RulesError> {
        if text.len() > MAX_RULES_FILE_SIZE {
            return Err(RulesError::TooLarge {
                size: text.len(),
                limit: MAX_RULES_FILE_SIZE,
            });
        }
        let raw: RawAllowlist = toml::from_str(text).map_err(|e| RulesError::Syntax {
            reason: e.to_string(),
        })?;
        if raw.schema_version != SCHEMA_VERSION {
            return Err(RulesError::Schema {
                found: raw.schema_version,
            });
        }
        if raw.domains.len() > MAX_ALLOWLIST_ENTRIES {
            return Err(RulesError::TooManyGroups {
                count: raw.domains.len(),
            });
        }
        let mut domains = Vec::with_capacity(raw.domains.len());
        for d in raw.domains {
            let ok = d.contains('.')
                && !d.starts_with('.')
                && !d.ends_with('.')
                && d.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-'
                });
            if !ok {
                return Err(RulesError::Invalid {
                    id: d,
                    reason: "allowlist domains must be lowercase names like \"example.com\" \
                             (no wildcards, no trailing dot)"
                        .into(),
                });
            }
            if !domains.contains(&d) {
                domains.push(d);
            }
        }
        domains.sort();
        Ok(Self { domains })
    }

    /// Union of `self` and `defaults` (allowlists only ever add). The merged
    /// list obeys the same entry limit as a single file.
    ///
    /// # Errors
    /// [`RulesError::TooManyGroups`] if the union is too large.
    pub fn merged_over(self, defaults: &IocAllowlist) -> Result<IocAllowlist, RulesError> {
        let mut domains = defaults.domains.clone();
        for d in self.domains {
            if !domains.contains(&d) {
                domains.push(d);
            }
        }
        if domains.len() > MAX_ALLOWLIST_ENTRIES {
            return Err(RulesError::TooManyGroups {
                count: domains.len(),
            });
        }
        domains.sort();
        Ok(IocAllowlist { domains })
    }

    /// `true` if `domain` (lowercase) is listed or a subdomain of a listed one.
    pub fn allows_domain(&self, domain: &str) -> bool {
        self.domains.iter().any(|d| {
            domain == d
                || domain
                    .strip_suffix(d.as_str())
                    .is_some_and(|rest| rest.ends_with('.'))
        })
    }
}

// ------------------------------------------------------------- analyzer

/// Extracts IOCs from the shared strings.
#[derive(Debug, Clone, Copy, Default)]
pub struct IocAnalyzer;

impl Analyzer for IocAnalyzer {
    fn name(&self) -> &'static str {
        "iocs"
    }

    fn applies_to(&self, _format: Format) -> bool {
        true
    }

    fn run(&self, ctx: &AnalysisContext<'_>, out: &mut ReportBuilder) -> Result<(), AnalysisError> {
        out.facts.iocs = Some(ctx.iocs()?.clone());
        Ok(())
    }
}

/// Extracts IOCs from `strings` (normally via [`AnalysisContext::iocs`]).
///
/// # Errors
/// [`AnalysisError::Timeout`] from `deadline`, [`AnalysisError::Internal`]
/// if a built-in pattern is invalid.
pub fn extract(
    strings: &StringsFacts,
    allow: &IocAllowlist,
    max_iocs: usize,
    deadline: &Deadline,
) -> Result<IocFacts, AnalysisError> {
    let classifier = classifier().map_err(|e| AnalysisError::Internal {
        reason: format!("built-in string pattern is invalid: {e}"),
    })?;
    let mut acc = Accumulator::new(max_iocs);
    for (i, s) in strings.items.iter().enumerate() {
        if i % DEADLINE_STRIDE == 0 {
            deadline.check()?;
        }
        if !s.kinds.iter().any(|k| IOC_STRING_KINDS.contains(k)) {
            continue;
        }
        for span in classifier.ioc_spans(&s.value) {
            let Some(raw) = s.value.get(span.start..span.end) else {
                continue;
            };
            for (kind, value) in normalize(span.kind, raw) {
                acc.add(kind, value, s.offset);
            }
        }
    }
    Ok(acc.finish(allow))
}

/// The IOC kind a rule's string kind is evaluated against, if any. Network
/// kinds are matched on IOCs so scope and allowlisting apply; the rest stay
/// plain string classifications.
pub fn ioc_kind_for(kind: StringKind) -> Option<IocKind> {
    match kind {
        StringKind::Url => Some(IocKind::Url),
        StringKind::Domain => Some(IocKind::Domain),
        StringKind::Ipv4 => Some(IocKind::Ipv4),
        StringKind::Ipv6 => Some(IocKind::Ipv6),
        StringKind::Email => Some(IocKind::Email),
        _ => None,
    }
}

/// Scope an IOC is judged by: its own for IPs, its host's for URLs with an
/// IP host (`localhost` counts as loopback), `None` otherwise.
pub fn effective_scope(ioc: &Ioc) -> Option<IpScope> {
    match ioc.kind {
        IocKind::Ipv4 | IocKind::Ipv6 => ioc.scope,
        IocKind::Url => {
            let u = split_url(&ioc.value)?;
            if u.host == "localhost" || u.host.ends_with(".localhost") {
                return Some(IpScope::Loopback); // RFC 6761
            }
            scope_of(IocKind::Ipv4, &u.host).or_else(|| scope_of(IocKind::Ipv6, &u.host))
        }
        _ => None,
    }
}

/// String kinds that can contain an IOC (cheap pre-filter).
const IOC_STRING_KINDS: &[StringKind] = &[
    StringKind::Url,
    StringKind::Ipv4,
    StringKind::Ipv6,
    StringKind::Domain,
    StringKind::Email,
    StringKind::CryptoWallet,
];

struct Entry {
    count: u64,
    offsets: Vec<u64>,
}

struct Accumulator {
    map: BTreeMap<(IocKind, String), Entry>,
    max: usize,
    limit_reached: bool,
}

impl Accumulator {
    fn new(max: usize) -> Self {
        Self {
            map: BTreeMap::new(),
            max,
            limit_reached: false,
        }
    }

    fn add(&mut self, kind: IocKind, value: String, offset: u64) {
        let key = (kind, value);
        if let Some(e) = self.map.get_mut(&key) {
            e.count = e.count.saturating_add(1);
            if e.offsets.len() < MAX_OFFSETS_PER_IOC && e.offsets.last() != Some(&offset) {
                e.offsets.push(offset);
            }
            return;
        }
        if self.map.len() >= self.max {
            self.limit_reached = true;
            return;
        }
        self.map.insert(
            key,
            Entry {
                count: 1,
                offsets: vec![offset],
            },
        );
    }

    fn finish(self, allow: &IocAllowlist) -> IocFacts {
        let mut items: Vec<Ioc> = self
            .map
            .into_iter()
            .map(|((kind, value), mut e)| {
                e.offsets.sort_unstable();
                e.offsets.dedup();
                Ioc {
                    kind,
                    value_defanged: defang(kind, &value),
                    scope: scope_of(kind, &value),
                    allowlisted: is_allowlisted(kind, &value, allow),
                    count: e.count,
                    offsets: e.offsets,
                    value,
                }
            })
            .collect();
        items.sort_by(|a, b| (a.kind, &a.value).cmp(&(b.kind, &b.value)));
        IocFacts {
            allowlisted: items.iter().filter(|i| i.allowlisted).count() as u64,
            items,
            limit_reached: self.limit_reached,
        }
    }
}

// ------------------------------------------------------------- normalization

/// Normalized IOCs for one raw match; a URL also yields its host.
fn normalize(kind: IocKind, raw: &str) -> Vec<(IocKind, String)> {
    match kind {
        IocKind::Url => match split_url(raw) {
            Some(u) => {
                let mut v = vec![(IocKind::Url, u.normalized())];
                if let Some(host) = host_ioc(&u.host) {
                    v.push(host);
                }
                v
            }
            None => Vec::new(),
        },
        IocKind::Email => vec![(IocKind::Email, raw.to_ascii_lowercase())],
        IocKind::Ipv4 => raw
            .parse::<Ipv4Addr>()
            .map(|ip| vec![(IocKind::Ipv4, ip.to_string())])
            .unwrap_or_default(),
        IocKind::Ipv6 => raw
            .parse::<Ipv6Addr>()
            .map(|ip| vec![(IocKind::Ipv6, ip.to_string())])
            .unwrap_or_default(),
        IocKind::Domain => {
            vec![(
                IocKind::Domain,
                raw.trim_end_matches('.').to_ascii_lowercase(),
            )]
        }
        IocKind::CryptoWallet => {
            let base58_btc = raw.starts_with('1') || raw.starts_with('3');
            if base58_btc && !base58check_ok(raw) {
                Vec::new()
            } else {
                vec![(IocKind::CryptoWallet, raw.to_owned())]
            }
        }
    }
}

/// A URL split into parts; `host` is lowercase, without brackets or port.
struct UrlParts<'a> {
    scheme: String,
    userinfo: Option<&'a str>,
    host: String,
    bracketed: bool,
    port: Option<&'a str>,
    rest: &'a str,
}

impl UrlParts<'_> {
    fn normalized(&self) -> String {
        let mut s = format!("{}://", self.scheme);
        if let Some(u) = self.userinfo {
            s.push_str(u);
            s.push('@');
        }
        if self.bracketed {
            s.push('[');
            s.push_str(&self.host);
            s.push(']');
        } else {
            s.push_str(&self.host);
        }
        if let Some(p) = self.port {
            s.push(':');
            s.push_str(p);
        }
        s.push_str(self.rest);
        s
    }
}

fn split_url(raw: &str) -> Option<UrlParts<'_>> {
    let (scheme, after) = raw.split_once("://")?;
    let auth_end = after.find(['/', '?', '#']).unwrap_or(after.len());
    let authority = after.get(..auth_end)?;
    let rest = after.get(auth_end..)?;
    let (userinfo, hostport) = match authority.rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, authority),
    };
    let (host, bracketed, port) = if let Some(inner) = hostport.strip_prefix('[') {
        let (h, tail) = inner.split_once(']')?;
        (h, true, tail.strip_prefix(':'))
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => {
                (h, false, Some(p))
            }
            _ => (hostport, false, None),
        }
    };
    if host.is_empty() {
        return None;
    }
    Some(UrlParts {
        scheme: scheme.to_ascii_lowercase(),
        userinfo,
        host: host.trim_end_matches('.').to_ascii_lowercase(),
        bracketed,
        port,
        rest,
    })
}

/// The host of a URL as its own IOC: IP, or a domain with an alphabetic TLD.
fn host_ioc(host: &str) -> Option<(IocKind, String)> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Some((IocKind::Ipv4, ip.to_string()));
    }
    if let Ok(ip) = host.parse::<Ipv6Addr>() {
        return Some((IocKind::Ipv6, ip.to_string()));
    }
    let valid = host.contains('.')
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
        && host
            .rsplit('.')
            .next()
            .is_some_and(|tld| tld.len() >= 2 && tld.bytes().all(|b| b.is_ascii_alphabetic()));
    valid.then(|| (IocKind::Domain, host.to_owned()))
}

/// Base58Check for legacy (`1...`) and P2SH (`3...`) Bitcoin addresses.
fn base58check_ok(s: &str) -> bool {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut out = [0u8; 25];
    for c in s.bytes() {
        let Some(digit) = ALPHABET.iter().position(|&a| a == c) else {
            return false;
        };
        let mut carry = digit as u32;
        for b in out.iter_mut().rev() {
            carry += u32::from(*b) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        if carry != 0 {
            return false; // more than 25 bytes
        }
    }
    let ones = s.bytes().take_while(|&b| b == b'1').count();
    let zeros = out.iter().take_while(|&&b| b == 0).count();
    if ones != zeros {
        return false;
    }
    let (payload, check) = out.split_at(21);
    let digest = Sha256::digest(Sha256::digest(payload));
    digest.get(..4) == Some(check)
}

fn is_allowlisted(kind: IocKind, value: &str, allow: &IocAllowlist) -> bool {
    match kind {
        IocKind::Domain => allow.allows_domain(value),
        IocKind::Url => split_url(value).is_some_and(|u| allow.allows_domain(&u.host)),
        IocKind::Email => value
            .rsplit_once('@')
            .is_some_and(|(_, d)| allow.allows_domain(d)),
        _ => false,
    }
}

// ------------------------------------------------------------- IP scope

fn scope_of(kind: IocKind, value: &str) -> Option<IpScope> {
    match kind {
        IocKind::Ipv4 => value.parse::<Ipv4Addr>().ok().map(scope_v4),
        IocKind::Ipv6 => value.parse::<Ipv6Addr>().ok().map(scope_v6),
        _ => None,
    }
}

/// Scope of an IPv4 address.
pub fn scope_v4(ip: Ipv4Addr) -> IpScope {
    let [a, b, c, _] = ip.octets();
    if ip.is_unspecified() {
        IpScope::Unspecified
    } else if ip.is_broadcast() {
        IpScope::Broadcast
    } else if ip.is_loopback() {
        IpScope::Loopback
    } else if ip.is_private() {
        IpScope::Private
    } else if ip.is_link_local() {
        IpScope::LinkLocal
    } else if ip.is_documentation() {
        IpScope::Documentation
    } else if ip.is_multicast() {
        IpScope::Multicast
    } else if a == 100 && (64..128).contains(&b) {
        IpScope::Shared
    } else if a == 0
        || a >= 240
        || (a == 198 && (b == 18 || b == 19))
        || (a == 192 && b == 0 && c == 0)
    {
        IpScope::Reserved
    } else {
        IpScope::Public
    }
}

/// Scope of an IPv6 address (IPv4-mapped addresses use the IPv4 rules).
pub fn scope_v6(ip: Ipv6Addr) -> IpScope {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return scope_v4(v4);
    }
    let first = ip.segments().first().copied().unwrap_or(0);
    let second = ip.segments().get(1).copied().unwrap_or(0);
    if ip.is_unspecified() {
        IpScope::Unspecified
    } else if ip.is_loopback() {
        IpScope::Loopback
    } else if ip.is_multicast() {
        IpScope::Multicast
    } else if first & 0xffc0 == 0xfe80 {
        IpScope::LinkLocal
    } else if first & 0xfe00 == 0xfc00 {
        IpScope::Private
    } else if first == 0x2001 && second == 0x0db8 {
        IpScope::Documentation
    } else {
        IpScope::Public
    }
}

// ------------------------------------------------------------- defang

/// Defanged form of a normalized IOC: `hxxp://evil[.]com/x`, `1[.]2[.]3[.]4`,
/// `2001[:]db8[:][:]1`, `user[@]evil[.]com`. Wallets are returned unchanged.
pub fn defang(kind: IocKind, value: &str) -> String {
    match kind {
        IocKind::Url => defang_url(value),
        IocKind::Domain | IocKind::Ipv4 => value.replace('.', "[.]"),
        IocKind::Ipv6 => value.replace(':', "[:]"),
        IocKind::Email => match value.rsplit_once('@') {
            Some((local, domain)) => format!("{local}[@]{}", domain.replace('.', "[.]")),
            None => value.to_owned(),
        },
        IocKind::CryptoWallet => value.to_owned(),
    }
}

/// `http`->`hxxp`, `ftp`->`fxp` (case-insensitive), dots in the authority
/// bracketed; the path is left as is.
fn defang_url(value: &str) -> String {
    let Some((scheme, after)) = value.split_once("://") else {
        return value.to_owned();
    };
    let lower = scheme.to_ascii_lowercase();
    let scheme = match lower.as_str() {
        "http" => "hxxp".to_owned(),
        "https" => "hxxps".to_owned(),
        "ftp" => "fxp".to_owned(),
        _ => lower,
    };
    let auth_end = after.find(['/', '?', '#']).unwrap_or(after.len());
    let authority = after.get(..auth_end).unwrap_or(after);
    let rest = after.get(auth_end..).unwrap_or_default();
    format!("{scheme}://{}{rest}", authority.replace('.', "[.]"))
}

/// Defangs every URL, domain, IP and email inside free text (evidence,
/// strings) for display. Text without IOCs is returned borrowed.
pub fn defang_text(s: &str) -> Cow<'_, str> {
    let Ok(c) = classifier() else {
        return Cow::Borrowed(s);
    };
    let spans: Vec<_> = c
        .ioc_spans(s)
        .into_iter()
        .filter(|sp| sp.kind != IocKind::CryptoWallet)
        .collect();
    if spans.is_empty() {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len().saturating_add(16));
    let mut at = 0;
    for sp in spans {
        let (Some(before), Some(raw)) = (s.get(at..sp.start), s.get(sp.start..sp.end)) else {
            continue;
        };
        out.push_str(before);
        out.push_str(&defang(sp.kind, raw));
        at = sp.end;
    }
    out.push_str(s.get(at..).unwrap_or_default());
    Cow::Owned(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::input::Input;
    use crate::report::Report;
    use crate::Registry;
    use rtriage_fixtures::elf::ElfBuilder;
    use std::sync::Arc;

    fn analyze_with(strings: &[&str], config: &Config) -> Report {
        let mut ro = Vec::new();
        for s in strings {
            ro.extend_from_slice(s.as_bytes());
            ro.push(0);
        }
        let bytes = ElfBuilder::x86_64().rodata(ro).build().bytes;
        let r = Registry::default().analyze(&Input::from_bytes("t", bytes), config);
        assert!(r.errors.is_empty(), "{:?}", r.errors);
        r
    }

    fn iocs(strings: &[&str]) -> IocFacts {
        analyze_with(strings, &Config::default())
            .facts
            .iocs
            .unwrap()
    }

    fn values(f: &IocFacts, kind: IocKind) -> Vec<&str> {
        f.items
            .iter()
            .filter(|i| i.kind == kind)
            .map(|i| i.value.as_str())
            .collect()
    }

    fn get<'a>(f: &'a IocFacts, value: &str) -> &'a Ioc {
        f.items.iter().find(|i| i.value == value).unwrap()
    }

    #[test]
    fn bundled_allowlist_is_valid() {
        let a = IocAllowlist::bundled().unwrap();
        assert!(a.allows_domain("schemas.microsoft.com"));
        assert!(a.allows_domain("microsoft.com"));
        assert!(!a.allows_domain("notmicrosoft.com"));
        assert!(!a.allows_domain("github.com"));
    }

    #[test]
    fn allowlist_rejects_wildcards_and_uppercase() {
        for bad in ["*.evil.com", "Example.com", "example.com.", "localhost"] {
            let t = format!("schema_version = 1\ndomains = [\"{bad}\"]");
            assert!(IocAllowlist::parse(&t).is_err(), "{bad}");
        }
    }

    #[test]
    fn url_with_path_and_host_ioc() {
        let f = iocs(&["GET HTTP://Evil.Example.COM:8080/a/b.php?id=1 now."]);
        assert_eq!(
            values(&f, IocKind::Url),
            ["http://evil.example.com:8080/a/b.php?id=1"]
        );
        assert_eq!(values(&f, IocKind::Domain), ["evil.example.com"]);
        let u = get(&f, "http://evil.example.com:8080/a/b.php?id=1");
        assert_eq!(
            u.value_defanged,
            "hxxp://evil[.]example[.]com:8080/a/b.php?id=1"
        );
    }

    #[test]
    fn url_ip_host_yields_ip_with_scope() {
        let f = iocs(&["http://45.13.227.8/x", "https://[2001:db8::1]:443/"]);
        assert_eq!(get(&f, "45.13.227.8").scope, Some(IpScope::Public));
        assert_eq!(get(&f, "2001:db8::1").scope, Some(IpScope::Documentation));
    }

    #[test]
    fn dedup_counts_and_offsets() {
        let f = iocs(&["c2 45.13.227.8", "again 45.13.227.8", "and 45.13.227.8"]);
        let ip = get(&f, "45.13.227.8");
        assert_eq!(ip.count, 3);
        assert_eq!(ip.offsets.len(), 3);
        assert!(ip.offsets.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(ip.value_defanged, "45[.]13[.]227[.]8");
    }

    #[test]
    fn email_is_not_also_a_domain() {
        let f = iocs(&["mail Admin@Evil-Corp.ru please"]);
        assert_eq!(values(&f, IocKind::Email), ["admin@evil-corp.ru"]);
        assert!(values(&f, IocKind::Domain).is_empty());
        assert_eq!(
            get(&f, "admin@evil-corp.ru").value_defanged,
            "admin[@]evil-corp[.]ru"
        );
    }

    #[test]
    fn versions_and_dll_names_are_not_iocs() {
        let f = iocs(&[
            "FileVersion 10.0.19041.1",
            "kernel32.dll",
            "setup.exe",
            "1.2.3.4.5",
        ]);
        assert!(f.items.is_empty(), "{:?}", f.items);
    }

    #[test]
    fn ip_scopes() {
        let cases = [
            ("127.0.0.1", IpScope::Loopback),
            ("10.1.2.3", IpScope::Private),
            ("192.168.1.10", IpScope::Private),
            ("169.254.1.1", IpScope::LinkLocal),
            ("100.64.0.1", IpScope::Shared),
            ("198.51.100.7", IpScope::Documentation),
            ("239.1.1.1", IpScope::Multicast),
            ("255.255.255.255", IpScope::Broadcast),
            ("0.0.0.0", IpScope::Unspecified),
            ("240.0.0.1", IpScope::Reserved),
            ("8.8.8.8", IpScope::Public),
        ];
        for (ip, scope) in cases {
            assert_eq!(scope_v4(ip.parse().unwrap()), scope, "{ip}");
        }
        assert_eq!(scope_v6("::1".parse().unwrap()), IpScope::Loopback);
        assert_eq!(scope_v6("fe80::1".parse().unwrap()), IpScope::LinkLocal);
        assert_eq!(scope_v6("fd00::1".parse().unwrap()), IpScope::Private);
        assert_eq!(
            scope_v6("::ffff:10.0.0.1".parse().unwrap()),
            IpScope::Private
        );
        assert_eq!(scope_v6("2a00:1450::1".parse().unwrap()), IpScope::Public);
    }

    #[test]
    fn allowlisted_iocs_are_kept_and_counted() {
        let f = iocs(&[
            "http://schemas.microsoft.com/SMI/2005/WindowsSettings",
            "http://evil.top/p",
        ]);
        assert_eq!(f.allowlisted, 2); // the URL and its host
        let ms = get(&f, "http://schemas.microsoft.com/SMI/2005/WindowsSettings");
        assert!(ms.allowlisted);
        assert!(!get(&f, "http://evil.top/p").allowlisted);
    }

    #[test]
    fn custom_allowlist_replaces_the_bundled_one() {
        let config = Config {
            ioc_allowlist: Some(Arc::new(
                IocAllowlist::parse("schema_version = 1\ndomains = [\"evil.top\"]").unwrap(),
            )),
            ..Config::default()
        };
        let f = analyze_with(
            &["http://evil.top/p", "http://schemas.microsoft.com/x"],
            &config,
        )
        .facts
        .iocs
        .unwrap();
        assert!(get(&f, "http://evil.top/p").allowlisted);
        assert!(!get(&f, "http://schemas.microsoft.com/x").allowlisted);
    }

    #[test]
    fn bitcoin_checksum_is_verified() {
        // The genesis-block address (public, well-known test vector).
        assert!(base58check_ok("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"));
        assert!(!base58check_ok("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"));
        let f = iocs(&[
            "pay 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "id 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb",
        ]);
        assert_eq!(
            values(&f, IocKind::CryptoWallet),
            ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"]
        );
    }

    #[test]
    fn limit_is_enforced() {
        let mut config = Config::default();
        config.limits.max_iocs = 2;
        let f = analyze_with(&["1.1.1.1", "8.8.8.8", "9.9.9.9"], &config)
            .facts
            .iocs
            .unwrap();
        assert_eq!(f.items.len(), 2);
        assert!(f.limit_reached);
    }

    #[test]
    fn defang_forms() {
        assert_eq!(defang(IocKind::Url, "https://a.b/c.d"), "hxxps://a[.]b/c.d");
        assert_eq!(defang(IocKind::Url, "ftp://a.b"), "fxp://a[.]b");
        assert_eq!(defang(IocKind::Ipv6, "2001:db8::1"), "2001[:]db8[:][:]1");
        assert_eq!(defang(IocKind::Domain, "evil.com"), "evil[.]com");
    }

    #[test]
    fn defang_text_rewrites_only_iocs() {
        assert_eq!(
            defang_text("connect to http://evil.com/x or 1.2.3.4, mail a@b.ru"),
            "connect to hxxp://evil[.]com/x or 1[.]2[.]3[.]4, mail a[@]b[.]ru"
        );
        assert!(matches!(defang_text("kernel32.dll v1.0"), Cow::Borrowed(_)));
    }

    #[test]
    fn deadline_is_honoured() {
        let input = Input::from_bytes("t", b"http://evil.com/x\0".to_vec());
        let r = Registry::default().analyze_with_deadline(
            &input,
            &Config::default(),
            crate::Deadline::expired(),
        );
        assert!(r.facts.iocs.is_none());
        assert!(r
            .errors
            .iter()
            .any(|e| e.analyzer == "iocs" && matches!(e.error, AnalysisError::Timeout { .. })));
    }
}

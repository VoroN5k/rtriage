# Heuristics and scoring

Every finding ID, its rationale, thresholds and known false positives are
documented here. IDs are stable: renaming one requires a changelog note.

> Status: scoring v1 is implemented in `crates/rtriage-core/src/scoring.rs`,
> a direct transcription of this section. `--explain` prints the breakdown;
> JSON always carries it in `risk.breakdown`.

## Scoring v1

Scoring is deterministic and integer-only. No floating point is involved.

### Points per finding

Points come from this fixed table. It was derived once as
`(severity × confidence% + 50) / 100` (round half up) with severity weights
High 40, Medium 15, Low 5, Info 0 and confidence 100 / 70 / 40 %, but the
code uses the table, not the formula.

| Severity \ Confidence | high | medium | low |
|---|---|---|---|
| High | 40 | 28 | 16 |
| Medium | 15 | 11 | 6 |
| Low | 5 | 4 | 2 |
| Info | 0 | 0 | 0 |

### Caps

Per category:

| Category | Cap |
|---|---|
| `packing` | 30 |
| `obfuscation` | 30 |
| `anomaly` | 20 |
| `anti_analysis` | 15 |
| `hardening` | 10 |
| `metadata` | 0 |
| `injection`, `persistence`, `network`, `credential_access`, `collection`, `impact` | 40 each |

Global: the sum contributed by all `low`-severity findings is at most **15**.

### Algorithm and order

0. **Explained-by** (see below): findings explained by a confirmed packer are
   marked `suppressed`. They are listed with 0 points and take part in
   nothing else below: no deduplication, no caps.
1. **Points.** Each finding gets its points from the table.
2. **Deduplicate by ID.** If several findings share an ID, only the one with
   the most points counts; ties keep the first in report order (step 3).
   The others are listed by `--explain` with 0 points ("duplicate").
3. **Sort.** Remaining findings are ordered by, in this priority:
   1. severity, descending (`high` > `medium` > `low` > `info`);
   2. confidence, descending (`high` > `medium` > `low`);
   3. ID, ascending, compared byte-wise (IDs are ASCII).

   After deduplication IDs are unique, so this is a total order and the
   result does not depend on analyzer order. It is the same order the report
   uses for `findings`.
4. **Accumulate greedily** in that order. Each finding contributes
   `min(points, category cap remaining, low cap remaining if severity is low)`,
   and both remainders are reduced by the contribution.
5. **Score** = sum of contributions (a non-negative integer, bounded by the
   sum of category caps).
6. **Level:**

   | Score | Level |
   |---|---|
   | 0–9 | `clean_looking` |
   | 10–29 | `low` |
   | 30–59 | `medium` |
   | ≥ 60 | `high` |

Because the highest-severity, highest-confidence findings are taken first,
caps cut the weakest contributions. `--explain` prints every finding with its
table points, its contribution, and which cap (if any) reduced it.

### Explained-by: packer symptoms

A packer makes a file *look* anomalous in predictable ways (RWX sections,
virtual-only sections, high-entropy code, a stub entry point, a tiny import
table). Counting all of those separately would push any legitimately packed
tool to `high`. So once a packer is **confirmed**, the findings it
necessarily causes are explained by it.

- **Data.** [`rules/packers.toml`](../rules/packers.toml) lists per packer
  the indicators required to confirm it (`confirm_with`) and the finding IDs
  it explains (`explains`). Only UPX is listed for now.
- **Confirmation needs independent indicators, all of them.** For UPX:
  - `section_names`: `UPX0`/`UPX1`/... present;
  - `header_signature`: `UPX!` in the first 4 KiB of the headers;
  - `stub_structure`: an executable section with no raw data and >= 1 page
    of virtual size, immediately followed by an executable section with raw
    data, starting at or after the first one's end, containing the entry
    point. This check ignores section names.

  Spoofed names alone, or names + signature without the stub layout, confirm
  nothing; `PE-PACKER-KNOWN` still fires, but nothing is suppressed. The rule
  loader rejects `confirm_with` with fewer than two different indicators and
  indicators rtriage cannot check for that packer.
- **What can be explained.** Only structural PE findings:
  `PE-SECTION-RWX`, `PE-SECTION-VIRTUAL-ONLY`, `PE-SECTION-HIGH-ENTROPY`,
  `PE-SECTION-NAME-UNUSUAL`, `PE-ENTRYPOINT-UNUSUAL`,
  `PE-IMPORTS-DYNAMIC-RESOLUTION`, `PE-IMPORTS-FEW`, `PE-PACKED-LIKELY`,
  **API behavior groups (`PE-API-*`) are never suppressed**: the loader
  rejects them, and the scorer skips them even if a rule slipped through.
- **Effect.** A suppressed finding stays in `findings` with
  `suppressed: { by: "PE-PACKER-KNOWN", packer: "UPX" }`, scores 0, and
  consumes no category or low-severity cap. `--explain` shows each one.
- **Analysis limited.** Whenever `PE-PACKER-KNOWN` or `PE-PACKED-LIKELY` is
  present (confirmed or not), the report carries
  `analysis_limited: ["packed"]` and the text output shows
  `[PACKED: analysis limited]`: imports, strings and code findings describe
  the unpacking stub, not the real program, so a low score is *not* evidence
  of a benign file.

### Calibration checks

| Scenario | Points | Level |
|---|---|---|
| Single full injection chain (`PE-API-INJECTION`, High/High) | 40 | medium |
| Injection + anti-debug (Low/Medium) | 40 + 4 = 44 | medium |
| Injection + known packer (15) + RWX section (11) | 66 | high |
| Packing signals alone, any number | ≤ 30 | at most medium |
| TLS callbacks (Low/Medium) + anti-debug (Low/Medium) | 4 + 4 = 8 | clean_looking |
| Confirmed UPX, nothing else (all symptoms explained) | 15 | low, `packed` |
| Confirmed UPX + TLS callbacks | 15 + 4 = 19 | low, `packed` |
| Confirmed UPX + injection chain | 15 + 40 = 55 | medium, `packed` |
| Spoofed UPX names on an RWX + dynamic-resolution file | nothing suppressed | full score |
| Confirmed UPX + encrypted `RT_RCDATA` | 15 (resource finding explained) | low, `packed` |
| Reflective-loader DLL + injection chain | 40 + 40, injection cap 40 | medium or above |
| Any file, signed vs. unsigned | identical score | unchanged |

These scenarios are end-to-end tests in `scoring.rs` (`end_to_end`).

**Packing cap = 30.** Packing on its own can reach the bottom of `medium`
but never `high`: packers are common in legitimate software (installers,
games, UPX-compressed tools), and a packed file deserves a look, not an alarm.

## Finding catalogue

Entries are added as analyzers land (M2 steps 2–6).

### PE headers (`pe-headers` analyzer)

#### `PE-TIMESTAMP-ZERO`

| | |
|---|---|
| Severity / confidence | Info / Medium (0 points) |
| Category | `anomaly` |
| Trigger | COFF `TimeDateStamp == 0`. |
| Evidence | `field TimeDateStamp = 0` |

**Rationale.** Clearing the link time hides when a sample was built; it is
context for the analyst, not a judgment.
**False positives.** Go binaries always have a zero timestamp; some
reproducible-build pipelines clear it too. Hence Info only.

#### `PE-TIMESTAMP-FUTURE`

| | |
|---|---|
| Severity / confidence | Low / Low (2 points) |
| Category | `anomaly` |
| Trigger | `TimeDateStamp` > analysis time + 24 h. |
| Evidence | `field TimeDateStamp = 0x… (ISO 8601 UTC)` |

**Rationale.** A forged build date is a weak anti-forensics signal.
**False positives.** MSVC `/Brepro` (reproducible builds) stores a hash
instead of a time, which is frequently "in the future". Hence Low/Low.
**Not flagged:** old-but-plausible dates. Borland Delphi linkers write the
constant `0x2A425E19` (1992-06-19), so "too old" would mostly hit Delphi.

#### `PE-CHECKSUM-MISMATCH`

| | |
|---|---|
| Severity / confidence | Info / Medium (0 points) for normal images; Low / High (5 points) for drivers |
| Category | `anomaly` |
| Trigger | Normal image: stored `CheckSum` **non-zero** and ≠ computed. Driver (subsystem `native`): stored `CheckSum` is 0 **or** ≠ computed. |
| Evidence | `field CheckSum`, `field computed` |

**Rationale.** The loader ignores the checksum for user-mode images, so a
mismatch there only shows the file changed after linking. The kernel requires
a correct checksum for drivers, so a bad one is a stronger tampering signal.
**False positives.** Normal images with a checksum of 0 are the default for
most linkers and are **never** flagged. Signing tools and some installers
patch files after linking. Native user-mode images (`smss.exe`, `autochk.exe`)
share the `native` subsystem with drivers and are treated as drivers.
**Algorithm.** Same as `CheckSumMappedFile`: 16-bit folded sum of the file
with the 4-byte `CheckSum` field read as zero, plus the file length.

### PE sections (`pe-sections` analyzer)

All section findings emit **one** finding per ID with every matching section
as evidence. Thresholds live in `Thresholds` (`config.rs`).

#### `PE-SECTION-RWX`

| | |
|---|---|
| Severity / confidence | Medium / Medium (11 points) |
| Category | `anomaly` |
| Trigger | Section has both `IMAGE_SCN_MEM_WRITE` and `IMAGE_SCN_MEM_EXECUTE`. |
| Evidence | `section`, `field Characteristics = 0x… (rwx)` per section |

**Rationale.** Writable code lets a program rewrite itself in place: packers,
self-decrypting loaders, shellcode stubs.
**False positives.** Some old compilers/linkers and legacy protectors, a few
games and JIT-style trampolines. Modern MSVC/Clang/GCC never emit it.

#### `PE-SECTION-NAME-UNUSUAL`

| | |
|---|---|
| Severity / confidence | Info / Low (0 points) |
| Category | `anomaly` |
| Trigger | Name is empty, contains non-printable/non-ASCII characters, or is not in the known-name list and does not start with a known prefix. |
| Evidence | `section` per unusual name |

Known names cover the Microsoft linker (`.text`, `.rdata`, `.pdata`, `.00cfg`,
`_RDATA`, `fothk`, ...), drivers (`INIT`, `PAGE*`), Borland/Delphi (`CODE`,
`DATA`, `BSS`, `.itext`), MinGW/GCC (`.eh_frame`, `.CRT`, DWARF `.debug_*`,
COFF long-name references `/<digits>`) and Go (`.symtab`). Matching is
case-sensitive: `.TEXT` is unusual.
**Rationale.** Packers and protectors name their sections (`UPX0`, `.aspack`,
`.themida`). Specific packer names are reported separately by
`PE-PACKER-KNOWN` (step 6); this finding is context only.
**False positives.** Custom linkers and rare toolchains. Info, 0 points.

#### `PE-SECTION-VIRTUAL-ONLY`

| | |
|---|---|
| Severity / confidence | Medium / Medium (11 points) |
| Category | `packing` |
| Trigger | Executable section with `SizeOfRawData == 0` and `VirtualSize >= virtual_only_min_size` (default 4096). |
| Evidence | `section`, `field VirtualSize` |

**Rationale.** Memory reserved for code that is not in the file is filled at
run time: the unpacking target of UPX-style packers (`UPX0`).
**Not flagged.** `.bss`-style uninitialized data (not executable), and tiny
executable stubs under one page.

#### `PE-SECTION-HIGH-ENTROPY`

| | |
|---|---|
| Severity / confidence | Medium / Medium (11 points) if any matching section is executable; otherwise Low / Low (2 points) |
| Category | `packing` |
| Trigger | Entropy of the section's raw data >= `entropy_high` (default 7.2). Sections with fewer than `section_entropy_min_size` (default 512) raw bytes in the file are skipped. |
| Evidence | `section`, `metric entropy` per section |

**Rationale.** Compiled code sits around 5.5–6.5 bits/byte; packed or
encrypted code approaches 8.
**False positives.** `.rsrc` with PNG/compressed resources, installers and
self-extracting archives carrying compressed data in a data section: hence
the Low/Low variant for non-executable sections. Entropy is computed over
the bytes actually present in the file (`raw_truncated` sections are clipped
at EOF).

#### `PE-ENTRYPOINT-UNUSUAL`

| Situation (first match wins) | Severity / confidence | Points |
|---|---|---|
| EP is 0 or below `SizeOfHeaders` and not in a section (EXE only) | Medium / High | 15 |
| EP outside every section | Medium / High | 15 |
| EP in a non-executable section | Medium / Medium | 11 |
| EP in the last section, which is not the first executable section | Medium / Medium | 11 |
| EP in an executable section other than the first one | Low / Low | 2 |

| | |
|---|---|
| Category | `anomaly` |
| Evidence | `field AddressOfEntryPoint`, `section` containing it (if any), `field first executable section` (if different) |

**Not flagged.** DLLs with `AddressOfEntryPoint == 0` (no `DllMain`,
resource-only DLLs). Managed .NET images (`managed_dotnet`): their entry is a
loader stub, or 0 for PE32+ IL-only assemblies. Single-section images.
**Rationale.** Compilers put the entry point at the start of the first code
section's region; packer stubs usually sit in an appended last section.
**False positives.** Some protectors used by legitimate software (DRM),
and unusual linker layouts (Low/Low variant).

### PE imports (`pe-imports` analyzer)

Imports are parsed by rtriage's own bounded parser (not goblin): at most
`max_import_libraries` (4096) descriptors and `max_imports` (65 536) thunks
**in total per file**, one budget step per loop iteration, names cut at 256
bytes. A table cut short by a limit sets `limit_reached`, reports a
`limit_exceeded` error, and is **not** judged by `PE-IMPORTS-FEW` /
`PE-IMPORTS-DYNAMIC-RESOLUTION` (a partial count would be meaningless).

#### Imphash

`facts.pe.imports.imphash` follows pefile's `get_imphash` exactly:

1. For each library in descriptor order, lowercase the DLL name and strip a
   trailing `.dll`, `.ocx` or `.sys` (other extensions such as `.drv` stay).
2. For each function in thunk order: its name, lowercased; for ordinal-only
   imports, the name from pefile's **frozen** imphash tables for
   `ws2_32.dll` / `wsock32.dll` / `oleaut32.dll`, else `ord<N>`.
3. Join `lib.func` pairs with `,` and take the MD5.

The ordinal tables are generated from pefile's `ordlookup/imphash_*.py`
(MIT) into `crates/rtriage-core/src/analyzers/pe/ordinals.rs`. pefile keeps
those tables frozen for compatibility with VirusTotal, YARA and YARA-X; the
non-frozen tables pefile uses elsewhere differ and must not be used here.
No imported functions → `imphash` is `null`.

#### `PE-IMPORTS-DYNAMIC-RESOLUTION`

| | |
|---|---|
| Severity / confidence | Medium / Medium (11 points) |
| Category | `obfuscation` |
| ATT&CK | T1027.007 (Dynamic API Resolution) |
| Trigger | Imports a loader (`LoadLibraryA/W`, `LoadLibraryExA/W`, `LdrLoadDll`) **and** a resolver (`GetProcAddress`, `LdrGetProcedureAddress`) **and** the table has at most `dynamic_resolution_max_imports` (20) functions. Not evaluated for managed .NET or a limit-truncated table. |
| Evidence | `import` of the loader and the resolver, `field imported functions` |

**Rationale.** A tiny table with a loader and a resolver means the real API
set is looked up at run time, hiding it from import analysis.
**False positives.** Small plugin hosts and launchers. Programs with normal
import tables (e.g. the Go runtime: 40 kernel32 imports including
`LoadLibraryW` + `GetProcAddress`) are above the size limit and not flagged.

#### `PE-IMPORTS-FEW`

| | |
|---|---|
| Severity / confidence | Low / Low (2 points) |
| Category | `anomaly` |
| Trigger | At most `imports_few_max` (10) imported functions, including none at all. |
| Not evaluated | Managed .NET; DLLs with `AddressOfEntryPoint == 0` (resource-only); limit-truncated tables; **files where `PE-IMPORTS-DYNAMIC-RESOLUTION` fired** (the stronger finding already explains the small table). |
| Evidence | `field imported functions`, every imported function |

**False positives.** Tiny utilities built without a C runtime, some drivers.

#### `PE-IMPORTS-ORDINAL-ONLY`

| | |
|---|---|
| Severity / confidence | Low / Low (2 points) |
| Category | `obfuscation` |
| Trigger | A library with at least one import where **every** import is by ordinal, excluding libraries legitimately imported that way: `ws2_32`, `wsock32`, `oleaut32`, `comctl32`, `shlwapi`, `shell32`, `msvbvm50/60`, and any `mfc*` DLL. |
| Evidence | up to 5 `import lib!#N` per library, `field more ordinals` for the rest |

**Rationale.** Importing a private DLL purely by number hides which
functions are used.
**False positives.** Vendor SDK DLLs exported by ordinal only.

### PE API behavior groups (`pe-api-groups` analyzer)

The groups are **data**, in [`rules/api_groups.toml`](../rules/api_groups.toml):
each group's rationale and false positives are written next to its
conditions there. The bundled file is compiled in; `--api-rules <FILE>`
replaces it with a file of the same format (validated strictly: unknown
fields, bad enum values, malformed or duplicate IDs, IDs without the
`PE-API-` prefix and bad API patterns are load errors, exit code 2).

**Matching.** APIs come from the import table: named imports, plus
ordinal-only imports of `ws2_32` / `wsock32` / `oleaut32` resolved to names.
Names are case-sensitive; a trailing `*` matches any suffix. A group fires
once, on its first matching `when` alternative; evidence lists the matched
imports and up to 5 matching strings. Strings are only extracted if some
rule needs them.

| ID | Sev / Conf | Points | Category | ATT&CK | Fires when |
|---|---|---|---|---|---|
| `PE-API-INJECTION` | High / High | 40 | `injection` | T1055 | `OpenProcess` + remote alloc (`VirtualAllocEx`, `NtAllocateVirtualMemory`, ...) + remote write (`WriteProcessMemory`, `NtWriteVirtualMemory`) + remote execution (`CreateRemoteThread*`, `NtCreateThreadEx`, `RtlCreateUserThread`, `QueueUserAPC`, `NtQueueApcThread`) |
| `PE-API-ANTIDEBUG` | Low / Medium | 4 | `anti_analysis` | T1622 | at least **2 different** of `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess`, `NtSetInformationThread`, `OutputDebugString*` |
| `PE-API-PERSISTENCE-REGISTRY` | Medium / Medium | 11 | `persistence` | T1547.001 | registry write (`RegSetValueEx*`, `RegCreateKeyEx*`, `RegSetKeyValue*`, `SHSetValue*`) + a string containing `CurrentVersion\Run`, `...\Policies\Explorer\Run` or `Windows NT\CurrentVersion\Winlogon` |
| `PE-API-PERSISTENCE-SERVICE` | Medium / Low | 6 | `persistence` | T1543.003 | `CreateService*` + `StartService*` |
| `PE-API-NETWORK` | Low / Medium | 4 | `network` | T1071 | WinINet (`InternetOpen*`, ...), WinHTTP (`WinHttpOpen`, ...) or Winsock (`WSAStartup` + `connect`/`WSAConnect*`) + a URL / IPv4 / IPv6 string |
| `PE-API-RANSOM-CRYPTO` | High / Low | 16 | `impact` | T1486 | `CryptEncrypt`/`BCryptEncrypt` + `FindFirstFile*` + `FindNextFile*` + strings mentioning at least **8 different** document/database extensions |
| `PE-API-CREDENTIALS` | Medium / Medium | 11 | `credential_access` | T1555 | `CredEnumerate*` or `LsaEnumerateLogonSessions`; **or** `CryptUnprotectData` + at least **3 different** browser password-store markers (`\Google\Chrome\User Data`, `\Mozilla\Firefox\Profiles`, `logins.json`, `key4.db`, `Login Data`, ...) |
| `PE-API-KEYLOGGING` | Medium / Low | 6 | `collection` | T1056.001 | `SetWindowsHookEx*` + key translation (`GetAsyncKeyState`, `ToUnicode*`, `GetKeyNameText*`, `MapVirtualKey*`, ...); **or** `GetAsyncKeyState` + `GetForegroundWindow` + `GetWindowText*` |

**Why combinations.** Every one of these APIs alone is common in benign
software. Notably the MSVC runtime imports `IsDebuggerPresent` into almost
every program, Chromium-based browsers call `CryptUnprotectData` on their own
`Login Data`, and the Go runtime imports thread-context and memory APIs:
negative tests cover each of these.

**False positives** (per group, also in the rules file): debuggers, profilers
and anti-cheat (injection); DRM and games (anti-debug, keylogging);
installers and "start with Windows" options (registry, service);
any app with a built-in update URL (network); backup/sync tools (ransom);
password managers and browser-migration tools (credentials); hotkey,
accessibility and macro tools (keylogging).

**Known gaps.** APIs resolved at run time (by name strings passed to
`GetProcAddress`) are not seen; `PE-IMPORTS-DYNAMIC-RESOLUTION` covers that
case. Extensions shorter than the minimum string length (`.pdf` alone, 4
characters, with the default of 5) only count when they appear inside a
longer string such as an extension list.

### PE overlay (`pe-overlay` analyzer)

The image ends at the furthest of `SizeOfHeaders` and every section's
`PointerToRawData + SizeOfRawData`. A certificate table (SECURITY directory,
which holds a file offset) starting at or after that point and ending within
the file is skipped: an Authenticode signature is expected trailing data.
Bytes after it are overlay (they are not covered by the signature).
A certificate entry pointing past EOF is ignored rather than trusted.
`kind` is recognised from magic bytes: `pe`, `zip`, `7z`, `rar`, `cab`,
`gzip`, `pdf`, `nsis`, `png`, `jpeg`, `gif`.

| ID | Sev / Conf | Points | Category | Trigger |
|---|---|---|---|---|
| `PE-OVERLAY` | Info / High | 0 | `anomaly` | Overlay present. Evidence: `range`, `field kind`. |
| `PE-OVERLAY-HIGH-ENTROPY` | Low / Medium | 4 | `packing` | Overlay of at least `section_entropy_min_size` bytes with entropy >= `entropy_high`, **and** `kind` is not a compressed format (`zip`, `7z`, `rar`, `cab`, `gzip`, `nsis`, `png`, `jpeg`, `gif`), whose own compression explains the entropy. Evidence: `range`, `metric entropy`. |
| `PE-OVERLAY-EMBEDDED-PE` | Medium / Low | 6 | `anomaly` | Overlay starts with a valid PE (`MZ` + `PE\0\0` at `e_lfanew`). Evidence: `range`. |

**False positives.** Installers and self-extractors (overlay with
compressed data, often in a custom format: high entropy). Embedded PEs:
installers and binders that carry a second program in plain form.

### PE TLS callbacks (`pe-tls` analyzer)

Bounded parser: at most `max_tls_callbacks` (256) callbacks, one budget step
each; VAs are converted with `ImageBase` using checked arithmetic.

#### `PE-TLS-CALLBACKS`

| | |
|---|---|
| Severity / confidence | Low / Medium (4 points) |
| Category | `anti_analysis` |
| Trigger | TLS directory with at least one callback (`AddressOfCallBacks != 0` and a non-empty array). |
| Evidence | `field callback = 0x<VA> in #<i> <section>`, up to 8 |

**Rationale.** Callbacks run before the entry point, which hides code from a
debugger stopped at the entry point; used for anti-debugging and early
unpacking.
**False positives.** Common in benign code: the Rust standard library and
MinGW/GCC runtimes register TLS callbacks for thread-local destructors.
A TLS directory with no callbacks (plain `thread_local` data) is not
flagged.

### PE debug information (`pe-debug` analyzer)

Reads at most `max_debug_entries` (64) debug directory entries and the first
CodeView record (`RSDS` = PDB 7.0 with GUID and age, or `NB10` = PDB 2.0),
capped at 1 KiB.

#### `PE-PDB-PATH`

| | |
|---|---|
| Severity / confidence | Info / High (0 points) |
| Category | `metadata` |
| Trigger | A CodeView record with a non-empty PDB path. |
| Evidence | `field PdbPath`; `field user` when the path contains `\Users\<name>\`, `\Documents and Settings\<name>\` or `/home/<name>/` (not `Public`). |

**Rationale.** Build paths leak user names, project names and build layouts:
useful for attribution and for clustering samples from one build machine.
Pure context, so Info.

### PE packers (`pe-packers` analyzer)

Name and signature matching only; nothing is unpacked or emulated.

#### `PE-PACKER-KNOWN`

| | |
|---|---|
| Severity / confidence | Medium / High (15 points) |
| Category | `packing` |
| Trigger | A section named exactly as a known packer writes it, or a known signature in the first 4 KiB of the headers. |
| Evidence | `field packer`, matching `section`s, `range` + `field signature` for signatures |

| Packer | Section names | Header signature |
|---|---|---|
| UPX | `UPX0`–`UPX3` | `UPX!` |
| ASPack | `.aspack`, `.adata` | |
| Themida/WinLicense | `.themida`, `.winlice` | |
| VMProtect | `.vmp0`–`.vmp2` | |
| MPRESS | `.MPRESS1`, `.MPRESS2` | |
| PECompact | `pec1`–`pec3`, `PEC2*` | |
| Petite | `.petite` | |
| NsPack | `.nsp0`–`.nsp2`, `nsp0`–`nsp2` | |
| Enigma Protector | `.enigma1`, `.enigma2` | |
| kkrunchy | `kkrunchy` | |

Names are case-sensitive (`.upx`, `upx0` do not match). The header signature
lets UPX be recognised even when its sections were renamed.
**False positives.** Legitimate software is packed too (UPX-compressed
tools, commercial protectors for licensing/DRM).

#### `PE-PACKED-LIKELY`

| | |
|---|---|
| Severity / confidence | Medium / Low (6 points) |
| Category | `packing` |
| Trigger | No known packer, not managed .NET, an executable section with at least `section_entropy_min_size` raw bytes and entropy >= `entropy_high`, **and** at most `imports_few_max` (10) imported functions (table not limit-truncated). |
| Evidence | `section`, `metric entropy`, `field imported functions` |

**Rationale.** Custom or modified packers have no known signature but keep
the shape: compressed code, minimal imports.
**False positives.** Small programs embedding encrypted/compressed blobs in
their code section. Low confidence for that reason.

### PE Rich header (`pe-rich` analyzer)

Searched in `0x40..min(e_lfanew, 4 KiB)`; records are XOR-decoded with the
key that follows `Rich`. The key doubles as a checksum: `DanS` offset + every
byte before `DanS` rotated left by its offset (skipping `e_lfanew` at
0x3c..0x40) + every `comp_id` rotated left by its count, mod 2^32.

| ID | Sev / Conf | Points | Category | Trigger |
|---|---|---|---|---|
| `PE-RICH-CHECKSUM-MISMATCH` | Low / Medium | 4 | `anomaly` | Rich header present, recomputed checksum ≠ stored key. Evidence: `field stored key`, `field computed`. |
| `PE-RICH-ABSENT` | Info / Low | 0 | `metadata` | No Rich header, `MajorLinkerVersion` in 6..=14 (MSVC range), not managed .NET. Evidence: `field MajorLinkerVersion`. |

**Rationale.** An edited Rich header means the build-tool fingerprint was
altered after linking, e.g. to plant a false flag (Olympic Destroyer). A
missing one on an MSVC-looking binary means it was stripped.
**False positives.** Mismatch: patchers that touch the DOS header area.
Absent: `lld-link` (Rust with lld, Clang) writes linker version 14 without a
Rich header; the C# compiler writes none either (managed .NET is skipped).
Go (linker 3.x), MinGW (2.x) and Delphi are outside the MSVC range.

### PE exports (`pe-exports` analyzer)

Bounded parser: `NumberOfFunctions` and `NumberOfNames` are each capped at
`max_exports`; every array must map contiguously into one section; a name
whose ordinal index is out of range is ignored. Forwarders are addresses
inside the export directory, read as `DLL.Function` strings.

| ID | Sev / Conf | Points | Category | ATT&CK | Trigger |
|---|---|---|---|---|---|
| `PE-EXPORTS-REFLECTIVE-LOADER` | High / High | 40 | `injection` | T1620 | An export named **exactly** `ReflectiveLoader`, `_ReflectiveLoader@0` or `_ReflectiveLoader@4`. No substring or case-insensitive matching. Evidence: `field export`. |
| `PE-EXPORTS-ALL-FORWARDED` | Low / Low | 2 | `anomaly` | T1574.002 | A DLL with at least 5 exports, all forwarded (table not limit-truncated). Evidence: count and up to 5 forwarders. |
| `PE-EXPORTS-NAME-MISMATCH` | Info / Medium | 0 | `anomaly` | | Export directory DLL name ≠ file name (case-insensitive). Skipped when the file is named like a hash (32/40/64 hex digits before the first dot), as sample stores do. Evidence: both names. |

**Rationale.** `ReflectiveLoader` is the self-mapping entry point of the
reflective DLL injection technique used by Metasploit, Cobalt Strike and
their derivatives; with exact names it is near-certain. All-forwarding DLLs
are proxies for DLL side-loading. A renamed DLL may be posing as another.
**False positives.** Reflective loader: red-team and research builds
(still offensive tooling). Proxies: compatibility shims, game mods,
`api-ms-win-*`-style forwarders. Name mismatch: DLLs renamed by installers.
Reflective loader and `PE-API-INJECTION` share the `injection` cap (40), so a
reflective DLL that also imports the injection chain scores 40 for both.

### PE resources (`pe-resources` analyzer)

Bounded walk: depth 3 (type / name / language), each directory offset
visited once (cycles and shared subdirectories cannot loop or multiply
work), at most `max_resources` (4096) leaves, one budget step per entry.

| ID | Sev / Conf | Points | Category | Trigger |
|---|---|---|---|---|
| `PE-RESOURCE-EMBEDDED-PE` | Medium / Low | 6 | `anomaly` | A resource's data starts with a valid PE (`MZ` + `PE\0\0` at `e_lfanew`); same check and level as `PE-OVERLAY-EMBEDDED-PE`. Evidence: `field resource`. |
| `PE-RESOURCE-HIGH-ENTROPY` | Low / Low | 2 | `packing` | A resource of at least `resource_entropy_min_size` (4096) bytes with entropy >= `entropy_high`, whose type is not image-like (`RT_ICON`, `RT_BITMAP`, `RT_CURSOR`, group/animated variants) and whose content is not a compressed format (`zip`, `png`, ...). Evidence: `field resource`, `metric entropy`. |

**False positives.** Installers and driver packages embed executables;
applications store compressed or encrypted data (licensing blobs, game
assets) as `RT_RCDATA`. Confirmed UPX explains `PE-RESOURCE-HIGH-ENTROPY`
(it compresses resources).

### PE signature (`pe-signature` analyzer)

Structure only: the SECURITY directory's file offset and size, 8-byte
aligned `WIN_CERTIFICATE` entries (at most 16), known revision, and a DER
PKCS#7 SignedData blob (OID `1.2.840.113549.1.7.2` in the first 32 bytes).
**No cryptographic verification.**

| ID | Sev / Conf | Points | Category | Trigger |
|---|---|---|---|---|
| `PE-SIGNED` | Info / High | 0 | `metadata` | Well-formed table with a SignedData entry: "signed (unverified)". Evidence: `range`, `field certificate entries`. |
| `PE-SIGNATURE-MALFORMED` | Low / Medium | 4 | `anomaly` | Table present but past EOF, inside the image, with an invalid/zero length, unknown revision, or no SignedData. Evidence: `range`, one `field problem` per problem. |

**A signature never lowers the risk.** It is not verified, and stolen or
fraudulently obtained certificates are common; rewarding an unverified
signature would give attackers a cheap way to whitewash a file. A test pins
that signing a file leaves its score unchanged.

### ELF headers (`elf-headers` analyzer)

**Program headers are the source of truth** (they are what the loader
uses): an unusable program header table (wrong `e_phentsize`, past EOF,
`e_phnum > max_segments`) is a parse error. Section header problems (wrong
`e_shentsize`, table past EOF, bad `e_shstrndx`, too many sections) are
recorded and analysis continues without sections; they surface as
`ELF-SECTIONS-INCONSISTENT` (step 3). Extended numbering (`PN_XNUM`,
`e_shnum == 0`, `SHN_XINDEX`) is followed through section 0.

#### `ELF-ENTRY-UNUSUAL`

| | |
|---|---|
| Severity / confidence | Medium / High (15 points) |
| Category | `anomaly` |
| Trigger | `e_type` is `EXEC` or `DYN`, `e_entry != 0`, and `e_entry` is not inside a `PT_LOAD` with `PF_X` (either in a non-executable `PT_LOAD`, or outside all of them). |
| Evidence | `field e_entry`, `field segment` (index and permissions) when inside a non-executable load |

**Not judged.** Relocatable objects and core files; `e_entry == 0`
(shared libraries without an entry point).
**False positives.** Practically none for files that actually run; loaders
refuse or crash on such files, so this means crafted or corrupted input.

#### `ELF-INTERP-UNUSUAL`

| Interpreter (`PT_INTERP`) | Severity / confidence | Points |
|---|---|---|
| Relative path, contains `..`, or under `/tmp/`, `/var/tmp/`, `/dev/shm/`, `/run/user/` | Medium / High | 15 |
| Any other absolute path that is not a known loader | Medium / Medium | 11 |

| | |
|---|---|
| Category | `anomaly` |
| Evidence | `field PT_INTERP` |

**Known loaders (never flagged):** a file named `ld-linux*`, `ld64.so.*`,
`ld.so.*`, `ld-musl-*` or `ld-uClibc*` directly in `/lib`, `/lib32`,
`/lib64`, `/libx32`, `/usr/lib`, `/usr/lib32` or `/usr/lib64`; Android
`/system/bin/linker[64]`; FreeBSD `/libexec/ld-elf[32].so.1`; OpenBSD
`/usr/libexec/ld.so`; NetBSD `/usr/libexec/ld.elf_so`; and loaders inside
the **Nix** (`/nix/store/`) and **Guix** (`/gnu/store/`) stores (any depth,
loader file name required).
**Rationale.** The interpreter runs before any program code with full
control of the process; a loader in a writable location is a hijack point.
**False positives.** Vendor toolchains and embedded SDKs shipping their own
loader under `/opt` (Medium/Medium variant).

### ELF segments and sections (`elf-segments` analyzer)

| ID | Sev / Conf | Points | Category | Trigger |
|---|---|---|---|---|
| `ELF-SEGMENT-RWX` | Medium / Medium; **Low / Low on MIPS, 32-bit PowerPC, ARM32** | 11 / 2 | `anomaly` | A `PT_LOAD` with both `PF_W` and `PF_X`. Evidence: `field segment` per segment. |
| `ELF-SEGMENT-HIGH-ENTROPY` | Medium / Medium if any matching segment is executable, else Low / Low | 11 / 2 | `packing` | Entropy of a `PT_LOAD`'s file bytes (`p_filesz`, clipped at EOF, at least `section_entropy_min_size`) >= `entropy_high`. Evidence: `field segment`, `metric entropy`. |
| `ELF-SECTIONS-MISSING` | Low / Medium | 4 | `anomaly` | `EXEC`/`DYN` with no section header table (`e_shoff == 0`) and no section problems. Evidence: `field e_shoff`. |
| `ELF-SECTIONS-INCONSISTENT` | Low / Low | 2 | `anomaly` | `EXEC`/`DYN` with section problems: any recorded by the parser (wrong `e_shentsize`, table past EOF, too many sections, unreadable `e_shstrndx`, `e_shnum` without `e_shoff`), a non-`NOBITS` section past EOF, or an `SHF_ALLOC` section whose address is in no `PT_LOAD`. Evidence: up to 8 `field problem`. |

**Rationale.** RWX segments let code rewrite itself; modern linkers never
emit them. Section headers are irrelevant to the loader, so removing or
corrupting them only hurts analysis tools: sstrip-style tools, packers and
hand-made binaries do it on purpose. Plain `strip` keeps the table.
**False positives.** RWX: legacy toolchains on MIPS, PPC32 (BSS-PLT) and
ARM32 (hence the lower level there), some JIT runtimes. Entropy: binaries
embedding compressed assets. Missing sections: deliberately minimised
embedded firmware. Relocatable objects and core files are not judged.
Confirmed UPX will explain these (M3 step 6).

### Facts that suppress heuristics

- `facts.pe.headers.managed_dotnet`: set when the CLR (COM descriptor) data
  directory is present. Managed assemblies legitimately have a single import
  (`mscoree.dll!_CorExeMain`) and a tiny native entry stub, so import-count
  and entry-point heuristics (steps 3–4) must not fire on them. Covered by
  the `.NET-like` negative fixture profile.
- The `Go-like` negative fixture profile (zero timestamp, `.symtab`, Go build
  ID, kernel32 runtime imports including thread-context and memory APIs) must
  produce only informational findings.

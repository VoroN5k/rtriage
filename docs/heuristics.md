# Heuristics and scoring

Every finding ID, its rationale, thresholds and known false positives are
documented here. IDs are stable: renaming one requires a changelog note.

> Status: the scoring rules below are agreed and fixed; they are implemented
> in M2 step 7. Findings are added to the catalogue as their analyzers land.

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

### Calibration checks

| Scenario | Points | Level |
|---|---|---|
| Single full injection chain (`PE-API-INJECTION`, High/High) | 40 | medium |
| Injection + anti-debug (Low/Medium) | 40 + 4 = 44 | medium |
| Injection + known packer (15) + RWX section (11) | 66 | high |
| Packing signals alone, any number | ≤ 30 | at most medium |
| TLS callbacks (Low/Medium) + anti-debug (Low/Medium) | 4 + 4 = 8 | clean_looking |

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

### Facts that suppress heuristics

- `facts.pe.headers.managed_dotnet`: set when the CLR (COM descriptor) data
  directory is present. Managed assemblies legitimately have a single import
  (`mscoree.dll!_CorExeMain`) and a tiny native entry stub, so import-count
  and entry-point heuristics (steps 3–4) must not fire on them. Covered by
  the `.NET-like` negative fixture profile.
- The `Go-like` negative fixture profile (zero timestamp, `.symtab`, Go build
  ID, kernel32 runtime imports including thread-context and memory APIs) must
  produce only informational findings.
